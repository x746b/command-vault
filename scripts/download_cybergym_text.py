"""Acquire only declared CyberGym text objects from validated local Git-LFS pointers."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


DATASET_URL = 'https://huggingface.co/datasets/sunblaze-ucb/cybergym'
BATCH_URL = DATASET_URL + '.git/info/lfs/objects/batch'
TEXT_FILES = ('description.txt', 'error.txt', 'patch.diff')
_TASK_ID = re.compile(r'(arvo|oss-fuzz):([A-Za-z0-9][A-Za-z0-9._-]*)\Z')
_POINTER = re.compile(
    rb'version https://git-lfs.github.com/spec/v1\r?\n'
    rb'oid sha256:([0-9a-f]{64})\r?\nsize (0|[1-9][0-9]*)\r?\n?\Z'
)
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_UNSAFE_HEADERS = {'host', 'connection', 'content-length', 'transfer-encoding', 'proxy-authorization',
                   'proxy-connection', 'upgrade', 'trailer', 'te'}
_RETRIES = 3


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        # Signed download actions must not redirect their supplied credentials.
        raise ValueError('Download redirects are not accepted')


def _directory(path, *, create=False):
    path = Path(path).absolute()
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise ValueError('Directory path must not contain symlinks')
        if component.exists() and not component.is_dir():
            raise ValueError('Directory path must contain only directories')
        if create and not component.exists():
            try:
                component.mkdir(mode=0o700)
            except FileExistsError:
                pass
            if component.is_symlink() or not component.is_dir():
                raise ValueError('Directory changed during creation')
    if not path.is_dir():
        raise ValueError('Required directory is missing')
    return path


def _regular_bytes(path, *, max_bytes):
    _directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Input must be a regular nonsymlink file')
        if info.st_size > max_bytes:
            raise ValueError('Input file exceeds its byte limit')
        data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError('Input file exceeds its byte limit')
        return data


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('JSON contains duplicate keys')
        result[key] = value
    return result


def _finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError('JSON must contain finite values')
    if isinstance(value, dict):
        for item in value.values():
            _finite(item)
    elif isinstance(value, list):
        for item in value:
            _finite(item)


def _load_json(data):
    try:
        value = json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=_json_pairs)
        _finite(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Input must contain finite UTF-8 JSON') from None


def _selection(pointer_root, limit):
    tasks_bytes = _regular_bytes(pointer_root / 'tasks.json', max_bytes=16 * 1024 * 1024)
    tasks = _load_json(tasks_bytes)
    if not isinstance(tasks, list):
        raise ValueError('Task metadata must be a list')
    selected = {}
    for record in tasks:
        identifier = record.get('task_id') if isinstance(record, dict) else None
        match = _TASK_ID.fullmatch(identifier) if isinstance(identifier, str) else None
        if match is None or identifier in selected:
            raise ValueError('Task IDs must be unique safe arvo or oss-fuzz identifiers')
        selected[identifier] = match.groups()
    ordered = sorted(selected)
    if limit is not None:
        ordered = ordered[:limit]
    objects = []
    for identifier in ordered:
        namespace, task = selected[identifier]
        for filename in TEXT_FILES:
            relative = f'data/{namespace}/{task}/{filename}'
            data = _regular_bytes(pointer_root / relative, max_bytes=512)
            match = _POINTER.fullmatch(data)
            if match is None:
                raise ValueError('Selected text source must be an exact Git-LFS v1 SHA-256 pointer')
            objects.append({'path': relative, 'oid': match[1].decode('ascii'), 'size': int(match[2])})
    return tasks_bytes, len(ordered), objects


def _existing_matches(path, size, digest):
    if not os.path.lexists(path):
        return False
    _directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Existing output must be a regular nonsymlink file')
        if info.st_size != size:
            raise ValueError('Existing output does not match its declared size and SHA-256')
        actual_hash = hashlib.sha256()
        remaining = size
        while remaining:
            block = stream.read(min(65_536, remaining))
            if not block:
                raise ValueError('Existing output does not match its declared size and SHA-256')
            remaining -= len(block)
            actual_hash.update(block)
        if stream.read(1) or actual_hash.hexdigest() != digest:
            raise ValueError('Existing output does not match its declared size and SHA-256')
    return True


def _publish(path, blocks, size, digest):
    """Publish only verified bytes, without replacing even a concurrent arrival."""
    _directory(path.parent, create=True)
    temporary = path.parent / ('.cybergym-' + uuid.uuid4().hex + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        actual_size = 0
        actual_hash = hashlib.sha256()
        with os.fdopen(descriptor, 'wb') as destination:
            for block in blocks:
                if not isinstance(block, bytes):
                    raise ValueError('Download stream must contain bytes')
                actual_size += len(block)
                if actual_size > size:
                    raise ValueError('Downloaded object exceeds its declared size')
                actual_hash.update(block)
                destination.write(block)
            if actual_size != size or actual_hash.hexdigest() != digest:
                raise ValueError('Downloaded object does not match its declared size and SHA-256')
            destination.flush()
            os.fsync(destination.fileno())
        # Hard-link publication is atomic and fails if the destination exists.
        # Both names are in the same directory/filesystem; no destination is replaced.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def _save_exact(path, data):
    digest = hashlib.sha256(data).hexdigest()
    if not _existing_matches(path, len(data), digest):
        _publish(path, (data,), len(data), digest)


def _retry_delay(headers):
    value = headers.get('Retry-After', '') if headers is not None else ''
    try:
        delay = float(value)
        if not math.isfinite(delay):
            return 60.0
    except (TypeError, ValueError):
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            delay = (when - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            delay = 1.0
    return min(60.0, max(0.0, delay))


def _open(opener, request):
    for attempt in range(_RETRIES + 1):
        try:
            return opener.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            delay = _retry_delay(error.headers)
            retry = error.code == 429 or 500 <= error.code <= 599
            error.close()
            if not retry or attempt == _RETRIES:
                raise ValueError('HTTP acquisition failed') from None
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == _RETRIES:
                raise ValueError('HTTP acquisition failed') from None
            time.sleep(1)


def _download_actions(opener, objects):
    request = urllib.request.Request(BATCH_URL, method='POST', data=json.dumps({
        'operation': 'download', 'transfers': ['basic'],
        'objects': [{'oid': item['oid'], 'size': item['size']} for item in objects],
    }).encode('utf-8'), headers={'Content-Type': 'application/vnd.git-lfs+json', 'Accept': 'application/vnd.git-lfs+json'})
    with closing(_open(opener, request)) as response:
        data = response.read(4_194_305)
    if len(data) > 4_194_304:
        raise ValueError('Git-LFS batch response exceeds its size limit')
    result = _load_json(data)
    expected = {item['oid']: item['size'] for item in objects}
    rows = result.get('objects') if isinstance(result, dict) else None
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError('Git-LFS batch object inventory does not match the request')
    actions = {}
    for item in rows:
        if (not isinstance(item, dict) or not isinstance(item.get('oid'), str)
                or item.get('oid') not in expected or item['oid'] in actions
                or type(item.get('size')) is not int or item['size'] != expected[item['oid']] or 'error' in item):
            raise ValueError('Git-LFS batch object does not match the request')
        action = item.get('actions', {}).get('download') if isinstance(item.get('actions'), dict) else None
        href = action.get('href') if isinstance(action, dict) else None
        try:
            parsed = urllib.parse.urlsplit(href) if isinstance(href, str) else None
            if (parsed is None or parsed.scheme != 'https' or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or any(ord(char) < 32 or ord(char) == 127 for char in href)):
                raise ValueError()
            parsed.port
        except ValueError:
            raise ValueError('Git-LFS download action must be a valid HTTPS URL without userinfo') from None
        headers = action.get('header', {})
        if not isinstance(headers, dict) or any(
            not isinstance(key, str) or not _HEADER.fullmatch(key) or key.lower() in _UNSAFE_HEADERS
            or not isinstance(value, str) or any(ord(char) < 32 or ord(char) > 126 for char in value)
            for key, value in headers.items()
        ):
            raise ValueError('Git-LFS download action contains unsafe headers')
        actions[item['oid']] = (href, headers)
    return actions


def build(pointer_root: Path, output: Path, revision: str, limit=None, batch_size=100, dry_run=False) -> dict:
    if not isinstance(revision, str) or re.fullmatch(r'[0-9a-f]{40}', revision) is None:
        raise ValueError('Revision must be 40 lowercase hexadecimal characters')
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError('Task limit must be positive')
    if type(batch_size) is not int or not 1 <= batch_size <= 100:
        raise ValueError('Batch size must be 1..100')
    pointer_root = _directory(pointer_root)
    tasks_bytes, task_count, objects = _selection(pointer_root, limit)
    report = {'selected_tasks': task_count, 'objects': len(objects), 'bytes': sum(item['size'] for item in objects),
              'downloaded': 0, 'skipped': 0, 'revision': revision}
    if dry_run:
        return report
    output = _directory(output, create=True)
    _save_exact(output / 'tasks.json', tasks_bytes)
    pending = []
    for item in objects:
        if _existing_matches(output / item['path'], item['size'], item['oid']):
            report['skipped'] += 1
        else:
            pending.append(item)
    opener = urllib.request.build_opener(_NoRedirect())
    for offset in range(0, len(pending), batch_size):
        batch = pending[offset:offset + batch_size]
        unique = {item['oid']: item for item in batch}
        if any(unique[item['oid']]['size'] != item['size'] for item in batch):
            raise ValueError('Repeated Git-LFS object has conflicting declared sizes')
        actions = _download_actions(opener, list(unique.values()))
        for item in batch:
            href, headers = actions[item['oid']]
            request = urllib.request.Request(href, headers=headers)
            with closing(_open(opener, request)) as response:
                def blocks():
                    while True:
                        block = response.read(65_536)
                        if not block:
                            break
                        yield block
                _publish(output / item['path'], blocks(), item['size'], item['oid'])
            report['downloaded'] += 1
    manifest = {'dataset_url': DATASET_URL, 'revision': revision, 'objects': objects}
    _save_exact(output / 'acquisition-manifest.json',
                (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pointer-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--batch-size', type=int, default=100)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        report = build(args.pointer_root, args.output, args.revision, args.limit, args.batch_size, args.dry_run)
    except (ValueError, OSError):
        raise SystemExit('Text acquisition failed; completed verified objects were preserved') from None
    print(json.dumps(report, indent=2, sort_keys=True))
    return report


if __name__ == '__main__':
    main()
