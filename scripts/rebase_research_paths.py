"""Create a release DB whose research paths target a future managed install root."""

import argparse
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

from command_vault.research import _read_bundle_file


def _regular(path, label):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError(f'{label} must be a regular nonsymlink file')
    return path.resolve(strict=True)


def _directory(path, label):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_dir():
        raise ValueError(f'{label} must be a real nonsymlink directory')
    return path.resolve(strict=True)


def _future_root(path):
    path = Path(path)
    if not path.is_absolute() or path == Path(path.anchor) or any(
        part in ('', '.', '..') or '\\' in part or any(ord(char) < 32 or ord(char) == 127 for char in part)
        for part in path.parts[1:]
    ):
        raise ValueError('Install root must be a safe non-root absolute path')
    normalized = Path(os.path.abspath(path))
    existing = normalized
    while not existing.exists():
        if existing == existing.parent:
            raise ValueError('Install root has no existing ancestor')
        existing = existing.parent
    if any(part.is_symlink() for part in (existing, *existing.parents)) or not existing.is_dir():
        raise ValueError('Install root ancestor must be a real nonsymlink directory')
    return normalized


def _fingerprint(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest(), os.fstat(stream.fileno()).st_size


def _integrity(connection):
    if [row[0] for row in connection.execute('PRAGMA integrity_check').fetchall()] != ['ok']:
        raise ValueError('SQLite integrity check failed')
    if connection.execute('PRAGMA foreign_key_check').fetchall():
        raise ValueError('SQLite foreign key check failed')


def rebase_research_paths(source, destination, current_root, install_root):
    source = _regular(source, 'Source database')
    destination = Path(destination).absolute()
    current_root = _directory(current_root, 'Current research root')
    install_root = _future_root(install_root)
    if destination.resolve() == source or destination.parent.is_symlink() or not destination.parent.is_dir():
        raise ValueError('Destination must be a new file beneath a real directory')
    if any(part.is_symlink() for part in destination.parent.parents):
        raise ValueError('Destination parent must not have symlink ancestors')
    if os.path.lexists(destination):
        raise ValueError('Destination already exists')
    source_before = _fingerprint(source)
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        reserved = os.fstat(descriptor)
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as original:
            original.execute('PRAGMA query_only=ON')
            _integrity(original)
            with closing(sqlite3.connect(destination.as_uri() + '?mode=rw', uri=True)) as target:
                current = destination.lstat()
                if (current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino):
                    raise ValueError('Destination changed after reservation')
                original.backup(target)
    finally:
        os.close(descriptor)
    try:
        root_fd = os.open(current_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with closing(sqlite3.connect(destination.as_uri() + '?mode=rw', uri=True)) as connection:
                connection.row_factory = sqlite3.Row
                if connection.execute('PRAGMA user_version').fetchone()[0] != 2:
                    raise ValueError('Research path rebase requires schema version 2')
                rows = connection.execute(
                    "SELECT id,filepath,content_hash FROM writeups WHERE writeup_type='research' ORDER BY id"
                ).fetchall()
                if not rows:
                    raise ValueError('Source database contains no research documents')
                updates = []
                for row in rows:
                    current = Path(row['filepath'])
                    try:
                        relative = current.resolve(strict=True).relative_to(current_root)
                    except (OSError, ValueError):
                        raise ValueError('Research filepath is outside the current managed root') from None
                    if relative.name != 'document.md':
                        raise ValueError('Research filepath must identify a managed document')
                    data = _read_bundle_file(current_root, root_fd, relative.as_posix(),
                                             limit=20_000_000, label='Managed document')
                    if hashlib.sha256(data).hexdigest() != row['content_hash']:
                        raise ValueError('Managed document hash does not match database')
                    updates.append((str(install_root / relative), row['id']))
                if len({path for path, _ in updates}) != len(updates):
                    raise ValueError('Rebased research paths collide')
                with connection:
                    for filepath, writeup_id in updates:
                        collision = connection.execute(
                            'SELECT id FROM writeups WHERE filepath=? AND id<>?', (filepath, writeup_id)
                        ).fetchone()
                        if collision:
                            raise ValueError('Rebased research path conflicts with another writeup')
                        connection.execute('UPDATE writeups SET filepath=? WHERE id=?', (filepath, writeup_id))
                _integrity(connection)
                changed = connection.execute(
                    "SELECT COUNT(*) FROM writeups WHERE writeup_type='research' AND filepath LIKE ?",
                    (str(install_root) + '/%',),
                ).fetchone()[0]
                if changed != len(rows):
                    raise ValueError('Not every research filepath was rebased')
        finally:
            os.close(root_fd)
        if stat.S_IMODE(destination.stat().st_mode) != 0o600:
            raise ValueError('Release database mode changed')
        return {
            'documents_rebased': len(rows), 'source_sha256': source_before[0],
            'release_sha256': _fingerprint(destination)[0], 'schema_version': 2,
            'integrity_check': 'ok', 'foreign_key_violations': 0,
        }
    finally:
        if _fingerprint(source) != source_before:
            raise ValueError('Source database changed during path rebase')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--current-root', type=Path, required=True)
    parser.add_argument('--install-root', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = rebase_research_paths(**vars(args))
    except (OSError, ValueError, sqlite3.Error):
        raise SystemExit('Research path rebase failed; any reserved destination was preserved for inspection') from None
    import json
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
