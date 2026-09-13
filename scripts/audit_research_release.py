"""Read-only audit of a schema-v2 research candidate and its managed corpus.

The only side effect is a new, create-only manifest directory.  Input files,
the database, and the managed corpus are never opened for writing.
"""

import argparse
import ctypes
import datetime as _datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import secrets
from typing import Any

from command_vault.research import DocumentSnapshot, load_research_bundle, read_document_snapshot


DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_FILE_BYTES = 33_554_432
DEFAULT_MAX_TOTAL_BYTES = 536_870_912
DEFAULT_MAX_SNAPSHOT_BYTES = 8_388_608


def _fail(message: str) -> None:
    # Do not put paths, untrusted database fields, or source contents in errors.
    raise ValueError(message)


def _limit(value: int, label: str) -> None:
    if type(value) is not int or value < 0:
        _fail(f'{label} must be a nonnegative integer')


def _absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _real_ancestors(path: Path) -> None:
    """Require the lexical path and every existing ancestor to be non-symlinks."""
    for component in (path, *path.parents):
        try:
            info = os.lstat(component)
        except OSError:
            _fail('Required input path is unavailable')
        if stat.S_ISLNK(info.st_mode):
            _fail('Symlinked input paths are not permitted')


def _regular_input(path: str | Path, label: str) -> Path:
    result = _absolute(path)
    _real_ancestors(result)
    try:
        info = os.lstat(result)
    except OSError:
        _fail(f'{label} must be an existing regular nonsymlink file')
    if not stat.S_ISREG(info.st_mode):
        _fail(f'{label} must be an existing regular nonsymlink file')
    return result


def _directory_input(path: str | Path, label: str) -> Path:
    result = _absolute(path)
    _real_ancestors(result)
    try:
        info = os.lstat(result)
    except OSError:
        _fail(f'{label} must be an existing real directory')
    if not stat.S_ISDIR(info.st_mode):
        _fail(f'{label} must be an existing real directory')
    return result


def _safe_relative(path: Path) -> str:
    parts = path.parts
    if (not parts or path.is_absolute() or any(
        part in ('', '.', '..') or '\\' in part or any(ord(char) < 32 or ord(char) == 127 for char in part)
        for part in parts
    )):
        _fail('Managed corpus contains an unsafe relative path')
    return path.as_posix()


def _safe_read(path: Path, size: int, *, expected_identity: tuple[int, int] | None = None) -> bytes:
    """Read a fixed regular file through a no-follow descriptor and detect swaps."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size:
            _fail('Input file changed or is not regular')
        if expected_identity is not None and (before.st_dev, before.st_ino) != expected_identity:
            _fail('Input file changed during audit')
        data = bytearray()
        while len(data) < size:
            chunk = os.read(descriptor, min(1_048_576, size - len(data)))
            if not chunk:
                _fail('Input file changed during audit')
            data.extend(chunk)
        if os.read(descriptor, 1):
            _fail('Input file changed during audit')
        after = os.fstat(descriptor)
        current = os.lstat(path)
        if (after.st_dev, after.st_ino, after.st_size) != (before.st_dev, before.st_ino, before.st_size) or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            _fail('Input file changed during audit')
        return bytes(data)
    except OSError:
        _fail('Input file cannot be read safely')
    finally:
        if 'descriptor' in locals():
            os.close(descriptor)


def _sha256_file(path: Path, size: int, *, expected_identity: tuple[int, int] | None = None) -> str:
    digest = hashlib.sha256()
    digest.update(_safe_read(path, size, expected_identity=expected_identity))
    return digest.hexdigest()


def _enumerate_corpus(root: Path, *, max_files: int, max_file_bytes: int, max_total_bytes: int) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    total = 0
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            target = current_path / name
            try:
                info = os.lstat(target)
            except OSError:
                _fail('Managed corpus directory cannot be inspected')
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                _fail('Managed corpus must contain only real directories and regular files')
        for name in names:
            target = current_path / name
            try:
                info = os.lstat(target)
            except OSError:
                _fail('Managed corpus file cannot be inspected')
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                _fail('Managed corpus must contain only real directories and regular files')
            relative = _safe_relative(target.relative_to(root))
            if info.st_size > max_file_bytes:
                _fail('Managed corpus file exceeds byte limit')
            total += info.st_size
            if total > max_total_bytes:
                _fail('Managed corpus total exceeds byte limit')
            if len(files) >= max_files:
                _fail('Managed corpus file count exceeds limit')
            files[relative] = {'path': relative, 'size': info.st_size,
                               'sha256': _sha256_file(target, info.st_size, expected_identity=(info.st_dev, info.st_ino))}
    return dict(sorted(files.items()))


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def _write_file(directory_fd: int, name: str, data: bytes) -> str:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(data).hexdigest()


def _rename_noreplace(parent_fd: int, source_name: str, destination_name: str) -> None:
    """Use Linux renameat2's NOREPLACE form; silently unsafe fallbacks are forbidden."""
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        _fail('Atomic no-replace publication is unavailable on this platform')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    result = function(parent_fd, os.fsencode(source_name), parent_fd, os.fsencode(destination_name), 1)
    if result:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            _fail('Output directory already exists')
        _fail('Atomic release manifest publication failed')


def _query_count(connection: sqlite3.Connection, sql: str, values: tuple = ()) -> int:
    return int(connection.execute(sql, values).fetchone()[0])


def _database_audit(connection: sqlite3.Connection, root: Path, files: dict[str, dict[str, Any]], *,
                    max_snapshot_bytes: int, max_file_bytes: int, max_total_bytes: int) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    connection.row_factory = sqlite3.Row
    if connection.execute('PRAGMA user_version').fetchone()[0] != 2:
        _fail('Candidate database does not use schema version 2')
    rows = [tuple(row) for row in connection.execute('PRAGMA integrity_check').fetchall()]
    if rows != [('ok',)]:
        _fail('SQLite integrity check failed')
    foreign_keys = [tuple(row) for row in connection.execute('PRAGMA foreign_key_check').fetchall()]
    if foreign_keys:
        _fail('Candidate database contains foreign key violations')
    duplicate = _query_count(connection, '''SELECT COUNT(*) FROM (
        SELECT source_collection_id, external_id, writeup_type FROM writeups
        WHERE writeup_type='research' GROUP BY source_collection_id, external_id, writeup_type HAVING COUNT(*) > 1
    )''')
    if duplicate:
        _fail('Candidate database contains duplicate research identities')
    research = connection.execute('''SELECT w.id,w.filepath,w.external_id,w.domain,w.document_kind,w.upstream_url,
        w.content_hash,sc.name AS source_name,sc.revision AS source_revision,sc.source_kind,
        ds.content_blob,ds.compression,ds.content_hash AS snapshot_hash,ds.uncompressed_bytes
        FROM writeups w LEFT JOIN source_collections sc ON sc.id=w.source_collection_id
        LEFT JOIN document_snapshots ds ON ds.writeup_id=w.id WHERE w.writeup_type='research' ORDER BY w.id''').fetchall()
    bundle_info: dict[str, dict[str, Any]] = {}
    for row in research:
        if any(row[field] is None or row[field] == '' for field in ('source_name', 'source_revision', 'upstream_url', 'external_id', 'content_hash')) or row['source_kind'] != 'research':
            _fail('Research source provenance is incomplete')
        if row['content_blob'] is None:
            _fail('Research document snapshot is missing')
        stored = Path(row['filepath'])
        if not stored.is_absolute():
            _fail('Research document path is not a managed absolute path')
        try:
            resolved = stored.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (OSError, ValueError):
            _fail('Research document is not a real managed descendant')
        reltext = _safe_relative(relative)
        if resolved.name != 'document.md' or reltext not in files:
            _fail('Research document is absent from the managed corpus')
        # All corpus symlinks have already been rejected.  This check also closes
        # a database path that references a different lexical spelling.
        if files[reltext]['sha256'] != row['content_hash']:
            _fail('Managed research document hash does not match the database')
        try:
            snapshot = DocumentSnapshot(row['content_blob'], row['compression'], row['snapshot_hash'], row['uncompressed_bytes'])
            document = read_document_snapshot(snapshot, max_uncompressed_bytes=max_snapshot_bytes).encode('utf-8')
        except (TypeError, ValueError):
            _fail('Research document snapshot is invalid')
        if hashlib.sha256(document).hexdigest() != files[reltext]['sha256'] or row['snapshot_hash'] != row['content_hash']:
            _fail('Research document snapshot does not match managed content')
        bundle_relative = str(Path(reltext).parent)
        if bundle_relative in bundle_info:
            _fail('Multiple research rows reference one managed document')
        bundle_info[bundle_relative] = {'row': row, 'document_relative': reltext}
    # Every directory with a manifest is a bundle.  It must be fully declared,
    # loader-valid, and matched to exactly one database research document.
    manifests = [key for key in files if Path(key).name == 'manifest.json']
    manifest_bundles = {str(Path(path).parent) for path in manifests}
    files_by_bundle: dict[str, set[str]] = {bundle: set() for bundle in manifest_bundles}
    for path in files:
        parts = Path(path).parts
        if len(parts) < 3:
            _fail('Managed research file is outside a declared bundle')
        bundle_relative = Path(*parts[:2]).as_posix()
        if bundle_relative not in files_by_bundle:
            _fail('Managed research file is outside a declared bundle')
        files_by_bundle[bundle_relative].add(Path(*parts[2:]).as_posix())
    for manifest_relative in manifests:
        bundle_relative = str(Path(manifest_relative).parent)
        if bundle_relative not in bundle_info:
            _fail('Managed research bundle is not represented in the database')
        bundle_root = root / bundle_relative
        try:
            loaded = load_research_bundle(bundle_root, max_manifest_bytes=max_file_bytes,
                                          max_document_bytes=max_snapshot_bytes,
                                          max_artifact_bytes=max_file_bytes,
                                          max_total_artifact_bytes=max_total_bytes)
        except (OSError, ValueError):
            _fail('Managed research bundle is invalid')
        allowed = {'manifest.json', 'document.md', *(item.path for item in loaded.manifest.artifacts)}
        actual = files_by_bundle[bundle_relative]
        if actual != allowed:
            _fail('Managed research bundle contains undeclared files')
        info = bundle_info[bundle_relative]
        row = info['row']
        if (loaded.manifest.source.name != row['source_name'] or loaded.manifest.source.revision != row['source_revision']
                or str(loaded.manifest.source.upstream_url) != row['upstream_url']
                or loaded.manifest.external_id != row['external_id']
                or loaded.document_sha256 != row['content_hash']):
            _fail('Managed research manifest does not match database provenance')
        for artifact in loaded.artifacts:
            relative = _safe_relative(artifact.path.relative_to(root))
            if files.get(relative, {}).get('sha256') != artifact.sha256 or files[relative]['size'] != artifact.size:
                _fail('Managed research artifact hash does not match enumerated content')
        info.update({'source': loaded.manifest.source.name, 'revision': loaded.manifest.source.revision,
                     'external_id': loaded.manifest.external_id, 'content_hash': loaded.document_sha256})
    if set(bundle_info) != manifest_bundles:
        _fail('Research database document has no managed bundle')
    scripts = connection.execute('''SELECT s.id,s.writeup_id,s.code,s.artifact_hash,s.normalized_hash
        FROM scripts s JOIN writeups w ON w.id=s.writeup_id WHERE w.writeup_type='research' ORDER BY s.id''').fetchall()
    for script in scripts:
        try:
            code = script['code'].encode('utf-8', errors='strict')
        except (AttributeError, UnicodeEncodeError):
            _fail('Research script code is not valid UTF-8')
        normalized = '\n'.join(line.rstrip() for line in script['code'].replace('\r\n', '\n').split('\n')).strip('\n').encode('utf-8')
        if (not isinstance(script['artifact_hash'], str) or not isinstance(script['normalized_hash'], str)
                or hashlib.sha256(code).hexdigest() != script['artifact_hash']
                or hashlib.sha256(normalized).hexdigest() != script['normalized_hash']):
            _fail('Research script hashes do not match stored code')
        evidence = _query_count(connection, """SELECT COUNT(*) FROM evidence_links
            WHERE writeup_id=? AND script_id=? AND source_anchor_hash IS NOT NULL AND source_anchor_hash<>''""",
                                (script['writeup_id'], script['id']))
        validation = _query_count(connection, '''SELECT COUNT(*) FROM validation_records
            WHERE artifact_kind='script' AND artifact_id=?''', (script['id'],))
        if not evidence or not validation:
            _fail('Research script provenance or validation is incomplete')
    orphan = _query_count(connection, '''SELECT COUNT(*) FROM evidence_links e JOIN writeups w ON w.id=e.writeup_id
        WHERE w.writeup_type='research' AND NOT (
          (e.command_id IS NOT NULL AND e.script_id IS NULL AND e.chunk_id IS NULL AND EXISTS(SELECT 1 FROM commands x WHERE x.id=e.command_id AND x.writeup_id=e.writeup_id)) OR
          (e.script_id IS NOT NULL AND e.command_id IS NULL AND e.chunk_id IS NULL AND EXISTS(SELECT 1 FROM scripts x WHERE x.id=e.script_id AND x.writeup_id=e.writeup_id)) OR
          (e.chunk_id IS NOT NULL AND e.command_id IS NULL AND e.script_id IS NULL AND EXISTS(SELECT 1 FROM writeup_chunks x WHERE x.id=e.chunk_id AND x.writeup_id=e.writeup_id))
        )''')
    if orphan:
        _fail('Research evidence contains orphaned references')
    tables = ('writeups', 'commands', 'scripts', 'writeup_chunks', 'source_collections', 'document_snapshots',
              'vulnerabilities', 'operational_stages', 'evidence_links', 'mitigations', 'validation_records')
    counts = {table: _query_count(connection, f'SELECT COUNT(*) FROM {table}') for table in tables}
    counts['research_writeups'] = len(research)
    counts['legacy_writeups'] = counts['writeups'] - len(research)
    def grouped(sql: str) -> dict[str, int]:
        return {str(row[0]): int(row[1]) for row in connection.execute(sql).fetchall() if row[0] not in (None, '')}
    aggregates = {
        'counts': counts,
        'writeup_types': grouped('SELECT writeup_type,COUNT(*) FROM writeups GROUP BY writeup_type ORDER BY writeup_type'),
        'by_source': grouped("SELECT sc.name,COUNT(*) FROM writeups w JOIN source_collections sc ON sc.id=w.source_collection_id WHERE w.writeup_type='research' GROUP BY sc.name ORDER BY sc.name"),
        'by_domain': grouped("SELECT domain,COUNT(*) FROM writeups WHERE writeup_type='research' GROUP BY domain ORDER BY domain"),
        'validation_statuses': grouped('SELECT status,COUNT(*) FROM validation_records GROUP BY status ORDER BY status'),
        'script_languages': grouped("SELECT language,COUNT(*) FROM scripts s JOIN writeups w ON w.id=s.writeup_id WHERE w.writeup_type='research' GROUP BY language ORDER BY language"),
        'stage_classes': grouped('SELECT stage_class,COUNT(*) FROM operational_stages GROUP BY stage_class ORDER BY stage_class'),
        'evidence_roles': grouped('SELECT evidence_role,COUNT(*) FROM evidence_links GROUP BY evidence_role ORDER BY evidence_role'),
        'mitigation_states': grouped('SELECT state,COUNT(*) FROM vulnerability_mitigations GROUP BY state ORDER BY state'),
        'source_revisions': grouped("SELECT name || '@' || revision,COUNT(*) FROM source_collections WHERE source_kind='research' GROUP BY name,revision ORDER BY name,revision"),
    }
    return aggregates, bundle_info


def audit_research_release(database: str | Path, research_root: str | Path, output: str | Path, *, application_commit: str,
                           baseline_sha256: str, sources_lock: str | Path, generated_at: str | None = None,
                           max_files: int = DEFAULT_MAX_FILES, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                           max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES, max_snapshot_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES) -> dict[str, Any]:
    if not isinstance(application_commit, str) or not __import__('re').fullmatch(r'[0-9a-f]{40}', application_commit):
        _fail('Application commit must be 40 lowercase hexadecimal characters')
    if not isinstance(baseline_sha256, str) or not __import__('re').fullmatch(r'[0-9a-f]{64}', baseline_sha256):
        _fail('Baseline SHA-256 must be 64 lowercase hexadecimal characters')
    for value, label in ((max_files, 'max_files'), (max_file_bytes, 'max_file_bytes'),
                         (max_total_bytes, 'max_total_bytes'), (max_snapshot_bytes, 'max_snapshot_bytes')):
        _limit(value, label)
    db_path = _regular_input(database, 'Database')
    if stat.S_IMODE(os.stat(db_path, follow_symlinks=False).st_mode) != 0o600:
        _fail('Candidate database mode must be exactly 0600')
    root = _directory_input(research_root, 'Research root')
    lock_path = _regular_input(sources_lock, 'Sources lock')
    output_path = _absolute(output)
    parent = _directory_input(output_path.parent, 'Output parent')
    if os.path.lexists(output_path):
        _fail('Output directory already exists')
    db_info = os.lstat(db_path)
    database_before = (_sha256_file(db_path, db_info.st_size, expected_identity=(db_info.st_dev, db_info.st_ino)), db_info.st_size)
    lock_info = os.lstat(lock_path)
    lock_bytes = _safe_read(lock_path, lock_info.st_size, expected_identity=(lock_info.st_dev, lock_info.st_ino))
    try:
        json.loads(lock_bytes.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _fail('Sources lock must contain finite UTF-8 JSON')
    files = _enumerate_corpus(root, max_files=max_files, max_file_bytes=max_file_bytes, max_total_bytes=max_total_bytes)
    try:
        connection = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
        connection.execute('PRAGMA query_only=ON')
        aggregates, bundles = _database_audit(connection, root, files, max_snapshot_bytes=max_snapshot_bytes,
                                               max_file_bytes=max_file_bytes, max_total_bytes=max_total_bytes)
    except sqlite3.Error:
        _fail('Candidate database cannot be audited read-only')
    finally:
        if 'connection' in locals():
            connection.close()
    db_after = os.lstat(db_path)
    if database_before != (_sha256_file(db_path, db_after.st_size, expected_identity=(db_after.st_dev, db_after.st_ino)), db_after.st_size):
        _fail('Candidate database changed during audit')
    corpus_files = []
    for relative, entry in files.items():
        item = dict(entry)
        parts = Path(relative).parts
        bundle = bundles.get(Path(*parts[:2]).as_posix()) if len(parts) >= 3 else None
        if bundle:
            item.update({
                'source': bundle['source'], 'revision': bundle['revision'],
                'external_id': bundle['external_id'], 'document_content_hash': bundle['content_hash'],
            })
        corpus_files.append(item)
    db_manifest = {'schema_version': 1, 'database': {'path': db_path.name, 'size': database_before[1], 'sha256': database_before[0], 'mode': '0600'},
                   'schema': 2, 'baseline_sha256': baseline_sha256, 'application_commit': application_commit, **aggregates}
    corpus_manifest = {'schema_version': 1, 'files': corpus_files, 'file_count': len(corpus_files),
                       'total_bytes': sum(item['size'] for item in corpus_files)}
    timestamp = generated_at if generated_at is not None else _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary_name = f'.audit-release-{secrets.token_hex(16)}'
    try:
        os.mkdir(temporary_name, 0o700, dir_fd=parent_fd)
        temporary_fd = os.open(temporary_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError:
        os.close(parent_fd)
        _fail('Cannot reserve release manifest output')
    try:
        os.fchmod(temporary_fd, 0o700)
        component_hashes = {
            'DB-MANIFEST.json': _write_file(temporary_fd, 'DB-MANIFEST.json', _json_bytes(db_manifest)),
            'RESEARCH-CORPUS-MANIFEST.json': _write_file(temporary_fd, 'RESEARCH-CORPUS-MANIFEST.json', _json_bytes(corpus_manifest)),
            'integrity-check.txt': _write_file(temporary_fd, 'integrity-check.txt', b'ok\n'),
            'foreign-key-check.txt': _write_file(temporary_fd, 'foreign-key-check.txt', b'no violations\n'),
            'schema-version.txt': _write_file(temporary_fd, 'schema-version.txt', b'2\n'),
            'application-commit.txt': _write_file(temporary_fd, 'application-commit.txt', (application_commit + '\n').encode('ascii')),
            'SOURCES.lock.json': _write_file(temporary_fd, 'SOURCES.lock.json', lock_bytes),
        }
        release = {'schema_version': 1, 'status': 'pre-promotion', 'generated_at': timestamp,
                   'components': {name: {'sha256': digest} for name, digest in sorted(component_hashes.items())},
                   'counts': {'corpus_files': len(corpus_files), 'research_documents': aggregates['counts']['research_writeups']},
                   'pending_decisions': ['external_vm_snapshot_identifier', 'durable_destination_outside_revert_boundary',
                                         'explicit_push_approval', 'explicit_promotion_approval',
                                         'p95_investigation_disposition_accepted']}
        release_hash = _write_file(temporary_fd, 'RELEASE-MANIFEST.json', _json_bytes(release))
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        _rename_noreplace(parent_fd, temporary_name, output_path.name)
        os.fsync(parent_fd)
    except Exception:
        if 'temporary_fd' in locals() and temporary_fd is not None:
            for name in ('DB-MANIFEST.json', 'RESEARCH-CORPUS-MANIFEST.json', 'integrity-check.txt', 'foreign-key-check.txt',
                         'schema-version.txt', 'application-commit.txt', 'SOURCES.lock.json', 'RELEASE-MANIFEST.json'):
                try:
                    os.unlink(name, dir_fd=temporary_fd)
                except FileNotFoundError:
                    pass
            os.close(temporary_fd)
        try:
            os.rmdir(temporary_name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(parent_fd)
    return {'release_manifest_sha256': release_hash, 'counts': release['counts'], 'aggregates': aggregates}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--research-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--application-commit', required=True)
    parser.add_argument('--baseline-sha256', required=True)
    parser.add_argument('--sources-lock', type=Path, required=True)
    parser.add_argument('--generated-at')
    args = parser.parse_args(argv)
    try:
        report = audit_research_release(**vars(args))
    except (OSError, ValueError, sqlite3.Error):
        raise SystemExit('Research release audit failed; no release manifest was published') from None
    print(json.dumps({'counts': report['counts'], 'release_manifest_sha256': report['release_manifest_sha256']}, sort_keys=True))
    return report


if __name__ == '__main__':
    main()
