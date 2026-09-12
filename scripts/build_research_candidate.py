"""Create a separate research candidate through SQLite backup and validated import."""

import argparse
from collections import Counter
from collections.abc import Sequence
from contextlib import closing
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

from command_vault.database import Database
from command_vault.research_indexer import ResearchIndexer


def _fingerprint(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        size = os.fstat(stream.fileno()).st_size
    return digest, size


def _real_directory(path):
    for component in (path, *path.parents):
        if component.is_symlink() or not component.is_dir():
            raise ValueError('Candidate parent must be an existing directory without symlink ancestors')


def _integrity(connection):
    rows = connection.execute('PRAGMA integrity_check').fetchall()
    if rows != [('ok',)]:
        raise ValueError('SQLite integrity check failed')
    return 'ok'


def build_candidate(baseline: Path, candidate: Path, bundles: Path | Sequence[Path], managed_root: Path | None = None) -> dict:
    baseline = Path(baseline).absolute()
    candidate = Path(candidate).absolute()
    if isinstance(bundles, (str, os.PathLike)):
        bundles = [bundles]
    elif not isinstance(bundles, Sequence) or not bundles:
        raise ValueError('Supply at least one bundle collection directory')
    collection_roots = []
    for collection in bundles:
        if not isinstance(collection, (str, os.PathLike)):
            raise ValueError('Bundle collections must be directory paths')
        collection_root = ResearchIndexer._managed_directory(collection)
        if collection_root in collection_roots:
            raise ValueError('Duplicate canonical bundle collection directory')
        collection_roots.append(collection_root)
    if managed_root is not None:
        managed_root = ResearchIndexer._managed_directory(managed_root)
        if any(not root.is_relative_to(managed_root) for root in collection_roots):
            raise ValueError('Bundles must be under the managed root')
    if baseline.is_symlink() or not baseline.is_file():
        raise ValueError('Baseline must be an existing nonsymlink regular file')
    if candidate.resolve() == baseline.resolve():
        raise ValueError('Candidate must not be the baseline')
    _real_directory(candidate.parent)
    if os.path.lexists(candidate):
        raise ValueError('Candidate already exists; refusing to overwrite')
    baseline_hash, baseline_size = _fingerprint(baseline)
    try:
        with closing(sqlite3.connect(baseline.as_uri() + '?mode=ro', uri=True)) as source:
            source.execute('PRAGMA query_only=ON')
            _integrity(source)
            # Reservation is atomic: competing writers cannot cause an existing
            # candidate to be opened and overwritten by this builder.
            descriptor = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                reserved = os.fstat(descriptor)
                with closing(sqlite3.connect(candidate.as_uri() + '?mode=rw', uri=True)) as destination:
                    current = candidate.lstat()
                    if (current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino):
                        raise ValueError('Candidate changed after reservation')
                    source.backup(destination)
            finally:
                os.close(descriptor)
        db = Database(str(candidate))
        indexer = ResearchIndexer(db, managed_root=managed_root)
        totals, redactions = Counter(), Counter()
        for collection_root in collection_roots:
            result = asdict(indexer.index_directory(collection_root))
            redactions.update(result.pop('redactions_by_type'))
            totals.update(result)
        index_report = {**totals, 'redactions_by_type': dict(sorted(redactions.items()))}
        with closing(sqlite3.connect(candidate.as_uri() + '?mode=ro', uri=True)) as connection:
            connection.execute('PRAGMA query_only=ON')
            integrity = _integrity(connection)
            violations = len(connection.execute('PRAGMA foreign_key_check').fetchall())
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            if violations:
                raise ValueError('Candidate contains foreign key violations')
        if stat.S_IMODE(candidate.stat().st_mode) != 0o600:
            raise ValueError('Candidate permissions changed during construction')
        candidate_hash, candidate_size = _fingerprint(candidate)
        return {
            'baseline_sha256': baseline_hash, 'baseline_bytes': baseline_size,
            'candidate_sha256': candidate_hash, 'candidate_bytes': candidate_size,
            'schema_version': version, 'integrity_check': integrity,
            'foreign_key_violations': violations, 'index': index_report,
            'collections': len(collection_roots),
            'stats': db.get_stats().model_dump(),
        }
    finally:
        if _fingerprint(baseline) != (baseline_hash, baseline_size):
            raise ValueError('Baseline changed during candidate construction')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--bundles', type=Path, action='append', required=True)
    parser.add_argument('--managed-root', type=Path, help='Existing managed root containing normalized bundles')
    args = parser.parse_args(argv)
    try:
        report = build_candidate(args.baseline, args.candidate, args.bundles, managed_root=args.managed_root)
    except (OSError, ValueError, sqlite3.Error):
        # Failures can involve untrusted filenames or parser input. Leave the
        # candidate intact and report no source content or local paths.
        raise SystemExit('Candidate build failed; any reserved candidate was preserved for inspection') from None
    print(json.dumps(report, sort_keys=True, indent=2))
    return report


if __name__ == '__main__':
    main()
