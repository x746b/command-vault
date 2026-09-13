"""Candidate-only research path relocation tests."""

import hashlib
import importlib.util
from pathlib import Path
import sqlite3

import pytest

import command_vault.database as database_module
from command_vault.database import Database


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('rebase_research_paths_test', ROOT / 'scripts/rebase_research_paths.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    managed = tmp_path / 'managed'
    bundle = managed / 'source' / 'one'
    bundle.mkdir(parents=True)
    document = b'# Fixture\n\nManaged content for relocation.\n'
    (bundle / 'document.md').write_bytes(document)
    import json
    (bundle / 'manifest.json').write_text(json.dumps({
        'schema_version': 1,
        'source': {'name': 'source', 'revision': 'r1', 'upstream_url': 'https://example.test/source'},
        'external_id': 'one', 'domain': 'software', 'artifacts': [],
    }))
    baseline = tmp_path / 'baseline.db'
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', 1)
        Database(str(baseline))
    builder_path = ROOT / 'scripts/build_research_candidate.py'
    spec = importlib.util.spec_from_file_location('rebase_builder', builder_path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    database = tmp_path / 'candidate.db'
    builder.build_candidate(baseline, database, managed / 'source', managed_root=managed)
    return managed, database


def test_rebase_is_create_only_preserves_source_ids_and_nonresearch(candidate, tmp_path):
    managed, source = candidate
    destination = tmp_path / 'release.db'
    future = tmp_path / 'future' / 'research'
    future.parent.mkdir()
    before = source.read_bytes()
    with sqlite3.connect(source) as connection:
        connection.execute("INSERT INTO writeups(filename,filepath,writeup_type) VALUES('legacy.md','/legacy.md','box')")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    report = module.rebase_research_paths(source, destination, managed, future)
    assert report['documents_rebased'] == 1 and report['source_sha256'] == source_hash
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    with sqlite3.connect(destination) as connection:
        research = connection.execute("SELECT id,filepath FROM writeups WHERE writeup_type='research'").fetchone()
        legacy = connection.execute("SELECT filepath FROM writeups WHERE writeup_type='box'").fetchone()[0]
        assert research[1] == str(future / 'source/one/document.md')
        assert legacy == '/legacy.md'
        assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match='exists'):
        module.rebase_research_paths(source, destination, managed, future)


@pytest.mark.parametrize('fault', ['outside', 'changed', 'collision', 'schema', 'mode'])
def test_rebase_refuses_inconsistent_source(candidate, tmp_path, fault):
    managed, source = candidate
    future = tmp_path / 'future' / 'research'
    future.parent.mkdir()
    with sqlite3.connect(source) as connection:
        if fault == 'outside':
            connection.execute("UPDATE writeups SET filepath='/outside/document.md' WHERE writeup_type='research'")
        elif fault == 'collision':
            connection.execute("INSERT INTO writeups(filename,filepath,writeup_type) VALUES('collision.md',?,'box')",
                               (str(future / 'source/one/document.md'),))
        elif fault == 'schema':
            connection.execute('PRAGMA user_version=1')
    if fault == 'changed':
        (managed / 'source/one/document.md').write_text('changed')
    if fault == 'mode':
        source.chmod(0o640)  # Source mode is allowed; output must still become 0600.
    destination = tmp_path / f'{fault}.db'
    if fault == 'mode':
        report = module.rebase_research_paths(source, destination, managed, future)
        assert report['integrity_check'] == 'ok' and destination.stat().st_mode & 0o777 == 0o600
    else:
        with pytest.raises(ValueError):
            module.rebase_research_paths(source, destination, managed, future)


def test_rebase_rejects_symlink_roots_and_unsafe_install_root(candidate, tmp_path):
    managed, source = candidate
    linked = tmp_path / 'linked'
    linked.symlink_to(managed, target_is_directory=True)
    with pytest.raises(ValueError):
        module.rebase_research_paths(source, tmp_path / 'one.db', linked, tmp_path / 'future')
    with pytest.raises(ValueError):
        module.rebase_research_paths(source, tmp_path / 'two.db', managed, Path('/'))
