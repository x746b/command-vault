"""Release audit fixtures exercise create-only, read-only corpus verification."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat

import pytest

import command_vault.database as database_module
from command_vault.database import Database


@pytest.fixture
def audit_module():
    script = Path(__file__).resolve().parents[1] / 'scripts' / 'audit_research_release.py'
    spec = importlib.util.spec_from_file_location('audit_research_release_test_module', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    root = tmp_path / 'managed'
    bundle = root / 'fixture-source' / 'fixture'
    bundle.mkdir(parents=True)
    document = '# Fixture\n\nA fully managed research document.\n'
    (bundle / 'document.md').write_text(document, encoding='utf-8')
    artifact = bundle / 'proof.c'
    artifact.write_text('int main(void) { return 0; }\n', encoding='utf-8')
    manifest = {
        'schema_version': 1,
        'source': {'name': 'Fixture source', 'revision': 'r1', 'upstream_url': 'https://example.org/item'},
        'external_id': 'fixture-1', 'domain': 'software',
        'artifacts': [{'path': 'proof.c', 'kind': 'proof', 'role': 'procedure',
                       'validation': 'syntax_checked', 'language': 'c',
                       'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()}],
    }
    (bundle / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    baseline = tmp_path / 'baseline.db'
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', 1)
        Database(str(baseline))
    destination = tmp_path / 'candidate.db'
    builder_path = Path(__file__).resolve().parents[1] / 'scripts' / 'build_research_candidate.py'
    spec = importlib.util.spec_from_file_location('audit_builder_module', builder_path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.build_candidate(baseline, destination, root / 'fixture-source', managed_root=root)
    destination.chmod(0o600)
    lock = tmp_path / 'sources.lock'
    lock_bytes = b'{"sources":["fixture"]}\n'
    lock.write_bytes(lock_bytes)
    return {'db': destination, 'root': root, 'lock': lock, 'lock_bytes': lock_bytes,
            'baseline': hashlib.sha256(baseline.read_bytes()).hexdigest()}


def _audit(module, candidate, output, **kwargs):
    return module.audit_research_release(
        candidate['db'], candidate['root'], output,
        application_commit='a' * 40, baseline_sha256=candidate['baseline'],
        sources_lock=candidate['lock'], generated_at='2030-01-02T03:04:05Z', **kwargs,
    )


def test_success_is_deterministic_create_only_and_content_free(audit_module, candidate, tmp_path, capsys):
    first = tmp_path / 'release-one'
    second = tmp_path / 'release-two'
    database_before = candidate['db'].read_bytes()
    report = _audit(audit_module, candidate, first)
    _audit(audit_module, candidate, second)
    assert candidate['db'].read_bytes() == database_before
    assert stat.S_IMODE(first.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in first.iterdir())
    assert sorted(path.name for path in first.iterdir()) == [
        'DB-MANIFEST.json', 'RELEASE-MANIFEST.json', 'RESEARCH-CORPUS-MANIFEST.json',
        'SOURCES.lock.json', 'application-commit.txt', 'foreign-key-check.txt',
        'integrity-check.txt', 'schema-version.txt',
    ]
    assert (first / 'SOURCES.lock.json').read_bytes() == candidate['lock_bytes']
    assert report['counts'] == {'corpus_files': 3, 'research_documents': 1}
    corpus = json.loads((first / 'RESEARCH-CORPUS-MANIFEST.json').read_text())
    assert all((item['source'], item['revision'], item['external_id']) == ('Fixture source', 'r1', 'fixture-1')
               for item in corpus['files'])
    for name in (path.name for path in first.iterdir()):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert str(candidate['root']) not in (first / 'RESEARCH-CORPUS-MANIFEST.json').read_text()
    with pytest.raises(ValueError, match='exists'):
        _audit(audit_module, candidate, first)
    audit_module.main([
        '--database', str(candidate['db']), '--research-root', str(candidate['root']),
        '--output', str(tmp_path / 'cli-release'), '--application-commit', 'a' * 40,
        '--baseline-sha256', candidate['baseline'], '--sources-lock', str(candidate['lock']),
        '--generated-at', '2030-01-02T03:04:05Z',
    ])
    stdout = capsys.readouterr().out
    assert str(candidate['root']) not in stdout and str(candidate['db']) not in stdout
    assert json.loads(stdout)['release_manifest_sha256']


def test_future_install_root_maps_database_paths_to_staging_corpus(audit_module, candidate, tmp_path):
    future = tmp_path / 'future-install' / 'research'
    with sqlite3.connect(candidate['db']) as connection:
        connection.execute(
            "UPDATE writeups SET filepath=? WHERE writeup_type='research'",
            (str(future / 'fixture-source/fixture/document.md'),),
        )
    output = tmp_path / 'future-release'
    _audit(audit_module, candidate, output, install_root=future)
    manifest = json.loads((output / 'DB-MANIFEST.json').read_text())
    assert manifest['managed_install_root'] == str(future)
    with pytest.raises(ValueError, match='install root'):
        _audit(audit_module, candidate, tmp_path / 'wrong-root')


@pytest.mark.parametrize('fault', ['hash', 'snapshot', 'foreign_key', 'duplicate', 'orphan', 'script', 'mode', 'schema'])
def test_database_validation_failures_publish_nothing(audit_module, candidate, tmp_path, fault):
    if fault == 'hash':
        (candidate['root'] / 'fixture-source' / 'fixture' / 'document.md').write_text('changed', encoding='utf-8')
    elif fault == 'snapshot':
        with sqlite3.connect(candidate['db']) as conn:
            conn.execute("UPDATE document_snapshots SET content_blob=X'00'")
    elif fault == 'foreign_key':
        with sqlite3.connect(candidate['db']) as conn:
            conn.execute('PRAGMA foreign_keys=OFF')
            conn.execute('INSERT INTO writeup_tags (writeup_id,tag_id) VALUES (9999,9999)')
    elif fault == 'duplicate':
        with sqlite3.connect(candidate['db']) as conn:
            row = conn.execute("SELECT source_collection_id,external_id FROM writeups WHERE writeup_type='research'").fetchone()
            conn.execute('INSERT INTO writeups (filename,filepath,writeup_type,source_collection_id,external_id) VALUES (?,?,?,?,?)',
                         ('duplicate.md', 'research://duplicate', 'research', row[0], row[1]))
    elif fault == 'orphan':
        with sqlite3.connect(candidate['db']) as conn:
            writeup_id = conn.execute("SELECT id FROM writeups WHERE writeup_type='research'").fetchone()[0]
            conn.execute("INSERT INTO evidence_links (writeup_id,command_id,evidence_role) VALUES (?,9999,'procedure')", (writeup_id,))
    elif fault == 'script':
        with sqlite3.connect(candidate['db']) as conn:
            conn.execute('UPDATE scripts SET artifact_hash=NULL')
    elif fault == 'mode':
        candidate['db'].chmod(0o640)
    elif fault == 'schema':
        with sqlite3.connect(candidate['db']) as conn:
            conn.execute('PRAGMA user_version=1')
    output = tmp_path / f'bad-{fault}'
    with pytest.raises(ValueError):
        _audit(audit_module, candidate, output)
    assert not output.exists()


@pytest.mark.parametrize('fault', ['symlink', 'undeclared', 'orphan-file', 'nonregular', 'bound'])
def test_corpus_validation_failures_publish_nothing(audit_module, candidate, tmp_path, fault):
    bundle = candidate['root'] / 'fixture-source' / 'fixture'
    if fault == 'symlink':
        (bundle / 'linked').symlink_to(bundle / 'document.md')
    elif fault == 'undeclared':
        (bundle / 'private.bin').write_bytes(b'not declared')
    elif fault == 'orphan-file':
        (candidate['root'] / 'loose.txt').write_bytes(b'not in a bundle')
    elif fault == 'nonregular':
        os.mkfifo(bundle / 'pipe')
    output = tmp_path / f'bad-{fault}'
    args = {'max_files': 1} if fault == 'bound' else {}
    with pytest.raises(ValueError):
        _audit(audit_module, candidate, output, **args)
    assert not output.exists()
