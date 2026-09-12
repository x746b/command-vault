"""Research storage tests use only handcrafted bundles and disposable databases."""

from dataclasses import FrozenInstanceError, asdict
import hashlib
import json
import logging
from pathlib import Path
import sqlite3
from urllib.parse import quote

import pytest

import command_vault.database as database_module
from command_vault.database import Database
from command_vault.knowledge import Knowledge
from command_vault.research import DocumentSnapshot, read_document_snapshot
from command_vault.research_indexer import ResearchIndexer, ResearchIndexResult
from command_vault.security import SecurityFilter


def make_bundle(root, external_id='task / 001', *, vulnerability=True):
    root.mkdir(parents=True)
    manifest = {
        'schema_version': 1,
        'source': {
            'name': 'Fixture / Research', 'revision': 'revision-1',
            'upstream_url': 'https://example.org/research/001',
            'repository_url': 'https://example.org/repository',
            'homepage': 'https://example.org/', 'license_expression': None,
        },
        'external_id': external_id, 'domain': 'Software', 'project': 'Fixture project',
        'language': 'c', 'document_kind': 'research-note',
    }
    if vulnerability:
        manifest['vulnerability'] = {
            'canonical_id': 'CVE-2099-0001', 'summary': 'Documented fixture finding.',
            'summary_provenance': 'source', 'class': 'example class',
            'class_provenance': 'curated', 'platform': 'linux',
        }
    write_manifest(root, manifest)
    (root / 'document.md').write_text(
        '# Fixture\n\n## Overview\nThis research record documents a harmless orchard observation.\n\n'
        '## Details\nAdditional orchard evidence is preserved exactly in a stored snapshot.\n\n'
        '```bash\necho orchard\n```\n', encoding='utf-8',
    )
    return root, manifest


def write_manifest(root, manifest):
    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')


def stored_state(db):
    with db._get_connection() as conn:
        return '\n'.join(conn.iterdump())


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / 'candidate.db'))


@pytest.fixture
def bundle(tmp_path):
    return make_bundle(tmp_path / 'bundles' / 'one')


def test_full_document_storage_search_snapshot_provenance_and_stats(db, bundle):
    root, manifest = bundle
    result = ResearchIndexer(db).index_bundle(root)
    assert asdict(result) == {
        'bundles_seen': 1, 'documents_indexed': 1, 'chunks_indexed': 2,
        'vulnerabilities_indexed': 1, 'redactions_by_type': {},
    }
    with pytest.raises(FrozenInstanceError):
        result.documents_indexed = 2
    with db._get_connection() as conn:
        row = conn.execute('SELECT * FROM writeups').fetchone()
        identity = 'research://' + quote(manifest['source']['name'], safe='') + '/' + quote(manifest['external_id'], safe='')
        assert row['filepath'] == identity
        assert row['filename'] == 'Fixture-Research--task-001.md'
        assert row['writeup_type'] == 'research'
        assert row['source_collection_id'] is not None
        assert row['external_id'] == manifest['external_id']
        assert row['domain'] == 'Software'
        assert row['document_kind'] == 'research-note'
        assert row['upstream_url'] == manifest['source']['upstream_url']
        assert row['parser_version'] == 'research-bundle-v1'
        assert row['title'] == 'CVE-2099-0001 — Documented fixture finding.'
        snapshot = conn.execute('SELECT * FROM document_snapshots').fetchone()
        document = read_document_snapshot(DocumentSnapshot(**{
            key: snapshot[key] for key in ('content_blob', 'compression', 'content_hash', 'uncompressed_bytes')
        }))
        assert document == (root / 'document.md').read_text()
        assert row['content_hash'] == snapshot['content_hash'] == hashlib.sha256(document.encode()).hexdigest()
        source = conn.execute('SELECT * FROM source_collections').fetchone()
        assert source['name'] == manifest['source']['name']
        assert source['source_kind'] == 'research'
        assert source['fetched_at'] is None and source['license_expression'] is None
        assert len(source['manifest_hash']) == 64
        vulnerability = conn.execute('SELECT * FROM vulnerabilities').fetchone()
        assert vulnerability['canonical_id'] == 'CVE-2099-0001'
        assert vulnerability['external_task_id'] == manifest['external_id']
        assert vulnerability['project_name'] == manifest['project']
        assert vulnerability['language'] == 'c'
        assert vulnerability['summary_provenance'] == 'source'
        assert vulnerability['class_provenance'] == 'curated'
        assert vulnerability['sanitizer'] is None
        assert conn.execute('SELECT count(*) FROM writeup_vulnerabilities').fetchone()[0] == 1
        assert conn.execute('SELECT count(*) FROM commands').fetchone()[0] == 0
        assert conn.execute('SELECT count(*) FROM scripts').fetchone()[0] == 0
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
        assert set(db._get_writeup_tags(conn, row['id'])) == {
            'research', 'fixture / research', 'software', 'cve-2099-0001',
        }
    assert str(root) not in stored_state(db)
    assert str(root.parent) not in stored_state(db)
    page = Knowledge(db).search('orchard', writeup_type='research')
    assert len(page.results) == 2
    assert all(hit.source.writeup_type == 'research' for hit in page.results)
    assert Knowledge(db).search('orchard', writeup_type='box').results == []
    stats = db.get_stats().model_dump()
    assert stats['writeups']['research'] == 1
    assert stats['research']['documents'] == stats['research']['vulnerabilities'] == 1
    assert stats['research']['by_source'] == {'Fixture / Research': 1}


def test_directory_selects_only_sorted_direct_bundles(db, tmp_path):
    root = tmp_path / 'collection'
    make_bundle(root / 'z-last', 'last')
    make_bundle(root / 'a-first', 'first')
    make_bundle(root / 'nested' / 'ignored', 'nested')
    (root / 'loose.txt').write_text('ignored')
    result = ResearchIndexer(db).index_directory(root)
    assert result.bundles_seen == result.documents_indexed == 2
    assert result.chunks_indexed == 4
    with db._get_connection() as conn:
        assert [row[0] for row in conn.execute('SELECT external_id FROM writeups ORDER BY id')] == ['first', 'last']
        assert conn.execute('SELECT count(*) FROM source_collections').fetchone()[0] == 1


def test_directory_rejects_loose_empty_missing_file_and_symlink(db, bundle, tmp_path):
    root, _ = bundle
    indexer = ResearchIndexer(db)
    with pytest.raises(ValueError, match='loose root manifest'):
        indexer.index_directory(root)
    empty = tmp_path / 'empty'
    empty.mkdir()
    with pytest.raises(ValueError, match='No direct child'):
        indexer.index_directory(empty)
    for path in (tmp_path / 'missing', root / 'document.md'):
        with pytest.raises(ValueError, match='directory'):
            indexer.index_directory(path)
    link = tmp_path / 'linked'
    link.symlink_to(root.parent, target_is_directory=True)
    with pytest.raises(ValueError, match='nonsymlink'):
        indexer.index_directory(link)
    child_collection = tmp_path / 'linked-children'
    child_collection.mkdir()
    (child_collection / 'one').symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        indexer.index_directory(child_collection)


def test_idempotent_reindex_retains_id_and_replaces_children(db, bundle):
    indexer = ResearchIndexer(db)
    indexer.index_bundle(bundle[0])
    with db._get_connection() as conn:
        before_id = conn.execute('SELECT id FROM writeups').fetchone()[0]
    result = indexer.index_bundle(bundle[0])
    assert result.chunks_indexed == 2
    with db._get_connection() as conn:
        assert conn.execute('SELECT id FROM writeups').fetchone()[0] == before_id
        for table, count in [('writeups', 1), ('source_collections', 1), ('writeup_chunks', 2),
                             ('document_snapshots', 1), ('vulnerabilities', 1), ('writeup_vulnerabilities', 1)]:
            assert conn.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == count
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []


@pytest.mark.parametrize('key,value', [
    ('revision', 'revision-2'), ('repository_url', 'https://example.org/different'),
    ('homepage', 'https://different.example.org/'), ('license_expression', 'Apache-2.0'),
])
def test_source_conflicts_preserve_prior_state(db, bundle, key, value):
    root, manifest = bundle
    manifest['source']['license_expression'] = 'MIT'
    write_manifest(root, manifest)
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    before = stored_state(db)
    manifest['source'][key] = value
    write_manifest(root, manifest)
    with pytest.raises(ValueError, match='conflict'):
        indexer.index_bundle(root)
    assert stored_state(db) == before


def test_nullable_source_metadata_can_be_filled_without_inference(db, bundle):
    root, manifest = bundle
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    manifest['source']['license_expression'] = 'MIT'
    write_manifest(root, manifest)
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        row = conn.execute('SELECT license_expression,fetched_at FROM source_collections').fetchone()
        assert tuple(row) == ('MIT', None)


def test_mid_import_failure_rolls_back_old_snapshot_chunks_and_metadata(db, bundle, monkeypatch):
    root, manifest = bundle
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    before = stored_state(db)
    (root / 'document.md').write_text('# New\n\n## One\n' + 'Changed source content. ' * 5 + '\n## Two\n' + 'More source content. ' * 5)
    manifest['source']['license_expression'] = 'MIT'
    write_manifest(root, manifest)
    original = db.insert_chunk
    calls = 0

    def fail_after_first(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError('Injected storage failure')
        return original(*args, **kwargs)

    monkeypatch.setattr(db, 'insert_chunk', fail_after_first)
    with pytest.raises(RuntimeError, match='Injected'):
        indexer.index_bundle(root)
    assert calls == 2
    assert stored_state(db) == before


def test_redaction_is_aggregate_only_even_with_debug_logging(db, bundle, caplog):
    root, manifest = bundle
    secret = 'HTB{private_fixture_marker}'
    token = 'a_private_token_value_123456'
    (root / 'document.md').write_text('# Observations\n\nFixture marker: ' + secret + '\ntoken=' + token + '\n')
    manifest['vulnerability']['summary'] = 'Source summary ' + secret
    write_manifest(root, manifest)
    supplied = SecurityFilter()
    indexer = ResearchIndexer(db, supplied)
    with caplog.at_level(logging.DEBUG):
        result = indexer.index_bundle(root)
    assert result.redactions_by_type == {'flag': 2, 'secret': 1}
    assert supplied.redaction_log == []
    assert all(set(entry) == {'type'} for entry in indexer.security.redaction_log)
    output = stored_state(db) + caplog.text + repr(result) + repr(indexer.security.redaction_log)
    assert secret not in output and token not in output
    with db._get_connection() as conn:
        row = conn.execute('SELECT content_blob,compression,content_hash,uncompressed_bytes FROM document_snapshots').fetchone()
        snapshot_text = read_document_snapshot(DocumentSnapshot(**dict(row)))
    assert secret not in snapshot_text and token not in snapshot_text
    assert '{FLAG_REDACTED}' in snapshot_text
    assert indexer.index_bundle(root).redactions_by_type == result.redactions_by_type


def test_readonly_and_schema_v1_rejected_without_writes(db, tmp_path, monkeypatch):
    before = db.db_path.read_bytes()
    with pytest.raises(ValueError, match='writable'):
        ResearchIndexer(Database(str(db.db_path), readonly=True))
    assert db.db_path.read_bytes() == before
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', 1)
        legacy = Database(str(tmp_path / 'v1.db'))
    before = legacy.db_path.read_bytes()
    with pytest.raises(ValueError, match='schema 2'):
        ResearchIndexer(legacy)
    assert legacy.db_path.read_bytes() == before


def test_unknown_vulnerability_remains_absent_and_project_is_title(db, tmp_path):
    root, _ = make_bundle(tmp_path / 'unknown', vulnerability=False)
    result = ResearchIndexer(db).index_bundle(root)
    assert result.vulnerabilities_indexed == 0
    with db._get_connection() as conn:
        assert conn.execute('SELECT count(*) FROM vulnerabilities').fetchone()[0] == 0
        assert conn.execute('SELECT title FROM writeups').fetchone()[0] == 'Fixture project'


def test_rebuild_removes_all_child_references_and_preserves_global_metadata(db, bundle):
    indexer = ResearchIndexer(db)
    root, manifest = bundle
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        conn.execute('PRAGMA foreign_keys=ON')
        wid = conn.execute('SELECT id FROM writeups').fetchone()[0]
        vid = conn.execute('SELECT id FROM vulnerabilities').fetchone()[0]
        chunk_id = conn.execute('SELECT id FROM writeup_chunks LIMIT 1').fetchone()[0]
        command_id = conn.execute('INSERT INTO commands (writeup_id,raw_command) VALUES (?,?)', (wid, 'echo fixture')).lastrowid
        script_id = conn.execute('INSERT INTO scripts (writeup_id,language,code) VALUES (?,?,?)', (wid, 'text', 'fixture')).lastrowid
        mitigation_id = conn.execute('INSERT INTO mitigations (canonical_name) VALUES (?)', ('fixture mitigation',)).lastrowid
        conn.execute('INSERT INTO vulnerability_mitigations (vulnerability_id,mitigation_id) VALUES (?,?)', (vid, mitigation_id))
        stage_id = conn.execute('INSERT INTO operational_stages (canonical_name,domain,stage_class) VALUES (?,?,?)', ('fixture', 'Software', 'diagnose')).lastrowid
        conn.execute('INSERT INTO stage_aliases (stage_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)', (stage_id, 'Fixture', 'fixture', 'source'))
        technique_id = conn.execute('INSERT INTO techniques (canonical_name,technique_type) VALUES (?,?)', ('fixture', 'analysis')).lastrowid
        conn.execute('INSERT INTO technique_writeups (technique_id,writeup_id) VALUES (?,?)', (technique_id, wid))
        tag_id = conn.execute('INSERT INTO tags (name) VALUES (?)', ('old-only',)).lastrowid
        conn.execute('INSERT INTO command_tags (command_id,tag_id) VALUES (?,?)', (command_id, tag_id))
        conn.execute('INSERT INTO writeup_tags (writeup_id,tag_id) VALUES (?,?)', (wid, tag_id))
        for kind, artifact_id, column in [('command', command_id, 'command_id'), ('script', script_id, 'script_id'), ('chunk', chunk_id, 'chunk_id')]:
            conn.execute('INSERT INTO validation_records (artifact_kind,artifact_id,status) VALUES (?,?,?)', (kind, artifact_id, 'source_documented'))
            conn.execute('INSERT INTO artifact_mitigation_observations (artifact_kind,artifact_id,mitigation_id) VALUES (?,?,?)', (kind, artifact_id, mitigation_id))
            conn.execute(f'INSERT INTO evidence_links (writeup_id,{column},vulnerability_id) VALUES (?,?,?)', (wid, artifact_id, vid))
        conn.commit()
    del manifest['vulnerability']
    write_manifest(root, manifest)
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        for table in ('commands', 'scripts', 'command_tags', 'technique_writeups', 'evidence_links',
                      'validation_records', 'artifact_mitigation_observations', 'writeup_vulnerabilities',
                      'vulnerabilities', 'vulnerability_mitigations'):
            assert conn.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == 0
        assert 'old-only' not in db._get_writeup_tags(conn, wid)
        for table in ('source_collections', 'operational_stages', 'stage_aliases', 'techniques', 'mitigations'):
            assert conn.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == 1
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []


def test_result_collection_defaults_are_independent():
    first = ResearchIndexResult()
    second = ResearchIndexResult()
    first.redactions_by_type['flag'] = 1
    assert second.redactions_by_type == {}
