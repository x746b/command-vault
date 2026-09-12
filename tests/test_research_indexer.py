"""Research storage tests use only handcrafted bundles and disposable databases."""

from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
import logging
from pathlib import Path
import sqlite3
from urllib.parse import quote

import pytest

import command_vault.database as database_module
import command_vault.research_indexer as indexer_module
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
        'scripts_indexed': 0, 'stages_linked': 0, 'evidence_links': 0, 'validation_records': 0,
        'mitigations_indexed': 0, 'mitigation_links': 0,
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


def test_affected_symbols_are_ordered_json_or_null_and_reindex_idempotently(db, bundle):
    root, manifest = bundle
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        assert conn.execute('SELECT affected_symbols FROM vulnerabilities').fetchone()[0] is None
    symbols = ['parse<std::pair<int, int>>', 'consume_record', '日本語_symbol']
    manifest['vulnerability']['affected_symbols'] = symbols
    write_manifest(root, manifest)
    first = indexer.index_bundle(root)
    assert indexer.index_bundle(root) == first
    with db._get_connection() as conn:
        rows = conn.execute('SELECT affected_symbols FROM vulnerabilities').fetchall()
        assert len(rows) == 1
        assert rows[0][0] == json.dumps(symbols, ensure_ascii=False)
        assert json.loads(rows[0][0]) == symbols
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 2
    manifest['vulnerability']['affected_symbols'] = []
    write_manifest(root, manifest)
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        assert conn.execute('SELECT affected_symbols FROM vulnerabilities').fetchone()[0] is None


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


def test_managed_identity_transition_retains_id_and_personal_paths(db, bundle):
    root, _ = bundle
    ResearchIndexer(db).index_bundle(root)
    with db._get_connection() as conn:
        original = conn.execute('SELECT id FROM writeups').fetchone()[0]
        conn.execute('INSERT INTO writeups (filename,filepath,writeup_type) VALUES (?,?,?)',
                     ('personal.md', '/unchanged/personal.md', 'box'))
        conn.commit()
    indexer = ResearchIndexer(db, managed_root=root.parent)
    indexer.index_bundle(root)
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        row = conn.execute('SELECT id,filepath FROM writeups WHERE writeup_type=?', ('research',)).fetchone()
        assert tuple(row) == (original, str((root / 'document.md').resolve()))
        assert conn.execute('SELECT filepath FROM writeups WHERE writeup_type=?', ('box',)).fetchone()[0] == '/unchanged/personal.md'
        assert conn.execute('SELECT COUNT(*) FROM document_snapshots').fetchone()[0] == 1
    ResearchIndexer(db).index_bundle(root)
    with db._get_connection() as conn:
        row = conn.execute('SELECT id,filepath FROM writeups WHERE writeup_type=?', ('research',)).fetchone()
        assert row['id'] == original and row['filepath'].startswith('research://')


@pytest.mark.parametrize('case', ['missing-root', 'symlink-root', 'symlink-ancestor', 'outside', 'equal', 'symlink-bundle'])
def test_invalid_managed_paths_leave_database_unchanged(db, bundle, tmp_path, case):
    root, _ = bundle
    managed = root.parent
    if case == 'missing-root':
        managed = tmp_path / 'missing-managed'
    elif case in ('symlink-root', 'symlink-ancestor'):
        link = tmp_path / 'linked-managed'
        link.symlink_to(root.parent, target_is_directory=True)
        managed = link if case == 'symlink-root' else link / root.name
    elif case == 'outside':
        managed = tmp_path / 'elsewhere'
        managed.mkdir()
    elif case == 'equal':
        managed = root
    else:
        link = managed / 'linked-bundle'
        link.symlink_to(root, target_is_directory=True)
        root = link
    before = stored_state(db)
    with pytest.raises(ValueError, match='Managed'):
        ResearchIndexer(db, managed_root=managed).index_bundle(root)
    assert stored_state(db) == before


@pytest.mark.parametrize('case', ['collision', 'duplicate'])
def test_managed_collision_or_duplicate_stable_identity_rolls_back(db, bundle, case):
    root, manifest = bundle
    ResearchIndexer(db).index_bundle(root)
    with db._get_connection() as conn:
        if case == 'collision':
            conn.execute('INSERT INTO writeups (filename,filepath,writeup_type) VALUES (?,?,?)',
                         ('personal.md', str((root / 'document.md').resolve()), 'box'))
        else:
            collection_id = conn.execute('SELECT source_collection_id FROM writeups').fetchone()[0]
            conn.execute('''INSERT INTO writeups (filename,filepath,writeup_type,source_collection_id,external_id)
                VALUES (?,?,?,?,?)''', ('duplicate.md', 'research://duplicate', 'research', collection_id, manifest['external_id']))
        conn.commit()
    before = stored_state(db)
    with pytest.raises(ValueError, match='conflict|Duplicate'):
        ResearchIndexer(db, managed_root=root.parent).index_bundle(root)
    assert stored_state(db) == before


def test_failed_managed_transition_restores_synthetic_identity(db, bundle, monkeypatch):
    root, _ = bundle
    ResearchIndexer(db).index_bundle(root)
    before = stored_state(db)

    def fail(*args, **kwargs):
        raise RuntimeError('Injected managed failure')

    monkeypatch.setattr(db, 'insert_chunk', fail)
    with pytest.raises(RuntimeError, match='managed failure'):
        ResearchIndexer(db, managed_root=root.parent).index_bundle(root)
    assert stored_state(db) == before


def add_mitigations(root, manifest):
    manifest['mitigations'] = [
        {'canonical_name': 'KASLR', 'raw_label': 'KASLR', 'state': 'bypassed',
         'assertion_provenance': 'deterministic', 'evidence_sections': ['Details', 'Overview']},
        {'canonical_name': 'SMEP', 'raw_label': 'SMEP', 'state': 'bypassed',
         'assertion_provenance': 'deterministic', 'evidence_sections': ['Overview']},
        {'canonical_name': 'SMAP', 'raw_label': 'SMAP', 'state': 'required',
         'assertion_provenance': 'source', 'evidence_sections': ['Missing exact section']},
    ]
    write_manifest(root, manifest)


def test_mitigation_relations_revision_references_deduped_evidence_and_stats(db, bundle):
    root, manifest = bundle
    add_mitigations(root, manifest)
    result = ResearchIndexer(db).index_bundle(root)
    assert result.mitigations_indexed == result.mitigation_links == 3
    assert result.evidence_links == 2
    assert result.validation_records == 0
    with db._get_connection() as conn:
        writeup = conn.execute('SELECT id,content_hash FROM writeups').fetchone()
        chunks = {row['section']: row for row in conn.execute('SELECT * FROM writeup_chunks')}
        relations = {row['canonical_name']: row for row in conn.execute('''SELECT m.canonical_name,vm.*
            FROM vulnerability_mitigations vm JOIN mitigations m ON m.id=vm.mitigation_id''')}
        suffix = f'@{writeup["id"]}.{writeup["content_hash"]}'
        assert relations['KASLR']['source_reference'] == f'chunk:{chunks["Overview"]["id"]}' + suffix
        assert relations['SMEP']['source_reference'] == relations['KASLR']['source_reference']
        assert relations['SMAP']['source_reference'] == f'document:{writeup["id"]}' + suffix
        assert relations['KASLR']['state'] == 'bypassed'
        assert relations['SMAP']['state'] == 'required'
        evidence = conn.execute('''SELECT e.*,c.content FROM evidence_links e
            JOIN writeup_chunks c ON c.id=e.chunk_id ORDER BY e.id''').fetchall()
        assert len(evidence) == 2
        for row in evidence:
            assert row['vulnerability_id'] == relations['KASLR']['vulnerability_id']
            assert row['evidence_role'] == 'mitigation'
            assert row['assertion_provenance'] == 'deterministic'
            assert row['validation_status'] == 'source_documented'
            assert row['observed_outcome'] == 'bypassed'
            assert row['source_anchor_hash'] == hashlib.sha256(row['content'].encode()).hexdigest()
        assert conn.execute('SELECT count(*) FROM validation_records').fetchone()[0] == 0
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
    for row in relations.values():
        assert Knowledge(db).read_context(row['source_reference']).source_status == 'snapshot'
    assert db.get_stats().research['mitigations'] == 3


@pytest.mark.parametrize('state', ['enabled', 'disabled', 'bypassed', 'required', 'discussed', 'unknown'])
def test_mitigation_state_is_preserved_without_runtime_inference(db, bundle, state):
    root, manifest = bundle
    add_mitigations(root, manifest)
    manifest['mitigations'] = [{**manifest['mitigations'][0], 'state': state, 'assertion_provenance': 'curated'}]
    write_manifest(root, manifest)
    ResearchIndexer(db).index_bundle(root)
    with db._get_connection() as conn:
        assert conn.execute('SELECT state FROM vulnerability_mitigations').fetchone()[0] == state
        rows = conn.execute('SELECT observed_outcome,assertion_provenance,validation_status FROM evidence_links').fetchall()
        assert all(tuple(row) == (state, 'curated', 'source_documented') for row in rows)
        assert conn.execute('SELECT count(*) FROM validation_records').fetchone()[0] == 0


def test_mitigation_reindex_rebuilds_relations_without_orphans(db, bundle):
    root, manifest = bundle
    add_mitigations(root, manifest)
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        global_rows = [tuple(row) for row in conn.execute('SELECT * FROM mitigations ORDER BY id')]
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        assert [tuple(row) for row in conn.execute('SELECT * FROM mitigations ORDER BY id')] == global_rows
        assert conn.execute('SELECT count(*) FROM vulnerability_mitigations').fetchone()[0] == 3
        assert conn.execute('SELECT count(*) FROM evidence_links').fetchone()[0] == 2
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []


def test_mitigations_without_vulnerability_remain_unlinked(db, bundle):
    root, manifest = bundle
    add_mitigations(root, manifest)
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    del manifest['vulnerability']
    write_manifest(root, manifest)
    result = indexer.index_bundle(root)
    assert result.mitigations_indexed == 3
    assert result.mitigation_links == result.evidence_links == 0
    with db._get_connection() as conn:
        assert conn.execute('SELECT count(*) FROM mitigations').fetchone()[0] == 3
        for table in ('vulnerabilities', 'vulnerability_mitigations', 'evidence_links'):
            assert conn.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == 0


@pytest.mark.parametrize('existing_label', [None, 'Earlier source label'])
def test_mitigation_upsert_fills_null_label_and_preserves_conflicting_global_metadata(db, bundle, existing_label):
    root, manifest = bundle
    add_mitigations(root, manifest)
    with db.transaction(), db._get_connection() as conn:
        conn.execute('INSERT INTO mitigations (canonical_name,raw_label,description) VALUES (?,?,?)',
                     ('KASLR', existing_label, 'Preserved description'))
    ResearchIndexer(db).index_bundle(root)
    with db._get_connection() as conn:
        row = conn.execute('SELECT raw_label,description FROM mitigations WHERE canonical_name=?', ('KASLR',)).fetchone()
        assert tuple(row) == (existing_label or 'KASLR', 'Preserved description')


def test_mitigation_insertion_failure_rolls_back_global_rows_and_prior_revision(db, bundle, monkeypatch):
    root, manifest = bundle
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    before = stored_state(db)
    add_mitigations(root, manifest)
    original = indexer._index_mitigations

    def failing(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError('Injected mitigation storage failure')

    monkeypatch.setattr(indexer, '_index_mitigations', failing)
    with pytest.raises(RuntimeError, match='Injected mitigation'):
        indexer.index_bundle(root)
    assert stored_state(db) == before


def test_directory_aggregates_mitigation_counts_and_reuses_global_controls(db, tmp_path):
    collection = tmp_path / 'collection'
    for external_id in ('first', 'second'):
        root, manifest = make_bundle(collection / external_id, external_id)
        add_mitigations(root, manifest)
    result = ResearchIndexer(db).index_directory(collection)
    assert result.mitigations_indexed == result.mitigation_links == 6
    assert result.evidence_links == 4
    assert db.get_stats().research['mitigations'] == 3


def test_original_capabilities_metadata_does_not_create_mitigations(db, bundle):
    root, manifest = bundle
    manifest['source_metadata'] = {'original_capabilities': ['KASLR', 'SMAP', 'userns', 'io_uring']}
    write_manifest(root, manifest)
    result = ResearchIndexer(db).index_bundle(root)
    assert result.mitigations_indexed == result.mitigation_links == 0
    assert db.get_stats().research['mitigations'] == 0


def test_managed_dedup_diagnostic_label_preserves_document_and_snapshot_hash(db, bundle):
    root, _ = bundle
    document = '# Diagnostic\n\n## Evidence\n  \tDEDUP_TOKEN: diagnostic_marker_with_more_than_twenty_chars\n'
    (root / 'document.md').write_text(document, encoding='utf-8')
    indexer = ResearchIndexer(db, managed_root=root.parent)
    first = indexer.index_bundle(root)
    assert first.redactions_by_type == {}
    with db._get_connection() as conn:
        row = conn.execute('SELECT id,content_hash FROM writeups').fetchone()
        snapshot = conn.execute('SELECT content_blob,compression,content_hash,uncompressed_bytes FROM document_snapshots').fetchone()
    assert read_document_snapshot(DocumentSnapshot(**dict(snapshot))) == document
    assert row['content_hash'] == snapshot['content_hash'] == hashlib.sha256(document.encode()).hexdigest()
    context = Knowledge(Database(str(db.db_path), readonly=True)).read_context(f'document:{row["id"]}')
    assert context.source_status == 'managed' and context.content == document
    assert indexer.index_bundle(root).redactions_by_type == {}
    assert (root / 'document.md').read_text() == document


@pytest.mark.parametrize('value,redacted,kind', [
    ('HTB{diagnostic_fixture_secret}', '{FLAG_REDACTED}', 'flag'),
    ('private_key=private_fixture_key', 'private_key={PRIVATE_KEY}', 'secret'),
    ('-----BEGIN OPENSSH PRIVATE KEY-----\nprivate_fixture_key\n-----END OPENSSH PRIVATE KEY-----',
     '{PRIVATE_KEY_REDACTED}', 'ssh_key'),
])
def test_dedup_value_still_runs_through_secret_filters_and_presanitized_content_is_stable(db, bundle, value, redacted, kind):
    root, _ = bundle
    document = '# Diagnostic\n\n## Evidence\nDEDUP_TOKEN: ' + value + '\n'
    expected = '# Diagnostic\n\n## Evidence\nDEDUP_TOKEN: ' + redacted + '\n'
    (root / 'document.md').write_text(document)
    indexer = ResearchIndexer(db, managed_root=root.parent)
    result = indexer.index_bundle(root)
    assert result.redactions_by_type == {kind: 1}
    assert all(set(entry) == {'type'} for entry in indexer.security.redaction_log)
    assert value not in repr(result) + repr(indexer.security.redaction_log)
    with db._get_connection() as conn:
        row = conn.execute('SELECT content_blob,compression,content_hash,uncompressed_bytes FROM document_snapshots').fetchone()
    assert read_document_snapshot(DocumentSnapshot(**dict(row))) == expected
    # A normalized adapter document already containing redactions must retain
    # its exact bytes through the indexer's independent defense pass.
    (root / 'document.md').write_text(expected)
    second = indexer.index_bundle(root)
    # The existing private_key pattern also counts its unchanged placeholder;
    # preserve that filter behavior while verifying byte idempotency below.
    assert second.redactions_by_type == ({'secret': 1} if value.startswith('private_key=') else {})
    context = Knowledge(db).read_context('document:1')
    assert context.source_status == 'managed' and context.content == expected


def test_only_exact_line_start_dedup_label_is_protected_and_marker_cannot_collide(db):
    indexer = ResearchIndexer(db)
    value = 'fixture_value_longer_than_twenty_characters'
    document = ('{CV_DIAGNOSTIC_LABEL}:\n_{CV_DIAGNOSTIC_LABEL}:\n'
                f'DEDUP_TOKEN: {value}\nTOKEN: {value}\n'
                f'prefix DEDUP_TOKEN: {value}\ndedup_token: {value}\n')
    sanitized = indexer._sanitize_document(document)
    assert sanitized.startswith('{CV_DIAGNOSTIC_LABEL}:\n_{CV_DIAGNOSTIC_LABEL}:\n')
    assert f'\nDEDUP_TOKEN: {value}\n' in sanitized
    assert '\nTOKEN: {TOKEN}\n' in sanitized
    assert '\nprefix DEDUP_TOKEN: {TOKEN}\n' in sanitized
    assert '\ndedup_token: {TOKEN}\n' in sanitized
    assert indexer.security.redaction_log == [{'type': 'secret'}]


def add_artifacts_and_stages(root, manifest):
    raw_code = b'\r\n  \r\n  /* HTB{artifact_private} */  \r\nint main(void) { return 0; }  \r\n \t\r\n'
    trace = b'Harmless fixture sanitizer trace with a documented diagnostic marker.\n'
    patch = b'Harmless fixture patch data describing the source remediation evidence.\n'
    (root / 'artifacts').mkdir()
    manifest['artifacts'] = []
    for name, content, kind, role, language in [
        ('pov.c', raw_code, 'reproducer', 'procedure', 'c'),
        ('trace.txt', trace, 'runtime-evidence', 'signal', None),
        ('patch.diff', patch, 'patch', 'remediation', None),
    ]:
        path = f'artifacts/{name}'
        (root / path).write_bytes(content)
        manifest['artifacts'].append({
            'path': path, 'kind': kind, 'role': role, 'language': language,
            'sha256': hashlib.sha256(content).hexdigest(), 'validation': 'source_documented',
        })
    with (root / 'document.md').open('a', encoding='utf-8') as source:
        source.write('\n## Sanitizer trace\n\n' + trace.decode() + '\n## Patch\n\n' + patch.decode())
    manifest['operational_stages'] = []
    for stage_class, section in [
        ('reach', 'Overview'), ('trigger', 'Details'), ('diagnose', 'Sanitizer trace'),
        ('primitive', 'Details'), ('control', 'Details'), ('objective', 'Details'),
        ('remediation', 'Patch'), ('diagnose', 'Missing exact section'),
    ]:
        manifest['operational_stages'].append({
            'canonical_name': f'{stage_class} {section}', 'stage_class': stage_class,
            'description': f'Documented {section} stage.', 'matched_alias': section,
            'assertion_provenance': 'deterministic', 'evidence_sections': [section],
        })
    # Equivalent normalized aliases reuse their row; another alias shares evidence.
    manifest['operational_stages'].append({**manifest['operational_stages'][0], 'matched_alias': '  OVERVIEW  '})
    manifest['operational_stages'].append({**manifest['operational_stages'][0], 'matched_alias': 'Other overview alias'})
    write_manifest(root, manifest)
    return raw_code


@pytest.fixture
def artifact_bundle(bundle):
    root, manifest = bundle
    code = add_artifacts_and_stages(root, manifest)
    return root, manifest, code


def test_artifact_script_hashes_source_anchor_validation_stages_and_stats(db, artifact_bundle):
    root, manifest, raw_code = artifact_bundle
    result = ResearchIndexer(db).index_bundle(root)
    assert (result.scripts_indexed, result.stages_linked, result.evidence_links, result.validation_records) == (1, 7, 8, 1)
    assert result.redactions_by_type == {'flag': 1}
    stored_code = raw_code.decode().replace('HTB{artifact_private}', '{FLAG_REDACTED}')
    normalized = '  /* {FLAG_REDACTED} */\nint main(void) { return 0; }'
    with db._get_connection() as conn:
        script = conn.execute('SELECT * FROM scripts').fetchone()
        assert script['code'] == stored_code
        assert script['language'] == 'c'
        assert script['purpose'] == 'reproducer'
        assert script['source_section'] == 'Artifact: artifacts/pov.c'
        assert script['artifact_hash'] == hashlib.sha256(stored_code.encode()).hexdigest()
        assert script['normalized_hash'] == hashlib.sha256(normalized.encode()).hexdigest()
        assert conn.execute('SELECT COUNT(*) FROM scripts').fetchone()[0] == 1
        evidence = conn.execute('SELECT * FROM evidence_links WHERE script_id IS NOT NULL').fetchone()
        assert evidence['writeup_id'] == script['writeup_id']
        assert evidence['script_id'] == script['id']
        assert evidence['evidence_role'] == 'procedure'
        assert evidence['assertion_provenance'] == 'source'
        assert evidence['validation_status'] == 'source_documented'
        assert evidence['source_anchor_hash'] == hashlib.sha256(raw_code).hexdigest()
        assert evidence['source_anchor_hash'] != script['artifact_hash']
        validation = conn.execute('SELECT * FROM validation_records').fetchone()
        assert (validation['artifact_kind'], validation['artifact_id']) == ('script', script['id'])
        assert validation['validation_level'] == validation['status'] == 'source_documented'
        assert validation['source_reference'] == manifest['artifacts'][0]['path']
        assert validation['validated_at'] is None
        role_map = {'reach': 'prerequisite', 'trigger': 'procedure', 'diagnose': 'signal',
                    'primitive': 'outcome', 'control': 'outcome', 'objective': 'outcome', 'remediation': 'remediation'}
        rows = conn.execute('''SELECT e.*,s.stage_class,c.content FROM evidence_links e
            JOIN operational_stages s ON s.id=e.stage_id JOIN writeup_chunks c ON c.id=e.chunk_id''').fetchall()
        assert len(rows) == 7
        for row in rows:
            assert row['evidence_role'] == role_map[row['stage_class']]
            assert row['assertion_provenance'] == 'deterministic'
            assert row['validation_status'] == 'source_documented'
            assert row['source_anchor_hash'] == hashlib.sha256(row['content'].encode()).hexdigest()
        assert conn.execute('SELECT COUNT(*) FROM operational_stages').fetchone()[0] == 8
        assert conn.execute('SELECT COUNT(*) FROM stage_aliases').fetchone()[0] == 9
        assert conn.execute('''SELECT COUNT(*) FROM evidence_links WHERE stage_id IN
            (SELECT id FROM operational_stages WHERE canonical_name=?)''', ('diagnose Missing exact section',)).fetchone()[0] == 0
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
    stats = db.get_stats()
    assert stats.scripts['total'] == 1
    assert stats.research['operational_stages'] == 8
    assert stats.research['evidence_links'] == 8
    assert stats.research['validation_records'] == 1
    assert stats.research['validation_by_status'] == {'source_documented': 1}


def test_explicit_syz_script_allowlist_and_nonallowlisted_artifact(db, bundle):
    root, manifest = bundle
    (root / 'artifacts').mkdir()
    syz = b'r0 = socket$inet_tcp(2, 1, 0)\nclose(r0)\n'
    python = b'print("not an imported research script")\n'
    for name, content in [('repro.syz', syz), ('helper.py', python)]:
        (root / 'artifacts' / name).write_bytes(content)
    manifest['artifacts'] = [
        {
            'path': 'artifacts/repro.syz', 'kind': 'reproducer', 'role': 'procedure',
            'language': 'syz', 'sha256': hashlib.sha256(syz).hexdigest(),
            'validation': 'harness_observed', 'license_expression': None,
        },
        {
            'path': 'artifacts/helper.py', 'kind': 'metadata-helper', 'role': 'signal',
            'language': 'python', 'sha256': hashlib.sha256(python).hexdigest(),
            'validation': 'source_documented', 'license_expression': None,
        },
    ]
    write_manifest(root, manifest)
    result = ResearchIndexer(db).index_bundle(root)
    assert result.scripts_indexed == result.validation_records == result.evidence_links == 1
    with db._get_connection() as conn:
        script = conn.execute('SELECT language,code,purpose FROM scripts').fetchone()
        assert tuple(script) == ('syz', syz.decode(), 'reproducer')
        evidence = conn.execute('SELECT validation_status,source_anchor_hash FROM evidence_links').fetchone()
        assert tuple(evidence) == ('harness_observed', hashlib.sha256(syz).hexdigest())
        assert conn.execute("SELECT count(*) FROM scripts WHERE language='python'").fetchone()[0] == 0
    results = db.search_scripts('socket inet tcp', language='syz')
    assert len(results) == 1 and results[0].language == 'syz'


def test_artifact_reindex_rebuilds_evidence_without_orphans_and_preserves_stages(db, artifact_bundle):
    root, _, _ = artifact_bundle
    indexer = ResearchIndexer(db)
    first = indexer.index_bundle(root)
    with db._get_connection() as conn:
        stages = [tuple(row) for row in conn.execute('SELECT * FROM operational_stages ORDER BY id')]
        aliases = [tuple(row) for row in conn.execute('SELECT * FROM stage_aliases ORDER BY stage_id,alias_normalized')]
    second = indexer.index_bundle(root)
    assert first == second
    with db._get_connection() as conn:
        assert [tuple(row) for row in conn.execute('SELECT * FROM operational_stages ORDER BY id')] == stages
        assert [tuple(row) for row in conn.execute('SELECT * FROM stage_aliases ORDER BY stage_id,alias_normalized')] == aliases
        assert conn.execute('SELECT COUNT(*) FROM scripts').fetchone()[0] == 1
        assert conn.execute('SELECT COUNT(*) FROM evidence_links').fetchone()[0] == 8
        assert conn.execute('SELECT COUNT(*) FROM validation_records').fetchone()[0] == 1
        assert conn.execute('''SELECT COUNT(*) FROM validation_records v LEFT JOIN scripts s
            ON s.id=v.artifact_id WHERE v.artifact_kind=? AND s.id IS NULL''', ('script',)).fetchone()[0] == 0
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []


def test_stage_validation_status_is_manifest_backed_and_idempotent_without_chunk_validations(db, artifact_bundle):
    root, manifest, _ = artifact_bundle
    for stage in manifest['operational_stages']:
        if stage['stage_class'] in ('trigger', 'diagnose'):
            stage['validation_status'] = 'harness_observed'
    write_manifest(root, manifest)
    indexer = ResearchIndexer(db)
    first = indexer.index_bundle(root)
    second = indexer.index_bundle(root)
    assert first == second
    assert first.validation_records == 1  # Only the existing C artifact has a validation record.
    with db._get_connection() as conn:
        rows = conn.execute('''SELECT s.stage_class,e.validation_status,e.assertion_provenance
            FROM evidence_links e JOIN operational_stages s ON s.id=e.stage_id
            WHERE e.chunk_id IS NOT NULL ORDER BY s.id''').fetchall()
        assert len(rows) == 7
        for row in rows:
            expected = 'harness_observed' if row['stage_class'] in ('trigger', 'diagnose') else 'source_documented'
            assert row['validation_status'] == expected
            assert row['assertion_provenance'] == 'deterministic'
        assert conn.execute('SELECT COUNT(*) FROM validation_records').fetchone()[0] == 1
        assert conn.execute('SELECT COUNT(*) FROM validation_records WHERE artifact_kind=?', ('chunk',)).fetchone()[0] == 0
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []


@pytest.mark.parametrize('case', ['class', 'description', 'provenance', 'empty-alias'])
def test_stage_conflicts_roll_back_script_validation_and_previous_state(db, artifact_bundle, case):
    root, manifest, _ = artifact_bundle
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    before = stored_state(db)
    stage = manifest['operational_stages'][0]
    if case == 'class':
        stage['stage_class'] = 'control'
    elif case == 'description':
        stage['description'] = 'Conflicting description'
    elif case == 'provenance':
        stage['assertion_provenance'] = 'inferred'
    else:
        stage['matched_alias'] = '  \t '
    write_manifest(root, manifest)
    with pytest.raises(ValueError, match='conflict|alias'):
        indexer.index_bundle(root)
    assert stored_state(db) == before


def test_stage_null_description_can_be_filled_and_later_omitted(db, artifact_bundle):
    root, manifest, _ = artifact_bundle
    indexer = ResearchIndexer(db)
    for stage in manifest['operational_stages']:
        stage['description'] = None
    write_manifest(root, manifest)
    indexer.index_bundle(root)
    manifest['operational_stages'][0]['description'] = 'Curated description'
    write_manifest(root, manifest)
    indexer.index_bundle(root)
    manifest['operational_stages'][0]['description'] = None
    write_manifest(root, manifest)
    indexer.index_bundle(root)
    with db._get_connection() as conn:
        assert conn.execute('SELECT description FROM operational_stages WHERE canonical_name=?',
                            (manifest['operational_stages'][0]['canonical_name'],)).fetchone()[0] == 'Curated description'


@pytest.mark.parametrize('valid_digest', [False, True])
def test_invalid_artifact_digest_or_utf8_never_partially_writes(db, artifact_bundle, valid_digest):
    root, manifest, _ = artifact_bundle
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    before = stored_state(db)
    data = b'private-artifact-content\xff'
    (root / manifest['artifacts'][0]['path']).write_bytes(data)
    if valid_digest:
        manifest['artifacts'][0]['sha256'] = hashlib.sha256(data).hexdigest()
        write_manifest(root, manifest)
    with pytest.raises(ValueError, match='UTF-8' if valid_digest else 'SHA-256') as error:
        indexer.index_bundle(root)
    assert 'private-artifact-content' not in str(error.value)
    assert stored_state(db) == before


def test_loaded_artifact_order_is_checked_without_reopening_paths(db, artifact_bundle, monkeypatch):
    root, _, _ = artifact_bundle
    loaded = indexer_module.load_research_bundle(root)
    monkeypatch.setattr(indexer_module, 'load_research_bundle', lambda _: replace(loaded, artifacts=tuple(reversed(loaded.artifacts))))
    before = stored_state(db)
    with pytest.raises(ValueError, match='path/order'):
        ResearchIndexer(db).index_bundle(root)
    assert stored_state(db) == before


def test_script_insertion_failure_rolls_back_existing_artifact_evidence(db, artifact_bundle, monkeypatch):
    root, _, _ = artifact_bundle
    indexer = ResearchIndexer(db)
    indexer.index_bundle(root)
    before = stored_state(db)
    original = db.insert_script

    def fail_after_insert(script):
        original(script)
        raise RuntimeError('Injected script insertion failure')

    monkeypatch.setattr(db, 'insert_script', fail_after_insert)
    with pytest.raises(RuntimeError, match='Injected'):
        indexer.index_bundle(root)
    assert stored_state(db) == before


def test_directory_aggregates_artifact_stage_counts_and_redaction_secrecy(db, tmp_path, caplog):
    collection = tmp_path / 'artifact-collection'
    for name in ('first', 'second'):
        root, manifest = make_bundle(collection / name, external_id=name)
        add_artifacts_and_stages(root, manifest)
    indexer = ResearchIndexer(db)
    with caplog.at_level(logging.DEBUG):
        result = indexer.index_directory(collection)
    assert result.scripts_indexed == result.validation_records == 2
    assert result.stages_linked == 14
    assert result.evidence_links == 16
    assert result.redactions_by_type == {'flag': 2}
    output = stored_state(db) + caplog.text + repr(result) + repr(indexer.security.redaction_log)
    assert 'HTB{artifact_private}' not in output
    assert all(set(entry) == {'type'} for entry in indexer.security.redaction_log)
