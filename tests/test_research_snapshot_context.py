"""Verified snapshot reads operate on disposable research databases only."""

import hashlib
from pathlib import Path
import zlib

import pytest

import command_vault.database as database_module
from command_vault.database import Database
from command_vault.documents import sections
from command_vault.indexer import Indexer
from command_vault.knowledge import Knowledge
from command_vault.research import make_document_snapshot


@pytest.fixture
def corpus(tmp_path):
    db = Database(str(tmp_path / 'candidate.db'))
    document = '# Snapshot\n\n## Observation\n' + 'Benign stored observation. ' * 45 + '\n![Image](example.png)\n'
    document += '\n## Details\nMore source context retained in the snapshot.\n'
    original = tmp_path / 'bundle'
    original.mkdir()
    (original / 'document.md').write_text(document)
    snapshot = make_document_snapshot(document)
    with db.transaction(), db._get_connection() as conn:
        wid = conn.execute('''INSERT INTO writeups
            (filename,filepath,writeup_type,content_hash,parser_version) VALUES (?,?,?,?,?)''',
            ('snapshot.md', 'research://Fixture/001', 'research', snapshot.content_hash, 'research-bundle-v1')).lastrowid
        conn.execute('''INSERT INTO document_snapshots
            (writeup_id,content_blob,compression,content_hash,uncompressed_bytes) VALUES (?,?,?,?,?)''',
            (wid, snapshot.content_blob, snapshot.compression, snapshot.content_hash, snapshot.uncompressed_bytes))
        chunk = conn.execute('INSERT INTO writeup_chunks (writeup_id,section,content,chunk_index) VALUES (?,?,?,?)',
                             (wid, 'Observation', 'Stored chunk fallback', 0)).lastrowid
        command = conn.execute('INSERT INTO commands (writeup_id,source_section,raw_command) VALUES (?,?,?)',
                               (wid, 'Observation', 'echo stored-command')).lastrowid
        script = conn.execute('INSERT INTO scripts (writeup_id,source_section,language,code) VALUES (?,?,?,?)',
                              (wid, 'Observation', 'text', 'stored-script')).lastrowid
    return db, document, {'document': wid, 'chunk': chunk, 'command': command, 'script': script}, original


@pytest.mark.parametrize('kind', ['document', 'chunk', 'command', 'script'])
def test_research_references_use_verified_snapshot_after_bundle_moves(corpus, kind):
    db, document, ids, original = corpus
    original.rename(original.with_name('moved'))
    readonly = Database(str(db.db_path), readonly=True)
    before = db.db_path.read_bytes()
    digest = hashlib.sha256(document.encode()).hexdigest()
    reference = f'{kind}:{ids[kind]}@{ids["document"]}.{digest}'
    result = Knowledge(readonly).read_context(reference)
    assert result.source_status == 'snapshot'
    assert result.source.current_revision == result.source.indexed_revision == digest
    assert result.source.image_references_present is True
    assert result.source.document_id == ids['document']
    expected = document if kind == 'document' else next(s['content'] for s in sections(document) if s['section'] == 'Observation')
    assert result.content == expected
    assert result.source.line_start == (1 if kind == 'document' else 4)
    assert result.evidence_only
    assert db.db_path.read_bytes() == before


def test_synthetic_research_path_never_reaches_filesystem_methods(corpus, monkeypatch):
    db, _, ids, _ = corpus
    readonly = Database(str(db.db_path), readonly=True)
    for method in ('stat', 'is_file', 'open', 'read_bytes', 'read_text', 'resolve'):
        original = getattr(Path, method)

        def guarded(path, *args, _original=original, **kwargs):
            assert not str(path).startswith('research:'), 'Synthetic source accessed through filesystem'
            return _original(path, *args, **kwargs)

        monkeypatch.setattr(Path, method, guarded)
    for kind, identifier in ids.items():
        assert Knowledge(readonly).read_context(f'{kind}:{identifier}').source_status == 'snapshot'


def test_snapshot_pagination_preserves_exact_document(corpus):
    db, document, ids, _ = corpus
    knowledge = Knowledge(Database(str(db.db_path), readonly=True))
    parts = []
    offset = 0
    while True:
        page = knowledge.read_context(f'document:{ids["document"]}', offset=offset, max_chars=500)
        parts.append(page.content)
        assert page.source_status == 'snapshot'
        if page.next_offset is None:
            assert not page.truncated
            break
        assert page.truncated and page.next_offset == offset + 500
        offset = page.next_offset
    assert ''.join(parts) == document


@pytest.mark.parametrize('kind,table,column,stored', [
    ('chunk', 'writeup_chunks', 'section', 'Stored chunk fallback'),
    ('command', 'commands', 'source_section', 'echo stored-command'),
    ('script', 'scripts', 'source_section', 'stored-script'),
])
def test_absent_section_falls_back_to_bounded_stored_artifact(corpus, kind, table, column, stored):
    db, document, ids, _ = corpus
    with db.transaction(), db._get_connection() as conn:
        conn.execute(f'UPDATE {table} SET {column}=? WHERE id=?', ('Missing section', ids[kind]))
    result = Knowledge(Database(str(db.db_path), readonly=True)).read_context(f'{kind}:{ids[kind]}', offset=2)
    assert result.content == stored[2:]
    assert result.source_status == 'section_unavailable'
    assert result.source.current_revision == hashlib.sha256(document.encode()).hexdigest()
    assert result.source.line_start is None


@pytest.mark.parametrize('fault,message', [
    ('missing', 'missing'), ('table_missing', 'missing'), ('corrupt', 'corrupt'),
    ('truncated', 'truncated'), ('trailing', 'trailing'), ('size', 'byte count'),
    ('null_size', 'nonnegative integer'), ('oversized', 'byte limit'),
    ('hash', 'indexed revision'), ('writeup_hash', 'indexed revision'), ('content_hash', 'SHA-256'),
])
def test_invalid_snapshots_fail_without_returning_content(corpus, fault, message):
    db, document, ids, _ = corpus
    with db.transaction(), db._get_connection() as conn:
        snapshot = conn.execute('SELECT * FROM document_snapshots').fetchone()
        if fault == 'missing':
            conn.execute('DELETE FROM document_snapshots')
        elif fault == 'table_missing':
            conn.execute('DROP TABLE document_snapshots')
        elif fault == 'writeup_hash':
            conn.execute('UPDATE writeups SET content_hash=?', ('0' * 64,))
        elif fault in ('corrupt', 'truncated', 'trailing', 'content_hash'):
            data = {'corrupt': b'private_bad_data', 'truncated': snapshot['content_blob'][:-1],
                    'trailing': snapshot['content_blob'] + b'private_trailer',
                    'content_hash': zlib.compress(document.replace('Benign', 'Hidden').encode())}[fault]
            conn.execute('UPDATE document_snapshots SET content_blob=?', (data,))
        elif fault == 'hash':
            conn.execute('UPDATE document_snapshots SET content_hash=?', ('0' * 64,))
        else:
            size = {'size': snapshot['uncompressed_bytes'] + 1, 'null_size': None, 'oversized': 20_000_001}[fault]
            conn.execute('UPDATE document_snapshots SET uncompressed_bytes=?', (size,))
    readonly = Database(str(db.db_path), readonly=True)
    before = db.db_path.read_bytes()
    with pytest.raises(ValueError, match=message) as error:
        Knowledge(readonly).read_context(f'document:{ids["document"]}')
    assert 'private_' not in str(error.value)
    assert 'Benign' not in str(error.value)
    assert db.db_path.read_bytes() == before


@pytest.mark.parametrize('size,allowed', [(8_388_609, True), (20_000_001, False)])
def test_snapshot_decompression_uses_twenty_mb_source_limit(corpus, size, allowed):
    db, _, ids, _ = corpus
    snapshot = make_document_snapshot('x' * size)
    with db.transaction(), db._get_connection() as conn:
        conn.execute('UPDATE writeups SET content_hash=?', (snapshot.content_hash,))
        conn.execute('UPDATE document_snapshots SET content_blob=?,content_hash=?,uncompressed_bytes=?',
                     (snapshot.content_blob, snapshot.content_hash, min(size, 20_000_000)))
    knowledge = Knowledge(Database(str(db.db_path), readonly=True))
    if allowed:
        result = knowledge.read_context(f'document:{ids["document"]}', max_chars=500)
        assert result.content == 'x' * 500
        assert result.truncated and result.source_status == 'snapshot'
    else:
        with pytest.raises(ValueError, match='byte limit'):
            knowledge.read_context(f'document:{ids["document"]}')


def test_stale_research_revision_reference_is_rejected(corpus):
    db, _, ids, _ = corpus
    with pytest.raises(ValueError, match='different indexed revision'):
        Knowledge(db).read_context(f'chunk:{ids["chunk"]}@{ids["document"]}.{"0" * 64}')


@pytest.mark.parametrize('version', [1, 2])
def test_personal_paths_preserve_behavior_without_snapshot_queries(tmp_path, monkeypatch, version):
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', version)
        db = Database(str(tmp_path / f'personal-v{version}.db'))
    source = tmp_path / 'personal.md'
    source.write_text('# Personal\n\n## Notes\nPersonal source content remains available from its original path.\n')
    Indexer(db).index_file(str(source))
    readonly = Database(str(db.db_path), readonly=True)
    before = db.db_path.read_bytes()
    trace = []
    with readonly.read_snapshot(), readonly._get_connection() as conn:
        conn.set_trace_callback(trace.append)
        result = Knowledge(readonly).read_context('document:1')
    assert result.source_status == 'current'
    assert result.content == source.read_text()
    assert not any('document_snapshots' in statement for statement in trace)
    assert db.db_path.read_bytes() == before
    source.write_text(source.read_text() + '\nChanged source content.\n')
    assert Knowledge(readonly).read_context('document:1').source_status == 'changed'
    source.unlink()
    assert Knowledge(readonly).read_context('document:1').source_status == 'unavailable'


def test_schema_v1_research_row_fails_without_probing_missing_snapshot_table(tmp_path, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', 1)
        db = Database(str(tmp_path / 'legacy.db'))
    with db.transaction(), db._get_connection() as conn:
        conn.execute('INSERT INTO writeups (filename,filepath,writeup_type) VALUES (?,?,?)',
                     ('legacy.md', 'research://Fixture/legacy', 'research'))
    readonly = Database(str(db.db_path), readonly=True)
    trace = []
    with readonly.read_snapshot(), readonly._get_connection() as conn:
        conn.set_trace_callback(trace.append)
        with pytest.raises(ValueError, match='schema 2'):
            Knowledge(readonly).read_context('document:1')
    assert not any('document_snapshots' in statement for statement in trace)
