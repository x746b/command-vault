"""Managed source reads use verified snapshots as an independent fallback."""

import hashlib
import json
import os

import pytest

from command_vault.database import Database
from command_vault.knowledge import Knowledge
from command_vault.research_indexer import ResearchIndexer
import command_vault.research as research


@pytest.fixture
def managed(tmp_path):
    root = tmp_path / 'managed'
    bundle = root / 'bundle'
    bundle.mkdir(parents=True)
    (bundle / 'manifest.json').write_text(json.dumps({
        'schema_version': 1, 'source': {'name': 'Fixture', 'revision': '1', 'upstream_url': 'https://example.org/source'},
        'external_id': 'one', 'domain': 'software',
    }), encoding='utf-8')
    text = '# Notes\n\n## Evidence\nA benign managed observation with enough text for a preserved chunk.\n'
    document = bundle / 'document.md'
    document.write_text(text, encoding='utf-8')
    db = Database(str(tmp_path / 'candidate.db'))
    ResearchIndexer(db, managed_root=root).index_bundle(bundle)
    with db._get_connection() as conn:
        writeup_id = conn.execute('SELECT id FROM writeups').fetchone()[0]
    return db, document, text, f'document:{writeup_id}'


def test_verified_managed_source_and_missing_snapshot_fallback_are_byte_stable(managed):
    db, path, text, reference = managed
    before = db.db_path.read_bytes()
    knowledge = Knowledge(Database(str(db.db_path), readonly=True))
    result = knowledge.read_context(reference)
    assert result.content == text and result.source_status == 'managed'
    assert result.source.current_revision == hashlib.sha256(text.encode()).hexdigest()
    path.unlink()
    result = knowledge.read_context(reference)
    assert result.content == text and result.source_status == 'snapshot'
    assert db.db_path.read_bytes() == before


@pytest.mark.parametrize('case', ['changed', 'symlink', 'directory', 'oversized', 'unreadable', 'symlink-parent'])
def test_untrusted_managed_file_falls_back_without_returning_changed_content(managed, tmp_path, monkeypatch, case):
    db, path, text, reference = managed
    changed = b'CHANGED UNTRUSTED CONTENT'
    if case == 'changed':
        path.write_bytes(changed)
    elif case == 'symlink':
        target = tmp_path / 'target'
        target.write_bytes(changed)
        path.unlink()
        path.symlink_to(target)
    elif case == 'directory':
        path.unlink()
        path.mkdir()
    elif case == 'oversized':
        with path.open('wb') as stream:
            stream.truncate(20_000_001)
    elif case == 'symlink-parent':
        original = path.parent
        replacement = original.with_name('relocated')
        original.rename(replacement)
        original.symlink_to(replacement, target_is_directory=True)
    else:
        original_open = os.open

        def denied(name, *args, **kwargs):
            if str(name) == 'document.md':
                raise PermissionError('Fixture permission denial')
            return original_open(name, *args, **kwargs)

        monkeypatch.setattr(research.os, 'open', denied)
    before = db.db_path.read_bytes()
    result = Knowledge(Database(str(db.db_path), readonly=True)).read_context(reference)
    assert result.source_status == 'snapshot_changed'
    assert result.content == text
    assert 'CHANGED UNTRUSTED CONTENT' not in result.content
    if case == 'changed':
        assert result.source.current_revision == hashlib.sha256(changed).hexdigest()
    else:
        assert result.source.current_revision is None
    assert db.db_path.read_bytes() == before


@pytest.mark.parametrize('case', ['missing', 'corrupt', 'wrong-hash'])
def test_invalid_snapshot_fails_closed_even_when_managed_source_matches(managed, case):
    db, path, _, reference = managed
    with db._get_connection() as conn:
        if case == 'missing':
            conn.execute('DELETE FROM document_snapshots')
        elif case == 'corrupt':
            conn.execute('UPDATE document_snapshots SET content_blob=?', (b'invalid-zlib',))
        else:
            conn.execute('UPDATE document_snapshots SET content_hash=?', ('0' * 64,))
        conn.commit()
    before = db.db_path.read_bytes()
    assert path.is_file()
    with pytest.raises(ValueError, match='snapshot|Snapshot'):
        Knowledge(Database(str(db.db_path), readonly=True)).read_context(reference)
    assert db.db_path.read_bytes() == before


def test_synthetic_research_and_personal_source_statuses_are_unchanged(managed, tmp_path):
    db, path, text, reference = managed
    ResearchIndexer(db).index_bundle(path.parent)
    assert Knowledge(db).read_context(reference).source_status == 'snapshot'
    personal = tmp_path / 'personal.md'
    personal.write_text(text, encoding='utf-8')
    with db._get_connection() as conn:
        writeup_id = conn.execute('''INSERT INTO writeups (filename,filepath,writeup_type,content_hash)
            VALUES (?,?,?,?)''', ('personal.md', str(personal), 'box', hashlib.sha256(text.encode()).hexdigest())).lastrowid
        conn.commit()
    result = Knowledge(db).read_context(f'document:{writeup_id}')
    assert result.source_status == 'current' and result.content == text
