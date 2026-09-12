"""Research stats preserve legacy output and never read stored content."""

import hashlib
import sqlite3

import pytest

from command_vault.database import Database, FTS_SCHEMA, SCHEMA


EMPTY_RESEARCH = {
    'documents': 0,
    'source_collections': 0,
    'vulnerabilities': 0,
    'operational_stages': 0,
    'evidence_links': 0,
    'validation_records': 0,
    'mitigations': 0,
    'by_source': {},
    'by_domain': {},
    'validation_by_status': {},
}


def _writeups(connection, records):
    for writeup_id, writeup_type, source, domain in records:
        connection.execute('''INSERT INTO writeups
            (id,filename,filepath,writeup_type,source_collection_id,domain)
            VALUES (?,?,?,?,?,?)''',
            (writeup_id, f'{writeup_id}.md', f'/fixture/{writeup_id}.md', writeup_type, source, domain))


@pytest.fixture
def populated(tmp_path):
    database = Database(str(tmp_path / 'populated.db'))
    with sqlite3.connect(database.db_path) as connection:
        connection.executemany('INSERT INTO source_collections (id,name,source_kind) VALUES (?,?,?)', [
            (1, 'Zeta', 'research'), (2, 'Alpha', 'research'), (3, 'Nonresearch only', 'personal-writeup'),
        ])
        _writeups(connection, [
            (1, 'research', 2, 'kernel'), (2, 'research', 1, 'parser'),
            (3, 'research', 2, 'parser'), (4, 'research', None, None),
            (5, 'research', 1, ''), (6, 'box', 1, 'excluded-box'),
            (7, 'challenge', 2, 'excluded-challenge'), (8, 'sherlock', 3, 'excluded-sherlock'),
        ])
        connection.executemany('INSERT INTO vulnerabilities (id,summary) VALUES (?,?)', [
            (10, 'sensitive-content'), (11, 'sensitive-content'),
        ])
        connection.execute('INSERT INTO mitigations (canonical_name,description) VALUES (?,?)',
                           ('KASLR', 'sensitive-content'))
        connection.executemany('''INSERT INTO operational_stages
            (id,canonical_name,domain,stage_class,description) VALUES (?,?,?,?,?)''', [
            (20, 'Observe', 'software', 'diagnose', 'sensitive-content'),
            (21, 'Repair', 'software', 'remediation', 'sensitive-content'),
        ])
        connection.execute('INSERT INTO commands (id,writeup_id,raw_command) VALUES (?,?,?)',
                           (30, 1, 'sensitive-content'))
        connection.execute('INSERT INTO writeup_chunks (id,writeup_id,content,chunk_index) VALUES (?,?,?,?)',
                           (40, 2, 'sensitive-content', 0))
        connection.execute('INSERT INTO evidence_links (writeup_id,command_id) VALUES (?,?)', (1, 30))
        connection.execute('INSERT INTO evidence_links (writeup_id,chunk_id) VALUES (?,?)', (2, 40))
        connection.executemany('INSERT INTO validation_records (status,notes) VALUES (?,?)', [
            ('reproduced_local', 'sensitive-content'), ('failed', 'sensitive-content'),
            ('reproduced_local', 'sensitive-content'), (None, 'sensitive-content'), ('', 'sensitive-content'),
        ])
        connection.execute('''INSERT INTO document_snapshots
            (writeup_id,content_blob,content_hash) VALUES (?,?,?)''', (1, b'sensitive-content', 'unused-hash'))
    return database


def test_empty_v2_stats_keep_legacy_keys_and_add_empty_research(tmp_path):
    stats = Database(str(tmp_path / 'empty.db')).get_stats()
    assert stats.writeups == {'total': 0, 'boxes': 0, 'challenges': 0, 'sherlocks': 0, 'research': 0}
    assert stats.commands == {'total': 0, 'by_category': {}}
    assert stats.scripts == {'total': 0, 'by_language': {}}
    assert stats.tools == {'total': 0, 'top_10': []}
    assert stats.chunks is None
    assert stats.history is None
    assert stats.research == EMPTY_RESEARCH
    assert set(stats.model_dump()) == {'writeups', 'commands', 'scripts', 'tools', 'chunks', 'history', 'research'}
    assert all(type(value) is int for value in stats.research.values() if not isinstance(value, dict))


def test_research_counts_groups_and_nonresearch_exclusion(populated):
    stats = populated.get_stats()
    assert stats.writeups == {'total': 8, 'boxes': 1, 'challenges': 1, 'sherlocks': 1, 'research': 5}
    assert 'researchs' not in stats.writeups
    assert stats.research == {
        'documents': 5,
        'source_collections': 3,
        'vulnerabilities': 2,
        'operational_stages': 2,
        'evidence_links': 2,
        'validation_records': 5,
        'mitigations': 1,
        'by_source': {'Alpha': 2, 'Zeta': 2},
        'by_domain': {'kernel': 1, 'parser': 2},
        'validation_by_status': {'failed': 1, 'reproduced_local': 2},
    }
    assert list(stats.research['by_source']) == ['Alpha', 'Zeta']
    assert list(stats.research['by_domain']) == ['kernel', 'parser']
    assert list(stats.research['validation_by_status']) == ['failed', 'reproduced_local']
    assert stats.commands == {'total': 1, 'by_category': {}}
    assert stats.chunks == {'total': 1}
    assert stats.model_dump()['research'] == stats.research


def test_v2_stats_query_only_counts_and_metadata(populated):
    content_columns = {
        ('document_snapshots', 'content_blob'), ('commands', 'raw_command'),
        ('scripts', 'code'), ('writeup_chunks', 'content'), ('vulnerabilities', 'summary'),
        ('operational_stages', 'description'), ('validation_records', 'notes'),
        ('mitigations', 'description'),
    }
    denied = []

    def authorize(operation, table, column, database, trigger):
        if operation == sqlite3.SQLITE_READ and (table, column) in content_columns:
            denied.append((table, column))
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    with populated.read_snapshot():
        with populated._get_connection() as connection:
            connection.set_authorizer(authorize)
            try:
                stats = populated.get_stats()
            finally:
                connection.set_authorizer(None)
    assert stats.research['documents'] == 5
    assert denied == []
    assert 'sensitive-content' not in stats.model_dump_json()


def test_readonly_v1_stats_return_zero_research_without_mutating_bytes(tmp_path):
    path = tmp_path / 'legacy-v1.db'
    # Construct the old schema directly: never invoke migration to make this fixture.
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)
        connection.executescript(FTS_SCHEMA)
        connection.executemany('''INSERT INTO writeups
            (id,filename,filepath,writeup_type) VALUES (?,?,?,?)''', [
            (42, 'box.md', '/fixture/box.md', 'box'),
            (57, 'challenge.md', '/fixture/challenge.md', 'challenge'),
            (68, 'sherlock.md', '/fixture/sherlock.md', 'sherlock'),
        ])
        connection.execute('INSERT INTO tools (id,name) VALUES (?,?)', (7, 'fixture-tool'))
        connection.execute('INSERT INTO commands (id,writeup_id,tool_id,raw_command) VALUES (?,?,?,?)',
                           (8, 42, 7, 'fixture-tool --version'))
        connection.execute('INSERT INTO scripts (writeup_id,language,code) VALUES (?,?,?)',
                           (57, 'python', 'print(1)'))
        connection.execute('PRAGMA user_version=1')
    before_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    before_files = set(tmp_path.iterdir())
    database = Database(str(path), readonly=True)
    stats = database.get_stats()
    assert stats.research == EMPTY_RESEARCH
    assert stats.writeups == {'total': 3, 'boxes': 1, 'challenges': 1, 'sherlocks': 1, 'research': 0}
    assert stats.commands == {'total': 1, 'by_category': {}}
    assert stats.scripts == {'total': 1, 'by_language': {'python': 1}}
    assert stats.tools == {'total': 1, 'top_10': ['fixture-tool']}
    assert stats.chunks is None
    assert stats.history is None
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before_hash
    assert set(tmp_path.iterdir()) == before_files
    with sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 1
        assert connection.execute('SELECT name FROM sqlite_master WHERE name=?', ('source_collections',)).fetchall() == []
