"""Schema-v2 migrations operate exclusively on disposable pytest databases."""

import sqlite3

import pytest

import command_vault.database as database_module
from command_vault.categories import CATEGORIES
from command_vault.database import CURRENT_SCHEMA_VERSION, Database, FTS_SCHEMA, SCHEMA


ADDED_COLUMNS = {
    'writeups': {'source_collection_id', 'external_id', 'domain', 'document_kind', 'upstream_url'},
    'techniques': {'description', 'domain'},
    'commands': {'artifact_hash', 'normalized_hash'},
    'scripts': {'artifact_hash', 'normalized_hash'},
}
RESEARCH_TABLES = {
    'source_collections', 'document_snapshots', 'vulnerabilities', 'writeup_vulnerabilities',
    'vulnerabilities_fts', 'technique_aliases', 'operational_stages', 'stage_aliases',
    'stage_edges', 'evidence_links', 'mitigations', 'vulnerability_mitigations',
    'technique_mitigations', 'artifact_mitigation_observations', 'validation_records',
}


def _populate_v1(conn):
    """Stable, nonsequential IDs and relationships in every v1 content table."""
    records = {
        'writeups': {
            'id': 42, 'filename': 'notes.md', 'filepath': '/fixtures/notes.md',
            'writeup_type': 'box', 'title': 'Recorded notes', 'content_hash': 'original',
            'parser_version': '1',
        },
        'categories': {'id': 1001, 'name': 'fixture-category', 'description': 'Preserve me'},
        'tools': {'id': 19, 'name': 'fixture-tool', 'category_id': 1001},
        'commands': {'id': 81, 'writeup_id': 42, 'tool_id': 19, 'raw_command': 'echo commandtoken'},
        'scripts': {'id': 93, 'writeup_id': 42, 'language': 'python', 'code': 'print("scripttoken")'},
        'tags': {'id': 23, 'name': 'fixture-tag'},
        'command_tags': {'command_id': 81, 'tag_id': 23},
        'writeup_tags': {'writeup_id': 42, 'tag_id': 23},
        'history_commands': {
            'id': 105, 'command_hash': 'fixture-hash', 'tool_id': 19,
            'raw_command': 'echo historytoken', 'sanitized_command': 'echo historytoken',
            'occurrence_count': 3,
        },
        'writeup_chunks': {'id': 117, 'writeup_id': 42, 'content': 'chunktoken', 'chunk_index': 0},
        'techniques': {'id': 131, 'canonical_name': 'Observation', 'technique_type': 'analysis'},
        'technique_writeups': {'technique_id': 131, 'writeup_id': 42},
    }
    for table, values in records.items():
        columns = ','.join(values)
        placeholders = ','.join('?' for _ in values)
        conn.execute(f'INSERT INTO {table} ({columns}) VALUES ({placeholders})', tuple(values.values()))


def _v1_database(path):
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.executescript(FTS_SCHEMA)
        conn.executemany('INSERT INTO categories (name,description) VALUES (?,?)', CATEGORIES.items())
        _populate_v1(conn)
        conn.execute('PRAGMA user_version=1')


def _legacy_aliases(path, records):
    with sqlite3.connect(path) as connection:
        connection.execute('''CREATE TABLE technique_aliases (
            id INTEGER PRIMARY KEY, alias TEXT UNIQUE NOT NULL,
            technique_id INTEGER NOT NULL REFERENCES techniques(id))''')
        connection.executemany('INSERT INTO technique_aliases (id,alias,technique_id) VALUES (?,?,?)', records)


def _snapshot(conn):
    """Include SQL definitions and FTS shadow-table data to detect partial DDL."""
    definitions = conn.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name').fetchall()
    rows = {}
    for kind, name, _, _ in definitions:
        if kind == 'table':
            columns = ','.join(f'"{row[1]}"' for row in conn.execute(f'PRAGMA table_info("{name}")'))
            rows[name] = conn.execute(f'SELECT * FROM "{name}" ORDER BY {columns}').fetchall()
    return definitions, rows


@pytest.fixture
def conn(tmp_path):
    path = tmp_path / 'research.db'
    Database(str(path))
    connection = sqlite3.connect(path)
    connection.execute('PRAGMA foreign_keys=ON')
    _populate_v1(connection)
    connection.execute('INSERT INTO vulnerabilities (id,summary) VALUES (?,?)', (7, 'Initial observation'))
    connection.executemany(
        'INSERT INTO operational_stages (id,canonical_name,domain,stage_class) VALUES (?,?,?,?)',
        [(1, 'Observe', 'research', 'diagnose'), (2, 'Repair', 'research', 'remediation')],
    )
    connection.execute('INSERT INTO mitigations (id,canonical_name) VALUES (?,?)', (9, 'Bounds checks'))
    yield connection
    connection.close()


def test_fresh_database_is_v2_and_reopens(tmp_path):
    path = tmp_path / 'fresh.db'
    Database(str(path))
    assert CURRENT_SCHEMA_VERSION == 2
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert RESEARCH_TABLES <= tables
        for table, columns in ADDED_COLUMNS.items():
            info = {row[1]: row for row in connection.execute(f'PRAGMA table_info({table})')}
            assert columns <= info.keys()
            assert all(info[column][3] == 0 for column in columns)
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        before = _snapshot(connection)
    Database(str(path))
    Database(str(path), readonly=True)
    with sqlite3.connect(path) as connection:
        assert _snapshot(connection) == before


def test_v1_migration_preserves_all_rows_ids_and_fts(tmp_path):
    path = tmp_path / 'legacy-v1.db'
    _v1_database(path)
    with sqlite3.connect(path) as connection:
        _, original_rows = _snapshot(connection)
        original_columns = {
            table: [row[1] for row in connection.execute(f'PRAGMA table_info({table})')]
            for table in original_rows
        }
    Database(str(path))
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
        for table, expected in original_rows.items():
            columns = ','.join(f'"{column}"' for column in original_columns[table])
            actual = connection.execute(f'SELECT {columns} FROM "{table}" ORDER BY {columns}').fetchall()
            assert actual == expected, table
        for table, token, expected_id in [
            ('commands_fts', 'commandtoken', 81), ('scripts_fts', 'scripttoken', 93),
            ('history_fts', 'historytoken', 105), ('writeup_chunks_fts', 'chunktoken', 117),
        ]:
            assert connection.execute(f'SELECT rowid FROM {table} WHERE {table} MATCH ?', (token,)).fetchall() == [(expected_id,)]
        for table, columns in ADDED_COLUMNS.items():
            assert connection.execute(f'SELECT {",".join(sorted(columns))} FROM {table}').fetchone() == (None,) * len(columns)
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []


def test_v0_identity_migration_reaches_v2(tmp_path):
    path = tmp_path / 'legacy-v0.db'
    with sqlite3.connect(path) as connection:
        connection.execute('''CREATE TABLE writeups (
            id INTEGER PRIMARY KEY, filename TEXT UNIQUE NOT NULL, filepath TEXT NOT NULL,
            writeup_type TEXT NOT NULL, challenge_type TEXT, difficulty TEXT, title TEXT,
            indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        connection.execute('INSERT INTO writeups (id,filename,filepath,writeup_type) VALUES (?,?,?,?)',
                           (42, 'same.md', '/first/same.md', 'box'))
    Database(str(path))
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
        assert connection.execute('SELECT id FROM writeups').fetchone() == (42,)
        connection.execute('INSERT INTO writeups (filename,filepath,writeup_type) VALUES (?,?,?)',
                           ('same.md', '/second/same.md', 'box'))
        assert connection.execute('SELECT COUNT(*) FROM writeups').fetchone()[0] == 2


@pytest.mark.parametrize('records', [[], [(17, '  Observe  ', 131), (203, 'Second Alias', 131)]])
def test_legacy_alias_migration_preserves_ids_labels_and_relations(tmp_path, records):
    path = tmp_path / 'legacy-aliases.db'
    _v1_database(path)
    _legacy_aliases(path, records)
    Database(str(path))
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
        assert connection.execute('''SELECT id,alias,technique_id,alias_normalized,provenance
            FROM technique_aliases ORDER BY id''').fetchall() == [
                (*record, record[1].strip().lower(), 'deterministic') for record in records
            ]
        assert connection.execute('''SELECT a.id,t.canonical_name FROM technique_aliases a
            JOIN techniques t ON t.id=a.technique_id ORDER BY a.id''').fetchall() == [
                (record[0], 'Observation') for record in records
            ]
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        assert connection.execute('SELECT name FROM sqlite_master WHERE name=?',
                                  ('technique_aliases_v1',)).fetchall() == []
        before = _snapshot(connection)
    Database(str(path))
    with sqlite3.connect(path) as connection:
        assert _snapshot(connection) == before


def test_legacy_alias_normalization_collision_rolls_back_schema_and_data(tmp_path):
    path = tmp_path / 'alias-collision.db'
    _v1_database(path)
    _legacy_aliases(path, [(17, 'Observe', 131), (203, '  OBSERVE  ', 131)])
    with sqlite3.connect(path) as connection:
        before = _snapshot(connection)
    with pytest.raises(sqlite3.IntegrityError, match='UNIQUE constraint failed: technique_aliases.alias_normalized'):
        Database(str(path))
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 1
        assert _snapshot(connection) == before
        assert connection.execute('SELECT name FROM sqlite_master WHERE name=?',
                                  ('technique_aliases_v1',)).fetchall() == []


@pytest.mark.parametrize('artifact_ids', [
    (None, None, None), (81, 93, None), (81, None, 117), (None, 93, 117), (81, 93, 117),
])
def test_evidence_rejects_zero_or_multiple_artifacts(conn, artifact_ids):
    with pytest.raises(sqlite3.IntegrityError, match='CHECK constraint failed'):
        conn.execute('INSERT INTO evidence_links (writeup_id,command_id,script_id,chunk_id) VALUES (?,?,?,?)',
                     (42, *artifact_ids))


@pytest.mark.parametrize('artifact_ids', [(81, None, None), (None, 93, None), (None, None, 117)])
def test_evidence_accepts_exactly_one_artifact(conn, artifact_ids):
    conn.execute('''INSERT INTO evidence_links
        (writeup_id,command_id,script_id,chunk_id,vulnerability_id,technique_id,stage_id,
         evidence_role,assertion_provenance) VALUES (?,?,?,?,?,?,?,?,?)''',
        (42, *artifact_ids, 7, 131, 1, 'signal', 'source'))


@pytest.mark.parametrize('sql,values', [
    ('INSERT INTO operational_stages (canonical_name,domain,stage_class) VALUES (?,?,?)', ('Bad', 'research', 'invalid')),
    ('INSERT INTO stage_edges (source_stage_id,target_stage_id,relation,domain) VALUES (?,?,?,?)', (1, 2, 'invalid', 'research')),
    ('INSERT INTO evidence_links (writeup_id,command_id,evidence_role) VALUES (?,?,?)', (42, 81, 'invalid')),
    ('INSERT INTO evidence_links (writeup_id,command_id,assertion_provenance) VALUES (?,?,?)', (42, 81, 'invalid')),
    ('INSERT INTO document_snapshots (writeup_id,content_blob,content_hash,compression) VALUES (?,?,?,?)', (42, b'data', 'hash', 'gzip')),
    ('INSERT INTO document_snapshots (writeup_id,content_blob,content_hash,uncompressed_bytes) VALUES (?,?,?,?)', (42, b'data', 'hash', -1)),
])
def test_research_check_constraints(conn, sql, values):
    with pytest.raises(sqlite3.IntegrityError, match='CHECK constraint failed'):
        conn.execute(sql, values)


@pytest.mark.parametrize('sql,values', [
    ('INSERT INTO source_collections (name,source_kind) VALUES (?,?)', ('Archive', 'repository')),
    ('INSERT INTO document_snapshots (writeup_id,content_blob,content_hash) VALUES (?,?,?)', (42, b'data', 'hash')),
    ('INSERT INTO writeup_vulnerabilities (writeup_id,vulnerability_id) VALUES (?,?)', (42, 7)),
    ('INSERT INTO technique_aliases (technique_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)', (131, 'Observe', 'observe', 'source')),
    ('INSERT INTO operational_stages (canonical_name,domain,stage_class) VALUES (?,?,?)', ('New stage', 'research', 'control')),
    ('INSERT INTO stage_aliases (stage_id,alias_normalized) VALUES (?,?)', (1, 'observe')),
    ('INSERT INTO stage_edges (source_stage_id,target_stage_id,relation,domain) VALUES (?,?,?,?)', (1, 2, 'enables', 'research')),
    ('INSERT INTO mitigations (canonical_name) VALUES (?)', ('New mitigation',)),
    ('INSERT INTO vulnerability_mitigations (vulnerability_id,mitigation_id) VALUES (?,?)', (7, 9)),
    ('INSERT INTO technique_mitigations (technique_id,mitigation_id) VALUES (?,?)', (131, 9)),
])
def test_research_uniqueness_constraints(conn, sql, values):
    conn.execute(sql, values)
    with pytest.raises(sqlite3.IntegrityError, match='UNIQUE constraint failed'):
        conn.execute(sql, values)


def test_alias_uniqueness_scopes(conn):
    conn.execute('INSERT INTO techniques (id,canonical_name) VALUES (?,?)', (132, 'Another observation'))
    conn.execute('INSERT INTO technique_aliases (technique_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)',
                 (131, 'Observe', 'observe', 'source'))
    with pytest.raises(sqlite3.IntegrityError, match='UNIQUE constraint failed'):
        conn.execute('INSERT INTO technique_aliases (technique_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)',
                     (132, 'Observe', 'observe', 'curated'))
    conn.executemany('INSERT INTO stage_aliases (stage_id,alias_normalized) VALUES (?,?)',
                     [(1, 'shared alias'), (2, 'shared alias')])
    conn.execute('INSERT INTO operational_stages (canonical_name,domain,stage_class) VALUES (?,?,?)',
                 ('Observe', 'another-domain', 'diagnose'))


def test_snapshot_defaults_and_required_values(conn):
    conn.execute('INSERT INTO document_snapshots (writeup_id,content_blob,content_hash,uncompressed_bytes) VALUES (?,?,?,?)',
                 (42, b'compressed', 'hash', 0))
    compression, created_at = conn.execute('SELECT compression,created_at FROM document_snapshots').fetchone()
    assert compression == 'zlib'
    assert created_at is not None
    with pytest.raises(sqlite3.IntegrityError, match='NOT NULL constraint failed'):
        conn.execute('UPDATE document_snapshots SET content_blob=?', (None,))


@pytest.mark.parametrize('sql,values', [
    ('INSERT INTO writeup_vulnerabilities (writeup_id,vulnerability_id) VALUES (?,?)', (42, 999)),
    ('INSERT INTO evidence_links (writeup_id,command_id) VALUES (?,?)', (42, 999)),
    ('INSERT INTO technique_aliases (technique_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)', (999, 'Missing', 'missing', 'source')),
    ('INSERT INTO stage_edges (source_stage_id,target_stage_id,relation,domain) VALUES (?,?,?,?)', (1, 999, 'requires', 'research')),
    ('UPDATE writeups SET source_collection_id=? WHERE id=?', (999, 42)),
    ('INSERT INTO artifact_mitigation_observations (artifact_kind,artifact_id,mitigation_id) VALUES (?,?,?)', ('command', 81, 999)),
])
def test_research_foreign_keys(conn, sql, values):
    with pytest.raises(sqlite3.IntegrityError, match='FOREIGN KEY constraint failed'):
        conn.execute(sql, values)


def test_vulnerabilities_fts_insert_update_delete_all_indexed_columns(conn):
    columns = ['canonical_id', 'external_task_id', 'project_name', 'summary',
               'vulnerability_class', 'sanitizer', 'subsystem', 'affected_symbols']
    initial = [f'initial{column.replace("_", "")}' for column in columns]
    updated = [f'updated{column.replace("_", "")}' for column in columns]
    conn.execute(f'INSERT INTO vulnerabilities (id,{",".join(columns)}) VALUES ({",".join("?" for _ in range(9))})',
                 (211, *initial))

    def matches(token):
        return conn.execute('SELECT rowid FROM vulnerabilities_fts WHERE vulnerabilities_fts MATCH ?', (token,)).fetchall()

    assert all(matches(token) == [(211,)] for token in initial)
    assignments = ','.join(f'{column}=?' for column in columns)
    conn.execute(f'UPDATE vulnerabilities SET {assignments} WHERE id=?', (*updated, 211))
    assert all(matches(token) == [] for token in initial)
    assert all(matches(token) == [(211,)] for token in updated)
    conn.execute('DELETE FROM vulnerabilities WHERE id=?', (211,))
    assert all(matches(token) == [] for token in updated)


@pytest.mark.parametrize('readonly', [False, True])
def test_reject_newer_database_without_mutation(tmp_path, readonly):
    path = tmp_path / 'future.db'
    _v1_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute('PRAGMA user_version=3')
        before = _snapshot(connection)
    with pytest.raises(ValueError, match='Unsupported database schema version: 3'):
        Database(str(path), readonly=readonly)
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 3
        assert _snapshot(connection) == before


@pytest.mark.parametrize('failure_point', ['middle', 'end'])
@pytest.mark.parametrize('with_legacy_aliases', [False, True])
def test_v2_ddl_failure_rolls_back_every_schema_and_data_change(
    tmp_path, monkeypatch, failure_point, with_legacy_aliases,
):
    path = tmp_path / 'rollback.db'
    _v1_database(path)
    if with_legacy_aliases:
        _legacy_aliases(path, [(17, 'Observe', 131)])
    with sqlite3.connect(path) as connection:
        before = _snapshot(connection)
    original = database_module.RESEARCH_SCHEMA
    invalid = '\nCREATE TABLE source_collections (id INTEGER PRIMARY KEY);\n'
    if failure_point == 'middle':
        broken = original.replace('CREATE TABLE vulnerabilities (', invalid + 'CREATE TABLE vulnerabilities (', 1)
    else:
        broken = original + invalid
    monkeypatch.setattr(database_module, 'RESEARCH_SCHEMA', broken)
    with pytest.raises(sqlite3.OperationalError, match='already exists'):
        Database(str(path))
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 1
        assert _snapshot(connection) == before
    monkeypatch.setattr(database_module, 'RESEARCH_SCHEMA', original)
    Database(str(path))
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2


def test_reset_recreates_complete_v2_schema(tmp_path):
    path = tmp_path / 'reset.db'
    database = Database(str(path))
    with sqlite3.connect(path) as connection:
        connection.execute('INSERT INTO vulnerabilities (summary) VALUES (?)', ('removabletoken',))
    database.reset()
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
        assert connection.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0] == 0
        assert connection.execute('SELECT rowid FROM vulnerabilities_fts WHERE vulnerabilities_fts MATCH ?',
                                  ('removabletoken',)).fetchall() == []
        assert RESEARCH_TABLES <= {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
