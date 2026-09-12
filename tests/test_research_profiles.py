"""Vulnerability profiles read only fixture metadata and evidence references."""

import hashlib
import sqlite3

import pytest
from pydantic import ValidationError

from command_vault.database import Database, SCHEMA
from command_vault.profiles import ResearchProfiles
from command_vault.responses import OperationalStageProfile, StageEdgeSummary, VulnerabilityProfile, VulnerabilityRecord


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / 'profiles.db'))
    with database._get_connection() as conn:
        conn.executemany('INSERT INTO source_collections (id,name,source_kind,revision) VALUES (?,?,?,?)',
                         [(1, 'Alpha', 'research', 'rev-one'), (2, 'Zeta', 'research', 'rev-two')])
        conn.executemany('''INSERT INTO writeups
            (id,filename,filepath,writeup_type,source_collection_id,domain,content_hash,upstream_url)
            VALUES (?,?,?,?,?,?,?,?)''', [
                (1, 'one.md', '/fixture/one', 'research', 1, 'kernel', 'abc123', 'https://example.org/one'),
                (2, 'two.md', '/fixture/two', 'research', 2, 'kernel', None, 'https://example.org/two'),
            ])
        conn.executemany('''INSERT INTO vulnerabilities
            (id,canonical_id,external_task_id,project_name,summary,summary_provenance,affected_symbols)
            VALUES (?,?,?,?,?,?,?)''', [
                (5, 'CVE-2099-0001', 'task-z', 'linux', 'Source summary', 'source', 'fixture_symbol'),
                (9, 'CVE-2099-0001', 'task-a', 'linux', 'Other summary', 'source', None),
                (12, 'CVE-2099-0010', 'unrelated', 'other', None, None, None),
            ])
        conn.executemany('INSERT INTO writeup_vulnerabilities VALUES (?,?)', [(1, 5), (2, 5), (2, 9)])
        conn.execute('INSERT INTO writeup_chunks (id,writeup_id,section,content,chunk_index) VALUES (?,?,?,?,?)',
                     (11, 1, 'Observation', 'PRIVATE STORED CONTENT', 0))
        conn.execute('INSERT INTO scripts (id,writeup_id,language,code,source_section) VALUES (?,?,?,?,?)',
                     (22, 2, 'c', 'PRIVATE STORED CONTENT', 'Artifact: fixture.c'))
        conn.execute('INSERT INTO commands (id,writeup_id,raw_command,source_section) VALUES (?,?,?,?)',
                     (33, 1, 'PRIVATE STORED CONTENT', 'Recorded command'))
        conn.execute('''INSERT INTO operational_stages
            (id,canonical_name,domain,stage_class,description) VALUES (?,?,?,?,?)''',
            (7, 'crash diagnosis', 'kernel', 'diagnose', 'Source diagnostic evidence'))
        conn.executemany('INSERT INTO stage_aliases (stage_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)',
                         [(7, 'Zeta alias', 'zeta alias', 'source'), (7, 'Alpha alias', 'alpha alias', 'deterministic')])
        conn.executemany('''INSERT INTO evidence_links
            (writeup_id,chunk_id,stage_id,evidence_role,assertion_provenance,validation_status,observed_outcome)
            VALUES (?,?,?,?,?,?,?)''', [(1, 11, 7, 'signal', 'deterministic', 'source_documented', 'Recorded marker')] * 2)
        conn.execute('''INSERT INTO evidence_links
            (writeup_id,script_id,evidence_role,assertion_provenance,validation_status) VALUES (?,?,?,?,?)''',
            (2, 22, 'procedure', 'source', 'not_tested'))
        conn.execute('''INSERT INTO evidence_links
            (writeup_id,command_id,evidence_role,assertion_provenance) VALUES (?,?,?,?)''',
            (1, 33, 'procedure', 'source'))
        conn.executemany('INSERT INTO mitigations (id,canonical_name,raw_label) VALUES (?,?,?)',
                         [(1, 'Zeta mitigation', None), (2, 'Alpha mitigation', 'Original label')])
        conn.executemany('INSERT INTO vulnerability_mitigations VALUES (?,?,?,?)',
                         [(5, 1, 'unknown', 'source-z'), (5, 2, 'documented', 'source-a')])
        conn.commit()
    return database


def test_canonical_and_task_matches_are_exact_case_insensitive_and_ordered(db):
    profiles = ResearchProfiles(db)
    result = profiles.get_vulnerability('cve-2099-0001')
    assert result.total_matches == 2
    assert [row.id for row in result.matches] == [9, 5]
    assert result.truncated is False
    assert profiles.get_vulnerability(' TASK-Z ').matches[0].id == 5
    assert profiles.get_vulnerability('CVE-2099-000').total_matches == 0
    assert profiles.get_vulnerability("' OR 1=1 --").matches == []
    assert profiles.get_vulnerability('unsupported').matches == []


def test_sources_mitigations_stages_evidence_and_revision_bound_references(db):
    match = ResearchProfiles(db).get_vulnerability('task-z').matches[0]
    assert match.summary == 'Source summary' and match.summary_provenance == 'source'
    assert match.affected_symbols == ['fixture_symbol']
    assert [source.source_name for source in match.sources] == ['Alpha', 'Zeta']
    assert [source.reference for source in match.sources] == ['document:1@1.abc123', 'document:2@2.legacy']
    assert match.sources[0].revision == 'rev-one'
    assert match.sources[0].upstream_url == 'https://example.org/one'
    assert [item.canonical_name for item in match.mitigations] == ['Alpha mitigation', 'Zeta mitigation']
    assert match.mitigations[0].raw_label == 'Original label'
    assert match.mitigations[0].state == 'documented'
    assert match.mitigations[0].source_reference == 'source-a'
    assert len(match.operational_stages) == 1
    stage = match.operational_stages[0]
    assert stage.canonical_name == 'crash diagnosis'
    assert stage.stage_class == 'diagnose'
    assert stage.aliases == []  # Global aliases without an exact evidenced section are excluded.
    assert stage.evidence_count == 1
    assert [item.reference for item in match.evidence] == ['chunk:11@1.abc123', 'command:33@1.abc123', 'script:22@2.legacy']
    chunk = match.evidence[0]
    assert chunk.kind == 'chunk' and chunk.evidence_role == 'signal'
    assert chunk.assertion_provenance == 'deterministic'
    assert chunk.validation_status == 'source_documented'
    assert chunk.observed_outcome == 'Recorded marker'
    assert chunk.stage == 'crash diagnosis' and chunk.section == 'Observation'
    script = match.evidence[-1]
    assert script.validation_status == 'not_tested'
    assert script.section == 'Artifact: fixture.c'
    assert 'PRIVATE STORED CONTENT' not in match.model_dump_json()


def test_evidence_budget_is_global_and_match_count_is_before_truncation(db):
    result = ResearchProfiles(db).get_vulnerability('CVE-2099-0001', limit=2)
    assert result.total_matches == len(result.matches) == 2
    assert sum(len(match.evidence) for match in result.matches) == 2
    assert result.truncated is True
    result = ResearchProfiles(db).get_vulnerability('CVE-2099-0001', limit=1)
    assert result.total_matches == 2 and len(result.matches) == 1
    assert result.truncated is True
    assert ResearchProfiles(db).get_vulnerability('task-z', limit=3).truncated is False


@pytest.mark.parametrize('identifier', ['', '  ', 'x' * 201, None, 17])
def test_invalid_identifiers(db, identifier):
    with pytest.raises(ValueError, match='Identifier'):
        ResearchProfiles(db).get_vulnerability(identifier)


@pytest.mark.parametrize('limit', [0, -1, 101, True, 1.5, None])
def test_invalid_limits(db, limit):
    with pytest.raises(ValueError, match='Limit'):
        ResearchProfiles(db).get_vulnerability('task-z', limit=limit)


def test_readonly_schema_v1_rejected_without_migration(tmp_path):
    path = tmp_path / 'v1.db'
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute('PRAGMA user_version=1')
    before = path.read_bytes()
    with pytest.raises(ValueError, match='schema 2'):
        ResearchProfiles(Database(str(path), readonly=True)).get_vulnerability('task-z')
    with pytest.raises(ValueError, match='schema 2'):
        ResearchProfiles(Database(str(path), readonly=True)).get_operational_stage('crash diagnosis')
    assert path.read_bytes() == before


def test_readonly_authorizer_blocks_content_and_writes_and_bytes_stay_unchanged(db):
    before = hashlib.sha256(db.db_path.read_bytes()).hexdigest()
    readonly = Database(str(db.db_path), readonly=True)
    blocked_columns = {('writeup_chunks', 'content'), ('scripts', 'code'), ('commands', 'raw_command'),
                       ('document_snapshots', 'content_blob'), ('evidence_links', 'environment_json')}
    violations = []

    def authorize(operation, table, column, database, trigger):
        if operation in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE} or (
            operation == sqlite3.SQLITE_READ and (table, column) in blocked_columns
        ):
            violations.append((operation, table, column))
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    with readonly.read_snapshot():
        with readonly._get_connection() as conn:
            conn.set_authorizer(authorize)
            try:
                result = ResearchProfiles(readonly).get_vulnerability('CVE-2099-0001')
                stage_result = ResearchProfiles(readonly).get_operational_stage('crash diagnosis')
                alias_result = ResearchProfiles(readonly).get_operational_stage('alpha alias', limit=1)
            finally:
                conn.set_authorizer(None)
    assert result.total_matches == 2 and violations == []
    assert stage_result.total_matches == 1
    assert alias_result.matches[0].matched_alias == 'Alpha alias'
    assert hashlib.sha256(db.db_path.read_bytes()).hexdigest() == before


def test_profile_records_reject_unknown_response_fields():
    with pytest.raises(ValidationError):
        VulnerabilityProfile(identifier='x', total_matches=0, truncated=False, unknown='data')


@pytest.mark.parametrize('stored,expected', [
    ('["last_symbol", "first_symbol", "last_symbol"]', ['last_symbol', 'first_symbol', 'last_symbol']),
    ('fixture_symbol', ['fixture_symbol']), ('legacy::operator[]', ['legacy::operator[]']),
    (None, []), ('', []), ('  \t ', []), ('[]', []),
])
def test_affected_symbols_decoding_preserves_order_and_legacy_metadata(db, stored, expected):
    with db._get_connection() as conn:
        conn.execute('UPDATE vulnerabilities SET affected_symbols=? WHERE id=?', (stored, 5))
        conn.commit()
    before = db.db_path.read_bytes()
    result = ResearchProfiles(Database(str(db.db_path), readonly=True)).get_vulnerability('task-z')
    assert result.matches[0].affected_symbols == expected
    assert result.model_dump()['matches'][0]['affected_symbols'] == expected
    assert 'PRIVATE STORED CONTENT' not in result.model_dump_json()
    assert db.db_path.read_bytes() == before


@pytest.mark.parametrize('stored', [
    '["private-symbol"', '["private-symbol", 2]', '["private-symbol", null]',
    '["private-symbol", ""]', '["private-symbol", "  "]', '{"private-symbol": 1}',
    '"private-symbol"', '"private-symbol', '["private-symbol"] trailing', 'null', '42', b'private-symbol',
])
def test_invalid_affected_symbols_fail_closed_without_echoing_metadata(db, stored):
    with db._get_connection() as conn:
        conn.execute('UPDATE vulnerabilities SET affected_symbols=? WHERE id=?', (stored, 5))
        conn.commit()
    before = db.db_path.read_bytes()
    with pytest.raises(ValueError, match='Affected symbols') as error:
        ResearchProfiles(Database(str(db.db_path), readonly=True)).get_vulnerability('task-z')
    assert 'private-symbol' not in str(error.value)
    assert db.db_path.read_bytes() == before


@pytest.mark.parametrize('symbols', [None, 'plain_symbol', [1], [b'bytes'], [''], [' \t '], ('symbol',)])
def test_affected_symbols_response_rejects_nonlist_or_invalid_members(symbols):
    with pytest.raises(ValidationError):
        VulnerabilityRecord(id=1, affected_symbols=symbols)


def test_affected_symbols_response_defaults_are_independent_and_schema_is_array():
    first = VulnerabilityRecord(id=1)
    second = VulnerabilityRecord(id=2)
    first.affected_symbols.append('symbol')
    assert second.affected_symbols == []
    schema = VulnerabilityRecord.model_json_schema()['properties']['affected_symbols']
    assert schema['type'] == 'array' and schema['items'] == {'type': 'string'}


@pytest.fixture
def stage_db(db):
    with db._get_connection() as conn:
        conn.executemany('INSERT INTO operational_stages (id,canonical_name,domain,stage_class) VALUES (?,?,?,?)', [
            (8, 'Crash Diagnosis', 'application', 'diagnose'),
            (9, 'Reach', 'userspace', 'reach'), (10, 'Remediation', 'other-domain', 'remediation'),
        ])
        conn.executemany('INSERT INTO stage_aliases (stage_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)', [
            (7, 'Shared   Diagnostic', 'shared diagnostic', 'source'),
            (8, 'SHARED diagnostic', 'shared diagnostic', 'source'),
            (7, 'CRASH DIAGNOSIS', 'crash diagnosis', 'source'),
        ])
        conn.executemany('''INSERT INTO stage_edges
            (source_stage_id,target_stage_id,relation,domain,evidence_reference) VALUES (?,?,?,?,?)''', [
            (9, 7, 'requires', 'edge-scope', 'incoming-reference'),
            (7, 10, 'enables', 'edge-scope', 'outgoing-reference'),
        ])
        conn.execute('''INSERT INTO evidence_links
            (writeup_id,script_id,stage_id,evidence_role,assertion_provenance,validation_status)
            VALUES (?,?,?,?,?,?)''', (2, 22, 8, 'signal', 'source', 'not_tested'))
        conn.commit()
    return db


def test_stage_canonical_normalization_alias_match_and_exact_domain(stage_db):
    profiles = ResearchProfiles(stage_db)
    canonical = profiles.get_operational_stage('  CRASH \t DIAGNOSIS  ')
    assert canonical.total_matches == 2 and not canonical.truncated
    assert [item.id for item in canonical.matches] == [8, 7]
    assert all(item.matched_alias is None for item in canonical.matches)
    alias = profiles.get_operational_stage('  SHARED   diagnostic ')
    assert [item.matched_alias for item in alias.matches] == ['SHARED diagnostic', 'Shared   Diagnostic']
    filtered = profiles.get_operational_stage('shared diagnostic', domain='KERNEL')
    assert filtered.total_matches == 1 and filtered.matches[0].id == 7
    assert profiles.get_operational_stage('crash').matches == []
    assert profiles.get_operational_stage('unsupported').matches == []
    assert profiles.get_operational_stage('crash diagnosis', domain='kern').matches == []
    assert profiles.get_operational_stage("' OR 1=1 --").matches == []


def test_stage_aliases_edges_direction_counterpart_domain_and_evidence(stage_db):
    result = ResearchProfiles(stage_db).get_operational_stage('crash diagnosis', domain='kernel')
    stage = result.matches[0]
    assert stage.matched_alias is None
    assert stage.aliases == ['Alpha alias', 'CRASH DIAGNOSIS', 'Shared   Diagnostic', 'Zeta alias']
    assert [edge.model_dump() for edge in stage.edges] == [
        {'direction': 'incoming', 'relation': 'requires', 'stage': 'Reach',
         'domain': 'userspace', 'evidence_reference': 'incoming-reference'},
        {'direction': 'outgoing', 'relation': 'enables', 'stage': 'Remediation',
         'domain': 'other-domain', 'evidence_reference': 'outgoing-reference'},
    ]
    # Duplicated evidence rows collapse; document-wide command/script rows do not leak into this stage.
    assert len(stage.evidence) == 1
    evidence = stage.evidence[0]
    assert evidence.reference == 'chunk:11@1.abc123'
    assert evidence.source.reference == 'document:1@1.abc123'
    assert evidence.assertion_provenance == 'deterministic'
    assert evidence.validation_status == 'source_documented'
    assert evidence.section == 'Observation'
    assert evidence.observed_outcome == 'Recorded marker'
    assert 'PRIVATE STORED CONTENT' not in result.model_dump_json()
    application = ResearchProfiles(stage_db).get_operational_stage('crash diagnosis', domain='application')
    assert application.matches[0].evidence[0].reference == 'script:22@2.legacy'


def test_stage_matches_and_global_evidence_budget(stage_db):
    with stage_db._get_connection() as conn:
        conn.execute('''INSERT INTO evidence_links
            (writeup_id,command_id,stage_id,evidence_role,assertion_provenance) VALUES (?,?,?,?,?)''',
            (1, 33, 7, 'procedure', 'source'))
        conn.commit()
    profiles = ResearchProfiles(stage_db)
    limited = profiles.get_operational_stage('shared diagnostic', limit=1)
    assert limited.total_matches == 2 and len(limited.matches) == 1 and limited.truncated
    limited = profiles.get_operational_stage('shared diagnostic', limit=2)
    assert len(limited.matches) == 2
    assert sum(len(item.evidence) for item in limited.matches) == 2
    assert limited.truncated
    complete = profiles.get_operational_stage('shared diagnostic', limit=3)
    assert not complete.truncated
    assert [item.reference for item in complete.matches[1].evidence] == ['chunk:11@1.abc123', 'command:33@1.abc123']


@pytest.mark.parametrize('identifier', ['', '  ', 'x' * 201, None, 17])
def test_stage_invalid_identifiers(db, identifier):
    with pytest.raises(ValueError, match='Identifier'):
        ResearchProfiles(db).get_operational_stage(identifier)


@pytest.mark.parametrize('domain', ['', '  ', 'x' * 101, 17, False])
def test_stage_invalid_domains(db, domain):
    with pytest.raises(ValueError, match='Domain'):
        ResearchProfiles(db).get_operational_stage('diagnose', domain=domain)


@pytest.mark.parametrize('limit', [0, -1, 101, True, 1.5, None])
def test_stage_invalid_limits(db, limit):
    with pytest.raises(ValueError, match='Limit'):
        ResearchProfiles(db).get_operational_stage('diagnose', limit=limit)


def test_stage_response_models_forbid_unknown_fields_and_invalid_edge_direction():
    with pytest.raises(ValidationError):
        OperationalStageProfile(identifier='x', total_matches=0, truncated=False, unknown='data')
    with pytest.raises(ValidationError):
        StageEdgeSummary(direction='sideways', relation='requires', stage='Reach', domain='kernel')


def test_vulnerability_stage_aliases_are_exact_evidenced_and_document_scoped(db):
    with db._get_connection() as conn:
        conn.execute('''INSERT INTO writeups (id,filename,filepath,writeup_type,domain,content_hash)
            VALUES (?,?,?,?,?,?)''', (3, 'unrelated.md', '/fixture/unrelated', 'research', 'kernel', 'otherhash'))
        conn.execute('INSERT INTO writeup_vulnerabilities VALUES (?,?)', (3, 12))
        conn.execute('INSERT INTO writeup_chunks (id,writeup_id,section,content,chunk_index) VALUES (?,?,?,?,?)',
                     (44, 3, 'Unrelated heading', 'PRIVATE STORED CONTENT', 0))
        conn.execute('INSERT INTO evidence_links (writeup_id,chunk_id,stage_id,evidence_role) VALUES (?,?,?,?)',
                     (3, 44, 7, 'signal'))
        conn.executemany('INSERT INTO stage_aliases (stage_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)', [
            (7, 'Observation', 'observation', 'source'),
            (7, 'Unrelated heading', 'unrelated heading', 'source'),
        ])
        conn.commit()
    before = db.db_path.read_bytes()
    profiles = ResearchProfiles(Database(str(db.db_path), readonly=True))
    target = profiles.get_vulnerability('task-z').matches[0]
    assert target.operational_stages[0].aliases == ['Observation']
    unrelated = profiles.get_vulnerability('unrelated').matches[0]
    assert unrelated.operational_stages[0].aliases == ['Unrelated heading']
    global_stage = profiles.get_operational_stage('crash diagnosis').matches[0]
    assert global_stage.aliases == ['Alpha alias', 'Observation', 'Unrelated heading', 'Zeta alias']
    assert db.db_path.read_bytes() == before


def test_alias_exact_section_ranks_before_earlier_documents_before_sql_limit(db):
    with db._get_connection() as conn:
        conn.execute('INSERT INTO writeup_chunks (id,writeup_id,section,content,chunk_index) VALUES (?,?,?,?,?)',
                     (99, 2, 'Alpha alias', 'PRIVATE STORED CONTENT', 1))
        conn.execute('INSERT INTO evidence_links (writeup_id,chunk_id,stage_id,evidence_role) VALUES (?,?,?,?)',
                     (2, 99, 7, 'signal'))
        conn.commit()
    before = db.db_path.read_bytes()
    profiles = ResearchProfiles(Database(str(db.db_path), readonly=True))
    alias = profiles.get_operational_stage('ALPHA ALIAS', limit=1)
    assert alias.truncated is True
    assert alias.matches[0].matched_alias == 'Alpha alias'
    assert [item.reference for item in alias.matches[0].evidence] == ['chunk:99@2.legacy']
    canonical = profiles.get_operational_stage('crash diagnosis', limit=1)
    assert [item.reference for item in canonical.matches[0].evidence] == ['chunk:11@1.abc123']
    complete = profiles.get_operational_stage('alpha alias', limit=2)
    assert [item.reference for item in complete.matches[0].evidence] == ['chunk:99@2.legacy', 'chunk:11@1.abc123']
    assert complete.truncated is False
    assert 'PRIVATE STORED CONTENT' not in complete.model_dump_json()
    assert db.db_path.read_bytes() == before


def test_alias_preferred_evidence_has_priority_in_the_shared_match_budget(stage_db):
    with stage_db._get_connection() as conn:
        conn.executemany('INSERT INTO writeup_chunks (id,writeup_id,section,content,chunk_index) VALUES (?,?,?,?,?)', [
            (90, 2, 'Nonmatching section', 'PRIVATE STORED CONTENT', 1),
            (99, 2, 'Shared   Diagnostic', 'PRIVATE STORED CONTENT', 2),
        ])
        conn.executemany('INSERT INTO evidence_links (writeup_id,chunk_id,stage_id,evidence_role) VALUES (?,?,?,?)',
                         [(2, 90, 8, 'signal'), (2, 99, 7, 'signal')])
        conn.commit()
    result = ResearchProfiles(stage_db).get_operational_stage('shared diagnostic', limit=2)
    assert result.truncated is True
    assert [match.id for match in result.matches] == [8, 7]
    assert sum(len(match.evidence) for match in result.matches) == 2
    assert [item.reference for item in result.matches[1].evidence] == ['chunk:99@2.legacy']
