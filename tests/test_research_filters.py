"""Exact knowledge filters over a small, disposable research corpus."""

import json
import sys

import pytest
from mcp import Client

import command_vault.database as database_module
from command_vault import cli
from command_vault.database import Database
from command_vault.knowledge import Knowledge
from command_vault.pagination import Cursor
from command_vault.server import create_server


FILTERS = {
    'source_name': 'Alpha', 'domain': 'linux', 'external_id': 'Task-A',
    'cve': 'CVE-2099-0001', 'project': 'Linux', 'vulnerability_class': 'Read issue',
    'sanitizer': 'KASAN', 'operational_stage': 'address disclosure',
    'mitigation': 'KASLR', 'validation_status': 'source_documented',
}


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def corpus(tmp_path):
    db = Database(str(tmp_path / 'filters.db'))
    with db.transaction(), db._get_connection() as conn:
        conn.executemany('INSERT INTO source_collections (id,name,source_kind) VALUES (?,?,?)',
                         [(1, 'Alpha', 'research'), (2, 'Beta', 'research')])
        for wid, source, domain, external in [(1, 1, 'linux', 'Task-A'), (2, 2, 'parser', 'Task-B')]:
            conn.execute('''INSERT INTO writeups
                (id,filename,filepath,writeup_type,source_collection_id,domain,external_id) VALUES (?,?,?,?,?,?,?)''',
                (wid, f'{wid}.md', f'research://fixture/{wid}', 'research', source, domain, external))
        conn.executemany('INSERT INTO writeup_chunks (id,writeup_id,section,content,chunk_index) VALUES (?,?,?,?,?)', [
            (11, 1, 'Observation', 'orchard Alpha first observation', 0),
            (12, 1, 'Details', 'orchard Alpha second observation', 1),
            (13, 1, 'Other', 'orchard Alpha third observation', 2),
            (21, 2, 'Observation', 'orchard Beta other observation', 0),
        ])
        conn.executemany('''INSERT INTO vulnerabilities
            (id,canonical_id,project_name,vulnerability_class,sanitizer) VALUES (?,?,?,?,?)''', [
            (1, 'CVE-2099-0001', 'Linux', 'Read issue', 'KASAN'),
            (2, 'CVE-2099-0002', 'Parser', 'Write issue', 'ASAN'),
        ])
        conn.executemany('INSERT INTO writeup_vulnerabilities (writeup_id,vulnerability_id) VALUES (?,?)', [(1, 1), (2, 2)])
        conn.execute('INSERT INTO operational_stages (id,canonical_name,domain,stage_class) VALUES (?,?,?,?)',
                     (1, '  Address   disclosure ', 'linux', 'primitive'))
        conn.execute('INSERT INTO stage_aliases (stage_id,alias,alias_normalized,provenance) VALUES (?,?,?,?)',
                     (1, 'Address Leak', 'address leak', 'deterministic'))
        conn.executemany('''INSERT INTO evidence_links
            (writeup_id,chunk_id,stage_id,validation_status) VALUES (?,?,?,?)''',
            [(1, 11, 1, 'source_documented'), (1, 12, None, 'failed')])
        conn.execute('INSERT INTO mitigations (id,canonical_name,raw_label) VALUES (?,?,?)', (1, 'KASLR', 'Address randomization'))
        conn.execute('INSERT INTO vulnerability_mitigations (vulnerability_id,mitigation_id,state) VALUES (?,?,?)', (1, 1, 'discussed'))
    return db


def ids(page):
    return [row.id for row in page.results]


@pytest.mark.parametrize('name', list(FILTERS)[:7])
def test_exact_document_metadata_filters(corpus, name):
    value = FILTERS[name]
    page = Knowledge(corpus).search('orchard', **{name: f' {value.swapcase()} '})
    assert set(ids(page)) == {11, 12, 13}
    assert page.applied_filters == {name: value.swapcase()}


def test_combination_and_stable_applied_filter_order(corpus):
    supplied = dict(reversed(list(FILTERS.items())))
    supplied['operational_stage'] = '  ADDRESS  \t DISCLOSURE  '
    page = Knowledge(corpus).search('orchard', **supplied)
    assert ids(page) == [11]
    assert page.applied_filters == FILTERS
    assert list(page.applied_filters) == list(FILTERS)


@pytest.mark.parametrize('value', ['address disclosure', ' ADDRESS  LEAK '])
def test_stage_canonical_alias_is_specific_to_current_chunk(corpus, value):
    page = Knowledge(corpus).search('orchard', operational_stage=value)
    assert ids(page) == [11]
    assert page.applied_filters['operational_stage'] == ' '.join(value.lower().split())


def test_mitigation_is_document_link_and_validation_is_current_chunk(corpus):
    assert set(ids(Knowledge(corpus).search('orchard', mitigation='kaslr'))) == {11, 12, 13}
    assert set(ids(Knowledge(corpus).search('orchard', mitigation='ADDRESS RANDOMIZATION'))) == {11, 12, 13}
    assert ids(Knowledge(corpus).search('orchard', validation_status='FAILED')) == [12]
    assert ids(Knowledge(corpus).search('orchard', validation_status='source_documented')) == [11]
    assert Knowledge(corpus).search('orchard', operational_stage='address disclosure', validation_status='failed').results == []


@pytest.mark.parametrize('value', ['Alp', "Alpha' OR 1=1 --", '%', 'Alpha*'])
def test_filters_are_exact_and_parameterized(corpus, value):
    assert Knowledge(corpus).search('orchard', source_name=value).results == []
    assert len(Knowledge(corpus).search('orchard').results) == 4


@pytest.mark.parametrize('name,value', [
    ('source_name', '  '), ('source_name', 7), ('source_name', 'a' * 201),
    ('domain', 'a' * 101), ('operational_stage', '\t\n'),
])
def test_filter_validation(corpus, name, value):
    with pytest.raises(ValueError, match=name):
        Knowledge(corpus).search('orchard', **{name: value})


def test_cursor_binds_structured_filters_and_unfiltered_behavior_is_preserved(corpus):
    knowledge = Knowledge(corpus)
    first = knowledge.search('orchard', source_name='Alpha', limit=1)
    assert first.next_cursor
    second = knowledge.search('orchard', source_name='Alpha', cursor=first.next_cursor)
    assert len(second.results) == 2
    with pytest.raises(ValueError, match='filters'):
        knowledge.search('orchard', source_name='Beta', cursor=first.next_cursor)
    with pytest.raises(ValueError, match='filters'):
        knowledge.search('orchard', source_name='Alpha', domain='linux', cursor=first.next_cursor)
    unfiltered = knowledge.search('orchard')
    positional = knowledge.search('orchard', None, None, None, 5, 10000, None)
    assert ids(unfiltered) == ids(positional)
    assert set(ids(unfiltered)) == {11, 12, 13, 21}
    assert unfiltered.match_mode == 'all_terms'
    assert unfiltered.applied_filters == {}
    assert knowledge.search('orchard nonexistent', source_name='Alpha').match_mode == 'any_terms'


def test_required_terms_stay_hard_constraints_under_structured_filters(corpus):
    page = Knowledge(corpus).search('orchard', source_name='Beta', required_terms=['Alpha'])
    assert page.results == []
    assert page.unmatched_required_terms == ['Alpha']


def test_schema_v1_rejects_structured_filters_but_keeps_unfiltered_search(tmp_path, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', 1)
        db = Database(str(tmp_path / 'legacy.db'))
    with db.transaction(), db._get_connection() as conn:
        conn.execute('INSERT INTO writeups (id,filename,filepath,writeup_type) VALUES (?,?,?,?)', (1, 'legacy.md', '/legacy.md', 'box'))
        conn.execute('INSERT INTO writeup_chunks (writeup_id,content,chunk_index) VALUES (?,?,?)', (1, 'orchard legacy observation', 0))
    readonly = Database(str(db.db_path), readonly=True)
    before = db.db_path.read_bytes()
    assert len(Knowledge(readonly).search('orchard').results) == 1
    with pytest.raises(ValueError, match='schema 2'):
        Knowledge(readonly).search('orchard', source_name='Alpha')
    assert db.db_path.read_bytes() == before


def test_readonly_filters_do_not_write_database(corpus):
    before = corpus.db_path.read_bytes()
    readonly = Database(str(corpus.db_path), readonly=True)
    statements = []
    with readonly.read_snapshot(), readonly._get_connection() as conn:
        conn.set_trace_callback(statements.append)
        assert ids(Knowledge(readonly).search('orchard', **FILTERS)) == [11]
    assert not any(sql.lstrip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP')) for sql in statements)
    assert corpus.db_path.read_bytes() == before


@pytest.mark.anyio
async def test_mcp_schema_read_annotation_and_keyword_forwarding(corpus, monkeypatch):
    calls = []
    original = Knowledge.search

    def observed(self, *args, **kwargs):
        calls.append(kwargs)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Knowledge, 'search', observed)
    async with Client(create_server(corpus)) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert set(FILTERS) <= set(tools['search_knowledge'].input_schema['properties'])
        assert not set(FILTERS).intersection(tools['search_writeup_prose'].input_schema['properties'])
        assert tools['search_knowledge'].annotations.read_only_hint
        assert 'applied_filters' in tools['search_knowledge'].output_schema['properties']
        result = await client.call_tool('search_knowledge', {'query': 'orchard', **FILTERS})
        assert not result.is_error
        assert [row['id'] for row in result.structured_content['results']] == [11]
        assert result.structured_content['applied_filters'] == FILTERS
    assert calls == [FILTERS]


def test_cli_knowledge_flags_forward_to_json_without_writes(corpus, monkeypatch, capsys):
    arguments = ['vault', '--db', str(corpus.db_path), 'knowledge', 'orchard', '--json']
    for name, value in FILTERS.items():
        flag = '--stage' if name == 'operational_stage' else '--' + name.replace('_', '-')
        arguments.extend((flag, value))
    monkeypatch.setattr(sys, 'argv', arguments)
    before = corpus.db_path.read_bytes()
    cli.main()
    captured = capsys.readouterr()
    assert captured.err == ''
    page = json.loads(captured.out)
    assert [row['id'] for row in page['results']] == [11]
    assert page['applied_filters'] == FILTERS
    assert corpus.db_path.read_bytes() == before


def test_cli_prose_does_not_accept_new_knowledge_flags(corpus, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['vault', '--db', str(corpus.db_path), 'prose', 'orchard', '--source-name', 'Alpha'])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert 'unrecognized arguments' in capsys.readouterr().err


@pytest.fixture
def diagnostic_corpus(corpus):
    with corpus.transaction(), corpus._get_connection() as conn:
        conn.execute('UPDATE writeups SET document_kind=? WHERE id=?', ('diagnostic-reference', 1))
        conn.execute('UPDATE writeups SET document_kind=? WHERE id=?', ('vulnerability-research', 2))
        conn.execute('INSERT INTO writeups (id,filename,filepath,writeup_type) VALUES (?,?,?,?)',
                     (3, 'personal.md', '/personal.md', 'box'))
        conn.execute('INSERT INTO writeup_chunks (id,writeup_id,section,content,chunk_index) VALUES (?,?,?,?,?)',
                     (31, 3, 'Personal', 'orchard personal observation', 0))
        conn.execute('INSERT INTO tags (id,name) VALUES (?,?)', (1, 'research'))
        conn.executemany('INSERT INTO writeup_tags (writeup_id,tag_id) VALUES (?,?)', [(1, 1), (2, 1)])
    return corpus


def test_default_scope_excludes_diagnostics_but_retains_personal_and_research(diagnostic_corpus):
    before = diagnostic_corpus.db_path.read_bytes()
    knowledge = Knowledge(Database(str(diagnostic_corpus.db_path), readonly=True))
    page = knowledge.search('orchard')
    assert set(ids(page)) == {21, 31}
    assert page.match_mode == 'all_terms' and page.applied_filters == {}
    assert 'Diagnostic references excluded; use type research or a structured filter.' in page.notice
    assert diagnostic_corpus.db_path.read_bytes() == before


@pytest.mark.parametrize('options,expected', [
    ({'writeup_type': 'research'}, {11, 12, 13, 21}),
    ({'tags': ['#ReSeArCh']}, {11, 12, 13, 21}),
    ({'writeup_type': 'box'}, {31}),
    ({'source_name': 'Alpha'}, {11, 12, 13}),
    ({'domain': 'linux'}, {11, 12, 13}),
    ({'external_id': 'Task-A'}, {11, 12, 13}),
    ({'cve': 'CVE-2099-0001'}, {11, 12, 13}),
    ({'project': 'Linux'}, {11, 12, 13}),
    ({'vulnerability_class': 'Read issue'}, {11, 12, 13}),
    ({'sanitizer': 'KASAN'}, {11, 12, 13}),
    ({'operational_stage': 'address disclosure'}, {11}),
    ({'mitigation': 'KASLR'}, {11, 12, 13}),
    ({'validation_status': 'failed'}, {12}),
])
def test_explicit_research_intent_disables_default_diagnostic_exclusion(diagnostic_corpus, options, expected):
    page = Knowledge(diagnostic_corpus).search('orchard', **options)
    assert set(ids(page)) == expected
    assert 'Diagnostic references excluded' not in page.notice
    assert page.applied_filters == {name: value for name, value in options.items() if name in FILTERS}


def test_required_and_unmatched_terms_are_evaluated_within_default_scope(diagnostic_corpus):
    knowledge = Knowledge(diagnostic_corpus)
    page = knowledge.search('orchard Alpha', required_terms=['Alpha'])
    assert page.results == []
    assert page.unmatched_query_terms == page.unmatched_required_terms == ['Alpha']
    explicit = knowledge.search('orchard Alpha', required_terms=['Alpha'], writeup_type='research')
    assert set(ids(explicit)) == {11, 12, 13}
    assert explicit.unmatched_required_terms == []


def test_default_scope_is_bound_into_cursor(diagnostic_corpus):
    knowledge = Knowledge(diagnostic_corpus)
    first = knowledge.search('orchard', limit=1)
    assert first.next_cursor
    assert len(knowledge.search('orchard', cursor=first.next_cursor).results) == 1
    with pytest.raises(ValueError, match='filters'):
        knowledge.search('orchard', writeup_type='research', cursor=first.next_cursor)
    previous_key = {'search': 'knowledge-v1', 'query': 'orchard', 'type': None, 'tags': [], 'required': []}
    token_without_scope = Cursor(diagnostic_corpus, previous_key, None).next(1)
    with pytest.raises(ValueError, match='filters'):
        knowledge.search('orchard', cursor=token_without_scope)
    scoped_key = {**previous_key, 'default_scope': 'exclude-diagnostic-reference'}
    assert Cursor(diagnostic_corpus, scoped_key, first.next_cursor).offset == 1


def test_schema_one_default_search_has_no_document_kind_predicate_or_scope_notice(tmp_path, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', 1)
        db = Database(str(tmp_path / 'v1-default.db'))
    with db.transaction(), db._get_connection() as conn:
        conn.execute('INSERT INTO writeups (id,filename,filepath,writeup_type) VALUES (?,?,?,?)',
                     (1, 'personal.md', '/personal.md', 'box'))
        conn.execute('INSERT INTO writeup_chunks (writeup_id,content,chunk_index) VALUES (?,?,?)',
                     (1, 'orchard legacy observation', 0))
    readonly = Database(str(db.db_path), readonly=True)
    before = db.db_path.read_bytes()
    statements = []
    with readonly.read_snapshot(), readonly._get_connection() as conn:
        conn.set_trace_callback(statements.append)
        page = Knowledge(readonly).search('orchard')
    assert len(page.results) == 1 and page.match_mode == 'all_terms'
    assert page.applied_filters == {} and 'Diagnostic references excluded' not in page.notice
    assert not any('document_kind' in query for query in statements)
    assert db.db_path.read_bytes() == before
