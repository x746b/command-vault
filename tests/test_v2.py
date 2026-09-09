import hashlib
import sqlite3

import pytest
from mcp import Client

from command_vault.database import Database
from command_vault.documents import knowledge_chunks, MAX_CHUNK_CHARS
from command_vault.indexer import Indexer
from command_vault.knowledge import Knowledge
from command_vault.models import Script, Writeup, WriteupType
from command_vault.server import create_server
from command_vault.tools import VaultTools
from command_vault.parser import WriteupParser


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path/'vault.db'))


@pytest.fixture
def source(tmp_path):
    path = tmp_path/'evidence.md'
    path.write_text('# Example\n\n#sherlock #windows\n\n## Cleared log\n'
                    'Which event records a cleared audit log?\n\n'
                    '```xml\n<EventID>1102</EventID>\n<Channel>Security</Channel>\n```\n')
    return path


def test_context_retains_xml_and_hard_identifier(db, source):
    Indexer(db).index_file(str(source), source_dir='unified')
    kb = Knowledge(db)
    page = kb.search('Security 1102', tags=['windows','windows'])
    assert page.results
    context = kb.read_context(page.results[0]['reference'])
    assert '<EventID>1102</EventID>' in context.content
    assert context.source_status == 'current'
    miss = kb.search('Security ZQXJ92814', required_terms=['ZQXJ92814'])
    assert miss.results == []
    assert 'ZQXJ92814' in miss.unmatched_terms


def test_source_missing_and_changed_are_explicit(db, source):
    Indexer(db).index_file(str(source), source_dir='unified')
    kb = Knowledge(db)
    ref = kb.search('1102').results[0]['reference']
    source.write_text(source.read_text()+'\nNew evidence\n')
    assert kb.read_context(ref).source_status == 'changed'
    source.unlink()
    result = kb.read_context(ref)
    assert result.source_status == 'unavailable'
    assert '1102' in result.content


def test_revision_reference_rejects_reindex(db, source):
    indexer=Indexer(db)
    indexer.index_file(str(source))
    kb=Knowledge(db)
    ref=kb.search('1102').results[0]['reference']
    source.write_text(source.read_text().replace('1102','9999'))
    indexer.index_file(str(source))
    with pytest.raises(ValueError,match='Reference'):
        kb.read_context(ref)


def test_chunk_bounds_and_fence_headings():
    text = '# Test\n## Evidence\n```text\n# not a heading\n' + 'event record\n'*2000 + '```\n'
    chunks = knowledge_chunks(text)
    assert len(chunks) > 2
    assert max(len(c['content']) for c in chunks) <= MAX_CHUNK_CHARS
    assert all(c['section'] == 'Evidence' for c in chunks)
    assert '# not a heading' in chunks[0]['content']


def test_duplicate_basenames_and_changed_sources(db, tmp_path):
    for directory in ('a','b'):
        root = tmp_path/directory
        root.mkdir()
        (root/'same.md').write_text(f'# {directory}\n\n## Evidence\nA distinct record for directory {directory} with enough content.\n')
    indexer = Indexer(db)
    first = indexer.index_directory(str(tmp_path), source_dir='unified')
    assert first.files_processed == 2
    assert db.get_writeup_count() == 2
    assert indexer.index_directory(str(tmp_path), source_dir='unified').files_processed == 0
    (tmp_path/'a'/'same.md').write_text('# A\n\n## Evidence\nUpdated record with another meaningful text paragraph.\n')
    assert indexer.index_directory(str(tmp_path), skip_existing=True, source_dir='unified').files_processed == 1
    with pytest.raises(ValueError, match='Ambiguous'):
        db.get_writeup_by_filename('same.md')


def test_document_import_rolls_back(db, source, monkeypatch):
    indexer = Indexer(db)
    indexer.index_file(str(source))
    before = [(r.id,r.content) for r in db.search_chunks('1102')]
    source.write_text(source.read_text().replace('1102','9999'))
    def fail(*a, **k):
        raise RuntimeError('simulated insert failure')
    monkeypatch.setattr(db, 'insert_chunk', fail)
    with pytest.raises(RuntimeError):
        indexer.index_file(str(source))
    assert [(r.id,r.content) for r in db.search_chunks('1102')] == before


def test_history_is_idempotent_and_rebuild_preserves_it(db, tmp_path, source):
    path = tmp_path/'.zsh_history'
    path.write_text('curl --version\ncurl --version\n')
    tools = VaultTools(db, {'unified':str(tmp_path)})
    tools.index_history(str(path))
    tools.index_history(str(path))
    with db._get_connection() as conn:
        row = conn.execute('SELECT occurrence_count,first_seen,last_seen FROM history_commands').fetchone()
        assert tuple(row) == (2,None,None)
    tools.index_writeups(force_rebuild=True)
    assert len(tools.search_history(query='curl')) == 1


def test_bad_rebuild_configuration_does_not_clear(db, source):
    Indexer(db).index_file(str(source))
    with pytest.raises(ValueError):
        Indexer(db).index_all({}, force_rebuild=True)
    assert db.get_writeup_count() == 1


def test_history_retains_first_and_last_execution(db, tmp_path):
    path=tmp_path/'.zsh_history'
    path.write_text(': 1700000000:0;curl --version\n: 1700001000:0;curl --version\n')
    tools=VaultTools(db,{})
    tools.index_history(str(path))
    tools.index_history(str(path))
    result=tools.search_history(query='curl')[0]
    assert result['first_seen']=='2023-11-14T22:13:20+00:00'
    assert result['last_seen']=='2023-11-14T22:30:00+00:00'
    assert result['occurrence_count']==2


def test_language_alias(db):
    wid = db.insert_writeup(Writeup(filename='x.md',filepath='/test/x.md',writeup_type=WriteupType.CHALLENGE))
    db.insert_script(Script(writeup_id=wid,language='js',code='console.log("hello");'))
    assert len(db.search_scripts(language='javascript')) == 1
    assert len(db.search_scripts(language='js')) == 1


def test_collection_directories_are_respected_in_unified_mode():
    parser=WriteupParser()
    assert parser.detect_writeup_type('/writeups/challenges/sample (forensics).md', source_dir='unified')['type']==WriteupType.CHALLENGE
    assert parser.detect_writeup_type('/writeups/sherlocks/sample (Easy).md', source_dir='unified')['type']==WriteupType.SHERLOCK


def test_legacy_schema_migration_preserves_identity(tmp_path):
    path=tmp_path/'old.db'
    conn=sqlite3.connect(path)
    conn.execute('''CREATE TABLE writeups (id INTEGER PRIMARY KEY, filename TEXT UNIQUE NOT NULL,
        filepath TEXT NOT NULL,writeup_type TEXT NOT NULL,challenge_type TEXT,difficulty TEXT,title TEXT,
        indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.execute("INSERT INTO writeups(id,filename,filepath,writeup_type) VALUES(42,'x.md','/a/x.md','box')")
    conn.commit();conn.close()
    db=Database(str(path))
    assert db.get_writeup_by_filename('x.md').id == 42
    db.insert_writeup(Writeup(filename='x.md',filepath='/b/x.md',writeup_type=WriteupType.BOX))
    assert db.get_writeup_count() == 2


@pytest.mark.anyio
async def test_mcp_structured_search_and_context(db, source):
    Indexer(db).index_file(str(source), source_dir='unified')
    async with Client(create_server(db)) as client:
        listing = await client.list_tools()
        tools = {t.name:t for t in listing.tools}
        assert 'index_writeups' not in tools
        assert tools['search_knowledge'].output_schema
        assert tools['search_knowledge'].annotations.read_only_hint
        assert tools['vault_stats'].output_schema
        assert (await client.call_tool('vault_stats',{})).structured_content
        result = await client.call_tool('search_knowledge', {'query':'1102'})
        assert not result.is_error
        page = result.structured_content
        assert page['results']
        context = await client.call_tool('read_context', {'reference':page['results'][0]['reference']})
        assert '<EventID>1102</EventID>' in context.structured_content['content']


@pytest.mark.anyio
async def test_legacy_readonly_override_disables_admin_tools(db, monkeypatch):
    monkeypatch.setenv('VAULT_READONLY', 'true')
    async with Client(create_server(db, allow_admin=True)) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert not names.intersection({'index_writeups', 'index_history', 'clear_history', 'enrich'})


@pytest.mark.anyio
async def test_mcp_errors_and_unknown_recency(db, tmp_path):
    history = tmp_path/'.zsh_history'
    history.write_text('curl --version\n')
    VaultTools(db,{}).index_history(str(history))
    async with Client(create_server(db)) as client:
        for tool, args in [('get_script',{'script_id':-1}),
                           ('suggest_command',{'goal':'read logs','context':{'os':'linux'}}),
                           ('search_history',{'since':'2020-01-01'}),
                           ('search_knowledge',{'query':'audit','limit':-1})]:
            result=await client.call_tool(tool,args)
            assert result.is_error


@pytest.mark.anyio
async def test_mcp_inventory_pagination(db):
    wid=db.insert_writeup(Writeup(filename='x.md',filepath='/x.md',writeup_type=WriteupType.BOX,
                                  tags=[f'tag{i}' for i in range(60)]))
    async with Client(create_server(db)) as client:
        cursor=None;names=[]
        while True:
            args={'limit':7}
            if cursor:args['cursor']=cursor
            result=(await client.call_tool('list_tags',args)).structured_content
            assert len(result['results'])<=7
            names.extend(r['name'] for r in result['results'])
            cursor=result['next_cursor']
            if cursor is None:break
        assert len(names)==len(set(names))==60


def test_readonly_startup_preserves_database_bytes(db):
    before=hashlib.sha256(db.db_path.read_bytes()).hexdigest()
    readonly=Database(str(db.db_path),readonly=True)
    create_server(readonly)
    assert hashlib.sha256(db.db_path.read_bytes()).hexdigest()==before
    with pytest.raises(sqlite3.OperationalError):
        with readonly._get_connection() as conn:
            conn.execute('DELETE FROM writeups')
