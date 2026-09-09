"""Regression tests for evidence reporting, bounded pagination, and typed records."""
import hashlib
import json

import pytest
from mcp import Client
from pydantic import ValidationError

from command_vault.database import Database
from command_vault.knowledge import Knowledge
from command_vault.models import Command, Script, Writeup, WriteupType
from command_vault.record_search import search_records, search_relations
from command_vault.responses import KnowledgeHit
from command_vault.server import create_server


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def records(tmp_path):
    db = Database(str(tmp_path/'vault.db'))
    with db.transaction():
        wid = db.insert_writeup(Writeup(filename='audit.md',filepath=str(tmp_path/'audit.md'),
                                        writeup_type=WriteupType.SHERLOCK,tags=['windows','sherlock']))
        tool = db.get_or_create_tool('echo')
        for i in range(125):
            text = f'Audit record {i}. ' + 'Event detail. '*200
            db.insert_chunk(wid,'Audit',text,i)
            db.insert_command(Command(writeup_id=wid,tool_id=tool,raw_command=f'echo audit_{i} '+'x'*600))
            db.insert_script(Script(writeup_id=wid,language='python',code=f'# audit {i}\nprint("ok")\n'+'# note\n'*30))
            db.insert_history_command(command_hash=str(i),raw_command=f'echo audit_{i}',
                sanitized_command=f'echo audit_{i} '+'x'*600,command_template=None,tool_id=tool,
                timestamp=None,source_file='test-history')
        # Exact duplicate evidence must not reappear on a later knowledge page.
        db.insert_chunk(wid,'Audit','Audit record 0. '+'Event detail. '*200,125)
    return db


def test_required_terms_independent_of_query_and_punctuation(records):
    kb=Knowledge(records)
    for query in ('read audit logs', 'read audit logs ZQXJ92814?'):
        page=kb.search(query,required_terms=['ZQXJ92814'])
        assert page.results==[]
        assert page.unmatched_required_terms==['ZQXJ92814']
        assert 'ZQXJ92814?' not in page.unmatched_terms
        assert 'ZQXJ92814' in page.unmatched_terms
    page=kb.search('audit',required_terms=['audit'],tags=['absent-tag'])
    assert page.unmatched_query_terms==['audit']
    assert page.unmatched_required_terms==['audit']


def test_individual_required_hits_do_not_claim_cooccurrence(records):
    with records._get_connection() as conn:
        wid=conn.execute('SELECT id FROM writeups').fetchone()[0]
    records.insert_chunk(wid,'A','Audit UNIQUEALPHA evidence only.',126)
    records.insert_chunk(wid,'B','Audit UNIQUEBETA evidence only.',127)
    page=Knowledge(records).search('audit',required_terms=['UNIQUEALPHA','UNIQUEBETA'])
    assert not page.results
    assert not page.unmatched_required_terms


@pytest.mark.parametrize('kind',['knowledge','command','script','history'])
def test_pages_cover_more_than_100_records_without_skips(records,kind):
    before=hashlib.sha256(records.db_path.read_bytes()).hexdigest()
    cursor=None; ids=[]; cursors=set()
    for _ in range(150):
        if kind=='knowledge':
            page=Knowledge(records).search('audit nonexistent',limit=100,max_chars=500,cursor=cursor)
        else:
            page=search_records(records,kind,'audit nonexistent',limit=100,max_chars=500,cursor=cursor)
        assert page.has_more == (page.next_cursor is not None)
        assert page.results
        ids.extend(row.id for row in page.results)
        if page.next_cursor is None:
            break
        assert page.next_cursor not in cursors
        cursors.add(page.next_cursor)
        cursor=page.next_cursor
    else:
        pytest.fail('Cursor did not terminate')
    assert len(ids)==len(set(ids))==125
    assert hashlib.sha256(records.db_path.read_bytes()).hexdigest()==before


def test_page_size_can_change_but_query_filters_and_revision_cannot(records):
    kb=Knowledge(records)
    first=kb.search('audit',tags=['windows'],limit=1)
    second=kb.search('audit',tags=['windows'],limit=10,max_chars=20000,cursor=first.next_cursor)
    assert second.results[0].id != first.results[0].id
    for kwargs in ({'query':'detail','tags':['windows']}, {'query':'audit','tags':['sherlock']},
                   {'query':'audit','tags':['windows'],'required_terms':['audit']}):
        with pytest.raises(ValueError,match='does not match'):
            kb.search(**kwargs,cursor=first.next_cursor)
    records.insert_chunk(1,'New','Another audit evidence record.',999)
    with pytest.raises(ValueError,match='Database changed'):
        kb.search('audit',tags=['windows'],cursor=first.next_cursor)


def test_cursor_corruption_and_wrong_search_tool(records):
    token=Knowledge(records).search('audit',limit=1).next_cursor
    for invalid in ('not-a-cursor',token+'x','x'*1600):
        with pytest.raises(ValueError,match='Invalid cursor'):
            Knowledge(records).search('audit',cursor=invalid)
    with pytest.raises(ValueError,match='does not match'):
        search_records(records,'command','audit',cursor=token)


def test_clipped_history_can_be_read_and_rows_omitted_are_distinct(records):
    page=search_records(records,'history','audit',limit=100,max_chars=500)
    assert page.records_clipped and page.has_more
    assert page.results[0].kind=='reference'
    context=Knowledge(records).read_context(page.results[0].reference)
    assert len(context.content)>500 and context.source_status=='indexed'
    page=search_records(records,'history','audit',limit=1,max_chars=20000)
    assert page.has_more and not page.records_clipped and not page.truncated


def test_typed_hit_rejects_extra_fields_and_bad_source(records):
    hit=Knowledge(records).search('audit',limit=1).results[0].model_dump()
    with pytest.raises(ValidationError):
        KnowledgeHit.model_validate({**hit,'fabricated_field':True})
    hit['source']['document_id']='not-an-id'
    with pytest.raises(ValidationError):
        KnowledgeHit.model_validate(hit)


def test_related_group_continuation_and_document_context(records,tmp_path):
    source=tmp_path/'source.md'
    source.write_text('# Audit\n\nComplete source evidence for the related document.\n')
    with records.transaction():
        tech=records.get_or_create_technique('Log review','dfir')
        for i in range(5):
            wid=records.insert_writeup(Writeup(filename=f'source{i}.md',filepath=str(source)+str(i),writeup_type=WriteupType.SHERLOCK))
            records.link_technique_writeup(tech,wid)
            records.insert_chunk(wid,'Audit',f'Audit document {i}, stored fallback evidence.',0)
    cursor=None; ids=[]
    while True:
        page=search_relations(records,'Log review',limit=2,cursor=cursor)
        group=page.results[0]
        assert group.total_writeup_count==5
        assert group.writeup_count==len(group.writeups)
        ids.extend(w.id for w in group.writeups)
        context=Knowledge(records).read_context(group.writeups[0].reference)
        assert context.source_status=='unavailable'
        cursor=page.next_cursor
        if cursor is None:break
    assert len(ids)==len(set(ids))==5


@pytest.mark.parametrize('kind',['knowledge','command'])
def test_and_exhaustion_does_not_switch_to_or(records,kind):
    for i in range(2):
        if kind=='knowledge':
            records.insert_chunk(1,'Specific',f'Audit SPECIALTOKEN record {i}.',200+i)
        else:
            records.insert_command(Command(writeup_id=1,raw_command=f'echo audit SPECIALTOKEN {i}'))
    fetch=(lambda **kwargs: Knowledge(records).search('audit SPECIALTOKEN',**kwargs)) if kind=='knowledge' else (
           lambda **kwargs: search_records(records,'command','audit SPECIALTOKEN',**kwargs))
    first=fetch(limit=1)
    assert first.match_mode=='all_terms' and first.has_more
    second=fetch(limit=1,cursor=first.next_cursor)
    assert second.match_mode=='all_terms' and not second.has_more
    assert first.results[0].id!=second.results[0].id


@pytest.mark.anyio
async def test_mcp_cursor_contract_and_output_models(records):
    async with Client(create_server(records)) as client:
        tools={t.name:t for t in (await client.list_tools()).tools}
        for name in ('search_knowledge','search_commands','search_scripts','search_history','get_tool_examples'):
            assert 'cursor' in tools[name].input_schema['properties']
            assert 'max_chars' in tools[name].input_schema['properties']
            items=tools[name].output_schema['properties']['results']['items']
            assert 'anyOf' in items or '$ref' in items
        first=(await client.call_tool('search_knowledge',{'query':'audit','limit':100,'max_chars':500})).structured_content
        assert first['next_cursor'] and first['has_more']
        second=(await client.call_tool('search_knowledge',{'query':'audit','cursor':first['next_cursor']})).structured_content
        assert first['results'][0]['id']!=second['results'][0]['id']
        bad=await client.call_tool('search_knowledge',{'query':'changed','cursor':first['next_cursor']})
        assert bad.is_error
        missing=(await client.call_tool('search_knowledge',{'query':'read audit logs','required_terms':['ZQXJ92814']})).structured_content
        assert missing['unmatched_required_terms']==['ZQXJ92814']
