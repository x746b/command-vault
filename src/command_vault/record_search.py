"""Cursor-based record search with the existing lexical matching policies."""
from datetime import datetime
import itertools
import json

from .database import _build_fts_query, _build_fts_query_or, _tokenize_fts
from .pagination import Cursor, paginate
from .responses import CommandHit, CommandPage, ScriptHit, ScriptPage, HistoryHit, HistoryPage
from .responses import SearchPage, RelatedWriteup, RelatedGroup, RelatedPage, ReferenceHit


def search_relations(db, technique, *, limit=20, max_chars=12000, cursor=None):
    with db.read_snapshot():
        position = Cursor(db, {'search':'relations-v1','technique':technique}, cursor)
        groups = db.search_related(technique, limit=db.get_writeup_count())
        group = groups[0] if groups else None
        def records():
            for writeup in group['writeups'] if group else []:
                data = dict(writeup)
                identifier = data.pop('document_id')
                reference = f"document:{identifier}@{identifier}.{data['revision'] or 'legacy'}"
                yield RelatedWriteup(id=identifier,reference=reference,**data)
        page = paginate(records(),position,SearchPage[RelatedWriteup | ReferenceHit],technique,limit,max_chars)
        metadata = page.model_dump(exclude={'results'})
        result = [RelatedGroup(technique=group['technique'],type=group['type'],
            writeup_count=len(page.results),total_writeup_count=group['writeup_count'],writeups=page.results)] if group else []
        return RelatedPage(results=result,**metadata)


def search_records(db, kind, query=None, *, limit=10, max_chars=12000, cursor=None,
                   tool=None, category=None, writeup_type=None, challenge_type=None,
                   tags=None, language=None, library=None, since=None):
    if query is not None and len(query)>1000:
        raise ValueError('Query must be at most 1000 characters')
    tags = sorted({t.lower().lstrip('#') for t in (tags or [])})
    language = language.lower() if language else None
    language = {'py':'python','js':'javascript','ps1':'powershell','syzlang':'syz'}.get(language, language)
    if since:
        datetime.fromisoformat(since)
    settings = dict(search=kind+'-v1', query=query, tool=tool, category=category,
                    writeup_type=writeup_type, challenge_type=challenge_type, tags=tags,
                    language=language, library=library, since=since)
    if kind == 'command':
        fields = '''c.id,c.raw_command,c.command_template template,c.purpose,c.source_section,
                    t.name tool,w.filename,w.writeup_type,w.challenge_type'''
        base = '''commands c LEFT JOIN tools t ON t.id=c.tool_id
                  LEFT JOIN categories cat ON cat.id=t.category_id LEFT JOIN writeups w ON w.id=c.writeup_id'''
        alias, fts, rank = 'c', 'commands_fts', 'bm25(commands_fts,10.0,2.0,0.2),c.id'
        page_type = CommandPage
    elif kind == 'script':
        fields = 's.id,s.language,s.code,s.purpose,s.libraries_used,w.filename,w.writeup_type,w.challenge_type'
        base = 'scripts s LEFT JOIN writeups w ON w.id=s.writeup_id'
        alias, fts, rank = 's', 'scripts_fts', 'bm25(scripts_fts),s.id'
        page_type = ScriptPage
    elif kind == 'history':
        fields = '''h.id,h.sanitized_command,h.command_template template,h.first_seen,h.last_seen,
                    h.occurrence_count,t.name tool'''
        base = 'history_commands h LEFT JOIN tools t ON t.id=h.tool_id'
        alias, fts, rank = 'h', 'history_fts', 'bm25(history_fts),h.id'
        page_type = HistoryPage
    else:
        raise ValueError('Unsupported record search')
    filters, params = [], []
    if tool:
        filters.append("t.name LIKE ? ESCAPE '\\'")
        params.append('%' + tool.replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%')
    if category:
        filters.append('cat.name=?'); params.append(category)
    if writeup_type:
        filters.append('w.writeup_type=?'); params.append(writeup_type)
    if challenge_type:
        filters.append('w.challenge_type=?'); params.append(challenge_type)
    for tag in tags:
        filters.append('EXISTS (SELECT 1 FROM writeup_tags wt JOIN tags tg ON tg.id=wt.tag_id WHERE wt.writeup_id=w.id AND lower(tg.name)=?)')
        params.append(tag)
    if language:
        aliases = {'python':['python','py'], 'javascript':['javascript','js'],
                   'powershell':['powershell','ps1'], 'syz':['syz','syzlang']}.get(language,[language])
        filters.append('s.language IN ('+','.join('?' for _ in aliases)+')'); params.extend(aliases)
    if library:
        filters.append("s.libraries_used LIKE ? ESCAPE '\\'")
        params.append('%"'+library.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'"%')
    if since:
        filters.append('julianday(h.last_seen)>=julianday(?)'); params.append(since)
    with db.read_snapshot(), db._get_connection() as conn:
        position = Cursor(db, settings, cursor)
        notice = 'Ranking is relative; expand a reference before relying on a clipped record.'
        if kind == 'history':
            known = conn.execute('SELECT count(*) FROM history_commands WHERE last_seen IS NOT NULL').fetchone()[0]
            if since and not known:
                raise ValueError('Execution timestamps are unavailable; omit since. Import dates are not execution dates.')
            notice += f' {known} records have execution timestamps; others have unknown recency.'
        def fetch(mode):
            conditions = list(filters)
            values = list(params)
            joins = ''
            if query:
                joins = f' JOIN {fts} ON {fts}.rowid={alias}.id'
                conditions.insert(0, f'{fts} MATCH ?')
                values.insert(0, (_build_fts_query_or if mode=='any_terms' else _build_fts_query)(query))
            order = rank if query and (kind!='history' or mode=='any_terms') else ('h.last_seen DESC,h.id' if kind=='history' else alias+'.id')
            where = ' WHERE '+' AND '.join(conditions) if conditions else ''
            return conn.execute(f'SELECT {fields} FROM {base}{joins}{where} ORDER BY {order}', values)
        mode = 'all_terms' if query else 'filtered'
        rows = fetch(mode)
        first = rows.fetchone()
        if first is None and query and len(_tokenize_fts(query))>1:
            mode = 'any_terms'
            rows = fetch(mode)
            first = rows.fetchone()
        def records():
            for row in itertools.chain([first] if first is not None else [], rows):
                data = dict(row)
                data['reference'] = f"{kind}:{data['id']}"
                if kind in ('command','script'):
                    data['source'] = {'file':data.pop('filename'), 'type':data.pop('writeup_type'),
                                      'challenge_type':data.pop('challenge_type')}
                    data['match_mode'] = mode
                if kind == 'command':
                    data['source']['section'] = data.pop('source_section')
                    yield CommandHit(**data)
                elif kind == 'script':
                    lines = data.pop('code').split('\n')
                    data['code_preview'] = '\n'.join(lines[:10]) + ('\n...' if len(lines)>10 else '')
                    data['libraries'] = json.loads(data.pop('libraries_used') or '[]')
                    yield ScriptHit(**data)
                else:
                    yield HistoryHit(**data)
        return paginate(records(), position, page_type, query, limit, max_chars,
                        match_mode=mode, notice=notice)
