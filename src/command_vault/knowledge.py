"""Bounded evidence retrieval and source-context access over the existing index."""

import hashlib
import itertools
from pathlib import Path
import re

from .database import Database, _tokenize_fts
from .documents import sections
from .security import SecurityFilter
from .pagination import Cursor, paginate
from .responses import SearchPage, KnowledgeHit, KnowledgePage, ContextPage


def bounded_page(rows, query='', max_chars=12000, **kwargs):
    import json
    output = []
    size = 0
    truncated = False
    if rows and 'match_mode' in rows[0] and 'match_mode' not in kwargs:
        kwargs['match_mode'] = rows[0]['match_mode']
    for original in rows:
        row = dict(original)
        for key in ('raw_command', 'code_preview', 'content', 'purpose', 'template', 'sanitized_command'):
            if isinstance(row.get(key), str) and len(row[key]) > 2000:
                row[key] = row[key][:2000]
                row['truncated'] = True
                truncated = True
        length = len(json.dumps(row, ensure_ascii=False))
        if size + length > max_chars:
            truncated = True
            if not output and row.get('reference'):
                output.append({'reference': row['reference'], 'truncated': True,
                               'notice': 'Read this reference for content; it exceeds the response budget.'})
            break
        output.append(row)
        size += length
    return SearchPage(results=output, query=query or '', truncated=truncated, **kwargs)


class Knowledge:
    def __init__(self, db: Database):
        self.db = db

    def search(self, query, writeup_type=None, tags=None, required_terms=None, limit=5, max_chars=10000, cursor=None):
        tokens = list(dict.fromkeys(_tokenize_fts(query)))
        required = list(dict.fromkeys(required_terms or []))
        if not tokens or len(query) > 1000 or len(required) > 10:
            raise ValueError('Supply a nonempty query of at most 1000 characters and at most 10 required terms')
        if any(not term.strip() or len(term)>1000 for term in required):
            raise ValueError('Required terms must be nonempty strings of at most 1000 characters')
        normalized_tags = sorted({t.lower().lstrip('#') for t in (tags or [])})
        filters = []
        params = []
        if writeup_type:
            filters.append('w.writeup_type=?')
            params.append(writeup_type)
        for tag in normalized_tags:
            filters.append('EXISTS (SELECT 1 FROM writeup_tags wt JOIN tags t ON t.id=wt.tag_id WHERE wt.writeup_id=w.id AND lower(t.name)=?)')
            params.append(tag)
        where = (' AND ' + ' AND '.join(filters)) if filters else ''
        quote = lambda term: '"' + term.replace('"', '""') + '"'
        base = ''' FROM writeup_chunks_fts f JOIN writeup_chunks ch ON f.rowid=ch.id
                   JOIN writeups w ON w.id=ch.writeup_id WHERE writeup_chunks_fts MATCH ?'''
        select = '''SELECT ch.id,ch.section,ch.content,w.id document_id,w.filename,w.filepath,w.content_hash,
                    w.writeup_type,w.indexed_at,bm25(writeup_chunks_fts,5,1) score,
                    snippet(writeup_chunks_fts,0,'','',' … ',64) excerpt'''
        with self.db.read_snapshot(), self.db._get_connection() as conn:
            position = Cursor(self.db, {'search':'knowledge-v1', 'query':query, 'type':writeup_type,
                                      'tags':normalized_tags, 'required':sorted(required)}, cursor)
            query_terms = list(dict.fromkeys(t.strip('?!,.;:') or t for t in tokens))
            def absent(terms):
                return [term for term in terms if not conn.execute('SELECT 1'+base+where+' LIMIT 1',
                        [quote(term), *params]).fetchone()]
            unmatched_query = absent(query_terms)
            unmatched_required = absent(required)
            def fetch(operator):
                match = '(' + f' {operator} '.join(map(quote, tokens)) + ')'
                if required:
                    match += ' AND ' + ' AND '.join(map(quote, required))
                return conn.execute(select+base+where+' ORDER BY score,ch.id', [match, *params])
            rows = fetch('AND')
            first = rows.fetchone()
            mode = 'all_terms'
            if first is None and len(tokens) > 1:
                rows = fetch('OR')
                first = rows.fetchone()
                mode = 'any_terms'
            def records():
                seen = set()
                for row in itertools.chain([first] if first is not None else [], rows):
                    digest = hashlib.sha256(row['content'].encode()).hexdigest()
                    if digest in seen:
                        continue
                    seen.add(digest)
                    content = row['content'].strip('_* \n')
                    yield KnowledgeHit(reference=f"chunk:{row['id']}@{row['document_id']}.{row['content_hash'] or 'legacy'}",
                        id=row['id'], section=row['section'], content=row['excerpt'],
                        question_only=len(content)<500 and content.endswith('?'), score=row['score'],
                        source={'document_id':row['document_id'], 'filename':row['filename'],
                                'writeup_type':row['writeup_type'], 'indexed_at':row['indexed_at'], 'revision':row['content_hash']})
            return paginate(records(), position, KnowledgePage, query, limit, max_chars, match_mode=mode,
                unmatched_query_terms=unmatched_query, unmatched_required_terms=unmatched_required,
                unmatched_terms=list(dict.fromkeys(unmatched_query + unmatched_required)),
                notice='Ranking is relative, not confidence. Read context before relying on an excerpt.'
                       + (' Query broadened to any term; required_terms were preserved.' if mode=='any_terms' else ''))

    def read_context(self, reference, offset=0, max_chars=8000):
        if offset < 0 or not 500 <= max_chars <= 20000:
            raise ValueError('offset must be nonnegative and max_chars must be 500..20000')
        match = re.fullmatch(r'(chunk|command|script|history|document):(\d+)(?:@(\d+)\.([a-f0-9]{64}|legacy))?', reference)
        if not match:
            raise ValueError('Use a returned chunk, command, script, history, or document reference')
        kind, identifier, expected_doc, expected_revision = match.groups()
        if kind == 'history':
            if expected_doc is not None:
                raise ValueError('History references do not have document revisions')
            with self.db._get_connection() as conn:
                row = conn.execute('SELECT sanitized_command,source_file FROM history_commands WHERE id=?', (int(identifier),)).fetchone()
            if row is None:
                raise ValueError('Reference not found; search again')
            content = row['sanitized_command']
            end = min(len(content), offset + max_chars)
            return ContextPage(reference=reference, source={'filename':Path(row['source_file'] or 'history').name,
                'section':'Indexed shell history'}, content=content[offset:end], offset=offset,
                next_offset=end if end<len(content) else None, truncated=end<len(content), source_status='indexed')
        with self.db._get_connection() as conn:
            if kind == 'document':
                row = conn.execute('SELECT NULL section, w.* FROM writeups w WHERE w.id=?', (int(identifier),)).fetchone()
                if row is not None:
                    row = dict(row)
                    row['stored'] = '\n\n'.join(r[0] for r in conn.execute('SELECT content FROM writeup_chunks WHERE writeup_id=? ORDER BY chunk_index', (int(identifier),)))
            else:
                table, section, field = {'chunk': ('writeup_chunks','section','content'),
                                        'command': ('commands','source_section','raw_command'),
                                        'script': ('scripts','source_section','code')}[kind]
                row = conn.execute(f'''SELECT x.{section} section,x.{field} stored,w.* FROM {table} x
                            JOIN writeups w ON w.id=x.writeup_id WHERE x.id=?''', (int(identifier),)).fetchone()
        if not row:
            raise ValueError('Reference not found; search again after a reindex')
        if expected_doc is not None and (int(expected_doc) != row['id'] or expected_revision != (row['content_hash'] or 'legacy')):
            raise ValueError('Reference belongs to a different indexed revision; search again')
        source = {'document_id':row['id'], 'filename':row['filename'], 'section':row['section'],
                  'indexed_revision':row['content_hash']}
        path = Path(row['filepath'])
        content = row['stored']
        status = 'unavailable'
        if path.is_file():
            if path.stat().st_size > 20_000_000:
                raise ValueError('Source exceeds 20 MB; use the bounded indexed excerpt')
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            status = 'current' if digest == row['content_hash'] else 'changed' if row['content_hash'] else 'unverified'
            source['current_revision'] = digest
            sanitized = SecurityFilter().sanitize_text(data.decode('utf-8', errors='replace'))
            matches = ([{'content':sanitized,'line_start':1}] if kind=='document' else
                       [s for s in sections(sanitized) if s['section'] == row['section']])
            if matches:
                content = '\n\n'.join(s['content'] for s in matches)
                source['line_start'] = matches[0]['line_start']
            else:
                status = 'section_unavailable'
        source['image_references_present'] = bool(re.search(r'!\[|<img\b', content))
        end = min(len(content), offset + max_chars)
        return ContextPage(reference=reference, source=source, content=content[offset:end],
            offset=offset, next_offset=end if end<len(content) else None,
            truncated=end<len(content), source_status=status)
