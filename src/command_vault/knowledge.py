"""Bounded evidence retrieval and source-context access over the existing index."""

import hashlib
import itertools
import os
from pathlib import Path
import re

from .database import Database, _tokenize_fts
from .documents import sections
from .security import SecurityFilter
from .pagination import Cursor, paginate
from .responses import SearchPage, KnowledgeHit, KnowledgePage, ContextPage
from .research import DocumentSnapshot, read_document_snapshot, _read_bundle_file


def _managed_document(filepath, expected_hash):
    """Read a bounded file through nonsymlink path components, never trusting stale bytes."""
    path = Path(filepath)
    if not path.is_absolute():
        return None, 'snapshot_changed', None
    descriptor = None
    try:
        anchor = Path(path.anchor)
        descriptor = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        data = _read_bundle_file(anchor, descriptor, str(path.relative_to(anchor)),
                                 limit=20_000_000, label='Managed document')
    except FileNotFoundError:
        return None, 'snapshot', None
    except (ValueError, OSError):
        return None, 'snapshot_changed', None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_hash:
        return None, 'snapshot_changed', digest
    try:
        return data.decode('utf-8', errors='strict'), 'managed', digest
    except UnicodeDecodeError:
        return None, 'snapshot_changed', digest


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

    def search(self, query, writeup_type=None, tags=None, required_terms=None, limit=5, max_chars=10000, cursor=None,
               source_name=None, domain=None, external_id=None, cve=None, project=None, vulnerability_class=None,
               sanitizer=None, operational_stage=None, mitigation=None, validation_status=None):
        applied_filters = {}
        for name, value in (
            ('source_name', source_name), ('domain', domain), ('external_id', external_id), ('cve', cve),
            ('project', project), ('vulnerability_class', vulnerability_class), ('sanitizer', sanitizer),
            ('operational_stage', operational_stage), ('mitigation', mitigation), ('validation_status', validation_status),
        ):
            if value is None:
                continue
            maximum = 100 if name == 'domain' else 200
            if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
                raise ValueError(f'{name} must be a nonblank string of at most {maximum} characters')
            applied_filters[name] = ' '.join(value.lower().split()) if name == 'operational_stage' else value.strip()
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
        for name, value in applied_filters.items():
            if name == 'source_name':
                filters.append('''EXISTS (SELECT 1 FROM source_collections sc
                    WHERE sc.id=w.source_collection_id AND sc.name=? COLLATE NOCASE)''')
                params.append(value)
            elif name in ('domain', 'external_id'):
                filters.append(f'w.{name}=? COLLATE NOCASE')
                params.append(value)
            elif name in ('cve', 'project', 'vulnerability_class', 'sanitizer'):
                column = {'cve': 'canonical_id', 'project': 'project_name',
                          'vulnerability_class': 'vulnerability_class', 'sanitizer': 'sanitizer'}[name]
                filters.append(f'''EXISTS (SELECT 1 FROM writeup_vulnerabilities wv
                    JOIN vulnerabilities v ON v.id=wv.vulnerability_id
                    WHERE wv.writeup_id=w.id AND v.{column}=? COLLATE NOCASE)''')
                params.append(value)
            elif name == 'operational_stage':
                filters.append('''EXISTS (SELECT 1 FROM evidence_links e JOIN operational_stages s ON s.id=e.stage_id
                    WHERE e.writeup_id=w.id AND e.chunk_id=ch.id AND
                    (_knowledge_stage_normalize(s.canonical_name)=? OR EXISTS (
                        SELECT 1 FROM stage_aliases a WHERE a.stage_id=s.id AND a.alias_normalized=?)))''')
                params.extend((value, value))
            elif name == 'mitigation':
                filters.append('''EXISTS (SELECT 1 FROM writeup_vulnerabilities wv
                    JOIN vulnerability_mitigations vm ON vm.vulnerability_id=wv.vulnerability_id
                    JOIN mitigations m ON m.id=vm.mitigation_id WHERE wv.writeup_id=w.id
                    AND (m.canonical_name=? COLLATE NOCASE OR m.raw_label=? COLLATE NOCASE))''')
                params.extend((value, value))
            elif name == 'validation_status':
                filters.append('''EXISTS (SELECT 1 FROM evidence_links e WHERE e.writeup_id=w.id
                    AND e.chunk_id=ch.id AND e.validation_status=? COLLATE NOCASE)''')
                params.append(value)
        where = (' AND ' + ' AND '.join(filters)) if filters else ''
        quote = lambda term: '"' + term.replace('"', '""') + '"'
        base = ''' FROM writeup_chunks_fts f JOIN writeup_chunks ch ON f.rowid=ch.id
                   JOIN writeups w ON w.id=ch.writeup_id WHERE writeup_chunks_fts MATCH ?'''
        select = '''SELECT ch.id,ch.section,ch.content,w.id document_id,w.filename,w.filepath,w.content_hash,
                    w.writeup_type,w.indexed_at,bm25(writeup_chunks_fts,5,1) score,
                    snippet(writeup_chunks_fts,0,'','',' … ',64) excerpt'''
        with self.db.read_snapshot(), self.db._get_connection() as conn:
            if applied_filters and conn.execute('PRAGMA user_version').fetchone()[0] < 2:
                raise ValueError('Structured research filters require database schema 2 or newer')
            if 'operational_stage' in applied_filters:
                conn.create_function('_knowledge_stage_normalize', 1,
                                     lambda value: ' '.join(value.lower().split()) if value is not None else None,
                                     deterministic=True)
            query_key = {'search':'knowledge-v1', 'query':query, 'type':writeup_type,
                         'tags':normalized_tags, 'required':sorted(required)}
            if applied_filters:
                query_key['structured_filters'] = applied_filters
            position = Cursor(self.db, query_key, cursor)
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
                applied_filters=applied_filters,
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
        snapshot = None
        with self.db.read_snapshot(), self.db._get_connection() as conn:
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
            if row is not None and row['writeup_type'] == 'research':
                if conn.execute('PRAGMA user_version').fetchone()[0] < 2:
                    raise ValueError('Research snapshots require database schema 2 or newer')
                available = conn.execute(
                    'SELECT 1 FROM sqlite_master WHERE type=? AND name=?',
                    ('table', 'document_snapshots'),
                ).fetchone()
                if not available:
                    raise ValueError('Research document snapshot is missing')
                snapshot_row = conn.execute('''SELECT content_blob,compression,content_hash,uncompressed_bytes
                    FROM document_snapshots WHERE writeup_id=?''', (row['id'],)).fetchone()
                if snapshot_row is None:
                    raise ValueError('Research document snapshot is missing')
                snapshot = DocumentSnapshot(**dict(snapshot_row))
        if not row:
            raise ValueError('Reference not found; search again after a reindex')
        if expected_doc is not None and (int(expected_doc) != row['id'] or expected_revision != (row['content_hash'] or 'legacy')):
            raise ValueError('Reference belongs to a different indexed revision; search again')
        source = {'document_id':row['id'], 'filename':row['filename'], 'section':row['section'],
                  'indexed_revision':row['content_hash']}
        content = row['stored']
        status = 'unavailable'
        if snapshot is not None:
            if snapshot.content_hash != row['content_hash']:
                raise ValueError('Research snapshot hash does not match the indexed revision')
            document = read_document_snapshot(snapshot, max_uncompressed_bytes=20_000_000)
            source['current_revision'] = snapshot.content_hash
            status = 'snapshot'
            if not row['filepath'].startswith('research://'):
                managed, status, digest = _managed_document(row['filepath'], snapshot.content_hash)
                source['current_revision'] = digest
                if managed is not None:
                    document = managed
            matches = ([{'content': document, 'line_start': 1}] if kind == 'document' else
                       [section for section in sections(document) if section['section'] == row['section']])
            if matches:
                content = '\n\n'.join(s['content'] for s in matches)
                source['line_start'] = matches[0]['line_start']
            else:
                status = 'section_unavailable'
        else:
            path = Path(row['filepath'])
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
