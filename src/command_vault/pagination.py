"""Stateless, revision-bound search cursors; no index or cursor storage writes."""
import base64
import binascii
import hashlib
import itertools
import json
from pathlib import Path

from .responses import ReferenceHit


def fingerprint(db):
    pieces = [str(db.db_path.resolve())]
    for suffix in ('', '-wal'):
        path = Path(str(db.db_path) + suffix)
        if path.exists():
            stat = path.stat()
            pieces.append((suffix, stat.st_ino, stat.st_size, stat.st_mtime_ns))
    return hashlib.sha256(json.dumps(pieces).encode()).hexdigest()


class Cursor:
    def __init__(self, db, query_key, token):
        self.db = db
        self.revision = fingerprint(db)
        self.key = hashlib.sha256(json.dumps(query_key, sort_keys=True).encode()).hexdigest()
        self.offset = 0
        if token is not None:
            try:
                if not isinstance(token, str) or len(token)>1500:
                    raise ValueError()
                encoded, checksum = token.split('.')
                raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
                if hashlib.sha256(raw).hexdigest()[:24] != checksum:
                    raise ValueError()
                data = json.loads(raw)
                if set(data) != {'v','q','r','o'} or data['v'] != 1 or type(data['o']) is not int or data['o'] < 0:
                    raise ValueError()
            except (ValueError, TypeError, binascii.Error, UnicodeError) as exc:
                raise ValueError('Invalid cursor; use next_cursor returned by this search') from exc
            if data['q'] != self.key:
                raise ValueError('Cursor does not match this query or its filters')
            if data['r'] != self.revision:
                raise ValueError('Database changed since this cursor was issued; restart the search')
            self.offset = data['o']

    def next(self, offset):
        raw = json.dumps({'v':1, 'q':self.key, 'r':self.revision, 'o':offset}, separators=(',',':')).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip('=') + '.' + hashlib.sha256(raw).hexdigest()[:24]

    def verify(self):
        if fingerprint(self.db) != self.revision:
            raise ValueError('Database changed during search; retry from the first page')


def paginate(rows, cursor, page_type, query='', limit=5, max_chars=10000, **metadata):
    """Page a deterministic record iterator. Budget is serialized result-record characters."""
    if not 1 <= limit <= 100 or not 500 <= max_chars <= 20000:
        raise ValueError('limit must be 1..100 and max_chars must be 500..20000')
    iterator = iter(rows)
    skipped = sum(1 for _ in itertools.islice(iterator, cursor.offset))
    if skipped != cursor.offset:
        raise ValueError('Cursor offset is outside this result set; restart the search')
    output = []
    used = 0
    clipped = False
    more = False
    budget_stopped = False
    while True:
        row = next(iterator, None)
        if row is None:
            break
        if len(output) == limit:
            more = True
            break
        data = row.model_dump()
        for field in ('raw_command','code_preview','content','purpose','template','sanitized_command'):
            if isinstance(data.get(field), str) and len(data[field])>2000:
                data[field] = data[field][:2000]
                data['truncated'] = True
        record = type(row).model_validate(data)
        size = len(json.dumps(record.model_dump(), ensure_ascii=False))
        if used + size > max_chars:
            budget_stopped = True
            if output:
                more = True
                break  # This row was not consumed: next cursor returns it.
            record = ReferenceHit(reference=row.reference, id=row.id)
            size = len(json.dumps(record.model_dump(), ensure_ascii=False))
            if size > max_chars:
                raise ValueError('Budget cannot hold a reference; increase max_chars')
        output.append(record)
        used += size
        clipped = clipped or record.truncated
    cursor.verify()
    return page_type(results=output, query=query or '', has_more=more,
        next_cursor=cursor.next(cursor.offset+len(output)) if more else None,
        truncated=clipped or budget_stopped, records_clipped=clipped, **metadata)
