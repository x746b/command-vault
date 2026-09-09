"""Build a separate candidate from a backup, retaining records with unavailable sources.

This script never replaces the live database. It refuses to overwrite its destination.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from command_vault.database import Database
from command_vault.indexer import Indexer
from command_vault.tools import VaultTools


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--writeups', type=Path, required=True)
    parser.add_argument('--history', type=Path, required=True)
    args = parser.parse_args()
    if args.candidate.exists():
        raise SystemExit('Candidate exists; refusing to overwrite')
    if not args.baseline.is_file() or not args.writeups.is_dir() or not args.history.is_file():
        raise SystemExit('All source locations must exist')
    started = time.monotonic()
    baseline = sqlite3.connect(args.baseline.resolve().as_uri()+'?mode=ro',uri=True)
    with sqlite3.connect(args.candidate) as candidate:
        baseline.backup(candidate)
    baseline.close()
    args.candidate.chmod(0o600)
    db = Database(str(args.candidate))
    byname = defaultdict(list)
    for path in sorted(args.writeups.rglob('*.md')):
        byname[path.name].append(str(path.resolve()))
    relocated = 0
    with db.transaction():
        with db._get_connection() as conn:
            for row in conn.execute('SELECT id,filename,filepath FROM writeups').fetchall():
                options = byname[row['filename']]
                if len(options) != 1 or options[0] == row['filepath']:
                    continue
                if conn.execute('SELECT 1 FROM writeups WHERE filepath=?',(options[0],)).fetchone():
                    continue
                conn.execute('UPDATE writeups SET filepath=? WHERE id=?',(options[0],row['id']))
                relocated += 1
    indexer = Indexer(db)
    result = indexer.index_all({'unified':str(args.writeups)})
    if result.errors:
        raise SystemExit(json.dumps({'index_errors':result.errors}))
    history = VaultTools(db,{}).index_history(str(args.history))
    if history.get('error'):
        raise SystemExit(history['error'])
    with db._get_connection() as conn:
        integrity = conn.execute('PRAGMA integrity_check').fetchone()[0]
        foreign_keys = len(conn.execute('PRAGMA foreign_key_check').fetchall())
        counts={t:conn.execute(f'SELECT count(*) FROM {t}').fetchone()[0]
                for t in ('writeups','commands','scripts','writeup_chunks','history_commands')}
        missing=sum(not Path(r[0]).is_file() for r in conn.execute('SELECT filepath FROM writeups'))
    with args.candidate.open('rb') as stream:
        digest=hashlib.file_digest(stream,'sha256').hexdigest()
    print(json.dumps({'candidate':str(args.candidate),'relocated_sources':relocated,
        'writeup_import':result.model_dump(),'history_import':history,'counts':counts,
        'unavailable_sources_retained':missing,'integrity':integrity,'foreign_key_violations':foreign_keys,
        'sha256':digest,'elapsed_seconds':round(time.monotonic()-started,2)},indent=2))


if __name__=='__main__':
    main()
