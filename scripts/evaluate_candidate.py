"""Read-only, deterministic evidence smoke evaluation; does not execute retrieved code.

The rubric checks supporting concepts, not factual correctness or blind agent performance.
The baseline uses recorded live result IDs; candidate uses the new retrieval/context interface.
"""
import argparse
import json
from pathlib import Path
import re
import sqlite3

from command_vault.database import Database
from command_vault.knowledge import Knowledge

RULES = {
    'successful_logon': [r'\b4624\b', r'successful|logon'],
    'security_log_cleared': [r'\b1102\b', r'log|security'],
    'powershell_script_text': [r'\b4104\b', r'ScriptBlock|Script.Block|PowerShell'],
    'execution_count': [r'prefetch|\.pf\b', r'run[ _-]?count'],
    'browser_download_origin': [r'chrome|edge|browser|history', r'download', r'URL|URI'],
    'linux_failed_logins': [r'/var/log/auth\.log', r'fail'],
    'process_parent': [r'\b4688\b', r'parent'],
    'file_creation_timeline': [r'MFT|USN', r'creat'],
}


def supports(task, text):
    return all(re.search(pattern,text,re.I) for pattern in RULES[task])


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline',required=True,type=Path)
    ap.add_argument('--candidate',required=True,type=Path)
    ap.add_argument('--live-results',required=True,type=Path)
    args=ap.parse_args()
    baseline=sqlite3.connect(args.baseline.resolve().as_uri()+'?mode=ro',uri=True)
    baseline.execute('PRAGMA query_only=ON')
    kb=Knowledge(Database(str(args.candidate),readonly=True))
    calls=json.loads(args.live_results.read_text())
    results=[]
    for case in calls:
        if case['id'] not in RULES:
            continue
        old=[baseline.execute('SELECT content FROM writeup_chunks WHERE id=?',(rid,)).fetchone()[0] for rid in case['ids']]
        page=kb.search(case['query'],writeup_type='sherlock',limit=5)
        context=[kb.read_context(row['reference']).content for row in page.results]
        rank=lambda texts:next((i+1 for i,text in enumerate(texts) if supports(case['id'],text)),None)
        results.append({'task':case['id'],'variant':case['variant'],
            'baseline_evidence_rank':rank(old),
            'candidate_excerpt_evidence_rank':rank([r['content'] for r in page.results]),
            'candidate_context_evidence_rank':rank(context),
            'candidate_ids':[r['id'] for r in page.results],
            'match_mode':page.match_mode,'response_chars':len(page.model_dump_json())})
    summary=[]
    for variant in ('keyword','natural','agent_query'):
        rows=[r for r in results if r['variant']==variant]
        summary.append({'variant':variant,'cases':len(rows),
             'baseline_supported_at_5':sum(r['baseline_evidence_rank'] is not None for r in rows),
             'candidate_excerpt_supported_at_5':sum(r['candidate_excerpt_evidence_rank'] is not None for r in rows),
             'candidate_context_supported_at_5':sum(r['candidate_context_evidence_rank'] is not None for r in rows)})
    negatives=[]
    for term in ('ZQXJ92814','VORPAL73926'):
        page=kb.search('Read audit logs from '+term,required_terms=[term])
        negatives.append({'term':term,'empty':not page.results,'reported_unmatched':term in page.unmatched_terms})
    print(json.dumps({'method':'Deterministic concept rubric, exploratory development cases; context measure allows reading up to five sections.',
                      'summary':summary,'negative_controls':negatives,'results':results},indent=2))


if __name__=='__main__':
    main()
