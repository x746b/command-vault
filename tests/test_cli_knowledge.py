"""Exercise the public CLI with benign source fixtures and real subprocesses."""
import hashlib
import json
import os
import subprocess
import sys

import pytest

from command_vault.database import Database
from command_vault.indexer import Indexer
from command_vault.knowledge import Knowledge


@pytest.fixture
def corpus(tmp_path):
    source = tmp_path / 'notes.md'
    source.write_text('# Notes\n\n#sherlock #windows\n\n## Audit log\n'
                      'A cleared Security audit log can be identified by event 1102.\n\n'
                      '```xml\n<EventID>1102</EventID>\n<Channel>Security</Channel>\n```\n\n'
                      + 'This paragraph provides further context about the audit record.\n' * 24)
    db = Database(str(tmp_path / 'vault.db'))
    Indexer(db).index_file(str(source), source_dir='unified')
    return db


def cli(db_path, *args):
    return subprocess.run([sys.executable, '-m', 'command_vault.cli', '--db', str(db_path), *args],
                          capture_output=True, text=True, timeout=15,
                          env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})


def test_search_context_json_parity_and_readonly(corpus):
    before = hashlib.sha256(corpus.db_path.read_bytes()).hexdigest()
    search = cli(corpus.db_path, 'knowledge', 'Security audit', '--type', 'sherlock',
                 '--tag', 'windows', '--tag', 'windows', '--require-term', '1102', '--limit', '1', '--json')
    assert search.returncode == 0, search.stderr
    page = json.loads(search.stdout)
    expected = Knowledge(corpus).search('Security audit', writeup_type='sherlock',
                                        tags=['windows', 'windows'], required_terms=['1102'], limit=1)
    assert page == expected.model_dump()
    reference = page['results'][0]['reference']
    first = cli(corpus.db_path, '--json', 'context', reference, '--max-chars', '500')
    assert first.returncode == 0, first.stderr
    context = json.loads(first.stdout)
    assert context == Knowledge(corpus).read_context(reference, max_chars=500).model_dump()
    assert context['source_status'] == 'current'
    assert context['next_offset'] == 500
    second = cli(corpus.db_path, 'context', reference, '--offset', '500', '--max-chars', '500', '--json')
    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout)['offset'] == 500
    assert hashlib.sha256(corpus.db_path.read_bytes()).hexdigest() == before


def test_required_term_and_human_metadata(corpus):
    missing = cli(corpus.db_path, '--json', 'knowledge', 'audit ZQXJ92814', '--require', 'ZQXJ92814')
    assert missing.returncode == 0, missing.stderr
    page = json.loads(missing.stdout)
    assert page['results'] == []
    assert 'ZQXJ92814' in page['unmatched_terms']
    output = cli(corpus.db_path, 'knowledge', 'audit')
    assert output.returncode == 0
    assert 'Match mode:' in output.stdout and 'Reference: chunk:' in output.stdout
    reference = Knowledge(corpus).search('audit').results[0]['reference']
    output = cli(corpus.db_path, 'context', reference, '--max-chars', '500')
    assert output.returncode == 0
    assert 'Source status: current' in output.stdout
    assert 'Next offset: 500' in output.stdout


@pytest.mark.parametrize('args', [
    ('knowledge', 'audit', '--limit', '0'),
    ('knowledge', 'audit', '--max-chars', '20001'),
    ('context', 'chunk:1', '--offset', '-1'),
    ('context', 'chunk:1', '--max-chars', '499'),
])
def test_argument_bounds(corpus, args):
    result = cli(corpus.db_path, *args)
    assert result.returncode == 2
    assert 'Traceback' not in result.stderr


def test_runtime_errors_and_missing_database(corpus, tmp_path):
    for reference in ('invalid', 'chunk:999999999'):
        result = cli(corpus.db_path, 'context', reference, '--json')
        assert result.returncode == 1
        assert result.stdout == ''
        assert json.loads(result.stderr)['error']
    missing = tmp_path / 'missing.db'
    result = cli(missing, 'knowledge', 'audit', '--json')
    assert result.returncode == 1
    assert json.loads(result.stderr)['error']
    assert not missing.exists()


def test_cli_continuation_and_required_reporting(corpus):
    for i in range(8):
        corpus.insert_chunk(1,'Audit',f'Extra audit entry {i} with independent evidence.',i+100)
    first=cli(corpus.db_path,'knowledge','audit','--limit','1','--json')
    page=json.loads(first.stdout)
    assert page['next_cursor']
    second=cli(corpus.db_path,'knowledge','audit','--cursor',page['next_cursor'],'--limit','1','--json')
    assert second.returncode==0,second.stderr
    assert json.loads(second.stdout)['results'][0]['id']!=page['results'][0]['id']
    missing=cli(corpus.db_path,'knowledge','audit','--require','ZQXJ92814','--json')
    assert json.loads(missing.stdout)['unmatched_required_terms']==['ZQXJ92814']
    records=cli(corpus.db_path,'search','audit','--page','--max-chars','500')
    assert records.returncode==0,records.stderr
    assert 'next_cursor' in json.loads(records.stdout)
