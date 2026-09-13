"""Managed research retention never enters legacy Markdown indexing."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from command_vault import cli, server
from command_vault.config import get_config
from command_vault.database import Database
from command_vault.indexer import Indexer
from command_vault.research_indexer import ResearchIndexer
from command_vault.tools import VaultTools


@pytest.fixture
def tree(tmp_path):
    legacy = tmp_path / 'writeups'
    research = legacy / 'research'
    bundle = research / 'source' / 'task'
    bundle.mkdir(parents=True)
    (bundle / 'artifacts').mkdir()
    (legacy / 'ordinary.md').write_text('# Personal notes\n\n## Observation\nOrdinary personal orchard evidence belongs in the legacy corpus.\n')
    (bundle / 'document.md').write_text('# Research notes\n\n## Observation\nRetained research source evidence must not enter legacy ingestion.\n')
    (bundle / 'manifest.json').write_text('{"retained":true}')
    (bundle / 'artifacts' / 'vulnerability.md').write_text(
        '# Retained artifact\n\nThis Markdown artifact also belongs to the managed bundle.\n'
    )
    return legacy, research


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / 'candidate.db'))


def source_bytes(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob('*') if path.is_file()}


def test_config_routes_research_separately_without_creating_directories(tmp_path, monkeypatch):
    personal = tmp_path / 'personal'
    research = tmp_path / 'retained' / 'research'
    monkeypatch.setenv('WRITEUPS', str(personal))
    monkeypatch.setenv('WRITEUPS_RESEARCH', str(research))
    config = get_config()
    assert config['research_dir'] == str(research.resolve())
    assert config['writeup_dirs'] == {'unified': str(personal.resolve())}
    assert not research.exists() and not research.parent.exists() and not personal.exists()


def test_config_without_research_env_preserves_unified_routing(tmp_path, monkeypatch):
    monkeypatch.delenv('WRITEUPS_RESEARCH', raising=False)
    monkeypatch.setenv('WRITEUPS', str(tmp_path / 'personal'))
    assert get_config()['research_dir'] is None
    assert set(get_config()['writeup_dirs']) == {'unified'}


def test_config_autodetects_existing_canonical_nested_research(tree, monkeypatch):
    legacy, research = tree
    monkeypatch.delenv('WRITEUPS_RESEARCH', raising=False)
    monkeypatch.setenv('WRITEUPS', str(legacy))
    config = get_config()
    assert config['writeup_dirs'] == {'unified': str(legacy.resolve())}
    assert config['research_dir'] == str(research.resolve())


def test_legacy_root_without_nested_research_keeps_ordinary_indexing(db, tmp_path):
    legacy = tmp_path / 'legacy'
    legacy.mkdir()
    (legacy / 'document.md').write_text('# Ordinary notes\n\nNo manifest sibling exists.\n')
    result = Indexer(db).index_directory(str(legacy), source_dir='unified')
    assert result.files_processed == 1 and result.errors == []


@pytest.mark.parametrize('entry', ['constructor', 'directory', 'all'])
def test_nested_research_is_excluded_before_parse_without_source_changes(db, tree, monkeypatch, entry):
    legacy, research = tree
    before = source_bytes(legacy)
    indexer = Indexer(db, research_dir=str(research) if entry == 'constructor' else None)
    original = indexer.parser.parse_file

    def guarded(path, *args, **kwargs):
        assert not Path(path).resolve().is_relative_to(research.resolve())
        return original(path, *args, **kwargs)

    monkeypatch.setattr(indexer.parser, 'parse_file', guarded)
    if entry == 'all':
        result = indexer.index_all({'unified': str(legacy)}, research_dir=str(research))
    elif entry == 'directory':
        result = indexer.index_directory(str(legacy), source_dir='unified', research_dir=str(research))
    else:
        result = indexer.index_directory(str(legacy), source_dir='unified')
    assert result.files_processed == 1 and result.errors == []
    assert result.chunks_extracted == 1
    assert source_bytes(legacy) == before
    with db._get_connection() as conn:
        assert [row[0] for row in conn.execute('SELECT filename FROM writeups')] == ['ordinary.md']


def test_equal_root_refusal_happens_before_rebuild_deletes_data(db, tree):
    legacy, research = tree
    Indexer(db).index_file(str(legacy / 'ordinary.md'))
    before = db.db_path.read_bytes()
    indexer = Indexer(db, research_dir=str(research))
    with pytest.raises(ValueError, match='dedicated manifest-driven ingestion'):
        indexer.index_directory(str(research))
    with pytest.raises(ValueError, match='dedicated manifest-driven ingestion'):
        indexer.index_all({'unified': str(research)}, force_rebuild=True)
    assert db.db_path.read_bytes() == before


@pytest.mark.parametrize('relationship', ['sibling', 'prefix-lookalike', 'outside'])
def test_unrelated_research_roots_do_not_exclude_legacy_content(db, tmp_path, relationship):
    research = tmp_path / 'research'
    research.mkdir()
    legacy = tmp_path / ('research-copy' if relationship == 'prefix-lookalike' else 'personal')
    legacy.mkdir()
    (legacy / 'ordinary.md').write_text('# Personal\n\nNormal orchard notes retain their original indexing behavior.\n')
    if relationship == 'outside':
        research = tmp_path / 'elsewhere' / 'uncreated-research'
    result = Indexer(db, research_dir=str(research)).index_directory(str(legacy))
    assert result.files_processed == 1 and result.errors == []


@pytest.mark.parametrize('ancestor', [False, True])
def test_symlink_research_configuration_is_rejected_without_following(db, tree, tmp_path, monkeypatch, ancestor):
    legacy, research = tree
    link = tmp_path / 'retention-link'
    link.symlink_to(research, target_is_directory=True)
    configured = link / 'source' if ancestor else link
    before = source_bytes(legacy)
    monkeypatch.setenv('WRITEUPS_RESEARCH', str(configured))
    with pytest.raises(ValueError, match='symlinks'):
        get_config()
    with pytest.raises(ValueError, match='symlinks'):
        Indexer(db, research_dir=str(configured)).index_directory(str(legacy))
    assert source_bytes(legacy) == before


def test_custom_admin_directories_use_same_research_exclusion(db, tree):
    legacy, research = tree
    vault = VaultTools(db, {}, research_dir=str(research))
    result = vault.index_writeups(directories=[str(legacy)])
    assert result['files_processed'] == 1 and result['errors'] == []
    with pytest.raises(ValueError, match='dedicated manifest-driven ingestion'):
        vault.index_writeups(directories=[str(research)], force_rebuild=True)
    assert db.get_writeup_count() == 1


def test_custom_admin_directory_autodetects_nested_research_without_config(db, tree):
    legacy, _ = tree
    result = VaultTools(db, {}).index_writeups(directories=[str(legacy)])
    assert result['files_processed'] == 1 and result['errors'] == []
    with db._get_connection() as conn:
        assert [row[0] for row in conn.execute('SELECT filename FROM writeups')] == ['ordinary.md']


def test_custom_root_inside_managed_tree_skips_document_and_markdown_artifacts(db, tree):
    _, research = tree
    result = VaultTools(db, {}).index_writeups(directories=[str(research / 'source')])
    assert result['files_processed'] == 0 and result['errors'] == []
    assert db.get_writeup_count() == 0


def test_legacy_constructor_without_explicit_research_still_autodetects_nested_root(db, tree):
    legacy, _ = tree
    vault = VaultTools(db, {'unified': str(legacy)})
    assert vault.research_dir is None and vault.indexer.research_dir is None
    assert vault.index_writeups()['files_processed'] == 1


def test_direct_managed_document_and_structural_force_rebuild_are_refused(db, tree):
    legacy, research = tree
    document = research / 'source/task/document.md'
    before = db.db_path.read_bytes()
    with pytest.raises(ValueError, match='manifest-driven'):
        Indexer(db).index_file(str(document), source_dir='unified')
    with pytest.raises(ValueError, match='manifest-driven'):
        Indexer(db).index_all({'custom': str(research)}, force_rebuild=True)
    assert db.db_path.read_bytes() == before


def test_autodetected_nested_research_symlink_is_rejected(db, tmp_path, monkeypatch):
    legacy = tmp_path / 'legacy'
    target = tmp_path / 'target'
    legacy.mkdir(); target.mkdir()
    (legacy / 'research').symlink_to(target, target_is_directory=True)
    monkeypatch.delenv('WRITEUPS_RESEARCH', raising=False)
    monkeypatch.setenv('WRITEUPS', str(legacy))
    with pytest.raises(ValueError, match='symlinks'):
        get_config()
    with pytest.raises(ValueError, match='symlinks'):
        Indexer(db).index_directory(str(legacy), source_dir='unified')


def _research_state(db):
    tables = (
        'source_collections', 'writeups', 'document_snapshots', 'vulnerabilities',
        'writeup_vulnerabilities', 'writeup_chunks', 'scripts', 'operational_stages',
        'stage_aliases', 'evidence_links', 'validation_records',
    )
    with db._get_connection() as conn:
        research_ids = [row[0] for row in conn.execute(
            "SELECT id FROM writeups WHERE writeup_type='research' ORDER BY id"
        )]
        state = {'research_ids': research_ids}
        for table in tables:
            if table == 'writeups':
                rows = conn.execute(
                    "SELECT * FROM writeups WHERE writeup_type='research' ORDER BY id"
                ).fetchall()
            elif table in ('document_snapshots', 'writeup_chunks', 'scripts', 'evidence_links'):
                rows = conn.execute(f'''SELECT * FROM {table} WHERE writeup_id IN
                    (SELECT id FROM writeups WHERE writeup_type='research') ORDER BY rowid''').fetchall()
            else:
                rows = conn.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
            state[table] = [tuple(row) for row in rows]
        return state


def test_cli_add_without_research_env_preserves_indexed_research_and_adds_only_dump(tmp_path):
    legacy = tmp_path / 'writeups'
    research = legacy / 'research'
    bundle = research / 'fixture-source' / 'fixture-task'
    artifacts = bundle / 'artifacts'
    artifacts.mkdir(parents=True)
    document = '# Research fixture\n\n## Runtime evidence\nA retained diagnostic observation.\n'
    code = 'int main(void) { return 0; }\n'
    (bundle / 'document.md').write_text(document)
    (artifacts / 'repro.c').write_text(code)
    manifest = {
        'schema_version': 1,
        'source': {'name': 'fixture-source', 'revision': 'fixture-revision',
                   'upstream_url': 'https://example.org/research'},
        'external_id': 'fixture-task', 'domain': 'linux-kernel', 'project': 'fixture',
        'language': 'c', 'document_kind': 'diagnostic-reference',
        'vulnerability': {'canonical_id': 'CVE-2099-0001', 'summary': 'Fixture issue',
                          'summary_provenance': 'source'},
        'artifacts': [{'path': 'artifacts/repro.c', 'kind': 'reproducer', 'role': 'procedure',
                       'language': 'c', 'validation': 'harness_observed',
                       'sha256': hashlib.sha256(code.encode()).hexdigest()}],
        'operational_stages': [{
            'canonical_name': 'crash reproduction', 'stage_class': 'trigger',
            'assertion_provenance': 'deterministic', 'validation_status': 'harness_observed',
            'matched_alias': 'Reproducer', 'evidence_sections': [],
        }],
    }
    (bundle / 'manifest.json').write_text(json.dumps(manifest))
    database = Database(str(tmp_path / 'candidate.db'))
    ResearchIndexer(database, managed_root=research).index_bundle(bundle)
    before = _research_state(database)
    (legacy / 'Dump.md').write_text('# Dump\n\n#linux\n\n## Notes\nA newly added personal note.\n')
    environment = dict(os.environ)
    environment.pop('WRITEUPS_RESEARCH', None)
    for key in ('WRITEUPS_BOXES', 'WRITEUPS_CHALLENGES', 'WRITEUPS_SHERLOCKS'):
        environment.pop(key, None)
    environment.update({'VAULT_DB': str(database.db_path), 'WRITEUPS': str(legacy),
                        'PYTHONDONTWRITEBYTECODE': '1'})
    command = [sys.executable, '-m', 'command_vault.cli', '--json', 'index', '--add']
    first = subprocess.run(command, capture_output=True, text=True, timeout=20, env=environment)
    assert first.returncode == 0, first.stderr
    assert json.loads(first.stdout)['files_processed'] == 1
    assert _research_state(database) == before
    with database._get_connection() as conn:
        added = conn.execute("SELECT filename,writeup_type FROM writeups WHERE writeup_type<>'research'").fetchall()
        assert [tuple(row) for row in added] == [('Dump.md', 'box')]
    second = subprocess.run(command, capture_output=True, text=True, timeout=20, env=environment)
    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout)['files_processed'] == 0
    assert _research_state(database) == before


@pytest.mark.parametrize('include_research_config', [False, True])
def test_server_forwards_research_config_without_changing_directory_override(db, tree, monkeypatch, include_research_config):
    legacy, research = tree
    config = {'db_path': str(db.db_path), 'writeup_dirs': {'unified': str(legacy)}}
    if include_research_config:
        config['research_dir'] = str(research)
    monkeypatch.setattr(server, 'get_config', lambda: config)
    received = []
    original = server.VaultTools

    def observed(database, directories, research_dir=None):
        received.append((database, directories, research_dir))
        return original(database, directories, research_dir=research_dir)

    monkeypatch.setattr(server, 'VaultTools', observed)
    override = {'custom': str(legacy)}
    server.create_server(db=db, writeup_dirs=override)
    assert received == [(db, override, str(research) if include_research_config else None)]


@pytest.mark.parametrize('include_research_config', [False, True])
def test_cli_forwards_research_config_for_legacy_tools_and_preserves_reads(db, tree, monkeypatch, capsys, include_research_config):
    legacy, research = tree
    config = {'db_path': str(db.db_path), 'writeup_dirs': {'unified': str(legacy)}}
    if include_research_config:
        config['research_dir'] = str(research)
    monkeypatch.setattr(cli, 'get_config', lambda: config)
    monkeypatch.setattr(sys, 'argv', ['vault', '--json', 'stats'])
    received = []
    original = cli.VaultTools

    def observed(database, directories, research_dir=None):
        received.append((directories, research_dir))
        return original(database, directories, research_dir=research_dir)

    monkeypatch.setattr(cli, 'VaultTools', observed)
    before = db.db_path.read_bytes()
    cli.main()
    assert received == [({'unified': str(legacy)}, str(research) if include_research_config else None)]
    assert 'writeups' in capsys.readouterr().out
    assert db.db_path.read_bytes() == before
