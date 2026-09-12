"""Managed research retention never enters legacy Markdown indexing."""

from pathlib import Path
import sys

import pytest

from command_vault import cli, server
from command_vault.config import get_config
from command_vault.database import Database
from command_vault.indexer import Indexer
from command_vault.tools import VaultTools


@pytest.fixture
def tree(tmp_path):
    legacy = tmp_path / 'writeups'
    research = legacy / 'research'
    bundle = research / 'source' / 'task'
    bundle.mkdir(parents=True)
    (legacy / 'ordinary.md').write_text('# Personal notes\n\n## Observation\nOrdinary personal orchard evidence belongs in the legacy corpus.\n')
    (bundle / 'document.md').write_text('# Research notes\n\n## Observation\nRetained research source evidence must not enter legacy ingestion.\n')
    (bundle / 'manifest.json').write_text('{"retained":true}')
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


def test_legacy_constructor_defaults_keep_existing_indexing_behavior(db, tree):
    legacy, _ = tree
    vault = VaultTools(db, {'unified': str(legacy)})
    assert vault.research_dir is None and vault.indexer.research_dir is None
    assert vault.index_writeups()['files_processed'] == 2


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
