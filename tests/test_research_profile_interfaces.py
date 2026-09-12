"""CLI/MCP profile interfaces use temporary candidate databases only."""

import hashlib
import json
import sys
from unittest.mock import Mock

import pytest
from mcp import Client

from command_vault import cli, server
from command_vault.database import Database
from command_vault.profiles import ResearchProfiles
from command_vault.responses import OperationalStageProfile, VulnerabilityProfile


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    db = Database(str(tmp_path / 'candidate.db'))
    with db._get_connection() as conn:
        conn.execute('INSERT INTO vulnerabilities (canonical_id,external_task_id,summary) VALUES (?,?,?)',
                     ('CVE-2099-0001', 'fixture-task', 'Recorded research summary'))
        conn.execute('INSERT INTO operational_stages (canonical_name,domain,stage_class) VALUES (?,?,?)',
                     ('crash diagnosis', 'kernel', 'diagnose'))
        conn.commit()
    config = {'db_path': str(db.db_path), 'writeup_dirs': {}}
    monkeypatch.setattr(cli, 'get_config', lambda: config)
    monkeypatch.setattr(server, 'get_config', lambda: config)
    monkeypatch.delenv('VAULT_READONLY', raising=False)
    return db


@pytest.mark.parametrize('arguments,expected', [
    (['--json', 'vulnerability', 'CVE-2099-0001'], 'CVE-2099-0001'),
    (['stage', 'crash diagnosis', '--domain', 'KERNEL', '--limit', '1', '--json'], 'crash diagnosis'),
    (['vulnerability', 'fixture-task'], 'fixture-task'),
])
def test_cli_profile_json_and_readonly_bytes(candidate, arguments, expected, monkeypatch, capsys):
    before = hashlib.sha256(candidate.db_path.read_bytes()).hexdigest()
    monkeypatch.setattr(sys, 'argv', ['vault', '--db', str(candidate.db_path), *arguments])
    cli.main()
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result['identifier'] == expected
    assert result['total_matches'] == 1 and result['truncated'] is False
    assert output.err == ''
    assert hashlib.sha256(candidate.db_path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize('command,extra,expected_kwargs', [
    ('vulnerability', [], {'limit': 25}),
    ('vulnerability', ['--limit', '7'], {'limit': 7}),
    ('stage', [], {'domain': None, 'limit': 25}),
    ('stage', ['--domain', 'kernel', '--limit', '7'], {'domain': 'kernel', 'limit': 7}),
])
def test_cli_dispatch_preserves_profile_defaults(candidate, command, extra, expected_kwargs, monkeypatch, capsys):
    profiles = Mock()
    profiles.get_vulnerability.return_value = VulnerabilityProfile(identifier='fixture', total_matches=0, truncated=False)
    profiles.get_operational_stage.return_value = OperationalStageProfile(identifier='fixture', total_matches=0, truncated=False)
    factory = Mock(return_value=profiles)
    monkeypatch.setattr(cli, 'ResearchProfiles', factory)
    monkeypatch.setattr(sys, 'argv', ['vault', '--db', str(candidate.db_path), '--json', command, 'fixture', *extra])
    cli.main()
    assert factory.call_args.args[0].readonly is True
    selected = profiles.get_vulnerability if command == 'vulnerability' else profiles.get_operational_stage
    selected.assert_called_once_with('fixture', **expected_kwargs)
    assert json.loads(capsys.readouterr().out)['matches'] == []


@pytest.mark.parametrize('command', ['vulnerability', 'stage'])
def test_cli_limit_bounds_and_runtime_error_json(candidate, command, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['vault', command, 'fixture', '--limit', '0'])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    capsys.readouterr()
    monkeypatch.setattr(sys, 'argv', ['vault', '--json', command, '  '])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert output.out == ''
    assert 'Identifier' in json.loads(output.err)['error']


@pytest.mark.anyio
async def test_mcp_profile_schemas_read_annotations_normal_readonly_and_success(candidate, monkeypatch):
    before = hashlib.sha256(candidate.db_path.read_bytes()).hexdigest()
    constructed = []
    original = server.ResearchProfiles

    def capture(db):
        constructed.append(db)
        return original(db)

    monkeypatch.setattr(server, 'ResearchProfiles', capture)
    app = server.create_server()
    assert len(constructed) == 1 and constructed[0].readonly is True
    async with Client(app) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert not set(tools).intersection({'index_writeups', 'index_history', 'clear_history', 'enrich'})
        for name in ('get_vulnerability_profile', 'get_operational_stage_profile'):
            tool = tools[name]
            assert tool.annotations.read_only_hint is True
            assert tool.annotations.destructive_hint is False
            assert tool.annotations.open_world_hint is False
            assert tool.input_schema['required'] == ['identifier']
            limit = tool.input_schema['properties']['limit']
            assert (limit['default'], limit['minimum'], limit['maximum']) == (25, 1, 100)
            assert {'identifier', 'matches', 'total_matches', 'truncated'} <= tool.output_schema['properties'].keys()
            assert 'read_context' in tool.description
            assert 'no generated attack plans' in tool.description
        assert tools['get_operational_stage_profile'].input_schema['properties']['domain']['default'] is None
        vulnerability = await client.call_tool('get_vulnerability_profile', {'identifier': 'fixture-task'})
        stage = await client.call_tool('get_operational_stage_profile', {'identifier': 'CRASH DIAGNOSIS', 'domain': 'KERNEL'})
        assert not vulnerability.is_error and not stage.is_error
        assert vulnerability.structured_content == ResearchProfiles(candidate).get_vulnerability('fixture-task').model_dump()
        assert stage.structured_content == ResearchProfiles(candidate).get_operational_stage('CRASH DIAGNOSIS', domain='KERNEL').model_dump()
    assert hashlib.sha256(candidate.db_path.read_bytes()).hexdigest() == before


@pytest.mark.anyio
async def test_mcp_profile_forwarding_and_valueerror_conversion(candidate, monkeypatch):
    profiles = Mock()
    profiles.get_vulnerability.return_value = VulnerabilityProfile(identifier='fixture', total_matches=0, truncated=False)
    profiles.get_operational_stage.return_value = OperationalStageProfile(identifier='fixture', total_matches=0, truncated=False)
    factory = Mock(return_value=profiles)
    monkeypatch.setattr(server, 'ResearchProfiles', factory)
    async with Client(server.create_server()) as client:
        await client.call_tool('get_vulnerability_profile', {'identifier': 'fixture', 'limit': 7})
        await client.call_tool('get_operational_stage_profile', {'identifier': 'fixture', 'domain': 'kernel', 'limit': 3})
        profiles.get_vulnerability.assert_called_once_with('fixture', limit=7)
        profiles.get_operational_stage.assert_called_once_with('fixture', domain='kernel', limit=3)
        profiles.get_vulnerability.side_effect = ValueError('Fixture profile error')
        failure = await client.call_tool('get_vulnerability_profile', {'identifier': 'fixture'})
        assert failure.is_error
        assert any('Fixture profile error' in getattr(item, 'text', '') for item in failure.content)
    assert factory.call_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize('name,arguments', [
    ('get_vulnerability_profile', {'identifier': ''}),
    ('get_vulnerability_profile', {'identifier': 'fixture', 'limit': 101}),
    ('get_operational_stage_profile', {'identifier': 'fixture', 'domain': ''}),
    ('get_operational_stage_profile', {'identifier': 'fixture', 'limit': 0}),
])
async def test_mcp_invalid_profile_input_returns_tool_error(candidate, name, arguments):
    before = candidate.db_path.read_bytes()
    async with Client(server.create_server()) as client:
        result = await client.call_tool(name, arguments)
        assert result.is_error
    assert candidate.db_path.read_bytes() == before
