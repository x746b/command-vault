"""Research is a read filter, never a legacy Markdown indexing type."""

import argparse
import sys
from unittest.mock import Mock

import pytest
from mcp import Client

from command_vault import cli, server
from command_vault.responses import CommandPage, KnowledgePage


READ_TOOLS = {
    'search_knowledge': {'query': 'notes'},
    'search_writeup_prose': {'query': 'notes'},
    'search_commands': {'query': 'notes'},
    'get_tool_examples': {'tool_name': 'example'},
    'list_tools': {},
}
LEGACY_TYPES = ['box', 'challenge', 'sherlock']


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def parse_cli(monkeypatch):
    # Stop immediately after actual argument parsing, before initialization.
    class Parsed(Exception):
        def __init__(self, args):
            self.args_namespace = args

    original = argparse.ArgumentParser.parse_args

    def capture(parser, *args, **kwargs):
        raise Parsed(original(parser, *args, **kwargs))

    monkeypatch.setattr(argparse.ArgumentParser, 'parse_args', capture)

    def parse(*args):
        monkeypatch.setattr(sys, 'argv', ['vault', *args])
        with pytest.raises(Parsed) as captured:
            cli.main()
        return captured.value.args_namespace

    return parse


@pytest.mark.parametrize('command', ['search', 'prose', 'knowledge'])
@pytest.mark.parametrize('source_type', [*LEGACY_TYPES, 'research'])
@pytest.mark.parametrize('flag', ['--type', '-T'])
def test_cli_read_type_choices(parse_cli, command, source_type, flag):
    assert parse_cli(command, 'notes', flag, source_type).type == source_type


@pytest.mark.parametrize('command', ['search', 'prose', 'knowledge', 'index'])
def test_cli_type_default_stays_none(parse_cli, command):
    args = [command] if command == 'index' else [command, 'notes']
    assert parse_cli(*args).type is None


@pytest.mark.parametrize('source_type', LEGACY_TYPES)
def test_cli_index_preserves_legacy_choices(parse_cli, source_type):
    assert parse_cli('index', '--type', source_type).type == source_type


@pytest.mark.parametrize('flag', ['--type', '-T'])
def test_cli_index_rejects_research_before_initialization(parse_cli, capsys, flag):
    with pytest.raises(SystemExit) as error:
        parse_cli('index', flag, 'research')
    assert error.value.code == 2
    assert "invalid choice: 'research'" in capsys.readouterr().err


@pytest.fixture
def adapter(monkeypatch):
    monkeypatch.delenv('VAULT_READONLY', raising=False)
    monkeypatch.setattr(server, 'get_config', lambda: {'writeup_dirs': {}})
    # Endpoint tests exercise validation and forwarding without opening a DB.
    knowledge = Mock(return_value=KnowledgePage())
    records = Mock(return_value=CommandPage())
    inventory = Mock(return_value=[])
    indexer = Mock(return_value={})
    monkeypatch.setattr(server.Knowledge, 'search', knowledge)
    monkeypatch.setattr(server, 'search_records', records)
    monkeypatch.setattr(server.VaultTools, 'list_tools', inventory)
    monkeypatch.setattr(server.VaultTools, 'index_writeups', indexer)
    return server.create_server(db=object(), writeup_dirs={}, allow_admin=True), knowledge, records, inventory, indexer


@pytest.mark.anyio
async def test_mcp_schemas_separate_read_and_index_types(adapter):
    async with Client(adapter[0]) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        for name in READ_TOOLS:
            field = tools[name].input_schema['properties']['writeup_type']
            assert field['anyOf'] == [
                {'enum': [*LEGACY_TYPES, 'research'], 'type': 'string'}, {'type': 'null'},
            ]
            assert field['default'] is None
            assert tools[name].annotations.read_only_hint
            assert tools[name].output_schema
        field = tools['index_writeups'].input_schema['properties']['writeup_type']
        assert field['anyOf'] == [
            {'enum': LEGACY_TYPES, 'type': 'string'}, {'type': 'null'},
        ]
        assert field['default'] is None
        assert not tools['index_writeups'].annotations.read_only_hint
        assert 'writeup_type' not in tools['search_scripts'].input_schema['properties']


@pytest.mark.anyio
@pytest.mark.parametrize('name,arguments', READ_TOOLS.items())
async def test_mcp_read_tools_accept_and_forward_research(adapter, name, arguments):
    app, knowledge, records, inventory, indexer = adapter
    async with Client(app) as client:
        result = await client.call_tool(name, {**arguments, 'writeup_type': 'research'})
        assert not result.is_error
        assert result.structured_content['results'] == []
    if name in ('search_knowledge', 'search_writeup_prose'):
        assert knowledge.call_args.args[1] == 'research'
    elif name in ('search_commands', 'get_tool_examples'):
        assert records.call_args.kwargs['writeup_type'] == 'research'
    else:
        assert inventory.call_args.args[1] == 'research'
    indexer.assert_not_called()


@pytest.mark.anyio
async def test_mcp_admin_rejects_research_before_indexer(adapter):
    async with Client(adapter[0]) as client:
        result = await client.call_tool('index_writeups', {'writeup_type': 'research'})
        assert result.is_error
    adapter[4].assert_not_called()


@pytest.mark.anyio
@pytest.mark.parametrize('source_type', [None, *LEGACY_TYPES])
async def test_mcp_admin_preserves_supported_types_and_defaults(adapter, source_type):
    arguments = {} if source_type is None else {'writeup_type': source_type}
    async with Client(adapter[0]) as client:
        result = await client.call_tool('index_writeups', arguments)
        assert not result.is_error
    adapter[4].assert_called_once_with(
        directories=None, force_rebuild=False, writeup_type=source_type,
    )
