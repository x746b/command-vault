"""Offline CyberGym CLI checks use only sanitized, nonfunctional fixtures."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess

import pytest

from command_vault.research import load_research_bundle


ROOT = Path(__file__).resolve().parents[1]
REVISION = '1' * 40
SPEC = importlib.util.spec_from_file_location('build_cybergym_bundles', ROOT / 'scripts/build_cybergym_bundles.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


@pytest.fixture
def dataset(tmp_path):
    root = tmp_path / 'dataset'
    shutil.copytree(ROOT / 'tests/fixtures/research/cybergym', root)
    return root


def test_cli_prints_sorted_aggregate_json_and_creates_loadable_bundle(dataset, tmp_path, capsys):
    output = tmp_path / 'output'
    builder.main(['--dataset', str(dataset), '--revision', REVISION, '--output', str(output)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report == {'records_seen': 1, 'records_selected': 1, 'artifacts': 3,
                      'redactions_by_type': {}, 'bundle_count': 1}
    assert captured.out == json.dumps(report, sort_keys=True, indent=2) + '\n'
    assert captured.err == ''
    assert str(tmp_path) not in captured.out
    assert 'arvo__9000001' not in captured.out
    assert 'fixture-parser' not in captured.out
    assert 'http' not in captured.out
    assert 'uninitialized' not in captured.out
    bundle = load_research_bundle(output / 'arvo__9000001')
    assert bundle.manifest.external_id == 'arvo:9000001'
    assert len(bundle.artifacts) == 3


def test_build_bundles_returns_only_json_safe_aggregates(dataset, tmp_path):
    report = builder.build_bundles(dataset, REVISION, tmp_path / 'output')
    assert json.loads(json.dumps(report)) == report
    assert set(report) == {'records_seen', 'records_selected', 'artifacts', 'redactions_by_type', 'bundle_count'}
    assert not any(isinstance(value, list) for value in report.values())


def test_invalid_revision_propagates_without_creating_output(dataset, tmp_path):
    output = tmp_path / 'output'
    with pytest.raises(ValueError, match='Revision'):
        builder.build_bundles(dataset, 'invalid-revision', output)
    assert not output.exists()


@pytest.mark.parametrize('case', ['missing', 'lfs'])
def test_incomplete_input_propagates_without_publishing_bundle(dataset, tmp_path, case):
    source = dataset / 'data/arvo/9000001/error.txt'
    if case == 'missing':
        source.unlink()
    else:
        source.write_text('version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 10\n')
    output = tmp_path / 'output'
    with pytest.raises((ValueError, FileNotFoundError)):
        builder.build_bundles(dataset, REVISION, output)
    assert list(output.iterdir()) == []


def test_existing_bundle_is_never_overwritten(dataset, tmp_path):
    output = tmp_path / 'output'
    builder.build_bundles(dataset, REVISION, output)
    manifest = output / 'arvo__9000001/manifest.json'
    before = manifest.read_bytes()
    with pytest.raises(ValueError, match='already exists'):
        builder.main(['--dataset', str(dataset), '--revision', REVISION, '--output', str(output)])
    assert manifest.read_bytes() == before


def test_wrapper_never_uses_network_execution_or_database(dataset, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Wrapper attempted network, execution, or database access')

    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    assert builder.build_bundles(dataset, REVISION, tmp_path / 'output')['bundle_count'] == 1


@pytest.mark.parametrize('missing', ['--dataset', '--revision', '--output'])
def test_all_cli_arguments_are_required(dataset, tmp_path, missing):
    arguments = {'--dataset': str(dataset), '--revision': REVISION, '--output': str(tmp_path / 'output')}
    argv = [part for key, value in arguments.items() if key != missing for part in (key, value)]
    with pytest.raises(SystemExit) as error:
        builder.main(argv)
    assert error.value.code == 2
    assert not (tmp_path / 'output').exists()
