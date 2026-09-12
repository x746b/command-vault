"""Create-only research builder tests never open a non-test database."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat

import pytest

import command_vault.database as database_module
from command_vault.database import Database
from command_vault.knowledge import Knowledge


@pytest.fixture
def builder():
    script = Path(__file__).resolve().parents[1] / 'scripts/build_research_candidate.py'
    spec = importlib.util.spec_from_file_location('research_candidate_test_module', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    baseline = tmp_path / 'baseline.db'
    with monkeypatch.context() as patch:
        patch.setattr(database_module, 'CURRENT_SCHEMA_VERSION', 1)
        db = Database(str(baseline))
    with db.transaction(), db._get_connection() as conn:
        conn.execute('INSERT INTO writeups (filename,filepath,writeup_type) VALUES (?,?,?)',
                     ('baseline.md', '/unavailable/personal-note.md', 'box'))
    baseline.chmod(0o640)
    bundles = tmp_path / 'bundles'
    bundle = bundles / 'one'
    bundle.mkdir(parents=True)
    (bundle / 'manifest.json').write_text(json.dumps({
        'schema_version': 1,
        'source': {'name': 'Fixture', 'revision': '1', 'upstream_url': 'https://example.org/record'},
        'external_id': 'one', 'domain': 'software',
        'vulnerability': {'summary': 'An ordinary fixture observation.', 'summary_provenance': 'source'},
    }))
    (bundle / 'document.md').write_text('# Notes\n\n## Observation\nOrchard information retained in a benign research fixture.\n')
    return baseline, tmp_path / 'candidate.db', bundles


def test_build_migrates_imports_reports_and_preserves_baseline(builder, inputs):
    baseline, candidate, bundles = inputs
    before = baseline.read_bytes()
    before_mode = stat.S_IMODE(baseline.stat().st_mode)
    report = builder.build_candidate(baseline, candidate, bundles)
    assert baseline.read_bytes() == before
    assert stat.S_IMODE(baseline.stat().st_mode) == before_mode == 0o640
    assert report['baseline_sha256'] == hashlib.sha256(before).hexdigest()
    assert report['baseline_bytes'] == len(before)
    assert report['candidate_sha256'] == hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert report['candidate_bytes'] == candidate.stat().st_size
    assert report['schema_version'] == 2
    assert report['collections'] == 1
    assert report['integrity_check'] == 'ok'
    assert report['foreign_key_violations'] == 0
    assert report['index']['documents_indexed'] == report['index']['bundles_seen'] == 1
    assert report['index']['chunks_indexed'] == 1
    assert report['index']['redactions_by_type'] == {}
    assert report['stats']['writeups']['boxes'] == report['stats']['writeups']['research'] == 1
    assert report['stats']['research']['documents'] == 1
    assert stat.S_IMODE(candidate.stat().st_mode) == 0o600
    assert str(baseline.parent) not in json.dumps(report)
    assert 'Orchard information' not in json.dumps(report)
    readonly = Database(str(candidate), readonly=True)
    assert Knowledge(readonly).search('Orchard', writeup_type='research').results
    with sqlite3.connect(baseline) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 1
    with sqlite3.connect(candidate) as conn:
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []


def test_cli_prints_sorted_json_only(builder, inputs, capsys):
    baseline, candidate, bundles = inputs
    report = builder.main(['--baseline', str(baseline), '--candidate', str(candidate), '--bundles', str(bundles)])
    captured = capsys.readouterr()
    assert captured.err == ''
    assert json.loads(captured.out) == report
    assert captured.out == json.dumps(report, indent=2, sort_keys=True) + '\n'


def test_existing_and_same_candidates_are_never_overwritten(builder, inputs):
    baseline, candidate, bundles = inputs
    before = baseline.read_bytes()
    candidate.write_bytes(b'preexisting candidate')
    with pytest.raises(ValueError, match='exists'):
        builder.build_candidate(baseline, candidate, bundles)
    assert candidate.read_bytes() == b'preexisting candidate'
    with pytest.raises(ValueError, match='baseline'):
        builder.build_candidate(baseline, baseline, bundles)
    assert baseline.read_bytes() == before


@pytest.mark.parametrize('target', ['baseline', 'candidate', 'dangling_candidate', 'parent', 'ancestor'])
def test_symlink_inputs_are_refused(builder, inputs, tmp_path, target):
    baseline, candidate, bundles = inputs
    actual_baseline = baseline
    before = baseline.read_bytes()
    if target == 'baseline':
        baseline = tmp_path / 'baseline-link.db'
        baseline.symlink_to(actual_baseline)
    elif target in ('candidate', 'dangling_candidate'):
        candidate.symlink_to(actual_baseline if target == 'candidate' else tmp_path / 'missing-target.db')
    else:
        real_parent = tmp_path / 'real-parent'
        real_parent.mkdir()
        link = tmp_path / 'linked-parent'
        link.symlink_to(real_parent, target_is_directory=True)
        if target == 'ancestor':
            (real_parent / 'child').mkdir()
            candidate = link / 'child' / 'candidate.db'
        else:
            candidate = link / 'candidate.db'
    with pytest.raises(ValueError):
        builder.build_candidate(baseline, candidate, bundles)
    assert actual_baseline.read_bytes() == before
    if target in ('parent', 'ancestor'):
        assert not candidate.exists()


@pytest.mark.parametrize('fault', ['missing_baseline', 'directory_baseline', 'missing_parent', 'file_parent'])
def test_nonregular_or_missing_inputs_are_refused(builder, inputs, tmp_path, fault):
    baseline, candidate, bundles = inputs
    if fault == 'missing_baseline':
        baseline = tmp_path / 'missing.db'
    elif fault == 'directory_baseline':
        baseline = tmp_path
    elif fault == 'missing_parent':
        candidate = tmp_path / 'missing-parent' / 'candidate.db'
    else:
        parent = tmp_path / 'file-parent'
        parent.write_bytes(b'not a directory')
        candidate = parent / 'candidate.db'
    with pytest.raises(ValueError):
        builder.build_candidate(baseline, candidate, bundles)
    assert not candidate.exists()


def test_corrupt_baseline_does_not_reserve_candidate(builder, inputs):
    baseline, candidate, bundles = inputs
    baseline.write_bytes(b'invalid sqlite fixture')
    before = baseline.read_bytes()
    with pytest.raises(sqlite3.DatabaseError):
        builder.build_candidate(baseline, candidate, bundles)
    assert baseline.read_bytes() == before
    assert not candidate.exists()


def test_invalid_bundle_preserves_inspectable_candidate(builder, inputs):
    baseline, candidate, bundles = inputs
    (bundles / 'one' / 'manifest.json').write_text('{invalid manifest')
    before = baseline.read_bytes()
    with pytest.raises(ValueError, match='Manifest'):
        builder.build_candidate(baseline, candidate, bundles)
    assert candidate.is_file()
    assert stat.S_IMODE(candidate.stat().st_mode) == 0o600
    assert baseline.read_bytes() == before
    with sqlite3.connect(candidate) as conn:
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 2
        assert conn.execute('SELECT count(*) FROM writeups').fetchone()[0] == 1


def test_atomic_exclusive_reservation_rejects_competing_file(builder, inputs, monkeypatch):
    baseline, candidate, bundles = inputs
    before = baseline.read_bytes()
    original = os.open

    def race(path, flags, mode=0o777, **kwargs):
        if Path(path) == candidate:
            assert flags & os.O_EXCL and flags & os.O_CREAT
            candidate.write_bytes(b'competing writer data')
        return original(path, flags, mode, **kwargs)

    monkeypatch.setattr(builder.os, 'open', race)
    with pytest.raises(FileExistsError):
        builder.build_candidate(baseline, candidate, bundles)
    assert candidate.read_bytes() == b'competing writer data'
    assert baseline.read_bytes() == before


def test_baseline_connection_is_readonly_and_query_only(builder, inputs, monkeypatch):
    baseline, candidate, bundles = inputs
    original = sqlite3.connect
    baseline_statements = []
    baseline_connections = []

    def observed(database, *args, **kwargs):
        connection = original(database, *args, **kwargs)
        if str(database).startswith(baseline.as_uri()):
            assert str(database).endswith('?mode=ro')
            assert kwargs['uri'] is True
            connection.set_trace_callback(baseline_statements.append)
            baseline_connections.append(database)
        return connection

    monkeypatch.setattr(builder.sqlite3, 'connect', observed)
    builder.build_candidate(baseline, candidate, bundles)
    assert len(baseline_connections) == 1
    assert baseline_statements[0] == 'PRAGMA query_only=ON'
    assert 'PRAGMA integrity_check' in baseline_statements


def test_foreign_key_failure_leaves_candidate_and_baseline_intact(builder, inputs):
    baseline, candidate, bundles = inputs
    with sqlite3.connect(baseline) as conn:
        conn.execute('INSERT INTO writeup_tags (writeup_id,tag_id) VALUES (?,?)', (12345, 54321))
    before = baseline.read_bytes()
    with pytest.raises(ValueError, match='foreign key'):
        builder.build_candidate(baseline, candidate, bundles)
    assert candidate.is_file()
    assert baseline.read_bytes() == before
    with sqlite3.connect(candidate) as conn:
        assert conn.execute('PRAGMA foreign_key_check').fetchall()


def test_baseline_fingerprint_is_rechecked_on_success_and_failure(builder, inputs, monkeypatch):
    baseline, candidate, bundles = inputs
    original = builder._fingerprint
    checks = []

    def changed_on_second_read(path):
        result = original(path)
        if path == baseline:
            checks.append(path)
            if len(checks) == 2:
                return '0' * 64, result[1]
        return result

    monkeypatch.setattr(builder, '_fingerprint', changed_on_second_read)
    before = baseline.read_bytes()
    with pytest.raises(ValueError, match='Baseline changed'):
        builder.build_candidate(baseline, candidate, bundles)
    assert len(checks) == 2
    assert candidate.exists()
    assert baseline.read_bytes() == before


def test_cli_failure_is_content_free_and_preserves_candidate(builder, inputs, capsys):
    baseline, candidate, bundles = inputs
    (bundles / 'one' / 'manifest.json').write_text('{private invalid input')
    with pytest.raises(SystemExit) as error:
        builder.main(['--baseline', str(baseline), '--candidate', str(candidate), '--bundles', str(bundles)])
    assert 'preserved for inspection' in str(error.value)
    assert 'private' not in str(error.value)
    assert str(baseline.parent) not in str(error.value)
    assert capsys.readouterr().out == ''
    assert candidate.exists()


def test_managed_root_option_stores_source_path_without_reporting_paths(builder, inputs, capsys):
    baseline, candidate, bundles = inputs
    before = baseline.read_bytes()
    report = builder.main(['--baseline', str(baseline), '--candidate', str(candidate),
                           '--bundles', str(bundles), '--managed-root', str(bundles)])
    assert baseline.read_bytes() == before
    assert str(bundles) not in json.dumps(report)
    assert str(bundles) not in capsys.readouterr().out
    with sqlite3.connect(candidate) as conn:
        writeup_id, filepath = conn.execute('SELECT id,filepath FROM writeups WHERE writeup_type=?', ('research',)).fetchone()
        assert filepath == str((bundles / 'one/document.md').resolve())
    assert Knowledge(Database(str(candidate), readonly=True)).read_context(f'document:{writeup_id}').source_status == 'managed'


def test_managed_root_outside_bundles_is_rejected_before_candidate_creation(builder, inputs, tmp_path):
    baseline, candidate, bundles = inputs
    managed = tmp_path / 'other-managed'
    managed.mkdir()
    before = baseline.read_bytes()
    with pytest.raises(ValueError, match='under the managed root'):
        builder.build_candidate(baseline, candidate, bundles, managed_root=managed)
    assert not candidate.exists()
    assert baseline.read_bytes() == before


def second_collection(first):
    collection = first.parent / 'second-source'
    bundle = collection / 'second'
    bundle.mkdir(parents=True)
    manifest = json.loads((first / 'one/manifest.json').read_text())
    manifest['source']['name'] = 'Second Fixture'
    manifest['external_id'] = 'two'
    (bundle / 'manifest.json').write_text(json.dumps(manifest))
    (bundle / 'document.md').write_text('# Notes\n\n## Second observation\nA separate orchard source has independent retained content.\n')
    return collection


def test_multiple_collections_aggregate_all_counts_in_supplied_order_and_migrate_once(builder, inputs, monkeypatch):
    baseline, candidate, first = inputs
    second = second_collection(first)
    for document in (first / 'one/document.md', second / 'second/document.md'):
        document.write_text(document.read_text() + '\nHTB{aggregate_fixture_redaction}\n')
    before, before_mode = baseline.read_bytes(), stat.S_IMODE(baseline.stat().st_mode)
    constructors = []
    original = builder.Database

    def observed(path, *args, **kwargs):
        constructors.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(builder, 'Database', observed)
    report = builder.build_candidate(baseline, candidate, [second, first], managed_root=first.parent)
    assert constructors == [str(candidate)]
    assert report['collections'] == 2
    assert report['index']['bundles_seen'] == report['index']['documents_indexed'] == 2
    assert report['index']['chunks_indexed'] == report['index']['vulnerabilities_indexed'] == 2
    assert report['index']['redactions_by_type'] == {'flag': 2}
    for field in ('scripts_indexed', 'stages_linked', 'evidence_links', 'validation_records', 'mitigations_indexed', 'mitigation_links'):
        assert report['index'][field] == 0
    assert report['stats']['research']['source_collections'] == 2
    assert report['stats']['research']['by_source'] == {'Fixture': 1, 'Second Fixture': 1}
    assert report['stats']['writeups']['research'] == 2
    assert report['integrity_check'] == 'ok' and report['foreign_key_violations'] == 0
    assert baseline.read_bytes() == before and stat.S_IMODE(baseline.stat().st_mode) == before_mode
    assert report['baseline_sha256'] == hashlib.sha256(before).hexdigest()
    assert str(first.parent) not in json.dumps(report) and 'aggregate_fixture_redaction' not in json.dumps(report)
    with sqlite3.connect(candidate) as conn:
        assert conn.execute('SELECT external_id FROM writeups WHERE writeup_type=? ORDER BY id', ('research',)).fetchall() == [('two',), ('one',)]


def test_cli_repeatable_bundles_and_single_collection_sequence_compatibility(builder, inputs, capsys):
    baseline, candidate, first = inputs
    second = second_collection(first)
    report = builder.main(['--baseline', str(baseline), '--candidate', str(candidate),
                           '--bundles', str(first), '--bundles', str(second)])
    assert report['collections'] == 2
    assert json.loads(capsys.readouterr().out) == report
    single = builder.build_candidate(baseline, candidate.with_name('single.db'), (first,))
    assert single['collections'] == 1 and single['index']['documents_indexed'] == 1


@pytest.mark.parametrize('case', ['empty', 'duplicate', 'canonical_duplicate', 'outside', 'missing', 'symlink'])
def test_invalid_collection_selection_fails_before_candidate_reservation(builder, inputs, case):
    baseline, candidate, first = inputs
    before = baseline.read_bytes()
    managed_root = first
    if case == 'empty':
        collections = []
    elif case == 'duplicate':
        collections = [first, first]
    elif case == 'canonical_duplicate':
        collections = [first, first / 'one' / '..']
    elif case == 'outside':
        collections = [first, second_collection(first)]
    elif case == 'missing':
        collections = [first, first.parent / 'missing']
    else:
        linked = first.parent / 'linked'
        linked.symlink_to(first, target_is_directory=True)
        collections = [first, linked]
    with pytest.raises(ValueError):
        builder.build_candidate(baseline, candidate, collections, managed_root=managed_root)
    assert not candidate.exists()
    assert baseline.read_bytes() == before


def test_later_collection_failure_preserves_first_committed_collection(builder, inputs):
    baseline, candidate, first = inputs
    second = second_collection(first)
    (second / 'second/manifest.json').write_text('{invalid second collection')
    before, before_mode = baseline.read_bytes(), stat.S_IMODE(baseline.stat().st_mode)
    with pytest.raises(ValueError, match='Manifest'):
        builder.build_candidate(baseline, candidate, [first, second], managed_root=first.parent)
    assert candidate.is_file() and stat.S_IMODE(candidate.stat().st_mode) == 0o600
    assert baseline.read_bytes() == before and stat.S_IMODE(baseline.stat().st_mode) == before_mode
    with sqlite3.connect(candidate) as conn:
        assert conn.execute('SELECT external_id FROM writeups WHERE writeup_type=?', ('research',)).fetchall() == [('one',)]
        assert conn.execute('SELECT name FROM source_collections').fetchall() == [('Fixture',)]
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
