"""Finite offline checks using only the sanitized CyberGym fixture tree."""

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess

import pytest

from command_vault.adapters.cybergym import CyberGymAdapter, _error_facts, _patch_facts
import command_vault.adapters.cybergym as adapter_module
from command_vault.research import load_research_bundle


FIXTURE = Path(__file__).parent / 'fixtures/research/cybergym'
TASK = 'data/arvo/9000001'
REVISION = '1' * 40


@pytest.fixture
def dataset(tmp_path):
    root = tmp_path / 'dataset'
    shutil.copytree(FIXTURE, root)
    return root


def _records(root):
    return json.loads((root / 'tasks.json').read_text())


def _save(root, records):
    (root / 'tasks.json').write_text(json.dumps(records), encoding='utf-8')


def _build(root, tmp_path, name='output', **kwargs):
    return CyberGymAdapter(root, REVISION, **kwargs).build(tmp_path / name)


def _tree(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob('*') if path.is_file()}


def test_valid_bundle_facts_stages_hashes_and_no_inference(dataset, tmp_path):
    report = _build(dataset, tmp_path)
    assert (report.records_seen, report.records_selected, report.artifacts) == (1, 1, 3)
    assert report.bundles[0].name == 'arvo__9000001'
    loaded = load_research_bundle(report.bundles[0])
    manifest = loaded.manifest
    assert manifest.source.name == 'cybergym'
    assert str(manifest.source.homepage) == str(manifest.source.repository_url) == 'https://huggingface.co/datasets/sunblaze-ucb/cybergym'
    assert str(manifest.source.upstream_url).endswith(f'/tree/{REVISION}/{TASK}')
    assert manifest.source.license_expression is None
    assert (manifest.external_id, manifest.domain, manifest.project, manifest.language) == ('arvo:9000001', 'userspace', 'fixture-parser', 'c++')
    assert manifest.source_path == TASK
    error = manifest.source_metadata['derived_error']
    assert error['provenance'] == 'deterministic'
    assert error['sanitizer'] == 'msan'
    assert error['vulnerability_class'] == 'use-of-uninitialized-value'
    assert error['dedup_tokens'] == ['parse_record--consume_record']
    assert error['frames'][0] == {'index': 0, 'function': 'parse_record', 'path': '/src/fixture/parser.c', 'line': 42, 'column': 7}
    assert error['affected_symbols'] == ['parse_record', 'consume_record']
    assert manifest.vulnerability.vulnerability_class == 'use-of-uninitialized-value'
    assert manifest.vulnerability.class_provenance.value == 'deterministic'
    assert manifest.vulnerability.summary_provenance.value == 'source'
    assert manifest.vulnerability.canonical_id is None and manifest.vulnerability.subsystem is None
    assert manifest.vulnerability.platform == 'linux'
    assert manifest.vulnerability.architecture is None
    completeness = manifest.source_metadata['evidence_completeness']
    assert completeness == {'description': True, 'runtime': True, 'patch': True, 'complete_triple': True,
                            'count': 3, 'provenance': 'deterministic'}
    assert '"evidence_completeness"' in loaded.document
    for key, value in _records(dataset)[0].items():
        assert manifest.source_metadata[key] == value
    assert [item.path for item in manifest.artifacts] == ['artifacts/description.txt', 'artifacts/error.txt', 'artifacts/patch.diff']
    assert [item.role.value for item in manifest.artifacts] == ['signal', 'signal', 'remediation']
    assert [item.validation.value for item in manifest.artifacts] == ['source_documented', 'harness_observed', 'source_documented']
    for declared, verified in zip(manifest.artifacts, loaded.artifacts):
        assert declared.sha256 == verified.sha256 == hashlib.sha256(verified.content).hexdigest()
        assert declared.license_expression is None
    assert [(stage.canonical_name, stage.stage_class.value, stage.evidence_sections) for stage in manifest.operational_stages] == [
        ('crash reproduction', 'trigger', ['Runtime evidence']),
        ('crash diagnosis', 'diagnose', ['Runtime evidence']), ('remediation', 'remediation', ['Patch']),
    ]
    assert all(stage.assertion_provenance.value == 'deterministic' for stage in manifest.operational_stages)
    assert [stage.validation_status.value for stage in manifest.operational_stages] == [
        'harness_observed', 'harness_observed', 'source_documented',
    ]
    headings = ['## Source metadata', '## Description', '## Derived error facts', '## Runtime evidence', '## Patch facts', '## Patch\n']
    assert [loaded.document.index(heading) for heading in headings] == sorted(loaded.document.index(heading) for heading in headings)
    with pytest.raises(FrozenInstanceError):
        report.artifacts = 0


def test_metadata_source_locations_and_blank_summary_are_preserved(dataset, tmp_path):
    records = _records(dataset)
    records[0].update(project_homepage='www.kamailio.org', project_main_repo='git://example.org/project.git', vulnerability_description='')
    _save(dataset, records)
    manifest = load_research_bundle(_build(dataset, tmp_path).bundles[0]).manifest
    assert manifest.source_metadata['project_homepage'] == 'www.kamailio.org'
    assert manifest.source_metadata['project_main_repo'] == 'git://example.org/project.git'
    assert manifest.source_metadata['vulnerability_description'] == ''
    assert manifest.vulnerability.summary is None and manifest.vulnerability.summary_provenance is None


def test_final_summary_ordered_tokens_template_frames_and_unique_symbols():
    text = ('SUMMARY: AddressSanitizer: heap-buffer-overflow old\n'
            '#0 0x1 in parse<std::pair<int, int> > /src/foo.cc:12:3\n'
            '#1 0x2 in parse<std::pair<int, int> > /src/foo.cc:14\n'
            'DEDUP_TOKEN: second--first\nDEDUP_TOKEN: third\n'
            'SUMMARY: MemorySanitizer: use-of-uninitialized-value final\n')
    facts = _error_facts(text)
    assert facts['sanitizer'] == 'msan' and facts['vulnerability_class'] == 'use-of-uninitialized-value'
    assert facts['raw_summary'] == 'SUMMARY: MemorySanitizer: use-of-uninitialized-value final'
    assert facts['dedup_tokens'] == ['second--first', 'third']
    assert facts['affected_symbols'] == ['parse<std::pair<int, int> >']
    assert facts['frames'][1]['line'] == 14 and facts['frames'][1]['column'] is None


@pytest.mark.parametrize('name,canonical', [('AddressSanitizer', 'asan'), ('MemorySanitizer', 'msan'),
    ('UndefinedBehaviorSanitizer', 'ubsan'), ('LeakSanitizer', 'lsan'), ('ThreadSanitizer', 'tsan'), ('HWAddressSanitizer', 'hwasan')])
def test_explicit_sanitizer_names_only(name, canonical):
    assert _error_facts(f'SUMMARY: {name}: unknown-condition')['sanitizer'] == canonical
    assert _error_facts(f'SUMMARY: {name}: unknown-condition')['vulnerability_class'] is None
    assert _error_facts('SUMMARY: UnknownSanitizer: unknown-condition')['sanitizer'] is None


def test_ambiguous_classes_are_not_inferred():
    assert _error_facts('SUMMARY: AddressSanitizer: heap-buffer-overflow or double-free')['vulnerability_class'] is None


def test_patch_facts_are_only_explicit_structure():
    patch = ('diff --git a/old.c b/new.c\n--- a/old.c\n+++ b/new.c\n'
             '@@ -4,2 +4,3 @@ int fixture(void) {\n-old\n+new\n+++actual added content\n same\n')
    facts = _patch_facts(patch)
    assert facts['changed_paths'] == ['old.c', 'new.c']
    assert facts['files'] == [{'old_path': 'old.c', 'new_path': 'new.c'}]
    assert (facts['added_lines'], facts['removed_lines']) == (2, 1)
    assert facts['hunks'][0] == {'header': '@@ -4,2 +4,3 @@ int fixture(void) {', 'old_start': 4,
                               'old_count': 2, 'new_start': 4, 'new_count': 3,
                               'context': 'int fixture(void) {', 'path': 'new.c'}
    assert set(facts) == {'provenance', 'changed_paths', 'files', 'hunks', 'added_lines', 'removed_lines'}


def test_namespaces_order_determinism_and_unknown_archives_never_read(dataset, tmp_path):
    records = _records(dataset)
    other = json.loads(json.dumps(records[0]))
    other['task_id'] = 'oss-fuzz:fixture-two'
    shutil.copytree(dataset / TASK, dataset / 'data/oss-fuzz/fixture-two')
    _save(dataset, [other, *records])
    for root in (dataset / TASK, dataset / 'data/oss-fuzz/fixture-two'):
        (root / 'repo-vul.tar.gz').write_bytes(b'\xffNEVER READ')
        (root / 'repo-fix.tar.gz').symlink_to(tmp_path / 'missing-archive')
    first = _build(dataset, tmp_path, 'first')
    second = _build(dataset, tmp_path, 'second')
    assert [path.name for path in first.bundles] == ['arvo__9000001', 'oss-fuzz__fixture-two']
    assert first.records_selected == 2 and first.artifacts == 6
    for left, right in zip(first.bundles, second.bundles):
        assert _tree(left) == _tree(right)


def test_redaction_never_retains_matched_details(dataset, tmp_path):
    secret = 'HTB{cybergym_fixture_secret}'
    records = _records(dataset)
    records[0]['vulnerability_description'] = secret
    _save(dataset, records)
    with (dataset / TASK / 'error.txt').open('a') as source:
        source.write(f'\n{secret}\n````\n')
    adapter = CyberGymAdapter(dataset, REVISION)
    report = adapter.build(tmp_path / 'output')
    assert report.redactions_by_type == {'flag': 2}
    assert adapter.security_filter.redaction_log == []
    assert secret not in repr(report)
    assert all(secret.encode() not in data for data in _tree(report.bundles[0]).values())
    assert '`````text' in load_research_bundle(report.bundles[0]).document


@pytest.mark.parametrize('case', ['lfs', 'missing', 'symlink', 'oversized'])
def test_incomplete_or_unsafe_selected_text_is_rejected(dataset, tmp_path, case):
    path = dataset / TASK / 'error.txt'
    kwargs = {}
    if case == 'lfs':
        path.write_text('version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 10\n')
    elif case == 'missing':
        path.unlink()
    elif case == 'symlink':
        path.unlink()
        path.symlink_to(dataset / TASK / 'description.txt')
    else:
        kwargs['max_source_file_bytes'] = 1
    with pytest.raises((ValueError, FileNotFoundError)):
        _build(dataset, tmp_path, **kwargs)
    assert not list((tmp_path / 'output').iterdir())


@pytest.mark.parametrize('case', ['duplicate', 'unsafe', 'namespace', 'wrong-type', 'invalid-json', 'duplicate-json-key', 'nonfinite'])
def test_metadata_rejection(dataset, tmp_path, case):
    records = _records(dataset)
    if case == 'duplicate':
        records.append(records[0])
    elif case == 'unsafe':
        records[0]['task_id'] = 'arvo:../outside'
    elif case == 'namespace':
        records[0]['task_id'] = 'unsupported:one'
    elif case == 'wrong-type':
        records[0]['task_difficulty'] = ['invalid']
    if case in ('invalid-json', 'duplicate-json-key', 'nonfinite'):
        (dataset / 'tasks.json').write_text({'invalid-json': '{invalid', 'duplicate-json-key': '[{"task_id":"x","task_id":"y"}]',
                                           'nonfinite': '[NaN]'}[case])
    else:
        _save(dataset, records)
    with pytest.raises(ValueError):
        _build(dataset, tmp_path)


def test_preexisting_output_and_symlink_roots_refused(dataset, tmp_path):
    report = _build(dataset, tmp_path)
    before = _tree(report.bundles[0])
    with pytest.raises(ValueError, match='already exists'):
        _build(dataset, tmp_path)
    assert _tree(report.bundles[0]) == before
    linked = tmp_path / 'linked-dataset'
    linked.symlink_to(dataset, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        CyberGymAdapter(linked, REVISION)
    output_link = tmp_path / 'output-link'
    output_link.symlink_to(tmp_path / 'output', target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        CyberGymAdapter(dataset, REVISION).build(output_link)


def test_no_execution_network_or_database_access(dataset, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Adapter attempted execution, networking, or DB access')

    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    assert _build(dataset, tmp_path).records_selected == 1


def test_invalid_utf8_is_normalized_with_raw_hashes_preserved(dataset, tmp_path):
    originals = {}
    for name in ('description.txt', 'error.txt', 'patch.diff'):
        original = (dataset / TASK / name).read_bytes() + b'\ninvalid byte: \xff\n'
        (dataset / TASK / name).write_bytes(original)
        originals[name] = original
    loaded = load_research_bundle(_build(dataset, tmp_path).bundles[0])
    for artifact in loaded.artifacts:
        name = artifact.path.name
        facts = loaded.manifest.source_metadata['source_files'][name]
        assert facts['utf8_valid'] is False
        assert facts['raw_sha256'] == hashlib.sha256(originals[name]).hexdigest()
        assert facts['raw_bytes'] == len(originals[name])
        assert facts['normalized_truncated'] is False and facts['omitted_bytes'] == 0
        assert b'\\xff' in artifact.content
        artifact.content.decode('utf-8', errors='strict')


def test_runtime_excerpt_and_facts_are_bounded_but_derived_from_full_text(dataset, tmp_path, monkeypatch):
    text = ('HEAD\n' + '日本語 filler\n' * 200
            + ''.join(f'    #{index} 0x1 in fn{index} /src/fixture.cc:{index + 1}:2\n' for index in range(300))
            + ''.join(f'DEDUP_TOKEN: fn{index}\n' for index in range(150))
            + 'SUMMARY: AddressSanitizer: heap-buffer-overflow final\nTAIL\n')
    data = text.encode('utf-8')
    (dataset / TASK / 'error.txt').write_bytes(data)
    monkeypatch.setattr(adapter_module, 'MAX_RUNTIME_BYTES', 1024)
    adapter = CyberGymAdapter(dataset, REVISION)
    assert adapter.max_source_file_bytes >= 40 * 1024 * 1024
    loaded = load_research_bundle(adapter.build(tmp_path / 'output').bundles[0])
    error_artifact = next(item for item in loaded.artifacts if item.path.name == 'error.txt')
    assert len(error_artifact.content) <= 1024
    excerpt = error_artifact.content.decode('utf-8', errors='strict')
    assert excerpt.startswith('HEAD\n') and excerpt.endswith('TAIL\n')
    source = loaded.manifest.source_metadata['source_files']['error.txt']
    assert source['raw_sha256'] == hashlib.sha256(data).hexdigest() and source['raw_bytes'] == len(data)
    assert source['normalized_truncated'] is True
    assert f'{source["omitted_bytes"]} normalized UTF-8 bytes omitted' in excerpt
    facts = loaded.manifest.source_metadata['derived_error']
    assert len(facts['frames']) == 256 and facts['frames_total'] == 300 and facts['frames_truncated']
    assert len(facts['affected_symbols']) == 256 and facts['affected_symbols_total'] == 300 and facts['affected_symbols_truncated']
    assert len(facts['dedup_tokens']) == 128 and facts['dedup_tokens_total'] == 150 and facts['dedup_tokens_truncated']
    assert facts['vulnerability_class'] == 'heap-buffer-overflow'
