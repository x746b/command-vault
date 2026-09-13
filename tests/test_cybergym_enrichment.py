"""Synthetic checks for the offline, metadata-only CyberGym enrichment adapter."""

import hashlib
import json
import os
import socket
import sqlite3
import subprocess

import pytest

from command_vault.adapters.cybergym_enrichment import CyberGymEnrichmentAdapter, _normal_class
from command_vault.research import load_research_bundle


REVISION = 'a' * 40
CYBER_REVISION = 'b' * 40


def _bundle(root, name, external_id, *, sanitizer=None, klass=None, architecture=None,
            source='cybergym', source_revision=CYBER_REVISION, document='# Fixture\n', artifact=b'fixture\n'):
    path = root / name
    (path / 'artifacts').mkdir(parents=True)
    (path / 'artifacts' / 'note.txt').write_bytes(artifact)
    manifest = {
        'schema_version': 1,
        'source': {'name': source, 'revision': source_revision, 'upstream_url': 'https://example.test/source'},
        'external_id': external_id, 'domain': 'userspace', 'project': 'fixture', 'language': 'c',
        'document_kind': 'vulnerability-research', 'source_path': 'data/task.json',
        'source_metadata': {},
        'artifacts': [{'path': 'artifacts/note.txt', 'kind': 'signal', 'role': 'signal',
                       'validation': 'source_documented', 'sha256': hashlib.sha256(artifact).hexdigest()}],
        'vulnerability': {'sanitizer': sanitizer, 'class': klass, 'architecture': architecture},
        'operational_stages': [], 'mitigations': [],
    }
    (path / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    (path / 'document.md').write_text(document, encoding='utf-8')


def _metadata(root, *, vul_type='Heap-buffer-overflow READ', images=None):
    images = images if images is not None else {
        'exp.none': 'example:none', 'exp.canary': 'example:canary', 'exp.pie': 'example:pie',
        'exp.relro': 'example:relro', 'exp.hardened': 'example:hardened',
    }
    path = root / 'src/cybergym/task'
    path.mkdir(parents=True)
    record = {'task_id': 'user:fixture', 'entry_name': 'cybergym/arvo_100', 'binary': 'fixture-bin',
              'project_name': 'fixture', 'vul_type': vul_type,
              'env': {'SANITIZER': 'address', 'ARCHITECTURE': 'x86_64', 'FUZZING_LANGUAGE': 'c'},
              'images': images}
    (path / 'metadata.json').write_text(json.dumps([record]), encoding='utf-8')


@pytest.fixture
def inputs(tmp_path):
    bundles, metadata = tmp_path / 'bundles', tmp_path / 'metadata'
    bundles.mkdir()
    _bundle(bundles, 'arvo__100', 'arvo:100')
    _bundle(bundles, 'other', 'oss-fuzz:other', artifact=b'unchanged bytes\x00')
    _metadata(metadata)
    return bundles, metadata


def _adapter(inputs):
    return CyberGymEnrichmentAdapter(*inputs, REVISION, expected_bundles=2, expected_enriched=1)


def test_complete_rebuild_preserves_unmatched_artifact_and_enriches_exact_match(inputs, tmp_path):
    report = _adapter(inputs).build(tmp_path / 'output')
    assert report.bundle_count == 2 and (report.enriched, report.unmatched) == (1, 1)
    assert (report.class_filled, report.sanitizer_filled, report.architecture_filled, report.mitigation_links) == (1, 1, 1, 4)
    matched = load_research_bundle(tmp_path / 'output/arvo__100')
    enrichment = matched.manifest.source_metadata['exploitgym_enrichment']
    assert enrichment['metadata'] == {'path': 'src/cybergym/task/metadata.json',
                                      'sha256': hashlib.sha256((inputs[1] / 'src/cybergym/task/metadata.json').read_bytes()).hexdigest()}
    assert enrichment['normalized'] == {'sanitizer': 'asan', 'class': 'heap-buffer-overflow'}
    assert enrichment['access_direction'] == 'read'
    assert [item['key'] for item in enrichment['mitigation_variants']] == ['exp.canary', 'exp.pie', 'exp.relro', 'exp.hardened']
    assert [item.canonical_name for item in matched.manifest.mitigations] == ['stack canary', 'PIE', 'RELRO', 'hardened build']
    assert all(item.state.value == 'discussed' for item in matched.manifest.mitigations)
    assert (tmp_path / 'output/other/artifacts/note.txt').read_bytes() == b'unchanged bytes\x00'


def test_existing_non_null_vulnerability_facts_win_and_null_architecture_fills(inputs, tmp_path):
    manifest = inputs[0] / 'arvo__100/manifest.json'
    data = json.loads(manifest.read_text())
    data['vulnerability'].update({'sanitizer': 'kasan', 'class': 'existing-class',
                                  'class_provenance': 'source', 'architecture': None})
    manifest.write_text(json.dumps(data), encoding='utf-8')
    report = _adapter(inputs).build(tmp_path / 'output')
    loaded = load_research_bundle(tmp_path / 'output/arvo__100').manifest
    assert (loaded.vulnerability.sanitizer, loaded.vulnerability.vulnerability_class,
            loaded.vulnerability.class_provenance.value, loaded.vulnerability.architecture) == (
                'kasan', 'existing-class', 'source', 'x86_64')
    assert (report.sanitizer_filled, report.class_filled, report.architecture_filled) == (0, 0, 1)


@pytest.mark.parametrize(('raw', 'expected', 'access'), [
    ('Heap-buffer-overflow READ', 'heap-buffer-overflow', 'read'),
    ('Stack-buffer-overflow WRITE', 'stack-buffer-overflow', 'write'),
    ('Global-buffer-overflow', 'global-buffer-overflow', None),
    ('Heap-use-after-free', 'heap-use-after-free', None), ('Heap-double-free', 'double-free', None),
    ('Use-of-uninitialized-value', 'use-of-uninitialized-value', None), ('Wild-address', 'wild-address-access', None),
    ('Index-out-of-bounds', 'out-of-bounds-access', None), ('Negative-size-param', 'negative-size-parameter', None),
    ('Bad-free', 'invalid-free', None), ('Use-after-poison', 'use-after-poison', None),
    ('Null-dereference', 'null-pointer-access', None), ('Bad-cast', 'invalid-cast', None),
    ('Stack-use-after-scope', 'stack-use-after-scope', None), ('Stack-buffer-underflow', 'stack-buffer-underflow', None),
    ('Dynamic-stack-buffer-overflow', 'stack-buffer-overflow', None), ('Container-overflow', 'container-overflow', None),
    ('Memcpy-param-overlap', 'overlapping-memory-copy', None),
    ('Incorrect-function-pointer-type', 'incorrect-function-pointer-type', None), ('Novel Type WRITE', 'novel-type', 'write'),
])
def test_contract_class_normalization(raw, expected, access):
    assert _normal_class(raw) == (expected, access)


@pytest.mark.parametrize('mutation', ['wrong-source', 'mixed-revision', 'duplicate-external'])
def test_collection_identity_guards(inputs, tmp_path, mutation):
    if mutation == 'wrong-source':
        _bundle(inputs[0] / 'bad-parent', 'bad', 'other:bad', source='other')
    elif mutation == 'mixed-revision':
        _bundle(inputs[0] / 'bad-parent', 'bad', 'other:bad', source_revision='c' * 40)
    else:
        _bundle(inputs[0] / 'bad-parent', 'bad', 'arvo:100')
    # Move the newly constructed child to a direct collection child.
    child = inputs[0] / 'bad-parent/bad'
    child.rename(inputs[0] / 'bad')
    (inputs[0] / 'bad-parent').rmdir()
    with pytest.raises(ValueError):
        CyberGymEnrichmentAdapter(*inputs, REVISION, expected_bundles=3, expected_enriched=1).build(tmp_path / 'out')


def test_real_reserved_heading_rejected_but_fenced_text_is_not(inputs, tmp_path):
    (inputs[0] / 'arvo__100/document.md').write_text('```text\n## ExploitGym metadata enrichment\n```\n', encoding='utf-8')
    _adapter(inputs).build(tmp_path / 'allowed')
    (inputs[0] / 'arvo__100/document.md').write_text('## ExploitGym metadata enrichment\n', encoding='utf-8')
    with pytest.raises(ValueError, match='section'):
        _adapter(inputs).build(tmp_path / 'rejected')


def test_create_only_and_reserved_metadata_rejected(inputs, tmp_path):
    output = tmp_path / 'output'
    _adapter(inputs).build(output)
    with pytest.raises(ValueError, match='already exists'):
        _adapter(inputs).build(output)
    manifest = inputs[0] / 'arvo__100/manifest.json'
    data = json.loads(manifest.read_text()); data['source_metadata']['exploitgym_enrichment'] = {}
    manifest.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(ValueError, match='reserved'):
        _adapter(inputs).build(tmp_path / 'reserved')


@pytest.mark.parametrize('mutation', ['missing', 'malformed', 'utf8', 'limit'])
def test_metadata_read_guards(inputs, tmp_path, mutation):
    path = inputs[1] / 'src/cybergym/task/metadata.json'
    if mutation == 'missing':
        path.unlink()
        adapter = _adapter(inputs)
    elif mutation == 'malformed':
        path.write_text('{', encoding='utf-8')
        adapter = _adapter(inputs)
    elif mutation == 'utf8':
        path.write_bytes(b'\xff')
        adapter = _adapter(inputs)
    else:
        adapter = CyberGymEnrichmentAdapter(*inputs, REVISION, expected_bundles=2,
                                            expected_enriched=1, max_metadata_bytes=1)
    with pytest.raises((ValueError, FileNotFoundError)):
        adapter.build(tmp_path / 'out')


def test_extra_mapping_bad_bundle_and_hash_fail_closed(inputs, tmp_path):
    metadata = inputs[1] / 'src/cybergym/task/metadata.json'
    records = json.loads(metadata.read_text())
    extra = dict(records[0]); extra['task_id'] = 'user:extra'; extra['entry_name'] = 'cybergym/arvo_999'
    records.append(extra); metadata.write_text(json.dumps(records), encoding='utf-8')
    with pytest.raises(ValueError, match='absent'):
        CyberGymEnrichmentAdapter(*inputs, REVISION, expected_bundles=2, expected_enriched=2).build(tmp_path / 'extra')
    # Restore a valid mapping, then show the declared source artifact is hash-verified before copy.
    metadata.write_text(json.dumps(records[:1]), encoding='utf-8')
    manifest = inputs[0] / 'other/manifest.json'
    data = json.loads(manifest.read_text()); data['artifacts'][0]['sha256'] = '0' * 64
    manifest.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(ValueError, match='SHA'):
        _adapter(inputs).build(tmp_path / 'hash')


def test_direct_symlink_child_and_external_services_are_not_used(inputs, tmp_path, monkeypatch):
    (inputs[0] / 'bad').symlink_to(inputs[0] / 'other', target_is_directory=True)
    with pytest.raises(ValueError, match='nonsymlink'):
        CyberGymEnrichmentAdapter(*inputs, REVISION, expected_bundles=3, expected_enriched=1).build(tmp_path / 'bad')
    # A separate clean fixture verifies the read path makes no service call.
    clean_bundles, clean_metadata = tmp_path / 'clean-bundles', tmp_path / 'clean-metadata'
    clean_bundles.mkdir(); _bundle(clean_bundles, 'arvo__100', 'arvo:100'); _bundle(clean_bundles, 'other', 'oss-fuzz:other')
    _metadata(clean_metadata)
    def forbidden(*_args, **_kwargs):
        pytest.fail('adapter attempted a network, execution, or database operation')
    monkeypatch.setattr(socket, 'socket', forbidden); monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden); monkeypatch.setattr(os, 'system', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    CyberGymEnrichmentAdapter(clean_bundles, clean_metadata, REVISION, expected_bundles=2,
                              expected_enriched=1).build(tmp_path / 'clean-output')
