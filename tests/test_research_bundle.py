"""Local, disposable fixtures for normalized bundle and snapshot validation."""

from dataclasses import FrozenInstanceError, replace
import errno
import hashlib
import json
from pathlib import Path
import zlib

import pytest

import command_vault.research as research
from command_vault.research import (
    DocumentSnapshot, LoadedResearchArtifact, LoadedResearchBundle,
    load_research_bundle, make_document_snapshot, read_document_snapshot,
)


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path / 'bundle'
    root.mkdir()
    (root / 'notes').mkdir()
    (root / 'notes' / 'second.bin').write_bytes(b'\x00\xffbinary artifact')
    (root / 'first.txt').write_bytes(b'first artifact')
    (root / 'document.md').write_text('# Report\n\nUnicode: café 日本語 🔎\n', encoding='utf-8')
    manifest = {
        'schema_version': 1,
        'source': {'name': 'Example', 'revision': 'rev1', 'upstream_url': 'https://example.org/report'},
        'external_id': 'report-001', 'domain': 'software',
        'artifacts': [
            {'path': 'notes/second.bin', 'kind': 'data', 'role': 'signal'},
            {'path': 'first.txt', 'kind': 'note', 'role': 'procedure',
             'sha256': hashlib.sha256(b'first artifact').hexdigest()},
        ],
    }
    _write_manifest(root, manifest)
    return root, manifest


def _write_manifest(root, manifest):
    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')


def _symlink(link, target, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except NotImplementedError:
        pytest.skip('Platform does not implement symlinks')
    except OSError as error:
        if error.errno in {errno.EPERM, errno.EACCES, errno.ENOTSUP}:
            pytest.skip('Platform or filesystem does not permit symlinks')
        raise


def test_valid_bundle_preserves_manifest_artifact_order_and_hashes(bundle):
    root, manifest = bundle
    loaded = load_research_bundle(root)
    assert isinstance(loaded, LoadedResearchBundle)
    assert loaded.root == root.resolve()
    assert loaded.manifest.model_dump()['external_id'] == manifest['external_id']
    document_bytes = (root / 'document.md').read_bytes()
    assert loaded.document == document_bytes.decode('utf-8')
    assert loaded.document_bytes == len(document_bytes)
    assert loaded.document_sha256 == hashlib.sha256(document_bytes).hexdigest()
    assert isinstance(loaded.artifacts, tuple)
    assert [artifact.path for artifact in loaded.artifacts] == [root / item['path'] for item in manifest['artifacts']]
    for artifact in loaded.artifacts:
        assert isinstance(artifact, LoadedResearchArtifact)
        data = artifact.path.read_bytes()
        assert artifact.sha256 == hashlib.sha256(data).hexdigest()
        assert artifact.size == len(data)
        assert artifact.content == data
        assert hashlib.sha256(artifact.content).hexdigest() == artifact.sha256
    with pytest.raises(FrozenInstanceError):
        loaded.root = Path('changed')
    with pytest.raises(FrozenInstanceError):
        loaded.artifacts[0].size = 0


def test_consumers_use_retained_bytes_instead_of_reopening_provenance_path(bundle):
    loaded = load_research_bundle(bundle[0])
    artifact = loaded.artifacts[0]
    verified_bytes = artifact.content
    artifact.path.write_bytes(b'Replacement content after validation')
    # A consumer uses returned bytes; path is only provenance/display metadata.
    assert artifact.content == verified_bytes
    assert hashlib.sha256(artifact.content).hexdigest() == artifact.sha256
    assert len(artifact.content) == artifact.size
    assert artifact.path.read_bytes() != artifact.content
    with pytest.raises(FrozenInstanceError):
        artifact.content = b'changed'


def test_loader_ignores_undeclared_files_and_symlinks(bundle):
    root, _ = bundle
    (root / 'undeclared.json').write_bytes(b'invalid UTF-8: \xff')
    _symlink(root / 'undeclared-link', root / 'missing')
    assert len(load_research_bundle(root).artifacts) == 2


@pytest.mark.parametrize('location', ['manifest', 'source', 'artifact'])
def test_unknown_manifest_fields_are_rejected_without_echoing_contents(bundle, location):
    root, manifest = bundle
    target = {'manifest': manifest, 'source': manifest['source'], 'artifact': manifest['artifacts'][0]}[location]
    target['unexpected'] = 'private-file-content'
    _write_manifest(root, manifest)
    with pytest.raises(ValueError, match='manifest schema') as error:
        load_research_bundle(root)
    assert 'private-file-content' not in str(error.value)


@pytest.mark.parametrize('name', ['manifest.json', 'document.md'])
def test_metadata_requires_strict_utf8(bundle, name):
    root, _ = bundle
    (root / name).write_bytes(b'private-file-content\xff')
    with pytest.raises(ValueError, match='UTF-8') as error:
        load_research_bundle(root)
    assert 'private-file-content' not in str(error.value)


@pytest.mark.parametrize('data', [b'{invalid private-file-content', b'', b'[]', b'null', b'{"unexpected":NaN}'])
def test_invalid_json_or_manifest_shape(bundle, data):
    root, _ = bundle
    (root / 'manifest.json').write_bytes(data)
    with pytest.raises(ValueError, match='Manifest') as error:
        load_research_bundle(root)
    assert 'private-file-content' not in str(error.value)


@pytest.mark.parametrize('name', ['manifest.json', 'document.md', 'first.txt'])
def test_missing_required_files(bundle, name):
    root, _ = bundle
    (root / name).unlink()
    with pytest.raises(FileNotFoundError, match='Missing'):
        load_research_bundle(root)


@pytest.mark.parametrize('name', ['manifest.json', 'document.md', 'first.txt'])
def test_required_files_cannot_be_directories(bundle, name):
    root, _ = bundle
    (root / name).unlink()
    (root / name).mkdir()
    with pytest.raises(ValueError, match='regular file'):
        load_research_bundle(root)


@pytest.mark.parametrize('name', ['manifest.json', 'document.md', 'first.txt'])
def test_metadata_and_artifact_symlinks_are_rejected_even_inside_root(bundle, name):
    root, _ = bundle
    saved = root / f'saved-{name}'
    (root / name).rename(saved)
    _symlink(root / name, saved)
    with pytest.raises(ValueError, match='symlink'):
        load_research_bundle(root)


@pytest.mark.parametrize('outside', [False, True])
def test_symlinked_artifact_parent_is_rejected(bundle, outside):
    root, _ = bundle
    saved = (root.parent if outside else root) / 'saved-notes'
    (root / 'notes').rename(saved)
    _symlink(root / 'notes', saved, directory=True)
    with pytest.raises(ValueError, match='symlink'):
        load_research_bundle(root)


def test_root_must_exist_and_be_a_directory(tmp_path):
    with pytest.raises(FileNotFoundError, match='root'):
        load_research_bundle(tmp_path / 'missing')
    root = tmp_path / 'file'
    root.write_bytes(b'not a directory')
    with pytest.raises(ValueError, match='directory'):
        load_research_bundle(root)


@pytest.mark.parametrize('outside', [False, True])
def test_bundle_root_itself_cannot_be_a_symlink(bundle, outside):
    root, _ = bundle
    target = root.parent / 'outside-root' if outside else root
    if outside:
        target.mkdir()
    link = root / 'root-link'
    _symlink(link, target, directory=True)
    with pytest.raises(ValueError, match='root must not be a symlink'):
        load_research_bundle(link)


def test_digest_mismatch(bundle):
    root, manifest = bundle
    manifest['artifacts'][0]['sha256'] = '0' * 64
    _write_manifest(root, manifest)
    with pytest.raises(ValueError, match='SHA-256'):
        load_research_bundle(root)


def test_duplicate_artifact_paths(bundle):
    root, manifest = bundle
    manifest['artifacts'].append(dict(manifest['artifacts'][0]))
    _write_manifest(root, manifest)
    with pytest.raises(ValueError, match='duplicate artifact paths'):
        load_research_bundle(root)


@pytest.mark.parametrize('path', ['../outside', '/outside', 'notes/../../outside', 'notes/./second.bin', 'notes\\second.bin'])
def test_traversal_paths_are_rejected_by_manifest_model(bundle, path):
    root, manifest = bundle
    manifest['artifacts'][0]['path'] = path
    _write_manifest(root, manifest)
    with pytest.raises(ValueError, match='manifest schema'):
        load_research_bundle(root)


@pytest.mark.parametrize('limit_name,label', [
    ('max_manifest_bytes', 'Manifest'), ('max_document_bytes', 'Document'),
    ('max_artifact_bytes', 'Artifact'), ('max_total_artifact_bytes', 'Total artifact'),
])
def test_each_size_limit_and_exact_boundary(bundle, limit_name, label):
    root, manifest = bundle
    artifact_sizes = [(root / item['path']).stat().st_size for item in manifest['artifacts']]
    sizes = {
        'max_manifest_bytes': (root / 'manifest.json').stat().st_size,
        'max_document_bytes': (root / 'document.md').stat().st_size,
        'max_artifact_bytes': max(artifact_sizes),
        'max_total_artifact_bytes': sum(artifact_sizes),
    }
    with pytest.raises(ValueError, match=f'{label}.*byte limit'):
        load_research_bundle(root, **{limit_name: sizes[limit_name] - 1})
    assert len(load_research_bundle(root, **{limit_name: sizes[limit_name]}).artifacts) == 2


def test_size_checked_before_file_read(bundle, monkeypatch):
    root, _ = bundle

    def forbidden_read(*args, **kwargs):
        pytest.fail('Oversized manifest was opened for reading')

    monkeypatch.setattr(research.os, 'fdopen', forbidden_read)
    with pytest.raises(ValueError, match='Manifest.*byte limit'):
        load_research_bundle(root, max_manifest_bytes=1)


@pytest.mark.parametrize('limit_name', [
    'max_manifest_bytes', 'max_document_bytes', 'max_artifact_bytes', 'max_total_artifact_bytes',
])
@pytest.mark.parametrize('invalid', [-1, True, 1.5])
def test_invalid_load_limits(bundle, limit_name, invalid):
    with pytest.raises(ValueError, match='nonnegative integer'):
        load_research_bundle(bundle[0], **{limit_name: invalid})


def test_zero_sized_document_and_artifacts(bundle):
    root, manifest = bundle
    (root / 'document.md').write_bytes(b'')
    for item in manifest['artifacts']:
        item.pop('sha256', None)
        (root / item['path']).write_bytes(b'')
    _write_manifest(root, manifest)
    loaded = load_research_bundle(root, max_document_bytes=0, max_artifact_bytes=0, max_total_artifact_bytes=0)
    assert loaded.document == ''
    assert loaded.document_bytes == 0
    assert all(artifact.size == 0 for artifact in loaded.artifacts)


@pytest.mark.parametrize('document', ['', 'A plain report\n', 'café 日本語 🔎\n', '\x00embedded null'])
def test_snapshot_round_trip_and_exact_limit(document):
    snapshot = make_document_snapshot(document)
    data = document.encode('utf-8')
    assert snapshot.compression == 'zlib'
    assert zlib.decompress(snapshot.content_blob) == data
    assert snapshot.content_hash == hashlib.sha256(data).hexdigest()
    assert snapshot.uncompressed_bytes == len(data)
    assert read_document_snapshot(snapshot, max_uncompressed_bytes=len(data)) == document
    with pytest.raises(FrozenInstanceError):
        snapshot.content_hash = 'changed'


@pytest.mark.parametrize('changes,message', [
    ({'content_hash': '0' * 64}, 'SHA-256'),
    ({'uncompressed_bytes': 99}, 'byte count'),
    ({'uncompressed_bytes': -1}, 'nonnegative integer'),
    ({'compression': 'gzip'}, 'compression'),
    ({'content_blob': b'corrupt'}, 'corrupt'),
    ({'content_blob': b''}, 'truncated'),
])
def test_snapshot_integrity_failures(changes, message):
    snapshot = replace(make_document_snapshot('report'), **changes)
    with pytest.raises(ValueError, match=message):
        read_document_snapshot(snapshot)


def test_snapshot_truncated_stream():
    snapshot = make_document_snapshot('report')
    with pytest.raises(ValueError, match='truncated'):
        read_document_snapshot(replace(snapshot, content_blob=snapshot.content_blob[:-1]))


@pytest.mark.parametrize('suffix', [b'trailing', zlib.compress(b'second stream')])
def test_snapshot_trailing_data_and_concatenated_streams(suffix):
    snapshot = make_document_snapshot('report')
    with pytest.raises(ValueError, match='trailing'):
        read_document_snapshot(replace(snapshot, content_blob=snapshot.content_blob + suffix))


def test_snapshot_invalid_utf8_after_valid_hash_and_size():
    data = b'private-file-content\xff'
    snapshot = DocumentSnapshot(zlib.compress(data), 'zlib', hashlib.sha256(data).hexdigest(), len(data))
    with pytest.raises(ValueError, match='UTF-8') as error:
        read_document_snapshot(snapshot)
    assert 'private-file-content' not in str(error.value)


def test_snapshot_reported_size_rejected_before_decompression(monkeypatch):
    snapshot = make_document_snapshot('larger than limit')

    def forbidden_decoder():
        pytest.fail('Oversized declared snapshot reached decompression')

    monkeypatch.setattr(research.zlib, 'decompressobj', forbidden_decoder)
    with pytest.raises(ValueError, match='byte limit'):
        read_document_snapshot(snapshot, max_uncompressed_bytes=1)


def test_snapshot_forged_size_cannot_bypass_bounded_decompression(monkeypatch):
    snapshot = replace(make_document_snapshot('a' * 1_000_000), uncompressed_bytes=1)
    original = zlib.decompressobj
    limits = []

    class ObservedDecoder:
        def __init__(self):
            self.decoder = original()

        def decompress(self, data, max_length):
            limits.append(max_length)
            result = self.decoder.decompress(data, max_length)
            assert len(result) <= 257
            return result

    monkeypatch.setattr(research.zlib, 'decompressobj', ObservedDecoder)
    with pytest.raises(ValueError, match='byte limit'):
        read_document_snapshot(snapshot, max_uncompressed_bytes=256)
    assert limits == [257]


@pytest.mark.parametrize('limit', [-1, True, 1.5])
def test_invalid_snapshot_limits(limit):
    with pytest.raises(ValueError, match='nonnegative integer'):
        read_document_snapshot(make_document_snapshot(''), max_uncompressed_bytes=limit)


def test_snapshot_make_rejects_invalid_unicode():
    with pytest.raises(ValueError, match='UTF-8'):
        make_document_snapshot('\ud800')
