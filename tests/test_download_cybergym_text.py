"""CyberGym acquisition tests use local pointers and mocked urllib responses only."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import urllib.error

import pytest


REVISION = '1' * 40


@pytest.fixture
def downloader():
    path = Path(__file__).resolve().parents[1] / 'scripts/download_cybergym_text.py'
    spec = importlib.util.spec_from_file_location('cybergym_downloader_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pointers(tmp_path):
    root = tmp_path / 'pointers'
    root.mkdir()
    records = [{'task_id': 'oss-fuzz:20', 'difficulty': {'path': '/never/use/archive.tar.gz'}},
               {'task_id': 'arvo:10', 'difficulty': {'path': '../../ignored'}}]
    (root / 'tasks.json').write_text(json.dumps(records))
    payloads = {}
    for record in records:
        namespace, task = record['task_id'].split(':')
        directory = root / 'data' / namespace / task
        directory.mkdir(parents=True)
        for filename in ('description.txt', 'error.txt', 'patch.diff'):
            content = f'benign {record["task_id"]} {filename}\n'.encode()
            digest = hashlib.sha256(content).hexdigest()
            payloads[digest] = content
            (directory / filename).write_text(f'version https://git-lfs.github.com/spec/v1\noid sha256:{digest}\nsize {len(content)}\n')
        (directory / 'archive.tar.gz').write_bytes(b'ignored archive')
    return root, tmp_path / 'output', payloads


class FakeOpener:
    def __init__(self, payloads, mutate_batch=None, mutate_download=None):
        self.payloads = payloads
        self.requests = []
        self.mutate_batch = mutate_batch
        self.mutate_download = mutate_download

    def open(self, request, timeout):
        self.requests.append(request)
        assert timeout == 60
        if request.get_method() == 'POST':
            data = json.loads(request.data)
            assert data['operation'] == 'download' and data['transfers'] == ['basic']
            response = {'objects': [{**item, 'actions': {'download': {
                'href': 'https://objects.example.org/' + item['oid'] + '?signed=private-signature',
                'header': {'X-Test-Header': 'safe', 'Authorization': 'Bearer private-token'},
            }}} for item in data['objects']]}
            if self.mutate_batch:
                self.mutate_batch(response)
            return io.BytesIO(json.dumps(response).encode())
        digest = request.full_url.split('/')[-1].split('?')[0]
        assert request.get_header('X-test-header') == 'safe'
        data = self.payloads[digest]
        if self.mutate_download:
            data = self.mutate_download(data)
        return io.BytesIO(data)


def install_opener(monkeypatch, downloader, payloads, **kwargs):
    opener = FakeOpener(payloads, **kwargs)
    monkeypatch.setattr(downloader.urllib.request, 'build_opener', lambda *args: opener)
    return opener


def test_selection_batches_download_hashes_and_manifest_exclude_archives(downloader, pointers, monkeypatch):
    root, output, payloads = pointers
    opener = install_opener(monkeypatch, downloader, payloads)
    report = downloader.build(root, output, REVISION, batch_size=2)
    assert report == {'selected_tasks': 2, 'objects': 6, 'bytes': sum(map(len, payloads.values())),
                      'downloaded': 6, 'skipped': 0, 'revision': REVISION}
    posts = [request for request in opener.requests if request.get_method() == 'POST']
    assert len(posts) == 3
    assert all(request.full_url == downloader.BATCH_URL for request in posts)
    manifest = json.loads((output / 'acquisition-manifest.json').read_text())
    assert manifest['dataset_url'] == downloader.DATASET_URL and manifest['revision'] == REVISION
    assert [item['path'] for item in manifest['objects']] == [
        f'data/{namespace}/{task}/{filename}' for namespace, task in [('arvo', '10'), ('oss-fuzz', '20')]
        for filename in downloader.TEXT_FILES
    ]
    for item in manifest['objects']:
        assert (output / item['path']).read_bytes() == payloads[item['oid']]
        assert (output / item['path']).stat().st_size == item['size']
    assert (output / 'tasks.json').read_bytes() == (root / 'tasks.json').read_bytes()
    assert not list(output.rglob('*.gz')) and not list(output.rglob('*.tmp'))
    metadata = json.dumps(manifest) + json.dumps(report)
    assert 'private-' not in metadata and 'objects.example.org' not in metadata
    assert str(root.parent) not in metadata


def test_resume_skips_only_verified_objects_without_network(downloader, pointers, monkeypatch):
    root, output, payloads = pointers
    install_opener(monkeypatch, downloader, payloads)
    downloader.build(root, output, REVISION)
    opener = install_opener(monkeypatch, downloader, payloads)
    report = downloader.build(root, output, REVISION)
    assert report['downloaded'] == 0 and report['skipped'] == 6
    assert opener.requests == []


def test_dry_run_limits_tasks_without_network_or_output(downloader, pointers, monkeypatch):
    root, output, _ = pointers
    monkeypatch.setattr(downloader.urllib.request, 'build_opener', lambda *args: pytest.fail('Network setup during dry run'))
    report = downloader.build(root, output, REVISION, limit=1, dry_run=True)
    assert report['selected_tasks'] == 1 and report['objects'] == 3
    assert report['downloaded'] == report['skipped'] == 0
    assert not output.exists()


@pytest.mark.parametrize('data', [b'not JSON', b'{}', b'\xff', b'[{"task_id":"arvo:10","x":NaN}]',
                                   b'[{"task_id":"arvo:10","x":1e999}]', b'[{"task_id":"arvo:../x"}]',
                                   b'[{"task_id":"other:10"}]', b'[{"task_id":"arvo:10"},{"task_id":"arvo:10"}]'])
def test_invalid_task_metadata_is_rejected(downloader, pointers, data):
    root, output, _ = pointers
    (root / 'tasks.json').write_bytes(data)
    with pytest.raises(ValueError):
        downloader.build(root, output, REVISION, dry_run=True)
    assert not output.exists()


@pytest.mark.parametrize('pointer', [b'ordinary text', b'version wrong\noid sha256:' + b'a' * 64 + b'\nsize 1\n',
                                      b'version https://git-lfs.github.com/spec/v1\noid sha256:' + b'A' * 64 + b'\nsize 1\n',
                                      b'version https://git-lfs.github.com/spec/v1\noid sha256:' + b'a' * 64 + b'\nsize -1\n'])
def test_invalid_lfs_pointers_are_rejected(downloader, pointers, pointer):
    root, output, _ = pointers
    (root / 'data/arvo/10/description.txt').write_bytes(pointer)
    with pytest.raises(ValueError, match='Git-LFS'):
        downloader.build(root, output, REVISION, dry_run=True)


@pytest.mark.parametrize('location', ['root', 'tasks', 'pointer', 'ancestor', 'output', 'output_ancestor'])
def test_symlink_sources_and_outputs_are_rejected(downloader, pointers, monkeypatch, location):
    root, output, payloads = pointers
    install_opener(monkeypatch, downloader, payloads)
    if location == 'root':
        link = root.parent / 'root-link'
        link.symlink_to(root, target_is_directory=True)
        root = link
    elif location in ('tasks', 'pointer'):
        path = root / ('tasks.json' if location == 'tasks' else 'data/arvo/10/description.txt')
        saved = path.with_name(path.name + '.saved')
        path.rename(saved)
        path.symlink_to(saved)
    elif location == 'ancestor':
        directory = root / 'data/arvo'
        saved = root / 'arvo-saved'
        directory.rename(saved)
        directory.symlink_to(saved, target_is_directory=True)
    else:
        real = root.parent / 'real-output'
        real.mkdir()
        output.symlink_to(real, target_is_directory=True)
        if location == 'output_ancestor':
            output = output / 'nested'
    with pytest.raises((ValueError, OSError)):
        downloader.build(root, output, REVISION)


@pytest.mark.parametrize('fault', ['hash', 'short', 'long'])
def test_bad_downloads_fail_without_publishing_and_clean_own_temp(downloader, pointers, monkeypatch, fault):
    root, output, payloads = pointers
    mutate = {'hash': lambda data: b'x' * len(data), 'short': lambda data: data[:-1], 'long': lambda data: data + b'x'}[fault]
    install_opener(monkeypatch, downloader, payloads, mutate_download=mutate)
    with pytest.raises(ValueError, match='declared size'):
        downloader.build(root, output, REVISION)
    assert not (output / 'data/arvo/10/description.txt').exists()
    assert not list(output.rglob('*.tmp'))


@pytest.mark.parametrize('fault', ['http', 'userinfo', 'oid', 'size', 'header', 'inventory'])
def test_bad_batch_actions_are_rejected_without_download(downloader, pointers, monkeypatch, fault):
    root, output, payloads = pointers

    def mutate(response):
        item = response['objects'][0]
        if fault == 'http':
            item['actions']['download']['href'] = 'http://example.org/private'
        elif fault == 'userinfo':
            item['actions']['download']['href'] = 'https://user:private@example.org/object'
        elif fault == 'oid':
            item['oid'] = '0' * 64
        elif fault == 'size':
            item['size'] += 1
        elif fault == 'header':
            item['actions']['download']['header'] = {'Authorization': 'private\r\nInjected: value'}
        else:
            response['objects'].pop()

    opener = install_opener(monkeypatch, downloader, payloads, mutate_batch=mutate)
    with pytest.raises(ValueError) as error:
        downloader.build(root, output, REVISION)
    assert 'private' not in str(error.value)
    assert all(request.get_method() == 'POST' for request in opener.requests)


def test_existing_mismatch_is_never_overwritten(downloader, pointers, monkeypatch):
    root, output, payloads = pointers
    target = output / 'data/arvo/10/description.txt'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'existing data')
    opener = install_opener(monkeypatch, downloader, payloads)
    with pytest.raises(ValueError, match='Existing output'):
        downloader.build(root, output, REVISION)
    assert target.read_bytes() == b'existing data'
    assert opener.requests == []


def test_atomic_publication_race_preserves_competitor_and_cleans_own_temp(downloader, pointers, monkeypatch):
    root, output, payloads = pointers
    install_opener(monkeypatch, downloader, payloads)
    original = os.link

    def racing(source, destination, **kwargs):
        if Path(destination).name == 'description.txt':
            Path(destination).write_bytes(b'concurrent data')
        return original(source, destination, **kwargs)

    monkeypatch.setattr(downloader.os, 'link', racing)
    with pytest.raises(FileExistsError):
        downloader.build(root, output, REVISION)
    assert (output / 'data/arvo/10/description.txt').read_bytes() == b'concurrent data'
    assert not list(output.rglob('*.tmp'))


def test_retry_after_wait_is_capped_and_retries_are_bounded(downloader, pointers, monkeypatch):
    root, output, _ = pointers
    attempts = []
    waits = []

    class Unavailable:
        def open(self, request, timeout):
            attempts.append(request)
            raise urllib.error.HTTPError('https://example.org/private-url', 429, 'private error', {'Retry-After': '9999'}, io.BytesIO(b'private response'))

    monkeypatch.setattr(downloader.urllib.request, 'build_opener', lambda *args: Unavailable())
    monkeypatch.setattr(downloader.time, 'sleep', waits.append)
    with pytest.raises(ValueError, match='HTTP acquisition failed') as error:
        downloader.build(root, output, REVISION)
    assert len(attempts) == 4 and waits == [60.0] * 3
    assert 'private' not in str(error.value)


def test_cli_json_and_content_free_error(downloader, pointers, monkeypatch, capsys):
    root, output, payloads = pointers
    install_opener(monkeypatch, downloader, payloads)
    args = ['--pointer-root', str(root), '--output', str(output), '--revision', REVISION, '--limit', '1']
    report = downloader.main(args)
    assert json.loads(capsys.readouterr().out) == report
    (root / 'tasks.json').write_text('private invalid JSON')
    with pytest.raises(SystemExit) as error:
        downloader.main(args)
    assert 'private' not in str(error.value) and str(root) not in str(error.value)
    assert capsys.readouterr().out == ''


@pytest.mark.parametrize('options', [{'revision': 'A' * 40}, {'limit': 0}, {'batch_size': 0}, {'batch_size': 101}])
def test_invalid_options_are_rejected_before_output(downloader, pointers, options):
    root, output, _ = pointers
    with pytest.raises(ValueError):
        downloader.build(root, output, **{'revision': REVISION, **options})
    assert not output.exists()


def guard_file_reads(monkeypatch, downloader, target, *, reject=False):
    """Observe only the chosen inode, including reads through descriptor streams."""
    identity = (target.stat().st_dev, target.stat().st_ino)
    original = os.fdopen
    reads = []

    class Guarded:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, size=-1):
            if reject:
                pytest.fail('Oversized file was read before size rejection')
            assert 0 <= size <= 65_536, 'Existing output used an unbounded or oversized read'
            reads.append(size)
            return self.stream.read(size)

    def observed(descriptor, *args, **kwargs):
        info = os.fstat(descriptor)
        stream = original(descriptor, *args, **kwargs)
        return Guarded(stream) if (info.st_dev, info.st_ino) == identity else stream

    monkeypatch.setattr(downloader.os, 'fdopen', observed)
    return reads


@pytest.mark.parametrize('kind', ['tasks', 'pointer', 'existing'])
def test_oversized_files_are_rejected_before_any_read(downloader, pointers, monkeypatch, kind):
    root, output, _ = pointers
    if kind == 'tasks':
        target = root / 'tasks.json'
        size = 16 * 1024 * 1024 + 1
    elif kind == 'pointer':
        target = root / 'data/arvo/10/description.txt'
        size = 513
    else:
        target = output / 'data/arvo/10/description.txt'
        target.parent.mkdir(parents=True)
        size = 1024 * 1024 * 1024
    with target.open('wb') as stream:
        stream.truncate(size)
    guard_file_reads(monkeypatch, downloader, target, reject=True)
    monkeypatch.setattr(downloader.urllib.request, 'build_opener', lambda *args: pytest.fail('Unexpected network setup'))
    with pytest.raises(ValueError, match='declared size' if kind == 'existing' else 'byte limit'):
        downloader.build(root, output, REVISION, dry_run=kind != 'existing')
    assert target.stat().st_size == size


def test_existing_objects_are_hashed_in_bounded_chunks(downloader, tmp_path, monkeypatch):
    target = tmp_path / 'existing.txt'
    content = b'benign text ' * 30_000
    target.write_bytes(content)
    reads = guard_file_reads(monkeypatch, downloader, target)
    assert downloader._existing_matches(target, len(content), hashlib.sha256(content).hexdigest())
    assert len(reads) > 2 and max(reads) <= 65_536 and reads[-1] == 1


def test_bounded_input_read_rejects_growth_after_stat(downloader, tmp_path, monkeypatch):
    target = tmp_path / 'pointer.txt'
    target.write_bytes(b'x' * 512)
    original = os.fstat
    grown = False

    def grow_after_stat(descriptor):
        nonlocal grown
        info = original(descriptor)
        if not grown and info.st_ino == target.stat().st_ino:
            grown = True
            with target.open('ab') as stream:
                stream.write(b'overflow')
        return info

    monkeypatch.setattr(downloader.os, 'fstat', grow_after_stat)
    with pytest.raises(ValueError, match='byte limit'):
        downloader._regular_bytes(target, max_bytes=512)
