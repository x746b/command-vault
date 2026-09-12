"""Load declared research bundle files and encode bounded document snapshots.

Artifact bytes are bounded, hashed, and returned; this module never executes or
imports content.
"""

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Literal
import zlib

from pydantic import ValidationError

from .models import ResearchManifest


@dataclass(frozen=True)
class LoadedResearchArtifact:
    """Verified bytes for consumers; path is provenance/display only.

    Consumers must use content instead of reopening path, which may change
    after bundle loading has completed.
    """

    path: Path
    sha256: str
    size: int
    content: bytes


@dataclass(frozen=True)
class LoadedResearchBundle:
    root: Path
    manifest: ResearchManifest
    document: str
    document_sha256: str
    document_bytes: int
    artifacts: tuple[LoadedResearchArtifact, ...]


@dataclass(frozen=True)
class DocumentSnapshot:
    content_blob: bytes
    compression: Literal['zlib']
    content_hash: str
    uncompressed_bytes: int


def _validate_limit(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f'{name} must be a nonnegative integer')


def _read_bundle_file(
    root: Path, root_fd: int, relative: str, *, limit: int, label: str,
) -> bytes:
    """Open each declared component relative to an anchored directory descriptor.

    O_NOFOLLOW closes symlink-swap races after the explicit checks. O_NONBLOCK
    avoids blocking if a file is replaced by a FIFO before it can be inspected.
    """
    try:
        with ExitStack() as stack:
            directory_fd = root_fd
            parts = Path(relative).parts
            for index, part in enumerate(parts):
                last = index == len(parts) - 1
                info = os.stat(part, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    raise ValueError(f'{label} must not contain symlinks')
                required_type = stat.S_ISREG if last else stat.S_ISDIR
                if not required_type(info.st_mode):
                    raise ValueError(f'{label} must be a regular file with directory parents')
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if not last:
                    flags |= os.O_DIRECTORY
                opened_fd = os.open(part, flags, dir_fd=directory_fd)
                stack.callback(os.close, opened_fd)
                directory_fd = opened_fd
            info = os.fstat(opened_fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f'{label} must be a regular file')
            if not (root / relative).resolve(strict=True).is_relative_to(root):
                raise ValueError(f'{label} must stay inside the bundle root')
            if info.st_size > limit:
                raise ValueError(f'{label} exceeds its byte limit')
            with os.fdopen(os.dup(opened_fd), 'rb') as source:
                data = source.read(limit + 1)
            if len(data) > limit:
                raise ValueError(f'{label} exceeds its byte limit')
            return data
    except FileNotFoundError:
        raise FileNotFoundError(f'Missing {label} file or parent directory') from None
    except (OSError, RuntimeError):
        raise ValueError(f'Cannot safely read {label} as a regular nonsymlink file') from None


def _decode_utf8(data: bytes, label: str) -> str:
    try:
        return data.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise ValueError(f'{label} must contain valid UTF-8') from None


def _reject_json_constant(_value: str):
    raise ValueError('Manifest must contain valid JSON')


def load_research_bundle(
    root: str | Path, *, max_manifest_bytes: int = 1_048_576,
    max_document_bytes: int = 8_388_608, max_artifact_bytes: int = 8_388_608,
    max_total_artifact_bytes: int = 33_554_432,
) -> LoadedResearchBundle:
    for name, limit in (
        ('max_manifest_bytes', max_manifest_bytes), ('max_document_bytes', max_document_bytes),
        ('max_artifact_bytes', max_artifact_bytes), ('max_total_artifact_bytes', max_total_artifact_bytes),
    ):
        _validate_limit(limit, name)
    try:
        root_path = Path(root)
        if root_path.is_symlink():
            raise ValueError('Research bundle root must not be a symlink')
        resolved_root = root_path.resolve(strict=True)
    except FileNotFoundError:
        raise FileNotFoundError('Research bundle root does not exist') from None
    except (OSError, RuntimeError):
        raise ValueError('Cannot resolve research bundle root') from None
    if not resolved_root.is_dir():
        raise ValueError('Research bundle root must be a directory')
    try:
        root_fd = os.open(resolved_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ValueError('Cannot safely open research bundle root directory') from None
    try:
        manifest_bytes = _read_bundle_file(
            resolved_root, root_fd, 'manifest.json', limit=max_manifest_bytes, label='Manifest',
        )
        manifest_text = _decode_utf8(manifest_bytes, 'Manifest')
        try:
            data = json.loads(manifest_text, parse_constant=_reject_json_constant)
        except (ValueError, RecursionError):
            raise ValueError('Manifest must contain valid JSON') from None
        try:
            manifest = ResearchManifest.model_validate(data)
        except ValidationError:
            # ValidationError includes rejected values; avoid disclosing file content.
            raise ValueError('Manifest does not satisfy the research manifest schema') from None
        paths = [artifact.path for artifact in manifest.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError('Manifest contains duplicate artifact paths')
        document_data = _read_bundle_file(
            resolved_root, root_fd, 'document.md', limit=max_document_bytes, label='Document',
        )
        document = _decode_utf8(document_data, 'Document')
        artifacts = []
        total_size = 0
        for artifact in manifest.artifacts:
            remaining = max_total_artifact_bytes - total_size
            artifact_data = _read_bundle_file(
                resolved_root, root_fd, artifact.path,
                limit=min(max_artifact_bytes, remaining),
                label='Artifact' if max_artifact_bytes <= remaining else 'Total artifact data',
            )
            digest = hashlib.sha256(artifact_data).hexdigest()
            if artifact.sha256 is not None and artifact.sha256 != digest:
                raise ValueError('Artifact SHA-256 does not match the manifest')
            total_size += len(artifact_data)
            artifacts.append(LoadedResearchArtifact(
                path=resolved_root / artifact.path, sha256=digest,
                size=len(artifact_data), content=artifact_data,
            ))
        return LoadedResearchBundle(
            root=resolved_root, manifest=manifest, document=document,
            document_sha256=hashlib.sha256(document_data).hexdigest(),
            document_bytes=len(document_data), artifacts=tuple(artifacts),
        )
    finally:
        os.close(root_fd)


def make_document_snapshot(document: str) -> DocumentSnapshot:
    if not isinstance(document, str):
        raise ValueError('Document must be a string')
    try:
        data = document.encode('utf-8', errors='strict')
    except UnicodeEncodeError:
        raise ValueError('Document must encode as valid UTF-8') from None
    return DocumentSnapshot(zlib.compress(data), 'zlib', hashlib.sha256(data).hexdigest(), len(data))


def read_document_snapshot(
    snapshot: DocumentSnapshot, *, max_uncompressed_bytes: int = 8_388_608,
) -> str:
    _validate_limit(max_uncompressed_bytes, 'max_uncompressed_bytes')
    if snapshot.compression != 'zlib':
        raise ValueError('Snapshot compression must be zlib')
    _validate_limit(snapshot.uncompressed_bytes, 'Snapshot uncompressed_bytes')
    if snapshot.uncompressed_bytes > max_uncompressed_bytes:
        raise ValueError('Snapshot exceeds the uncompressed byte limit')
    if not isinstance(snapshot.content_blob, bytes):
        raise ValueError('Snapshot content_blob must be bytes')
    decoder = zlib.decompressobj()
    try:
        data = decoder.decompress(snapshot.content_blob, max_uncompressed_bytes + 1)
    except zlib.error:
        raise ValueError('Snapshot contains corrupt zlib data') from None
    if len(data) > max_uncompressed_bytes:
        raise ValueError('Snapshot exceeds the uncompressed byte limit')
    if not decoder.eof:
        raise ValueError('Snapshot contains truncated zlib data')
    if decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('Snapshot contains trailing compressed data')
    if len(data) != snapshot.uncompressed_bytes:
        raise ValueError('Snapshot uncompressed byte count does not match')
    if hashlib.sha256(data).hexdigest() != snapshot.content_hash:
        raise ValueError('Snapshot SHA-256 does not match')
    return _decode_utf8(data, 'Snapshot')
