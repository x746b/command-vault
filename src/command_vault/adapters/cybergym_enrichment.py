"""Offline, create-only ExploitGym provenance enrichment for CyberGym bundles.

The adapter deliberately reads one ExploitGym JSON file and the declared files
of an already-normalized bundle collection.  In particular, image references
are data, not inputs: no task tree, container image, executable, database, or
network service is opened.
"""

from collections import Counter
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from pydantic import ValidationError

from ..models import ResearchManifest
from ..research import _decode_utf8, _read_bundle_file, _validate_limit, load_research_bundle
from ..security import SecurityFilter
from .exploitgym import _directory_root, _headings, _invalid_constant, _json_object, _publish, _validate_json


_METADATA = 'src/cybergym/task/metadata.json'
_REPOSITORY_URL = 'https://github.com/sunblaze-ucb/exploitgym'
_ENTRY = re.compile(r'cybergym/(arvo|oss-fuzz)_([A-Za-z0-9][A-Za-z0-9._-]*)\Z')
_REVISION = re.compile(r'[0-9a-f]{40}\Z')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_SECTION = 'ExploitGym metadata enrichment'
_MITIGATIONS = (
    ('exp.canary', 'stack canary'), ('exp.pie', 'PIE'),
    ('exp.relro', 'RELRO'), ('exp.hardened', 'hardened build'),
)
_SANITIZERS = {'address': 'asan', 'memory': 'msan', 'undefined': 'ubsan'}
_CLASSES = {
    'Heap-buffer-overflow': 'heap-buffer-overflow',
    'Stack-buffer-overflow': 'stack-buffer-overflow',
    'Global-buffer-overflow': 'global-buffer-overflow',
    'Heap-use-after-free': 'heap-use-after-free',
    'Heap-double-free': 'double-free',
    'Use-of-uninitialized-value': 'use-of-uninitialized-value',
    'Wild-address': 'wild-address-access',
    'Index-out-of-bounds': 'out-of-bounds-access',
    'Negative-size-param': 'negative-size-parameter',
    'Bad-free': 'invalid-free',
    'Use-after-poison': 'use-after-poison',
    'Null-dereference': 'null-pointer-access',
    'Bad-cast': 'invalid-cast',
    'Stack-use-after-scope': 'stack-use-after-scope',
    'Stack-buffer-underflow': 'stack-buffer-underflow',
    'Dynamic-stack-buffer-overflow': 'stack-buffer-overflow',
    'Container-overflow': 'container-overflow',
    'Memcpy-param-overlap': 'overlapping-memory-copy',
    'Incorrect-function-pointer-type': 'incorrect-function-pointer-type',
}


@dataclass(frozen=True)
class CyberGymEnrichmentReport:
    """Aggregate-only result; paths and source strings are intentionally absent."""

    bundle_count: int
    enriched: int
    unmatched: int
    class_filled: int
    sanitizer_filled: int
    architecture_filled: int
    mitigation_links: int
    redactions_by_type: dict[str, int]


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _normal_class(raw):
    """Return only the narrow source-label normalization allowed by the contract."""
    if not isinstance(raw, str) or not raw.strip():
        return None, None
    value = raw.strip()
    access = None
    suffix = re.search(r'\s+(READ|WRITE)\Z', value)
    if suffix:
        access = suffix[1].lower()
        value = value[:suffix.start()].rstrip()
    if value in _CLASSES:
        return _CLASSES[value], access
    # This is a representation of an unknown source label, not a conclusion.
    return re.sub(r'[^a-z0-9]+', '-', value.lower()).strip('-') or None, access


def _normal_sanitizer(raw):
    return _SANITIZERS.get(raw.strip().lower()) if isinstance(raw, str) else None


def _safe_root(path, *, create=False):
    """Use the reviewed directory checks without allowing an output symlink."""
    return _directory_root(path, create=create)


class CyberGymEnrichmentAdapter:
    """Rebuild a complete collection, adding deterministic metadata to matches only."""

    def __init__(self, bundles_root, metadata_root, revision, security_filter=None, *,
                 expected_bundles=1507, expected_enriched=484,
                 max_metadata_bytes=4_194_304):
        if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
            raise ValueError('Revision must be exactly 40 lowercase hexadecimal characters')
        for value, name in ((expected_bundles, 'expected_bundles'),
                            (expected_enriched, 'expected_enriched'),
                            (max_metadata_bytes, 'max_metadata_bytes')):
            _validate_limit(value, name)
        self.bundles_root = _safe_root(bundles_root)
        self.metadata_root = _safe_root(metadata_root)
        self.revision = revision
        self.expected_bundles = expected_bundles
        self.expected_enriched = expected_enriched
        self.max_metadata_bytes = max_metadata_bytes
        self.security_filter = copy.copy(security_filter if security_filter is not None else SecurityFilter())
        self.security_filter.redaction_log = []
        self._redactions = Counter()
        self.security_filter._log_redaction = self._record_redaction

    def _record_redaction(self, _source, kind, _detail):
        self._redactions[kind if isinstance(kind, str) and re.fullmatch(r'[a-z_]+', kind) else 'other'] += 1

    def _sanitize(self, value):
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError('Selected ExploitGym metadata strings must be strings or null')
        return self.security_filter.sanitize_text(value, source_file='ExploitGym metadata')

    def _metadata(self):
        root_fd = os.open(self.metadata_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            raw = _read_bundle_file(self.metadata_root, root_fd, _METADATA,
                                    limit=self.max_metadata_bytes, label='ExploitGym metadata')
        finally:
            os.close(root_fd)
        try:
            records = json.loads(_decode_utf8(raw, 'ExploitGym metadata'), object_pairs_hook=_json_object,
                                 parse_constant=_invalid_constant)
            _validate_json(records)
        except (ValueError, RecursionError):
            raise ValueError('ExploitGym metadata must contain valid finite UTF-8 JSON') from None
        if not isinstance(records, list):
            raise ValueError('ExploitGym metadata must be a list')
        selected, identities = {}, set()
        for record in records:
            if not isinstance(record, dict):
                raise ValueError('ExploitGym metadata records must be objects')
            entry = record.get('entry_name')
            match = _ENTRY.fullmatch(entry) if isinstance(entry, str) else None
            if not match:
                continue
            identity = f'{match[1]}:{match[2]}'
            if identity in identities:
                raise ValueError('ExploitGym metadata contains duplicate CyberGym mapping')
            identities.add(identity)
            task = record.get('task_id')
            if not isinstance(task, str) or not task or _CONTROL.search(task):
                raise ValueError('Selected ExploitGym task_id must be a safe nonempty string')
            env, images = record.get('env', {}), record.get('images', {})
            if not isinstance(env, dict) or not isinstance(images, dict):
                raise ValueError('Selected ExploitGym env and images must be objects')
            for name, value in env.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise ValueError('Selected ExploitGym env must map strings to strings')
            for name, value in images.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise ValueError('Selected ExploitGym images must map strings to strings')
            for field in ('binary', 'project_name', 'vul_type'):
                if field in record and record[field] is not None and not isinstance(record[field], str):
                    raise ValueError('Selected ExploitGym fields must be strings or null')
            selected[identity] = record
        if len(selected) != self.expected_enriched:
            raise ValueError('ExploitGym metadata selected count does not match the fixed contract')
        return selected, {'path': _METADATA, 'sha256': _sha256(raw)}

    def _bundles(self):
        """Load every direct child once, rejecting incidental files and aliases."""
        try:
            with os.scandir(self.bundles_root) as entries:
                entries = list(entries)
        except OSError:
            raise ValueError('Cannot enumerate normalized CyberGym collection') from None
        if len(entries) != self.expected_bundles:
            raise ValueError('Normalized CyberGym bundle count does not match the fixed contract')
        loaded, external_ids, names, source_revisions = [], set(), set(), set()
        for entry in sorted(entries, key=lambda item: item.name):
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError:
                raise ValueError('Cannot inspect normalized CyberGym bundle child') from None
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise ValueError('Normalized CyberGym collection must contain direct nonsymlink bundle directories only')
            if entry.name in names:
                raise ValueError('Normalized CyberGym bundle names must be unique')
            names.add(entry.name)
            bundle = load_research_bundle(entry.path)
            if bundle.manifest.source.name != 'cybergym':
                raise ValueError('Every normalized collection bundle must retain source cybergym')
            if 'exploitgym_enrichment' in bundle.manifest.source_metadata:
                raise ValueError('Input bundle already contains reserved exploitgym_enrichment metadata')
            source_revisions.add(bundle.manifest.source.revision)
            if bundle.manifest.external_id in external_ids:
                raise ValueError('Normalized CyberGym collection external IDs must be unique')
            external_ids.add(bundle.manifest.external_id)
            loaded.append((entry.name, bundle))
        if len(source_revisions) != 1:
            raise ValueError('Normalized CyberGym collection must retain one source revision')
        return loaded

    def _enrichment(self, record, metadata_fact):
        env, images = record['env'], record['images']
        raw_sanitizer = self._sanitize(env.get('SANITIZER'))
        raw_type = self._sanitize(record.get('vul_type'))
        raw_architecture = self._sanitize(env.get('ARCHITECTURE'))
        raw_language = self._sanitize(env.get('FUZZING_LANGUAGE'))
        all_images = [
            {'key': self._sanitize(key), 'ref': self._sanitize(value)}
            for key, value in sorted(images.items())
        ]
        variants = [
            {'key': key, 'ref': self._sanitize(images[key])}
            for key, _name in _MITIGATIONS if key in images
        ]
        normalized_class, access = _normal_class(raw_type)
        return {
            'source': 'exploitgym', 'revision': self.revision,
            'url': f'{_REPOSITORY_URL}/blob/{self.revision}/{_METADATA}',
            'metadata': metadata_fact,
            'task_id': self._sanitize(record['task_id']),
            'entry_id': self._sanitize(record['entry_name']),
            'project': self._sanitize(record.get('project_name')),
            'binary': self._sanitize(record.get('binary')),
            'raw': {'sanitizer': raw_sanitizer, 'vul_type': raw_type,
                    'architecture': raw_architecture, 'language': raw_language},
            'image_variants': all_images,
            'normalized': {'sanitizer': _normal_sanitizer(raw_sanitizer), 'class': normalized_class},
            'access_direction': access,
            'mitigation_variants': variants,
            'temporal_status': 'unknown',
        }

    @staticmethod
    def _heading_exists(document):
        return any(heading.strip().rstrip('#').strip() == _SECTION for heading in _headings(document))

    def _changed(self, bundle, record, metadata_fact):
        data = bundle.manifest.model_dump(mode='json', by_alias=True)
        if 'exploitgym_enrichment' in data['source_metadata']:
            raise ValueError('Input bundle already contains reserved exploitgym_enrichment metadata')
        if not isinstance(data.get('vulnerability'), dict):
            raise ValueError('Matched CyberGym bundle must retain its existing vulnerability profile')
        enrichment = self._enrichment(record, metadata_fact)
        vulnerability = data['vulnerability']
        counters = Counter()
        for field, source, count_name in (
            ('sanitizer', enrichment['normalized']['sanitizer'], 'sanitizer_filled'),
            ('class', enrichment['normalized']['class'], 'class_filled'),
            ('architecture', enrichment['raw']['architecture'], 'architecture_filled'),
        ):
            # None is the only fillable state; blank source labels remain no-op.
            if vulnerability.get(field) is None and source is not None:
                vulnerability[field] = source
                counters[count_name] += 1
                if field == 'class':
                    vulnerability['class_provenance'] = 'deterministic'
        existing = {' '.join(item['canonical_name'].split()).casefold() for item in data['mitigations']}
        for key, name in _MITIGATIONS:
            if key in record['images'] and ' '.join(name.split()).casefold() not in existing:
                data['mitigations'].append({
                    'canonical_name': name, 'raw_label': key, 'state': 'discussed',
                    'assertion_provenance': 'deterministic', 'evidence_sections': [_SECTION],
                })
                existing.add(' '.join(name.split()).casefold())
                counters['mitigation_links'] += 1
        data['source_metadata']['exploitgym_enrichment'] = enrichment
        try:
            manifest = ResearchManifest.model_validate(data)
        except ValidationError:
            raise ValueError('Enriched manifest does not satisfy the research manifest schema') from None
        if self._heading_exists(bundle.document):
            raise ValueError('Input document already contains ExploitGym metadata enrichment section')
        raw = enrichment['raw']
        available = ', '.join(item['key'] for item in enrichment['mitigation_variants']) or 'none declared'
        section = (
            f'## {_SECTION}\n\n'
            f'Provenance: ExploitGym revision {self.revision}; metadata SHA-256 {metadata_fact["sha256"]}. '
            f'Raw sanitizer: {raw["sanitizer"]!r}; raw vulnerability type: {raw["vul_type"]!r}; '
            f'normalized sanitizer: {enrichment["normalized"]["sanitizer"]!r}; '
            f'normalized class: {enrichment["normalized"]["class"]!r}; '
            f'access direction: {enrichment["access_direction"]!r}; available variants: {available}.\n'
        )
        return manifest, bundle.document.rstrip() + '\n\n' + section, counters

    def _copy(self, root, bundle, manifest, document):
        (root / 'manifest.json').write_text(
            json.dumps(manifest.model_dump(mode='json', by_alias=True), sort_keys=True, indent=2,
                       ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')
        (root / 'document.md').write_text(document, encoding='utf-8')
        for declared, artifact in zip(manifest.artifacts, bundle.artifacts, strict=True):
            destination = root / declared.path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(artifact.content)
        load_research_bundle(root)

    def build(self, output_root):
        """Atomically publish a complete new collection without replacing any path."""
        self._redactions.clear()
        selected, metadata_fact = self._metadata()
        source_bundles = self._bundles()
        source_counts = Counter(bundle.manifest.external_id for _name, bundle in source_bundles)
        if any(source_counts[identity] != 1 for identity in selected):
            raise ValueError('ExploitGym mapping contains an external ID absent from the CyberGym collection')
        target = Path(output_root).absolute()
        parent = _safe_root(target.parent)
        if target.name in ('', '.', '..') or target.exists() or target.is_symlink():
            raise ValueError('Enrichment output already exists')
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temporary = Path(tempfile.mkdtemp(prefix=f'.{target.name}.enrichment-', dir=parent))
        totals = Counter()
        try:
            for name, bundle in source_bundles:
                destination = temporary / name
                destination.mkdir()
                record = selected.get(bundle.manifest.external_id)
                if record is None:
                    manifest, document = bundle.manifest, bundle.document
                    totals['unmatched'] += 1
                else:
                    manifest, document, changes = self._changed(bundle, record, metadata_fact)
                    totals.update(changes)
                    totals['enriched'] += 1
                self._copy(destination, bundle, manifest, document)
            if totals['enriched'] != self.expected_enriched or totals['unmatched'] + totals['enriched'] != self.expected_bundles:
                raise ValueError('Enrichment output does not satisfy the complete collection contract')
            _publish(temporary, target, parent_fd)
        finally:
            os.close(parent_fd)
            if temporary.exists():
                if temporary.is_symlink() or temporary.resolve().parent != parent:
                    raise ValueError('Refusing to clean an unexpected enrichment temporary path')
                shutil.rmtree(temporary)
        return CyberGymEnrichmentReport(
            self.expected_bundles, totals['enriched'], totals['unmatched'], totals['class_filled'],
            totals['sanitizer_filled'], totals['architecture_filled'], totals['mitigation_links'],
            dict(sorted(self._redactions.items())),
        )
