"""Offline, selective-text CyberGym adapter with structural fact extraction."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shlex

from ..models import ResearchManifest
from ..research import _decode_utf8, _read_bundle_file
from .exploitgym import (
    ExploitGymKernelCTFAdapter, _fenced, _invalid_constant, _json_object, _validate_json,
)


_DATASET_URL = 'https://huggingface.co/datasets/sunblaze-ucb/cybergym'
MAX_RUNTIME_BYTES = 4 * 1024 * 1024
_TASK = re.compile(r'(arvo|oss-fuzz):([A-Za-z0-9][A-Za-z0-9._-]*)\Z')
_SANITIZERS = {
    'AddressSanitizer': 'asan', 'MemorySanitizer': 'msan', 'UndefinedBehaviorSanitizer': 'ubsan',
    'LeakSanitizer': 'lsan', 'ThreadSanitizer': 'tsan', 'HWAddressSanitizer': 'hwasan',
}
_CLASSES = (
    'heap-buffer-overflow', 'stack-buffer-overflow', 'global-buffer-overflow', 'heap-use-after-free',
    'stack-use-after-return', 'stack-use-after-scope', 'use-of-uninitialized-value', 'double-free',
    'invalid-free', 'alloc-dealloc-mismatch', 'null-pointer-access', 'signed-integer-overflow',
    'unsigned-integer-overflow', 'shift-out-of-bounds', 'division-by-zero', 'data-race', 'leak',
    'segmentation-fault',
)


@dataclass(frozen=True)
class CyberGymAdapterReport:
    bundles: tuple[Path, ...]
    records_seen: int
    records_selected: int
    artifacts: int
    redactions_by_type: dict[str, int]


def _error_facts(text):
    summaries = [line.strip() for line in text.splitlines() if line.lstrip().startswith('SUMMARY:')]
    summary = summaries[-1] if summaries else None
    diagnostic = summary if summary is not None else text
    names = [name for name in _SANITIZERS if re.search(r'\b' + re.escape(name) + r'\b', diagnostic)]
    sanitizer = _SANITIZERS[names[0]] if len(names) == 1 else None
    labels = set()
    for line in diagnostic.splitlines():
        # Only a report label immediately following an explicit diagnostic prefix.
        prefixes = '|'.join(map(re.escape, _SANITIZERS))
        label = re.search(r'(?:' + prefixes + r'|runtime error):\s*(.*)', line)
        if not label:
            continue
        for canonical in _CLASSES:
            spelling = re.escape(canonical).replace(r'\-', r'[- ]')
            if re.search(r'(?:^|\b(?:or|and)\s+)' + spelling + r'(?![\w-])', label[1], re.I):
                labels.add(canonical)
        if re.match(r'(?:SEGV|DEADLYSIGNAL|segmentation fault)(?![\w-])', label[1]):
            labels.add('segmentation-fault')
    tokens, frames, symbols, seen_symbols = [], [], [], set()
    token_total = frame_total = 0
    for line in text.splitlines():
        token = re.match(r'^\s*DEDUP_TOKEN:\s*(.*)$', line)
        if token:
            token_total += 1
            if len(tokens) < 128:
                tokens.append(token[1])
        match = re.match(r'^\s*#(\d+)\s+(?:0x[0-9a-fA-F]+\s+)?(?:in\s+)?(.*)$', line)
        if not match:
            continue
        frame_total += 1
        index, body = int(match[1]), match[2].strip()
        frame = {'index': index, 'function': None, 'path': None, 'line': None, 'column': None}
        location = re.match(r'^(?:(.*?)\s+)?([^\s]+?):(\d+)(?::(\d+))?(?:\s+\(.*\))?$', body)
        if location:
            frame.update(function=location[1], path=location[2], line=int(location[3]),
                         column=int(location[4]) if location[4] else None)
        elif body:
            # Binary/module offsets are not source locations or line numbers.
            frame['function'] = re.sub(r'\s+\([^)]*\+0x[0-9a-fA-F]+\)$', '', body)
        if frame['function'] and frame['function'] not in seen_symbols:
            seen_symbols.add(frame['function'])
            if len(symbols) < 256:
                symbols.append(frame['function'])
        if len(frames) < 256:
            frames.append(frame)
    return {
        'provenance': 'deterministic', 'sanitizer': sanitizer, 'raw_summary': summary,
        'vulnerability_class': next(iter(labels)) if len(labels) == 1 else None,
        'dedup_tokens': tokens, 'frames': frames, 'affected_symbols': symbols,
        'frames_total': frame_total, 'frames_truncated': frame_total > len(frames),
        'dedup_tokens_total': token_total, 'dedup_tokens_truncated': token_total > len(tokens),
        'affected_symbols_total': len(seen_symbols), 'affected_symbols_truncated': len(seen_symbols) > len(symbols),
    }


def _bounded_runtime(text, limit):
    data = text.encode('utf-8')
    if len(data) <= limit:
        return text, False, 0
    # Reserve enough room for the explicit marker; decode boundary fragments only.
    budget = max(0, limit - 128)
    head = data[:budget // 2].decode('utf-8', errors='ignore')
    tail = data[len(data) - (budget - budget // 2):].decode('utf-8', errors='ignore') if budget else ''
    omitted = len(data) - len(head.encode('utf-8')) - len(tail.encode('utf-8'))
    marker = f'\n[... {omitted} normalized UTF-8 bytes omitted ...]\n'
    return head + marker + tail, True, omitted


def _patch_facts(text):
    paths, files, hunks = [], [], []
    added = removed = 0
    current = None
    in_hunk = False
    for line in text.splitlines():
        if line.startswith('diff --git '):
            in_hunk = False
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            if len(parts) == 4:
                old, new = parts[2].removeprefix('a/'), parts[3].removeprefix('b/')
                current = {'old_path': old, 'new_path': new}
                files.append(current)
                for path in (old, new):
                    if path not in paths:
                        paths.append(path)
            continue
        hunk = re.match(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$', line)
        if hunk:
            in_hunk = True
            hunks.append({
                'header': line, 'old_start': int(hunk[1]), 'old_count': int(hunk[2]) if hunk[2] else 1,
                'new_start': int(hunk[3]), 'new_count': int(hunk[4]) if hunk[4] else 1,
                'context': hunk[5].strip(), 'path': current['new_path'] if current else None,
            })
        elif in_hunk:
            added += line.startswith('+')
            removed += line.startswith('-')
    return {'provenance': 'deterministic', 'changed_paths': paths, 'files': files,
            'hunks': hunks, 'added_lines': added, 'removed_lines': removed}


class CyberGymAdapter(ExploitGymKernelCTFAdapter):
    """Reuse the reviewed bounded reader, sanitizer, and atomic publication only."""

    def __init__(self, dataset_root, revision, security_filter=None,
                 max_metadata_bytes=8_388_608, max_source_file_bytes=50_331_648):
        super().__init__(dataset_root, revision, security_filter, max_metadata_bytes, max_source_file_bytes)
        self.dataset_root = self.repository_root

    def _records(self, root_fd):
        data = _read_bundle_file(self.dataset_root, root_fd, 'tasks.json',
                                 limit=self.max_metadata_bytes, label='Task metadata')
        try:
            records = json.loads(_decode_utf8(data, 'Task metadata'), object_pairs_hook=_json_object,
                                 parse_constant=_invalid_constant)
            _validate_json(records)
        except (ValueError, RecursionError):
            raise ValueError('Task metadata must contain valid finite UTF-8 JSON') from None
        if not isinstance(records, list):
            raise ValueError('Task metadata must be a list')
        seen = set()
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get('task_id'), str) or not _TASK.fullmatch(record['task_id']):
                raise ValueError('Task ID must use arvo or oss-fuzz and one safe identifier segment')
            if record['task_id'] in seen:
                raise ValueError('Duplicate task ID')
            seen.add(record['task_id'])
            for field in ('project_name', 'project_language', 'vulnerability_description'):
                if not isinstance(record.get(field), str):
                    raise ValueError('Project, language, and vulnerability description must be strings')
            for field in ('project_homepage', 'project_main_repo'):
                value = record.get(field)
                if not isinstance(value, str) or not value.strip() or re.search(r'[\x00-\x1f\x7f]', value):
                    raise ValueError('Project source locations must be nonempty strings without ASCII controls')
            difficulty = record.get('task_difficulty')
            if not isinstance(difficulty, dict) or not all(isinstance(items, list) and all(isinstance(item, str) for item in items)
                                                          for items in difficulty.values()):
                raise ValueError('Task difficulty must map names to lists of strings')
            if {'derived_error', 'derived_patch', 'evidence_completeness', 'source_files'}.intersection(record):
                raise ValueError('Task metadata contains reserved derived-fact keys')
        return records, sorted(records, key=lambda record: record['task_id'])

    def _sanitize_runtime(self, text):
        # DEDUP_TOKEN is diagnostic metadata, not a credential assignment. Hide
        # only its known label from that generic rule; sanitize its value normally.
        marker = '__CYBERGYM_DEDUP_LABEL__'
        while marker in text:
            marker += '_'
        protected = re.sub(r'(?m)^(\s*)DEDUP_TOKEN:', lambda match: match[1] + marker + ':', text)
        return self._sanitize(protected).replace(marker + ':', 'DEDUP_TOKEN:')

    def _task(self, root_fd, record):
        namespace, task_id = _TASK.fullmatch(record['task_id']).groups()
        source_path = f'data/{namespace}/{task_id}'
        artifacts, source_files = {}, {}
        for name in ('description.txt', 'error.txt', 'patch.diff'):
            data = _read_bundle_file(self.dataset_root, root_fd, f'{source_path}/{name}',
                                     limit=self.max_source_file_bytes, label='Selected task text')
            if data.startswith(b'version https://git-lfs.github.com/spec/v1'):
                raise ValueError('Incomplete task: selected text is a Git-LFS pointer')
            try:
                text = data.decode('utf-8', errors='strict')
                utf8_valid = True
            except UnicodeDecodeError:
                text = data.decode('utf-8', errors='backslashreplace')
                utf8_valid = False
            artifacts[name] = self._sanitize_runtime(text) if name == 'error.txt' else self._sanitize(text)
            source_files[name] = {'raw_bytes': len(data), 'raw_sha256': hashlib.sha256(data).hexdigest(),
                                  'utf8_valid': utf8_valid, 'normalized_truncated': False, 'omitted_bytes': 0}
        source_record = self._sanitize_metadata(record)
        error = _error_facts(artifacts['error.txt'])
        patch = _patch_facts(artifacts['patch.diff'])
        excerpt, truncated, omitted = _bounded_runtime(artifacts['error.txt'], MAX_RUNTIME_BYTES)
        artifacts['error.txt'] = excerpt
        source_files['error.txt'].update(normalized_truncated=truncated, omitted_bytes=omitted)
        completeness = {'description': True, 'runtime': True, 'patch': True,
                        'complete_triple': True, 'count': 3, 'provenance': 'deterministic'}
        facts = {**source_record, 'derived_error': error, 'derived_patch': patch,
                 'evidence_completeness': completeness, 'source_files': source_files}
        upstream_url = f'{_DATASET_URL}/tree/{self.revision}/{source_path}'
        stages = [
            {'canonical_name': name, 'stage_class': stage_class, 'assertion_provenance': 'deterministic',
             'matched_alias': section, 'evidence_sections': [section],
             'validation_status': 'harness_observed' if section == 'Runtime evidence' else 'source_documented'}
            for name, stage_class, section in (
                ('crash reproduction', 'trigger', 'Runtime evidence'),
                ('crash diagnosis', 'diagnose', 'Runtime evidence'), ('remediation', 'remediation', 'Patch'),
            )
        ]
        manifest_artifacts = []
        for name, kind, role, validation, media_type in (
            ('description.txt', 'vulnerability-description', 'signal', 'source_documented', 'text/plain'),
            ('error.txt', 'runtime-evidence', 'signal', 'harness_observed', 'text/plain'),
            ('patch.diff', 'patch', 'remediation', 'source_documented', 'text/x-diff'),
        ):
            manifest_artifacts.append({'path': f'artifacts/{name}', 'kind': kind, 'role': role,
                                       'validation': validation, 'media_type': media_type, 'license_expression': None,
                                       'sha256': hashlib.sha256(artifacts[name].encode('utf-8')).hexdigest()})
        summary = source_record['vulnerability_description'] or None
        manifest = ResearchManifest.model_validate({
            'schema_version': 1, 'source': {'name': 'cybergym', 'revision': self.revision,
                'repository_url': _DATASET_URL, 'homepage': _DATASET_URL, 'upstream_url': upstream_url,
                'license_expression': None},
            'external_id': source_record['task_id'], 'domain': 'userspace', 'project': source_record['project_name'],
            'language': source_record['project_language'], 'document_kind': 'vulnerability-research',
            'source_path': source_path, 'source_metadata': facts, 'artifacts': manifest_artifacts,
            'operational_stages': stages,
            'vulnerability': {'summary': summary, 'summary_provenance': 'source' if summary else None,
                'class': error['vulnerability_class'], 'class_provenance': 'deterministic' if error['vulnerability_class'] else None,
                'sanitizer': error['sanitizer'], 'platform': 'linux', 'affected_symbols': error['affected_symbols']},
        })
        json_text = lambda value: json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        title = ' '.join(f'{source_record["project_name"]}: {source_record["task_id"]}'.split())
        document = (
            f'# {title}\n\nSource: cybergym\nRevision: {self.revision}\nUpstream: {upstream_url}\n\n'
            + '## Source metadata\n\n' + _fenced(json_text({**source_record, 'source_files': source_files}), 'json') + '\n'
            + '## Description\n\n' + artifacts['description.txt'] + '\n\n'
            + '## Derived error facts\n\n' + _fenced(json_text({**error, 'evidence_completeness': completeness}), 'json') + '\n'
            + '## Runtime evidence\n\n' + _fenced(artifacts['error.txt'], 'text') + '\n'
            + '## Patch facts\n\n' + _fenced(json_text(patch), 'json') + '\n'
            + '## Patch\n\n' + _fenced(artifacts['patch.diff'], 'diff')
        )
        return manifest, document, artifacts, 0

    def build(self, output_root):
        report = super().build(output_root)
        return CyberGymAdapterReport(report.bundles, report.records_seen, report.records_selected,
                                    report.artifacts, report.redactions_by_type)
