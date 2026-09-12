"""Transactional storage of validated research documents; content is never executed."""

from collections import Counter
from copy import copy
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from types import MethodType
from urllib.parse import quote

from .documents import knowledge_chunks
from .models import Script
from .research import load_research_bundle, make_document_snapshot
from .security import SecurityFilter


@dataclass(frozen=True)
class ResearchIndexResult:
    bundles_seen: int = 0
    documents_indexed: int = 0
    chunks_indexed: int = 0
    vulnerabilities_indexed: int = 0
    redactions_by_type: dict[str, int] = field(default_factory=dict)
    scripts_indexed: int = 0
    stages_linked: int = 0
    evidence_links: int = 0
    validation_records: int = 0
    mitigations_indexed: int = 0
    mitigation_links: int = 0


def _aggregate_redaction(security, source, redaction_type, detail):
    # SecurityFilter's normal logger includes matched details. Research imports
    # retain only categories, including when debug logging is enabled.
    security.redaction_log.append({'type': redaction_type})


def _slug(value):
    return re.sub(r'[^a-zA-Z0-9_-]+', '-', value).strip('-')[:80] or 'research'


class ResearchIndexer:
    def __init__(self, db, security_filter=None, managed_root=None):
        if db.readonly:
            raise ValueError('Research indexing requires a writable candidate database')
        with db._get_connection() as conn:
            if conn.execute('PRAGMA user_version').fetchone()[0] < 2:
                raise ValueError('Research indexing requires database schema 2 or newer')
        self.db = db
        self.managed_root = self._managed_directory(managed_root) if managed_root is not None else None
        self.security = copy(security_filter) if security_filter is not None else SecurityFilter()
        self.security.redaction_log = []
        self.security._log_redaction = MethodType(_aggregate_redaction, self.security)

    @staticmethod
    def _managed_directory(path):
        path = Path(path).absolute()
        if any(component.is_symlink() or not component.is_dir() for component in (path, *path.parents)):
            raise ValueError('Managed directories must exist and have no symlink ancestors')
        return path.resolve(strict=True)

    def _sanitize_document(self, document):
        # The diagnostic label is not a credential key. Protect only that
        # line-start label, leaving its complete value visible to every filter.
        marker = '{CV_DIAGNOSTIC_LABEL}:'
        while marker in document:
            marker = '_' + marker
        protected = re.sub(r'(?m)^([ \t]*)DEDUP_TOKEN:',
                           lambda match: match[1] + marker, document)
        sanitized = self.security.sanitize_text(protected, source_file='research document')
        return sanitized.replace(marker, 'DEDUP_TOKEN:')

    def index_directory(self, root):
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            raise ValueError('Research bundle directory must be a real nonsymlink directory')
        if (root / 'manifest.json').exists() or (root / 'manifest.json').is_symlink():
            raise ValueError('Expected a collection of bundles, not a loose root manifest')
        selected = [path for path in sorted(root.iterdir())
                    if path.is_dir() and ((path / 'manifest.json').exists()
                                          or (path / 'manifest.json').is_symlink())]
        if not selected:
            raise ValueError('No direct child research bundles found')
        totals = Counter()
        redactions = Counter()
        for path in selected:
            result = self.index_bundle(path)
            for name in (
                'bundles_seen', 'documents_indexed', 'chunks_indexed', 'vulnerabilities_indexed',
                'scripts_indexed', 'stages_linked', 'evidence_links', 'validation_records',
                'mitigations_indexed', 'mitigation_links',
            ):
                totals[name] += getattr(result, name)
            redactions.update(result.redactions_by_type)
        return ResearchIndexResult(**totals, redactions_by_type=dict(sorted(redactions.items())))

    def index_bundle(self, root):
        if self.managed_root is not None:
            bundle_root = self._managed_directory(root)
            if bundle_root == self.managed_root or not bundle_root.is_relative_to(self.managed_root):
                raise ValueError('Managed bundle must be a real descendant of the managed root')
        loaded = load_research_bundle(root)
        manifest = loaded.manifest
        self.security.redaction_log = []
        document = self._sanitize_document(loaded.document)
        snapshot = make_document_snapshot(document)
        chunks = knowledge_chunks(document)
        vulnerability = manifest.vulnerability
        summary = (self.security.sanitize_text(vulnerability.summary, source_file='research summary')
                   if vulnerability is not None and vulnerability.summary is not None else None)
        scripts = []
        for artifact, verified in zip(manifest.artifacts, loaded.artifacts, strict=True):
            if verified.path != loaded.root / artifact.path:
                raise ValueError('Loaded artifact path/order conflicts with the manifest')
            if artifact.language != 'c':
                continue
            try:
                text = verified.content.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                raise ValueError('C artifact must contain valid UTF-8') from None
            code = self.security.sanitize_text(text, source_file='research C artifact')
            normalized = '\n'.join(line.rstrip() for line in code.replace('\r\n', '\n').split('\n')).strip('\n')
            scripts.append((artifact, verified.sha256, code,
                            hashlib.sha256(code.encode('utf-8')).hexdigest(),
                            hashlib.sha256(normalized.encode('utf-8')).hexdigest()))
        canonical_id = vulnerability.canonical_id if vulnerability is not None else None
        title = ' — '.join(part for part in (canonical_id, summary) if part)
        title = title or manifest.project or manifest.external_id
        identity = f'research://{quote(manifest.source.name, safe="")}/{quote(manifest.external_id, safe="")}'
        if self.managed_root is not None:
            identity = str(loaded.root / 'document.md')
        filename = f'{_slug(manifest.source.name)}--{_slug(manifest.external_id)}.md'
        tags = {"research", manifest.source.name.lower(), manifest.domain.lower()}
        if canonical_id and re.fullmatch(r'CVE-\d{4}-\d+', canonical_id, re.IGNORECASE):
            tags.add(canonical_id.lower())
        with self.db.transaction():
            with self.db._get_connection() as conn:
                collection_id = self._source_collection(conn, manifest.source)
                existing = conn.execute('''SELECT id FROM writeups
                    WHERE source_collection_id=? AND external_id=? AND writeup_type=?''',
                    (collection_id, manifest.external_id, 'research')).fetchall()
                if len(existing) > 1:
                    raise ValueError('Duplicate research source/external identity')
                old = existing[0] if existing else None
                collision = conn.execute('SELECT id FROM writeups WHERE filepath=?', (identity,)).fetchone()
                if collision is not None and (old is None or collision['id'] != old['id']):
                    raise ValueError('Research filepath conflicts with another writeup')
                if old:
                    self._clear_children(conn, old['id'])
                conn.execute('''INSERT INTO writeups
                    (id,filename,filepath,writeup_type,title,source_collection_id,external_id,domain,
                     document_kind,upstream_url,content_hash,parser_version)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        filename=excluded.filename,filepath=excluded.filepath,writeup_type=excluded.writeup_type,title=excluded.title,
                        source_collection_id=excluded.source_collection_id,external_id=excluded.external_id,
                        domain=excluded.domain,document_kind=excluded.document_kind,upstream_url=excluded.upstream_url,
                        content_hash=excluded.content_hash,parser_version=excluded.parser_version,
                        indexed_at=CURRENT_TIMESTAMP''',
                    (old['id'] if old else None, filename, identity, 'research', title, collection_id, manifest.external_id,
                     manifest.domain, manifest.document_kind, str(manifest.source.upstream_url),
                     snapshot.content_hash, 'research-bundle-v1'))
                writeup_id = conn.execute('SELECT id FROM writeups WHERE filepath=?', (identity,)).fetchone()['id']
                self.db._set_writeup_tags(conn, writeup_id, sorted(tags))
                stored_chunks = []
                for chunk in chunks:
                    chunk_id = self.db.insert_chunk(writeup_id, chunk['section'], chunk['content'], chunk['chunk_index'])
                    stored_chunks.append((chunk_id, chunk))
                conn.execute('''INSERT INTO document_snapshots
                    (writeup_id,content_blob,compression,content_hash,uncompressed_bytes) VALUES (?,?,?,?,?)''',
                    (writeup_id, snapshot.content_blob, snapshot.compression,
                     snapshot.content_hash, snapshot.uncompressed_bytes))
                vulnerability_id = None
                if vulnerability is not None:
                    cursor = conn.execute('''INSERT INTO vulnerabilities
                        (canonical_id,external_task_id,project_name,summary,summary_provenance,
                         vulnerability_class,class_provenance,sanitizer,architecture,platform,subsystem,language)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (canonical_id, manifest.external_id, manifest.project, summary,
                         vulnerability.summary_provenance, vulnerability.vulnerability_class,
                         vulnerability.class_provenance, vulnerability.sanitizer, vulnerability.architecture,
                         vulnerability.platform, vulnerability.subsystem, manifest.language))
                    vulnerability_id = cursor.lastrowid
                    conn.execute('INSERT INTO writeup_vulnerabilities (writeup_id,vulnerability_id) VALUES (?,?)',
                                 (writeup_id, vulnerability_id))
                for artifact, source_hash, code, artifact_hash, normalized_hash in scripts:
                    script_id = self.db.insert_script(Script(
                        writeup_id=writeup_id, language='c', code=code, purpose=artifact.kind,
                        source_section=f'Artifact: {artifact.path}',
                    ))
                    conn.execute('UPDATE scripts SET artifact_hash=?,normalized_hash=? WHERE id=?',
                                 (artifact_hash, normalized_hash, script_id))
                    conn.execute('''INSERT INTO evidence_links
                        (writeup_id,script_id,evidence_role,assertion_provenance,validation_status,source_anchor_hash)
                        VALUES (?,?,?,?,?,?)''',
                        (writeup_id, script_id, artifact.role, 'source', artifact.validation, source_hash))
                    conn.execute('''INSERT INTO validation_records
                        (artifact_kind,artifact_id,validation_level,status,source_reference) VALUES (?,?,?,?,?)''',
                        ('script', script_id, artifact.validation, artifact.validation, artifact.path))
                stages_linked, stage_evidence = self._index_stages(conn, writeup_id, manifest, stored_chunks)
                mitigations_indexed, mitigation_links, mitigation_evidence = self._index_mitigations(
                    conn, writeup_id, vulnerability_id, snapshot.content_hash, manifest, stored_chunks,
                )
        counts = Counter(item['type'] for item in self.security.redaction_log)
        return ResearchIndexResult(
            bundles_seen=1, documents_indexed=1, chunks_indexed=len(chunks),
            vulnerabilities_indexed=int(vulnerability is not None), redactions_by_type=dict(sorted(counts.items())),
            scripts_indexed=len(scripts), stages_linked=stages_linked,
            evidence_links=len(scripts) + stage_evidence + mitigation_evidence, validation_records=len(scripts),
            mitigations_indexed=mitigations_indexed, mitigation_links=mitigation_links,
        )

    @staticmethod
    def _index_mitigations(conn, writeup_id, vulnerability_id, content_hash, manifest, chunks):
        encountered, evidence = set(), set()
        links = 0
        for mitigation in manifest.mitigations:
            conn.execute('''INSERT INTO mitigations (canonical_name,raw_label) VALUES (?,?)
                ON CONFLICT(canonical_name) DO UPDATE SET raw_label=COALESCE(mitigations.raw_label,excluded.raw_label)''',
                (mitigation.canonical_name, mitigation.raw_label))
            mitigation_id = conn.execute('SELECT id FROM mitigations WHERE canonical_name=?',
                                         (mitigation.canonical_name,)).fetchone()['id']
            encountered.add(mitigation_id)
            if vulnerability_id is None:
                continue
            matched = [(chunk_id, chunk) for chunk_id, chunk in chunks
                       if chunk['section'] in mitigation.evidence_sections]
            reference = (f'chunk:{matched[0][0]}' if matched else f'document:{writeup_id}')
            reference += f'@{writeup_id}.{content_hash}'
            conn.execute('''INSERT INTO vulnerability_mitigations
                (vulnerability_id,mitigation_id,state,source_reference) VALUES (?,?,?,?)''',
                (vulnerability_id, mitigation_id, mitigation.state, reference))
            links += 1
            for chunk_id, chunk in matched:
                # Per-control identity is retained by vulnerability_mitigations;
                # the evidence table has no mitigation_id column.
                key = (chunk_id, mitigation.assertion_provenance, mitigation.state)
                if key in evidence:
                    continue
                conn.execute('''INSERT INTO evidence_links
                    (writeup_id,chunk_id,vulnerability_id,evidence_role,assertion_provenance,
                     validation_status,observed_outcome,source_anchor_hash) VALUES (?,?,?,?,?,?,?,?)''',
                    (writeup_id, chunk_id, vulnerability_id, 'mitigation', mitigation.assertion_provenance,
                     'source_documented', mitigation.state, hashlib.sha256(chunk['content'].encode('utf-8')).hexdigest()))
                evidence.add(key)
        return len(encountered), links, len(evidence)

    @staticmethod
    def _index_stages(conn, writeup_id, manifest, chunks):
        roles = {
            'reach': 'prerequisite', 'trigger': 'procedure', 'diagnose': 'signal',
            'primitive': 'outcome', 'control': 'outcome', 'objective': 'outcome', 'remediation': 'remediation',
        }
        linked_stages, linked_chunks = set(), set()
        for stage in manifest.operational_stages:
            existing = conn.execute('''SELECT id,stage_class,description FROM operational_stages
                WHERE canonical_name=? AND domain=?''', (stage.canonical_name, manifest.domain)).fetchone()
            if existing is not None:
                if existing['stage_class'] != stage.stage_class:
                    raise ValueError('Operational stage class conflicts with existing metadata')
                if (existing['description'] is not None and stage.description is not None
                        and existing['description'] != stage.description):
                    raise ValueError('Operational stage description conflicts with existing metadata')
                stage_id = existing['id']
                conn.execute('UPDATE operational_stages SET description=COALESCE(description,?) WHERE id=?',
                             (stage.description, stage_id))
            else:
                stage_id = conn.execute('''INSERT INTO operational_stages
                    (canonical_name,domain,stage_class,description) VALUES (?,?,?,?)''',
                    (stage.canonical_name, manifest.domain, stage.stage_class, stage.description)).lastrowid
            alias_normalized = ' '.join(stage.matched_alias.lower().split())
            if not alias_normalized:
                raise ValueError('Operational stage alias must contain non-whitespace text')
            alias = conn.execute('''SELECT provenance FROM stage_aliases
                WHERE stage_id=? AND alias_normalized=?''', (stage_id, alias_normalized)).fetchone()
            if alias is not None:
                if alias['provenance'] != stage.assertion_provenance:
                    raise ValueError('Operational stage alias provenance conflicts with existing metadata')
            else:
                conn.execute('''INSERT INTO stage_aliases (stage_id,alias,alias_normalized,provenance)
                    VALUES (?,?,?,?)''',
                    (stage_id, stage.matched_alias, alias_normalized, stage.assertion_provenance))
            for chunk_id, chunk in chunks:
                if chunk['section'] not in stage.evidence_sections:
                    continue
                key = (stage_id, chunk_id)
                if key in linked_chunks:
                    continue
                conn.execute('''INSERT INTO evidence_links
                    (writeup_id,chunk_id,stage_id,evidence_role,assertion_provenance,validation_status,source_anchor_hash)
                    VALUES (?,?,?,?,?,?,?)''',
                    (writeup_id, chunk_id, stage_id, roles[stage.stage_class], stage.assertion_provenance,
                     'source_documented', hashlib.sha256(chunk['content'].encode('utf-8')).hexdigest()))
                linked_chunks.add(key)
                linked_stages.add(stage_id)
        return len(linked_stages), len(linked_chunks)

    @staticmethod
    def _source_collection(conn, source):
        existing = conn.execute('SELECT * FROM source_collections WHERE name=?', (source.name,)).fetchone()
        values = {'repository_url': str(source.repository_url) if source.repository_url else None,
                  'homepage': str(source.homepage) if source.homepage else None,
                  'license_expression': source.license_expression}
        if existing is not None:
            if existing['source_kind'] != 'research' or existing['revision'] != source.revision:
                raise ValueError('Research source collection kind or revision conflicts with existing metadata')
            if any(existing[key] is not None and value is not None and existing[key] != value
                   for key, value in values.items()):
                raise ValueError('Research source collection metadata conflicts with existing metadata')
            conn.execute('''UPDATE source_collections SET repository_url=COALESCE(repository_url,?),
                homepage=COALESCE(homepage,?),license_expression=COALESCE(license_expression,?) WHERE id=?''',
                (values['repository_url'], values['homepage'], values['license_expression'], existing['id']))
            return existing['id']
        cursor = conn.execute('''INSERT INTO source_collections
            (name,source_kind,homepage,repository_url,revision,license_expression,manifest_hash)
            VALUES (?,?,?,?,?,?,?)''',
            (source.name, 'research', values['homepage'], values['repository_url'], source.revision,
             values['license_expression'], hashlib.sha256(source.model_dump_json().encode('utf-8')).hexdigest()))
        return cursor.lastrowid

    @staticmethod
    def _clear_children(conn, writeup_id):
        # Polymorphic artifact references must disappear before IDs can be reused.
        conn.execute('DELETE FROM evidence_links WHERE writeup_id=?', (writeup_id,))
        for kind, table, evidence_column in (
            ('command', 'commands', 'command_id'), ('script', 'scripts', 'script_id'),
            ('chunk', 'writeup_chunks', 'chunk_id'),
        ):
            conn.execute(f'DELETE FROM evidence_links WHERE {evidence_column} IN '
                         f'(SELECT id FROM {table} WHERE writeup_id=?)', (writeup_id,))
            for polymorphic in ('validation_records', 'artifact_mitigation_observations'):
                conn.execute(f'DELETE FROM {polymorphic} WHERE artifact_kind=? AND artifact_id IN '
                             f'(SELECT id FROM {table} WHERE writeup_id=?)', (kind, writeup_id))
        conn.execute('DELETE FROM command_tags WHERE command_id IN (SELECT id FROM commands WHERE writeup_id=?)',
                     (writeup_id,))
        for table in ('commands', 'scripts', 'writeup_chunks', 'technique_writeups', 'writeup_tags', 'document_snapshots'):
            conn.execute(f'DELETE FROM {table} WHERE writeup_id=?', (writeup_id,))
        old_vulnerabilities = [row[0] for row in conn.execute(
            'SELECT vulnerability_id FROM writeup_vulnerabilities WHERE writeup_id=?', (writeup_id,))]
        conn.execute('DELETE FROM writeup_vulnerabilities WHERE writeup_id=?', (writeup_id,))
        for vulnerability_id in old_vulnerabilities:
            referenced = conn.execute('''SELECT 1 FROM writeup_vulnerabilities WHERE vulnerability_id=?
                UNION ALL SELECT 1 FROM evidence_links WHERE vulnerability_id=? LIMIT 1''',
                (vulnerability_id, vulnerability_id)).fetchone()
            if referenced is None:
                conn.execute('DELETE FROM vulnerability_mitigations WHERE vulnerability_id=?', (vulnerability_id,))
                conn.execute('DELETE FROM vulnerabilities WHERE id=?', (vulnerability_id,))
