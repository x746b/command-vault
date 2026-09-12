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
from .research import load_research_bundle, make_document_snapshot
from .security import SecurityFilter


@dataclass(frozen=True)
class ResearchIndexResult:
    bundles_seen: int = 0
    documents_indexed: int = 0
    chunks_indexed: int = 0
    vulnerabilities_indexed: int = 0
    redactions_by_type: dict[str, int] = field(default_factory=dict)


def _aggregate_redaction(security, source, redaction_type, detail):
    # SecurityFilter's normal logger includes matched details. Research imports
    # retain only categories, including when debug logging is enabled.
    security.redaction_log.append({'type': redaction_type})


def _slug(value):
    return re.sub(r'[^a-zA-Z0-9_-]+', '-', value).strip('-')[:80] or 'research'


class ResearchIndexer:
    def __init__(self, db, security_filter=None):
        if db.readonly:
            raise ValueError('Research indexing requires a writable candidate database')
        with db._get_connection() as conn:
            if conn.execute('PRAGMA user_version').fetchone()[0] < 2:
                raise ValueError('Research indexing requires database schema 2 or newer')
        self.db = db
        self.security = copy(security_filter) if security_filter is not None else SecurityFilter()
        self.security.redaction_log = []
        self.security._log_redaction = MethodType(_aggregate_redaction, self.security)

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
            for name in ('bundles_seen', 'documents_indexed', 'chunks_indexed', 'vulnerabilities_indexed'):
                totals[name] += getattr(result, name)
            redactions.update(result.redactions_by_type)
        return ResearchIndexResult(**totals, redactions_by_type=dict(sorted(redactions.items())))

    def index_bundle(self, root):
        loaded = load_research_bundle(root)
        manifest = loaded.manifest
        self.security.redaction_log = []
        document = self.security.sanitize_text(loaded.document, source_file='research document')
        snapshot = make_document_snapshot(document)
        chunks = knowledge_chunks(document)
        vulnerability = manifest.vulnerability
        summary = (self.security.sanitize_text(vulnerability.summary, source_file='research summary')
                   if vulnerability is not None and vulnerability.summary is not None else None)
        canonical_id = vulnerability.canonical_id if vulnerability is not None else None
        title = ' — '.join(part for part in (canonical_id, summary) if part)
        title = title or manifest.project or manifest.external_id
        identity = f'research://{quote(manifest.source.name, safe="")}/{quote(manifest.external_id, safe="")}'
        filename = f'{_slug(manifest.source.name)}--{_slug(manifest.external_id)}.md'
        tags = {"research", manifest.source.name.lower(), manifest.domain.lower()}
        if canonical_id and re.fullmatch(r'CVE-\d{4}-\d+', canonical_id, re.IGNORECASE):
            tags.add(canonical_id.lower())
        with self.db.transaction():
            with self.db._get_connection() as conn:
                collection_id = self._source_collection(conn, manifest.source)
                old = conn.execute('SELECT id FROM writeups WHERE filepath=?', (identity,)).fetchone()
                if old:
                    self._clear_children(conn, old['id'])
                conn.execute('''INSERT INTO writeups
                    (filename,filepath,writeup_type,title,source_collection_id,external_id,domain,
                     document_kind,upstream_url,content_hash,parser_version)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(filepath) DO UPDATE SET
                        filename=excluded.filename,writeup_type=excluded.writeup_type,title=excluded.title,
                        source_collection_id=excluded.source_collection_id,external_id=excluded.external_id,
                        domain=excluded.domain,document_kind=excluded.document_kind,upstream_url=excluded.upstream_url,
                        content_hash=excluded.content_hash,parser_version=excluded.parser_version,
                        indexed_at=CURRENT_TIMESTAMP''',
                    (filename, identity, 'research', title, collection_id, manifest.external_id,
                     manifest.domain, manifest.document_kind, str(manifest.source.upstream_url),
                     snapshot.content_hash, 'research-bundle-v1'))
                writeup_id = conn.execute('SELECT id FROM writeups WHERE filepath=?', (identity,)).fetchone()['id']
                self.db._set_writeup_tags(conn, writeup_id, sorted(tags))
                for chunk in chunks:
                    self.db.insert_chunk(writeup_id, chunk['section'], chunk['content'], chunk['chunk_index'])
                conn.execute('''INSERT INTO document_snapshots
                    (writeup_id,content_blob,compression,content_hash,uncompressed_bytes) VALUES (?,?,?,?,?)''',
                    (writeup_id, snapshot.content_blob, snapshot.compression,
                     snapshot.content_hash, snapshot.uncompressed_bytes))
                if vulnerability is not None:
                    cursor = conn.execute('''INSERT INTO vulnerabilities
                        (canonical_id,external_task_id,project_name,summary,summary_provenance,
                         vulnerability_class,class_provenance,sanitizer,architecture,platform,subsystem,language)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (canonical_id, manifest.external_id, manifest.project, summary,
                         vulnerability.summary_provenance, vulnerability.vulnerability_class,
                         vulnerability.class_provenance, vulnerability.sanitizer, vulnerability.architecture,
                         vulnerability.platform, vulnerability.subsystem, manifest.language))
                    conn.execute('INSERT INTO writeup_vulnerabilities (writeup_id,vulnerability_id) VALUES (?,?)',
                                 (writeup_id, cursor.lastrowid))
        counts = Counter(item['type'] for item in self.security.redaction_log)
        return ResearchIndexResult(1, 1, len(chunks), int(vulnerability is not None), dict(sorted(counts.items())))

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
