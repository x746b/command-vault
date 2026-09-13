"""SQLite database operations for Command Vault."""

import re
import sqlite3
import json
import logging
import threading
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from .models import (
    Writeup, Tool, Command, Script,
    CommandResult, ScriptResult, ChunkResult, ToolInfo, CategoryInfo, VaultStats,
    WriteupType
)
from .categories import get_tool_category, get_category_description, CATEGORIES

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = 2


def _tokenize_fts(query: str) -> list[str]:
    """Clean and tokenize a query string for FTS5."""
    cleaned = re.sub(r'["\'\*\(\)\{\}\^\\\x00]', ' ', query)
    return cleaned.split()


def _build_fts_query(query: str) -> str:
    """Build an FTS5 AND query from user input.

    Tokenizes input and joins with AND so multi-word queries like
    "certipy ESC" match documents containing ALL words (anywhere in
    the text), not just the exact phrase.  Single-word queries pass
    through unchanged.
    FTS5 special characters are stripped to prevent syntax errors.
    """
    tokens = _tokenize_fts(query)
    if not tokens:
        return '""'
    if len(tokens) == 1:
        return '"' + tokens[0] + '"'
    # Multi-word: each token quoted, joined with AND (all words required)
    return ' AND '.join('"' + t + '"' for t in tokens)


def _build_fts_query_or(query: str) -> str:
    """Build an FTS5 OR query for fallback/ranked search.

    Used when AND returns no results — OR matches any word,
    relies on bm25() ranking to surface relevant results.
    """
    tokens = _tokenize_fts(query)
    if not tokens:
        return '""'
    if len(tokens) == 1:
        return '"' + tokens[0] + '"'
    return ' OR '.join('"' + t + '"' for t in tokens)


SCHEMA = """
-- Writeup sources metadata
CREATE TABLE IF NOT EXISTS writeups (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    filepath TEXT UNIQUE NOT NULL,
    writeup_type TEXT NOT NULL,
    challenge_type TEXT,
    difficulty TEXT,
    title TEXT,
    indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    content_hash TEXT,
    parser_version TEXT
);

-- Tool categories
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- Known tools
CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    category_id INTEGER,
    description TEXT,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

-- Extracted commands
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY,
    tool_id INTEGER,
    writeup_id INTEGER,
    raw_command TEXT NOT NULL,
    command_template TEXT,
    flags_used TEXT,
    purpose TEXT,
    context TEXT,
    source_section TEXT,
    shell_type TEXT DEFAULT 'bash',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tool_id) REFERENCES tools(id),
    FOREIGN KEY (writeup_id) REFERENCES writeups(id)
);

-- Full exploit scripts
CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY,
    writeup_id INTEGER,
    language TEXT NOT NULL,
    code TEXT NOT NULL,
    purpose TEXT,
    libraries_used TEXT,
    source_section TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (writeup_id) REFERENCES writeups(id)
);

-- Tags
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

-- Command tags (many-to-many)
CREATE TABLE IF NOT EXISTS command_tags (
    command_id INTEGER,
    tag_id INTEGER,
    PRIMARY KEY (command_id, tag_id),
    FOREIGN KEY (command_id) REFERENCES commands(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
);

-- Writeup tags (many-to-many)
CREATE TABLE IF NOT EXISTS writeup_tags (
    writeup_id INTEGER,
    tag_id INTEGER,
    PRIMARY KEY (writeup_id, tag_id),
    FOREIGN KEY (writeup_id) REFERENCES writeups(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
);

-- Shell history commands (separate from writeup commands)
CREATE TABLE IF NOT EXISTS history_commands (
    id INTEGER PRIMARY KEY,
    command_hash TEXT UNIQUE NOT NULL,
    raw_command TEXT NOT NULL,
    sanitized_command TEXT NOT NULL,
    command_template TEXT,
    tool_id INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    occurrence_count INTEGER DEFAULT 1,
    source_file TEXT,
    shell_type TEXT DEFAULT 'zsh',
    FOREIGN KEY (tool_id) REFERENCES tools(id)
);

-- Writeup prose chunks
CREATE TABLE IF NOT EXISTS writeup_chunks (
    id INTEGER PRIMARY KEY,
    writeup_id INTEGER NOT NULL,
    section TEXT,
    content TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    FOREIGN KEY (writeup_id) REFERENCES writeups(id)
);

-- Known attack techniques
CREATE TABLE IF NOT EXISTS techniques (
    id INTEGER PRIMARY KEY,
    canonical_name TEXT UNIQUE NOT NULL,
    technique_type TEXT
);

-- Technique-writeup junction
CREATE TABLE IF NOT EXISTS technique_writeups (
    technique_id INTEGER,
    writeup_id INTEGER,
    PRIMARY KEY (technique_id, writeup_id),
    FOREIGN KEY (technique_id) REFERENCES techniques(id),
    FOREIGN KEY (writeup_id) REFERENCES writeups(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_technique_writeups_tech ON technique_writeups(technique_id);
CREATE INDEX IF NOT EXISTS idx_technique_writeups_wu ON technique_writeups(writeup_id);
CREATE INDEX IF NOT EXISTS idx_commands_tool ON commands(tool_id);
CREATE INDEX IF NOT EXISTS idx_commands_writeup ON commands(writeup_id);
CREATE INDEX IF NOT EXISTS idx_scripts_writeup ON scripts(writeup_id);
CREATE INDEX IF NOT EXISTS idx_writeups_type ON writeups(writeup_type);
CREATE INDEX IF NOT EXISTS idx_writeups_challenge_type ON writeups(challenge_type);
CREATE INDEX IF NOT EXISTS idx_tools_category ON tools(category_id);
CREATE INDEX IF NOT EXISTS idx_history_hash ON history_commands(command_hash);
CREATE INDEX IF NOT EXISTS idx_history_tool ON history_commands(tool_id);
CREATE INDEX IF NOT EXISTS idx_chunks_writeup ON writeup_chunks(writeup_id);
"""

FTS_SCHEMA = """
-- Full-text search for commands
CREATE VIRTUAL TABLE IF NOT EXISTS commands_fts USING fts5(
    raw_command,
    purpose,
    context,
    content=commands,
    content_rowid=id
);

-- Full-text search for scripts
CREATE VIRTUAL TABLE IF NOT EXISTS scripts_fts USING fts5(
    code,
    purpose,
    content=scripts,
    content_rowid=id
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS commands_ai AFTER INSERT ON commands BEGIN
    INSERT INTO commands_fts(rowid, raw_command, purpose, context)
    VALUES (new.id, new.raw_command, new.purpose, new.context);
END;

CREATE TRIGGER IF NOT EXISTS commands_ad AFTER DELETE ON commands BEGIN
    INSERT INTO commands_fts(commands_fts, rowid, raw_command, purpose, context)
    VALUES('delete', old.id, old.raw_command, old.purpose, old.context);
END;

CREATE TRIGGER IF NOT EXISTS commands_au AFTER UPDATE ON commands BEGIN
    INSERT INTO commands_fts(commands_fts, rowid, raw_command, purpose, context)
    VALUES('delete', old.id, old.raw_command, old.purpose, old.context);
    INSERT INTO commands_fts(rowid, raw_command, purpose, context)
    VALUES (new.id, new.raw_command, new.purpose, new.context);
END;

CREATE TRIGGER IF NOT EXISTS scripts_ai AFTER INSERT ON scripts BEGIN
    INSERT INTO scripts_fts(rowid, code, purpose)
    VALUES (new.id, new.code, new.purpose);
END;

CREATE TRIGGER IF NOT EXISTS scripts_ad AFTER DELETE ON scripts BEGIN
    INSERT INTO scripts_fts(scripts_fts, rowid, code, purpose)
    VALUES('delete', old.id, old.code, old.purpose);
END;

CREATE TRIGGER IF NOT EXISTS scripts_au AFTER UPDATE ON scripts BEGIN
    INSERT INTO scripts_fts(scripts_fts, rowid, code, purpose)
    VALUES('delete', old.id, old.code, old.purpose);
    INSERT INTO scripts_fts(rowid, code, purpose)
    VALUES (new.id, new.code, new.purpose);
END;

-- Full-text search for writeup chunks
CREATE VIRTUAL TABLE IF NOT EXISTS writeup_chunks_fts USING fts5(
    content, section,
    content='writeup_chunks', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON writeup_chunks BEGIN
    INSERT INTO writeup_chunks_fts(rowid, content, section)
    VALUES (new.id, new.content, new.section);
END;

CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON writeup_chunks BEGIN
    INSERT INTO writeup_chunks_fts(writeup_chunks_fts, rowid, content, section)
    VALUES('delete', old.id, old.content, old.section);
END;

CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON writeup_chunks BEGIN
    INSERT INTO writeup_chunks_fts(writeup_chunks_fts, rowid, content, section)
    VALUES('delete', old.id, old.content, old.section);
    INSERT INTO writeup_chunks_fts(rowid, content, section)
    VALUES (new.id, new.content, new.section);
END;

-- Full-text search for history commands
CREATE VIRTUAL TABLE IF NOT EXISTS history_fts USING fts5(
    raw_command,
    sanitized_command,
    content=history_commands,
    content_rowid=id
);

-- Triggers for history FTS
CREATE TRIGGER IF NOT EXISTS history_ai AFTER INSERT ON history_commands BEGIN
    INSERT INTO history_fts(rowid, raw_command, sanitized_command)
    VALUES (new.id, new.raw_command, new.sanitized_command);
END;

CREATE TRIGGER IF NOT EXISTS history_ad AFTER DELETE ON history_commands BEGIN
    INSERT INTO history_fts(history_fts, rowid, raw_command, sanitized_command)
    VALUES('delete', old.id, old.raw_command, old.sanitized_command);
END;

CREATE TRIGGER IF NOT EXISTS history_au AFTER UPDATE ON history_commands BEGIN
    INSERT INTO history_fts(history_fts, rowid, raw_command, sanitized_command)
    VALUES('delete', old.id, old.raw_command, old.sanitized_command);
    INSERT INTO history_fts(rowid, raw_command, sanitized_command)
    VALUES (new.id, new.raw_command, new.sanitized_command);
END;
"""


RESEARCH_SCHEMA = """
CREATE TABLE source_collections (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    source_kind TEXT NOT NULL,
    homepage TEXT,
    repository_url TEXT,
    revision TEXT,
    license_expression TEXT,
    fetched_at TIMESTAMP,
    manifest_hash TEXT
);

ALTER TABLE writeups ADD COLUMN source_collection_id INTEGER REFERENCES source_collections(id);
ALTER TABLE writeups ADD COLUMN external_id TEXT;
ALTER TABLE writeups ADD COLUMN domain TEXT;
ALTER TABLE writeups ADD COLUMN document_kind TEXT;
ALTER TABLE writeups ADD COLUMN upstream_url TEXT;
ALTER TABLE techniques ADD COLUMN description TEXT;
ALTER TABLE techniques ADD COLUMN domain TEXT;
ALTER TABLE commands ADD COLUMN artifact_hash TEXT;
ALTER TABLE commands ADD COLUMN normalized_hash TEXT;
ALTER TABLE scripts ADD COLUMN artifact_hash TEXT;
ALTER TABLE scripts ADD COLUMN normalized_hash TEXT;

CREATE TABLE document_snapshots (
    writeup_id INTEGER PRIMARY KEY REFERENCES writeups(id),
    content_blob BLOB NOT NULL,
    compression TEXT NOT NULL DEFAULT 'zlib' CHECK (compression = 'zlib'),
    content_hash TEXT NOT NULL,
    uncompressed_bytes INTEGER CHECK (uncompressed_bytes >= 0),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    canonical_id TEXT,
    external_task_id TEXT,
    project_name TEXT,
    summary TEXT,
    summary_provenance TEXT,
    vulnerability_class TEXT,
    class_provenance TEXT,
    sanitizer TEXT,
    architecture TEXT,
    platform TEXT,
    subsystem TEXT,
    language TEXT,
    affected_symbols TEXT,
    introduced_revision TEXT,
    fixed_revision TEXT
);

CREATE TABLE writeup_vulnerabilities (
    writeup_id INTEGER NOT NULL REFERENCES writeups(id),
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
    PRIMARY KEY (writeup_id, vulnerability_id)
);

CREATE VIRTUAL TABLE vulnerabilities_fts USING fts5(
    canonical_id, external_task_id, project_name, summary,
    vulnerability_class, sanitizer, subsystem, affected_symbols,
    content='vulnerabilities', content_rowid='id'
);

CREATE TRIGGER vulnerabilities_ai AFTER INSERT ON vulnerabilities BEGIN
    INSERT INTO vulnerabilities_fts (
        rowid, canonical_id, external_task_id, project_name, summary,
        vulnerability_class, sanitizer, subsystem, affected_symbols
    ) VALUES (
        new.id, new.canonical_id, new.external_task_id, new.project_name, new.summary,
        new.vulnerability_class, new.sanitizer, new.subsystem, new.affected_symbols
    );
END;

CREATE TRIGGER vulnerabilities_ad AFTER DELETE ON vulnerabilities BEGIN
    INSERT INTO vulnerabilities_fts (
        vulnerabilities_fts, rowid, canonical_id, external_task_id, project_name,
        summary, vulnerability_class, sanitizer, subsystem, affected_symbols
    ) VALUES (
        'delete', old.id, old.canonical_id, old.external_task_id, old.project_name,
        old.summary, old.vulnerability_class, old.sanitizer, old.subsystem, old.affected_symbols
    );
END;

CREATE TRIGGER vulnerabilities_au AFTER UPDATE ON vulnerabilities BEGIN
    INSERT INTO vulnerabilities_fts (
        vulnerabilities_fts, rowid, canonical_id, external_task_id, project_name,
        summary, vulnerability_class, sanitizer, subsystem, affected_symbols
    ) VALUES (
        'delete', old.id, old.canonical_id, old.external_task_id, old.project_name,
        old.summary, old.vulnerability_class, old.sanitizer, old.subsystem, old.affected_symbols
    );
    INSERT INTO vulnerabilities_fts (
        rowid, canonical_id, external_task_id, project_name, summary,
        vulnerability_class, sanitizer, subsystem, affected_symbols
    ) VALUES (
        new.id, new.canonical_id, new.external_task_id, new.project_name, new.summary,
        new.vulnerability_class, new.sanitizer, new.subsystem, new.affected_symbols
    );
END;

CREATE TABLE technique_aliases (
    id INTEGER PRIMARY KEY,
    technique_id INTEGER NOT NULL REFERENCES techniques(id),
    alias TEXT NOT NULL,
    alias_normalized TEXT UNIQUE NOT NULL,
    provenance TEXT NOT NULL
);

CREATE TABLE operational_stages (
    id INTEGER PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    domain TEXT NOT NULL,
    stage_class TEXT NOT NULL CHECK (
        stage_class IN ('reach', 'trigger', 'diagnose', 'primitive', 'control', 'objective', 'remediation')
    ),
    description TEXT,
    UNIQUE (canonical_name, domain)
);

CREATE TABLE stage_aliases (
    stage_id INTEGER NOT NULL REFERENCES operational_stages(id),
    alias TEXT,
    alias_normalized TEXT,
    provenance TEXT,
    UNIQUE (alias_normalized, stage_id)
);

CREATE TABLE stage_edges (
    source_stage_id INTEGER NOT NULL REFERENCES operational_stages(id),
    target_stage_id INTEGER NOT NULL REFERENCES operational_stages(id),
    relation TEXT NOT NULL CHECK (relation IN ('requires', 'enables', 'blocks', 'mitigates', 'subsumes')),
    domain TEXT NOT NULL,
    evidence_reference TEXT,
    PRIMARY KEY (source_stage_id, target_stage_id, relation, domain)
);

CREATE TABLE evidence_links (
    id INTEGER PRIMARY KEY,
    writeup_id INTEGER NOT NULL REFERENCES writeups(id),
    command_id INTEGER REFERENCES commands(id),
    script_id INTEGER REFERENCES scripts(id),
    chunk_id INTEGER REFERENCES writeup_chunks(id),
    vulnerability_id INTEGER REFERENCES vulnerabilities(id),
    technique_id INTEGER REFERENCES techniques(id),
    stage_id INTEGER REFERENCES operational_stages(id),
    evidence_role TEXT CHECK (
        evidence_role IN ('prerequisite', 'procedure', 'signal', 'outcome', 'mitigation', 'remediation')
    ),
    assertion_provenance TEXT CHECK (
        assertion_provenance IN ('source', 'deterministic', 'curated', 'inferred')
    ),
    validation_status TEXT,
    observed_outcome TEXT,
    environment_json TEXT,
    source_anchor_hash TEXT,
    CHECK ((command_id IS NOT NULL) + (script_id IS NOT NULL) + (chunk_id IS NOT NULL) = 1)
);

CREATE TABLE mitigations (
    id INTEGER PRIMARY KEY,
    canonical_name TEXT UNIQUE NOT NULL,
    raw_label TEXT,
    description TEXT
);

CREATE TABLE vulnerability_mitigations (
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
    mitigation_id INTEGER NOT NULL REFERENCES mitigations(id),
    state TEXT,
    source_reference TEXT,
    PRIMARY KEY (vulnerability_id, mitigation_id)
);

CREATE TABLE technique_mitigations (
    technique_id INTEGER NOT NULL REFERENCES techniques(id),
    mitigation_id INTEGER NOT NULL REFERENCES mitigations(id),
    state TEXT,
    source_reference TEXT,
    PRIMARY KEY (technique_id, mitigation_id)
);

CREATE TABLE artifact_mitigation_observations (
    id INTEGER PRIMARY KEY,
    artifact_kind TEXT,
    artifact_id INTEGER,
    mitigation_id INTEGER REFERENCES mitigations(id),
    state TEXT,
    source_reference TEXT
);

CREATE TABLE validation_records (
    id INTEGER PRIMARY KEY,
    artifact_kind TEXT,
    artifact_id INTEGER,
    validation_level TEXT,
    status TEXT,
    environment_json TEXT,
    expected_signal TEXT,
    observed_signal TEXT,
    validated_at TIMESTAMP,
    validator TEXT,
    source_reference TEXT,
    notes TEXT
);

CREATE INDEX idx_writeups_collection ON writeups(source_collection_id);
CREATE INDEX idx_writeups_external_id ON writeups(external_id);
CREATE INDEX idx_writeups_domain_kind ON writeups(domain, document_kind);
CREATE INDEX idx_commands_artifact_hash ON commands(artifact_hash);
CREATE INDEX idx_commands_normalized_hash ON commands(normalized_hash);
CREATE INDEX idx_scripts_artifact_hash ON scripts(artifact_hash);
CREATE INDEX idx_scripts_normalized_hash ON scripts(normalized_hash);
CREATE INDEX idx_vulnerabilities_canonical_id ON vulnerabilities(canonical_id);
CREATE INDEX idx_vulnerabilities_external_task_id ON vulnerabilities(external_task_id);
CREATE INDEX idx_writeup_vulnerabilities_vulnerability ON writeup_vulnerabilities(vulnerability_id);
CREATE INDEX idx_technique_aliases_technique ON technique_aliases(technique_id);
CREATE INDEX idx_stage_aliases_stage ON stage_aliases(stage_id);
CREATE INDEX idx_stage_edges_target ON stage_edges(target_stage_id);
CREATE INDEX idx_evidence_links_writeup ON evidence_links(writeup_id);
CREATE INDEX idx_evidence_links_command ON evidence_links(command_id);
CREATE INDEX idx_evidence_links_script ON evidence_links(script_id);
CREATE INDEX idx_evidence_links_chunk ON evidence_links(chunk_id);
CREATE INDEX idx_evidence_links_vulnerability ON evidence_links(vulnerability_id);
CREATE INDEX idx_evidence_links_technique ON evidence_links(technique_id);
CREATE INDEX idx_evidence_links_stage ON evidence_links(stage_id);
CREATE INDEX idx_vulnerability_mitigations_mitigation ON vulnerability_mitigations(mitigation_id);
CREATE INDEX idx_technique_mitigations_mitigation ON technique_mitigations(mitigation_id);
CREATE INDEX idx_artifact_mitigations_artifact ON artifact_mitigation_observations(artifact_kind, artifact_id);
CREATE INDEX idx_artifact_mitigations_mitigation ON artifact_mitigation_observations(mitigation_id);
CREATE INDEX idx_validation_records_artifact ON validation_records(artifact_kind, artifact_id);
"""


class _BatchConnection(sqlite3.Connection):
    defer_commit = False

    def commit(self):
        if not self.defer_commit:
            super().commit()


class Database:
    """SQLite database wrapper for Command Vault."""

    def __init__(self, db_path: str, readonly: bool = False):
        self.db_path = Path(db_path)
        self.readonly = readonly
        self._local = threading.local()
        if readonly:
            if not self.db_path.is_file():
                raise FileNotFoundError(f"Vault database not found: {self.db_path}")
            with self._get_connection() as conn:
                version = conn.execute('PRAGMA user_version').fetchone()[0]
                if version > CURRENT_SCHEMA_VERSION:
                    raise ValueError(f"Unsupported database schema version: {version}")
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            version = conn.execute('PRAGMA user_version').fetchone()[0]
            if version > CURRENT_SCHEMA_VERSION:
                raise ValueError(f"Unsupported database schema version: {version}")
            exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='writeups'").fetchone()
            if exists and version == 0:
                # Preserve IDs and child references; only source identity changes.
                conn.executescript('''
                    BEGIN;
                    CREATE TABLE writeups_v1 (
                        id INTEGER PRIMARY KEY, filename TEXT NOT NULL,
                        filepath TEXT UNIQUE NOT NULL, writeup_type TEXT NOT NULL,
                        challenge_type TEXT, difficulty TEXT, title TEXT,
                        indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        content_hash TEXT, parser_version TEXT);
                    INSERT INTO writeups_v1
                        (id,filename,filepath,writeup_type,challenge_type,difficulty,title,indexed_at)
                        SELECT id,filename,filepath,writeup_type,challenge_type,difficulty,title,indexed_at FROM writeups;
                    DROP TABLE writeups;
                    ALTER TABLE writeups_v1 RENAME TO writeups;
                    COMMIT;
                ''')
            if version < 1:
                conn.executescript(SCHEMA)
                conn.executescript(FTS_SCHEMA)
                conn.execute('PRAGMA user_version=1')
                conn.commit()
                version = 1
            if version < CURRENT_SCHEMA_VERSION:
                conn.execute('BEGIN IMMEDIATE')
                try:
                    self._migrate_v2(conn)
                    conn.execute('PRAGMA user_version=2')
                    conn.commit()
                except BaseException:
                    conn.rollback()
                    raise
            self._seed_categories(conn)
            conn.commit()

    def _migrate_v2(self, conn: sqlite3.Connection):
        """Apply additive research DDL without executescript's implicit commit.

        complete_statement keeps trigger bodies intact while each execute stays
        inside the transaction owned by _init_db.
        """
        legacy_aliases = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type=? AND name=?",
            ('table', 'technique_aliases'),
        ).fetchone()
        if legacy_aliases:
            conn.execute('ALTER TABLE technique_aliases RENAME TO technique_aliases_v1')
        statement = ''
        for line in RESEARCH_SCHEMA.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                conn.execute(statement)
                statement = ''
        if statement.strip():
            raise ValueError('Incomplete research migration SQL')
        if legacy_aliases:
            # A normalized collision must abort the migration, never discard an alias.
            conn.execute('''
                INSERT INTO technique_aliases (id, technique_id, alias, alias_normalized, provenance)
                SELECT id, technique_id, alias, lower(trim(alias)), ? FROM technique_aliases_v1
            ''', ('deterministic',))
            conn.execute('DROP TABLE technique_aliases_v1')

    def _seed_categories(self, conn: sqlite3.Connection):
        """Seed categories table with predefined categories."""
        for name, description in CATEGORIES.items():
            conn.execute(
                "INSERT OR IGNORE INTO categories (name, description) VALUES (?, ?)",
                (name, description)
            )

    @contextmanager
    def _get_connection(self):
        """Get database connection with row factory."""
        active = getattr(self._local, 'connection', None)
        if active is not None:
            yield active
            return
        conn = sqlite3.connect(self.db_path.resolve().as_uri() + ('?mode=ro' if self.readonly else '?mode=rwc'),
                               uri=True, timeout=30, factory=_BatchConnection)
        conn.row_factory = sqlite3.Row
        if self.readonly:
            conn.execute('PRAGMA query_only=ON')
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def read_snapshot(self):
        """Share a consistent read transaction across retrieval helpers in this thread."""
        if getattr(self._local, 'connection', None) is not None:
            yield
            return
        with self._get_connection() as conn:
            conn.execute('BEGIN')
            self._local.connection = conn
            try:
                yield
            finally:
                conn.rollback()
                self._local.connection = None

    @contextmanager
    def transaction(self):
        """One atomic transaction per document/history import, local to this thread."""
        if getattr(self._local, 'connection', None) is not None:
            yield
            return
        with self._get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.defer_commit = True
            self._local.connection = conn
            try:
                yield
                conn.defer_commit = False
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.defer_commit = False
                self._local.connection = None

    def source_fingerprint(self, filepath: str):
        with self._get_connection() as conn:
            row = conn.execute('SELECT content_hash,parser_version FROM writeups WHERE filepath=?',
                               (str(Path(filepath).resolve()),)).fetchone()
            return tuple(row) if row else None

    def set_source_fingerprint(self, writeup_id: int, digest: str, parser_version: str):
        with self._get_connection() as conn:
            conn.execute('UPDATE writeups SET content_hash=?,parser_version=? WHERE id=?',
                         (digest, parser_version, writeup_id))
            conn.commit()

    def clear_writeups(self):
        """Rebuild writeup content without deleting shell history or its tools."""
        with self.transaction():
            with self._get_connection() as conn:
                for table in ('command_tags','commands','scripts','writeup_chunks',
                              'technique_writeups','writeup_tags','writeups'):
                    conn.execute(f'DELETE FROM {table}')

    def reset(self):
        """Drop all tables and recreate schema."""
        with self._get_connection() as conn:
            # Drop FTS tables first (triggers depend on them)
            conn.execute("DROP TABLE IF EXISTS commands_fts")
            conn.execute("DROP TABLE IF EXISTS scripts_fts")
            conn.execute("DROP TABLE IF EXISTS history_fts")
            conn.execute("DROP TABLE IF EXISTS writeup_chunks_fts")
            conn.execute("DROP TABLE IF EXISTS vulnerabilities_fts")

            # Drop triggers
            for trigger in ['commands_ai', 'commands_ad', 'commands_au',
                           'scripts_ai', 'scripts_ad', 'scripts_au',
                           'history_ai', 'history_ad', 'history_au',
                           'chunks_ai', 'chunks_ad', 'chunks_au',
                           'vulnerabilities_ai', 'vulnerabilities_ad', 'vulnerabilities_au']:
                conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")

            # Drop main tables
            for table in ['validation_records', 'artifact_mitigation_observations',
                         'vulnerability_mitigations', 'technique_mitigations', 'mitigations',
                         'evidence_links', 'stage_edges', 'stage_aliases', 'operational_stages',
                         'technique_aliases', 'writeup_vulnerabilities', 'vulnerabilities',
                         'document_snapshots', 'technique_writeups', 'techniques',
                         'command_tags', 'writeup_tags', 'commands', 'scripts',
                         'writeup_chunks', 'writeups', 'source_collections', 'tools', 'tags',
                         'categories', 'history_commands']:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
            conn.execute('PRAGMA user_version=0')
            conn.commit()

        self._init_db()
        logger.info("Database reset complete")

    # =========================================================================
    # WRITEUP OPERATIONS
    # =========================================================================

    def insert_writeup(self, writeup: Writeup) -> int:
        """Insert a writeup and return its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO writeups
                   (filename, filepath, writeup_type, challenge_type, difficulty, title)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(filepath) DO UPDATE SET
                   filename=excluded.filename,
                   writeup_type=excluded.writeup_type,
                   challenge_type=excluded.challenge_type,
                   difficulty=excluded.difficulty,
                   title=excluded.title,
                   indexed_at=CURRENT_TIMESTAMP""",
                (writeup.filename, str(Path(writeup.filepath).resolve()), writeup.writeup_type.value,
                 writeup.challenge_type, writeup.difficulty, writeup.title)
            )
            conn.commit()

            # Get the ID (either inserted or existing)
            row = conn.execute(
                "SELECT id FROM writeups WHERE filepath = ?",
                (str(Path(writeup.filepath).resolve()),)
            ).fetchone()
            writeup_id = row['id']

            # Handle tags
            self._set_writeup_tags(conn, writeup_id, writeup.tags)
            conn.commit()

            return writeup_id

    def get_writeup_by_filename(self, filename: str) -> Optional[Writeup]:
        """Get writeup by filename."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM writeups WHERE filename = ?",
                (filename,)
            ).fetchall()
            if len(rows) > 1:
                raise ValueError('Ambiguous filename; use read_context with a search reference instead')
            row = rows[0] if rows else None

            if not row:
                return None

            tags = self._get_writeup_tags(conn, row['id'])
            return Writeup(
                id=row['id'],
                filename=row['filename'],
                filepath=row['filepath'],
                writeup_type=WriteupType(row['writeup_type']),
                challenge_type=row['challenge_type'],
                difficulty=row['difficulty'],
                title=row['title'],
                tags=tags
            )

    def _set_writeup_tags(self, conn: sqlite3.Connection, writeup_id: int, tags: list[str]):
        """Set tags for a writeup."""
        # Clear existing tags
        conn.execute("DELETE FROM writeup_tags WHERE writeup_id = ?", (writeup_id,))

        for tag in tags:
            # Insert tag if not exists
            conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
            tag_row = conn.execute("SELECT id FROM tags WHERE name = ?", (tag,)).fetchone()

            # Link tag to writeup
            conn.execute(
                "INSERT OR IGNORE INTO writeup_tags (writeup_id, tag_id) VALUES (?, ?)",
                (writeup_id, tag_row['id'])
            )

    def _get_writeup_tags(self, conn: sqlite3.Connection, writeup_id: int) -> list[str]:
        """Get tags for a writeup."""
        rows = conn.execute(
            """SELECT t.name FROM tags t
               JOIN writeup_tags wt ON t.id = wt.tag_id
               WHERE wt.writeup_id = ?""",
            (writeup_id,)
        ).fetchall()
        return [row['name'] for row in rows]

    # =========================================================================
    # TOOL OPERATIONS
    # =========================================================================

    def get_or_create_tool(self, tool_name: str) -> int:
        """Get tool ID, creating if necessary."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT id FROM tools WHERE name = ?",
                (tool_name,)
            ).fetchone()

            if row:
                return row['id']

            # Create new tool with category
            category = get_tool_category(tool_name)
            cat_row = conn.execute(
                "SELECT id FROM categories WHERE name = ?",
                (category,)
            ).fetchone()

            cursor = conn.execute(
                "INSERT INTO tools (name, category_id) VALUES (?, ?)",
                (tool_name, cat_row['id'] if cat_row else None)
            )
            conn.commit()
            return cursor.lastrowid

    # =========================================================================
    # COMMAND OPERATIONS
    # =========================================================================

    def insert_command(self, command: Command) -> int:
        """Insert a command and return its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO commands
                   (tool_id, writeup_id, raw_command, command_template,
                    flags_used, purpose, context, source_section, shell_type)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (command.tool_id, command.writeup_id, command.raw_command,
                 command.command_template, json.dumps(command.flags_used),
                 command.purpose, command.context, command.source_section,
                 command.shell_type.value if command.shell_type else 'bash')
            )
            conn.commit()
            return cursor.lastrowid

    def search_commands(
        self,
        query: Optional[str] = None,
        tool: Optional[str] = None,
        category: Optional[str] = None,
        writeup_type: Optional[str] = None,
        challenge_type: Optional[str] = None,
        tags: Optional[list[str]] = None,
        limit: int = 10
    ) -> list[CommandResult]:
        """Search commands with AND-first, ranked-OR-fallback for FTS."""
        with self._get_connection() as conn:
            def _build_cmd_query(fts_query: Optional[str], rank: bool = True):
                params = []
                where_clauses = []

                if fts_query:
                    base_query = """
                        SELECT c.id, c.raw_command, c.command_template, c.purpose,
                               c.source_section, t.name as tool_name, cat.name as category,
                               w.filename, w.writeup_type, w.challenge_type
                        FROM commands_fts fts
                        JOIN commands c ON fts.rowid = c.id
                        LEFT JOIN tools t ON c.tool_id = t.id
                        LEFT JOIN categories cat ON t.category_id = cat.id
                        LEFT JOIN writeups w ON c.writeup_id = w.id
                        WHERE commands_fts MATCH ?
                    """
                    params.append(fts_query)
                else:
                    base_query = """
                        SELECT c.id, c.raw_command, c.command_template, c.purpose,
                               c.source_section, t.name as tool_name, cat.name as category,
                               w.filename, w.writeup_type, w.challenge_type
                        FROM commands c
                        LEFT JOIN tools t ON c.tool_id = t.id
                        LEFT JOIN categories cat ON t.category_id = cat.id
                        LEFT JOIN writeups w ON c.writeup_id = w.id
                    """

                if tool:
                    where_clauses.append("t.name LIKE ? ESCAPE '\\'")
                    escaped_tool = tool.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                    params.append(f"%{escaped_tool}%")
                if category:
                    where_clauses.append("cat.name = ?")
                    params.append(category)
                if writeup_type:
                    where_clauses.append("w.writeup_type = ?")
                    params.append(writeup_type)
                if challenge_type:
                    where_clauses.append("w.challenge_type = ?")
                    params.append(challenge_type)
                if tags:
                    tag_list = sorted({t.lower().lstrip('#') for t in tags})
                    placeholders = ','.join('?' * len(tag_list))
                    where_clauses.append(f"""
                        w.id IN (
                            SELECT wt.writeup_id FROM writeup_tags wt
                            JOIN tags tg ON wt.tag_id = tg.id
                            WHERE LOWER(tg.name) IN ({placeholders})
                            GROUP BY wt.writeup_id
                            HAVING COUNT(DISTINCT tg.id) = ?
                        )
                    """)
                    params.extend(tag_list)
                    params.append(len(tag_list))

                if where_clauses:
                    joiner = " AND " if fts_query else " WHERE "
                    base_query += joiner + " AND ".join(where_clauses)

                if rank and fts_query:
                    base_query += " ORDER BY bm25(commands_fts, 10.0, 2.0, 0.2), c.id"
                base_query += " LIMIT ?"
                params.append(max(1, min(int(limit), 100)))
                return base_query, params

            # Try AND first (precise)
            and_q, and_p = _build_cmd_query(
                _build_fts_query(query) if query else None
            )
            rows = conn.execute(and_q, and_p).fetchall()
            match_mode = 'all_terms' if query else 'filtered'

            # Fallback to ranked OR if AND returned nothing and query is multi-word
            if not rows and query and len(_tokenize_fts(query)) > 1:
                match_mode = 'any_terms'
                or_q, or_p = _build_cmd_query(
                    _build_fts_query_or(query), rank=True
                )
                rows = conn.execute(or_q, or_p).fetchall()

            return [
                CommandResult(
                    id=row['id'],
                    match_mode=match_mode,
                    tool=row['tool_name'],
                    raw_command=row['raw_command'],
                    template=row['command_template'],
                    purpose=row['purpose'],
                    source={
                        'file': row['filename'],
                        'type': row['writeup_type'],
                        'section': row['source_section'],
                        'challenge_type': row['challenge_type']
                    }
                )
                for row in rows
            ]

    # =========================================================================
    # SCRIPT OPERATIONS
    # =========================================================================

    def insert_script(self, script: Script) -> int:
        """Insert a script and return its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO scripts
                   (id, writeup_id, language, code, purpose, libraries_used, source_section)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (script.id, script.writeup_id, script.language, script.code,
                 script.purpose, json.dumps(script.libraries_used),
                 script.source_section)
            )
            conn.commit()
            return cursor.lastrowid

    def search_scripts(
        self,
        query: Optional[str] = None,
        language: Optional[str] = None,
        library: Optional[str] = None,
        challenge_type: Optional[str] = None,
        limit: int = 10
    ) -> list[ScriptResult]:
        """Search scripts with AND-first, ranked-OR-fallback for FTS."""
        with self._get_connection() as conn:
            def _build_script_query(fts_query: Optional[str], rank: bool = True):
                params = []
                where_clauses = []

                if fts_query:
                    base_query = """
                        SELECT s.id, s.language, s.code, s.purpose, s.libraries_used,
                               w.filename, w.writeup_type, w.challenge_type
                        FROM scripts_fts fts
                        JOIN scripts s ON fts.rowid = s.id
                        LEFT JOIN writeups w ON s.writeup_id = w.id
                        WHERE scripts_fts MATCH ?
                    """
                    params.append(fts_query)
                else:
                    base_query = """
                        SELECT s.id, s.language, s.code, s.purpose, s.libraries_used,
                               w.filename, w.writeup_type, w.challenge_type
                        FROM scripts s
                        LEFT JOIN writeups w ON s.writeup_id = w.id
                    """

                if language:
                    canonical = {'py': 'python', 'js': 'javascript', 'ps1': 'powershell',
                                 'syzlang': 'syz'}.get(language.lower(), language.lower())
                    aliases = {'python': ('python', 'py'), 'javascript': ('javascript', 'js'),
                               'powershell': ('powershell', 'ps1'), 'syz': ('syz', 'syzlang')}.get(canonical, (canonical,))
                    where_clauses.append('s.language IN (' + ','.join('?' for _ in aliases) + ')')
                    params.extend(aliases)
                if library:
                    where_clauses.append("s.libraries_used LIKE ? ESCAPE '\\'")
                    escaped_lib = library.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                    params.append(f'%"{escaped_lib}"%')
                if challenge_type:
                    where_clauses.append("w.challenge_type = ?")
                    params.append(challenge_type)

                if where_clauses:
                    joiner = " AND " if fts_query else " WHERE "
                    base_query += joiner + " AND ".join(where_clauses)

                if rank and fts_query:
                    base_query += " ORDER BY bm25(scripts_fts)"
                base_query += " LIMIT ?"
                params.append(max(1, min(int(limit), 100)))
                return base_query, params

            # Try AND first (precise)
            and_q, and_p = _build_script_query(
                _build_fts_query(query) if query else None
            )
            rows = conn.execute(and_q, and_p).fetchall()
            match_mode = 'all_terms' if query else 'filtered'

            # Fallback to ranked OR if AND returned nothing and query is multi-word
            if not rows and query and len(_tokenize_fts(query)) > 1:
                match_mode = 'any_terms'
                or_q, or_p = _build_script_query(
                    _build_fts_query_or(query), rank=True
                )
                rows = conn.execute(or_q, or_p).fetchall()

            results = []
            for row in rows:
                code = row['code']
                code_preview = '\n'.join(code.split('\n')[:10])
                if len(code.split('\n')) > 10:
                    code_preview += '\n...'

                libraries = json.loads(row['libraries_used']) if row['libraries_used'] else []

                results.append(ScriptResult(
                    id=row['id'],
                    match_mode=match_mode,
                    language=row['language'],
                    purpose=row['purpose'],
                    libraries=libraries,
                    code_preview=code_preview,
                    source={
                        'file': row['filename'],
                        'type': row['writeup_type'],
                        'challenge_type': row['challenge_type']
                    }
                ))

            return results

    def list_libraries(self) -> list[dict]:
        """List all libraries found in indexed scripts with counts."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT libraries_used FROM scripts WHERE libraries_used IS NOT NULL"
            ).fetchall()
            libs: dict[str, int] = {}
            for row in rows:
                for lib in json.loads(row['libraries_used']):
                    libs[lib] = libs.get(lib, 0) + 1
            return [
                {'library': lib, 'count': count}
                for lib, count in sorted(libs.items(), key=lambda x: -x[1])
            ]

    def get_script_by_id(self, script_id: int) -> Optional[dict]:
        """Get full script code by ID."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT s.id, s.language, s.code, s.purpose, s.libraries_used,
                       s.source_section, w.filename, w.writeup_type, w.challenge_type
                FROM scripts s
                LEFT JOIN writeups w ON s.writeup_id = w.id
                WHERE s.id = ?
            """, (script_id,)).fetchone()

            if not row:
                return None

            libraries = json.loads(row['libraries_used']) if row['libraries_used'] else []
            return {
                'id': row['id'],
                'language': row['language'],
                'code': row['code'],
                'purpose': row['purpose'],
                'libraries': libraries,
                'section': row['source_section'],
                'source': {
                    'file': row['filename'],
                    'type': row['writeup_type'],
                    'challenge_type': row['challenge_type']
                }
            }

    def get_commands_by_writeup(self, writeup_id: int) -> list[CommandResult]:
        """Get all commands for a specific writeup."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT c.id, c.raw_command, c.command_template, c.purpose,
                       c.source_section, t.name as tool_name, cat.name as category,
                       w.filename, w.writeup_type, w.challenge_type
                FROM commands c
                LEFT JOIN tools t ON c.tool_id = t.id
                LEFT JOIN categories cat ON t.category_id = cat.id
                LEFT JOIN writeups w ON c.writeup_id = w.id
                WHERE c.writeup_id = ?
            """, (writeup_id,)).fetchall()

            return [
                CommandResult(
                    id=row['id'],
                    tool=row['tool_name'],
                    raw_command=row['raw_command'],
                    template=row['command_template'],
                    purpose=row['purpose'],
                    source={
                        'file': row['filename'],
                        'type': row['writeup_type'],
                        'section': row['source_section'],
                        'challenge_type': row['challenge_type']
                    }
                )
                for row in rows
            ]

    def get_scripts_by_writeup(self, writeup_id: int) -> list[ScriptResult]:
        """Get all scripts for a specific writeup."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT s.id, s.language, s.code, s.purpose, s.libraries_used,
                       w.filename, w.writeup_type, w.challenge_type
                FROM scripts s
                LEFT JOIN writeups w ON s.writeup_id = w.id
                WHERE s.writeup_id = ?
            """, (writeup_id,)).fetchall()

            results = []
            for row in rows:
                code = row['code']
                code_preview = '\n'.join(code.split('\n')[:10])
                if len(code.split('\n')) > 10:
                    code_preview += '\n...'

                libraries = json.loads(row['libraries_used']) if row['libraries_used'] else []

                results.append(ScriptResult(
                    id=row['id'],
                    language=row['language'],
                    purpose=row['purpose'],
                    libraries=libraries,
                    code_preview=code_preview,
                    source={
                        'file': row['filename'],
                        'type': row['writeup_type'],
                        'challenge_type': row['challenge_type']
                    }
                ))

            return results

    # =========================================================================
    # LISTING OPERATIONS
    # =========================================================================

    def list_tools(
        self,
        category: Optional[str] = None,
        writeup_type: Optional[str] = None
    ) -> list[ToolInfo]:
        """List tools with command counts."""
        with self._get_connection() as conn:
            params = []
            where_clause = ""

            query = """
                SELECT t.name, cat.name as category, COUNT(c.id) as cmd_count
                FROM tools t
                LEFT JOIN categories cat ON t.category_id = cat.id
                LEFT JOIN commands c ON t.id = c.tool_id
                LEFT JOIN writeups w ON c.writeup_id = w.id
            """

            if category:
                where_clause = "WHERE cat.name = ?"
                params.append(category)

            if writeup_type:
                if where_clause:
                    where_clause += " AND w.writeup_type = ?"
                else:
                    where_clause = "WHERE w.writeup_type = ?"
                params.append(writeup_type)

            query += where_clause + " GROUP BY t.id ORDER BY cmd_count DESC"

            rows = conn.execute(query, params).fetchall()

            return [
                ToolInfo(
                    name=row['name'],
                    category=row['category'],
                    command_count=row['cmd_count']
                )
                for row in rows
            ]

    def list_categories(self) -> list[CategoryInfo]:
        """List categories with counts."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT cat.name, cat.description,
                       COUNT(DISTINCT t.id) as tool_count,
                       COUNT(c.id) as cmd_count
                FROM categories cat
                LEFT JOIN tools t ON cat.id = t.category_id
                LEFT JOIN commands c ON t.id = c.tool_id
                GROUP BY cat.id
                ORDER BY cmd_count DESC
            """).fetchall()

            return [
                CategoryInfo(
                    name=row['name'],
                    description=row['description'],
                    tool_count=row['tool_count'],
                    command_count=row['cmd_count']
                )
                for row in rows
            ]

    def list_tags(self, min_count: int = 1) -> list[dict]:
        """
        List all tags with their usage counts.

        Args:
            min_count: Minimum writeup count to include a tag (default 1)

        Returns:
            List of dicts with 'name', 'writeup_count', 'command_count'
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT t.name,
                       COUNT(DISTINCT wt.writeup_id) as writeup_count,
                       (SELECT COUNT(*) FROM commands c
                        WHERE c.writeup_id IN (
                            SELECT wt2.writeup_id FROM writeup_tags wt2
                            WHERE wt2.tag_id = t.id
                        )) as command_count
                FROM tags t
                LEFT JOIN writeup_tags wt ON t.id = wt.tag_id
                GROUP BY t.id
                HAVING writeup_count >= ?
                ORDER BY writeup_count DESC, t.name
            """, (min_count,)).fetchall()

            return [
                {
                    'name': row['name'],
                    'writeup_count': row['writeup_count'],
                    'command_count': row['command_count']
                }
                for row in rows
            ]

    def get_stats(self) -> VaultStats:
        """Get database statistics."""
        with self._get_connection() as conn:
            # Writeup counts
            writeup_stats = {'total': 0, 'boxes': 0, 'challenges': 0, 'sherlocks': 0, 'research': 0}
            type_to_plural = {
                'box': 'boxes', 'challenge': 'challenges', 'sherlock': 'sherlocks', 'research': 'research',
            }
            for row in conn.execute(
                "SELECT writeup_type, COUNT(*) as cnt FROM writeups GROUP BY writeup_type"
            ).fetchall():
                plural_key = type_to_plural.get(row['writeup_type'], row['writeup_type'] + 's')
                writeup_stats[plural_key] = row['cnt']
                writeup_stats['total'] += row['cnt']

            # Command counts
            cmd_total = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
            cmd_by_cat = {}
            for row in conn.execute("""
                SELECT cat.name, COUNT(c.id) as cnt
                FROM commands c
                JOIN tools t ON c.tool_id = t.id
                JOIN categories cat ON t.category_id = cat.id
                GROUP BY cat.name
                ORDER BY cnt DESC
            """).fetchall():
                cmd_by_cat[row['name']] = row['cnt']

            # Script counts
            script_total = conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0]
            script_by_lang = {}
            for row in conn.execute(
                "SELECT language, COUNT(*) as cnt FROM scripts GROUP BY language"
            ).fetchall():
                script_by_lang[row['language']] = row['cnt']

            # Tool counts
            tool_total = conn.execute("SELECT COUNT(*) FROM tools").fetchone()[0]
            # Exclude common non-security tools and garbage from top_10
            excluded_tools = (
                'cat', 'ls', 'cd', 'echo', 'pwd', 'cp', 'mv', 'rm', 'mkdir',
                'chmod', 'chown', 'grep', 'find', 'head', 'tail', 'less', 'more',
                'vi', 'vim', 'nano', 'touch', 'file', 'which', 'whoami', 'id',
                'export', 'source', 'alias', 'unset', 'set', 'env', 'printenv',
                'post', 'get', 'put', 'delete',  # HTTP verbs from output
                '│', '├', '└', '─', '|', '-', '--', '>'  # Table/output garbage
            )
            placeholders = ','.join('?' * len(excluded_tools))
            top_tools = [row['name'] for row in conn.execute(f"""
                SELECT t.name, COUNT(c.id) as cnt
                FROM tools t
                JOIN commands c ON t.id = c.tool_id
                WHERE t.name NOT IN ({placeholders})
                AND length(t.name) > 1
                GROUP BY t.id
                ORDER BY cnt DESC
                LIMIT 10
            """, excluded_tools).fetchall()]

            # Chunk counts
            chunk_stats = None
            try:
                chunk_total = conn.execute("SELECT COUNT(*) FROM writeup_chunks").fetchone()[0]
                if chunk_total > 0:
                    chunk_stats = {'total': chunk_total}
            except Exception:
                pass

            # History stats
            history_stats = None
            try:
                history_total = conn.execute("SELECT COUNT(*) FROM history_commands").fetchone()[0]
                if history_total > 0:
                    history_unique_tools = conn.execute(
                        "SELECT COUNT(DISTINCT tool_id) FROM history_commands WHERE tool_id IS NOT NULL"
                    ).fetchone()[0]

                    history_top_tools = []
                    for row in conn.execute("""
                        SELECT t.name, COUNT(h.id) as cnt
                        FROM history_commands h
                        JOIN tools t ON h.tool_id = t.id
                        GROUP BY t.id
                        ORDER BY cnt DESC
                        LIMIT 5
                    """).fetchall():
                        history_top_tools.append({'tool': row['name'], 'count': row['cnt']})

                    history_sources = {}
                    for row in conn.execute(
                        "SELECT source_file, COUNT(*) as cnt FROM history_commands GROUP BY source_file"
                    ).fetchall():
                        history_sources[row['source_file']] = row['cnt']

                    history_stats = {
                        'total': history_total,
                        'unique_tools': history_unique_tools,
                        'top_tools': history_top_tools,
                        'sources': history_sources
                    }
            except Exception:
                pass  # Table might not exist in older databases

            return VaultStats(
                writeups=writeup_stats,
                commands={'total': cmd_total, 'by_category': cmd_by_cat},
                scripts={'total': script_total, 'by_language': script_by_lang},
                tools={'total': tool_total, 'top_10': top_tools},
                chunks=chunk_stats,
                history=history_stats,
                research=self._get_research_stats(conn, writeup_stats['research']),
            )

    def _get_research_stats(self, conn: sqlite3.Connection, document_count: int) -> dict:
        """Count research metadata without reading document or artifact content."""
        result = {
            'documents': 0,
            'source_collections': 0,
            'vulnerabilities': 0,
            'operational_stages': 0,
            'evidence_links': 0,
            'validation_records': 0,
            'mitigations': 0,
            'by_source': {},
            'by_domain': {},
            'validation_by_status': {},
        }
        if conn.execute('PRAGMA user_version').fetchone()[0] < 2:
            return result
        result['documents'] = document_count
        for table in (
            'source_collections', 'vulnerabilities', 'operational_stages',
            'evidence_links', 'validation_records', 'mitigations',
        ):
            result[table] = conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
        result['by_source'] = {
            row['name']: row['cnt'] for row in conn.execute('''
                SELECT s.name, COUNT(*) AS cnt
                FROM source_collections s JOIN writeups w ON w.source_collection_id=s.id
                WHERE w.writeup_type=?
                GROUP BY s.name ORDER BY s.name
            ''', ('research',))
        }
        result['by_domain'] = {
            row['domain']: row['cnt'] for row in conn.execute('''
                SELECT domain, COUNT(*) AS cnt FROM writeups
                WHERE writeup_type=? AND domain IS NOT NULL AND domain<>?
                GROUP BY domain ORDER BY domain
            ''', ('research', ''))
        }
        result['validation_by_status'] = {
            row['status']: row['cnt'] for row in conn.execute('''
                SELECT status, COUNT(*) AS cnt FROM validation_records
                WHERE status IS NOT NULL AND status<>?
                GROUP BY status ORDER BY status
            ''', ('',))
        }
        return result

    def clear_writeup_data(self, writeup_id: int):
        """Clear commands, scripts, chunks, and technique links for a writeup (for re-indexing)."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM commands WHERE writeup_id = ?", (writeup_id,))
            conn.execute("DELETE FROM scripts WHERE writeup_id = ?", (writeup_id,))
            conn.execute("DELETE FROM writeup_chunks WHERE writeup_id = ?", (writeup_id,))
            conn.execute("DELETE FROM technique_writeups WHERE writeup_id = ?", (writeup_id,))
            conn.commit()

    # =========================================================================
    # CHUNK OPERATIONS
    # =========================================================================

    def insert_chunk(self, writeup_id: int, section: str, content: str, chunk_index: int,
                     record_id: Optional[int] = None) -> int:
        """Insert a prose chunk and return its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO writeup_chunks (id, writeup_id, section, content, chunk_index)
                   VALUES (?, ?, ?, ?, ?)""",
                (record_id, writeup_id, section, content, chunk_index)
            )
            conn.commit()
            return cursor.lastrowid

    def search_chunks(
        self,
        query: str,
        writeup_type: Optional[str] = None,
        tags: Optional[list[str]] = None,
        limit: int = 10
    ) -> list[ChunkResult]:
        """Search prose chunks via FTS with AND-first, ranked-OR-fallback.

        Multi-word queries try AND first (all words required).
        If AND returns no results, falls back to OR with bm25() ranking
        so the most relevant matches surface to the top.
        """
        with self._get_connection() as conn:
            def _build_chunk_query(fts_query: str, rank: bool = True):
                params = []
                base_query = """
                    SELECT ch.id, ch.section, ch.content,
                           w.filename, w.writeup_type, w.title
                    FROM writeup_chunks_fts fts
                    JOIN writeup_chunks ch ON fts.rowid = ch.id
                    LEFT JOIN writeups w ON ch.writeup_id = w.id
                    WHERE writeup_chunks_fts MATCH ?
                """
                params.append(fts_query)

                if writeup_type:
                    base_query += " AND w.writeup_type = ?"
                    params.append(writeup_type)

                if tags:
                    tag_list = sorted({t.lower().lstrip('#') for t in tags})
                    placeholders = ','.join('?' * len(tag_list))
                    base_query += f"""
                        AND w.id IN (
                            SELECT wt.writeup_id FROM writeup_tags wt
                            JOIN tags tg ON wt.tag_id = tg.id
                            WHERE LOWER(tg.name) IN ({placeholders})
                            GROUP BY wt.writeup_id
                            HAVING COUNT(DISTINCT tg.id) = ?
                        )
                    """
                    params.extend(tag_list)
                    params.append(len(tag_list))

                if rank:
                    base_query += " ORDER BY bm25(writeup_chunks_fts)"
                base_query += " LIMIT ?"
                params.append(max(1, min(int(limit), 100)))
                return base_query, params

            # Try AND first (precise)
            and_query, and_params = _build_chunk_query(_build_fts_query(query))
            rows = conn.execute(and_query, and_params).fetchall()

            # Fallback to ranked OR if AND returned nothing and query is multi-word
            if not rows and len(_tokenize_fts(query)) > 1:
                or_query, or_params = _build_chunk_query(
                    _build_fts_query_or(query), rank=True
                )
                rows = conn.execute(or_query, or_params).fetchall()

            return [
                ChunkResult(
                    id=row['id'],
                    section=row['section'],
                    content=row['content'],
                    source={
                        'filename': row['filename'],
                        'writeup_type': row['writeup_type'],
                        'title': row['title']
                    }
                )
                for row in rows
            ]

    def get_indexed_filenames(self) -> set[str]:
        """Get set of all indexed writeup filenames."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT filename FROM writeups").fetchall()
            return {row['filename'] for row in rows}

    def get_writeup_count(self) -> int:
        """Get total number of indexed writeups."""
        with self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM writeups").fetchone()[0]

    # =========================================================================
    # TECHNIQUE OPERATIONS
    # =========================================================================

    def get_or_create_technique(self, canonical_name: str, technique_type: Optional[str] = None) -> int:
        """Get technique ID, creating if necessary."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT id FROM techniques WHERE canonical_name = ?",
                (canonical_name,)
            ).fetchone()
            if row:
                return row['id']
            cursor = conn.execute(
                "INSERT INTO techniques (canonical_name, technique_type) VALUES (?, ?)",
                (canonical_name, technique_type)
            )
            conn.commit()
            return cursor.lastrowid

    def link_technique_writeup(self, technique_id: int, writeup_id: int):
        """Link a technique to a writeup."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO technique_writeups (technique_id, writeup_id) VALUES (?, ?)",
                (technique_id, writeup_id)
            )
            conn.commit()

    def search_related(self, technique: str, limit: int = 20) -> list[dict]:
        """Search for writeups related to a technique."""
        with self._get_connection() as conn:
            # Find technique by name (exact, then LIKE)
            tech_row = conn.execute(
                "SELECT id, canonical_name, technique_type FROM techniques WHERE LOWER(canonical_name) = LOWER(?)",
                (technique,)
            ).fetchone()
            if not tech_row:
                tech_row = conn.execute(
                    "SELECT id, canonical_name, technique_type FROM techniques WHERE LOWER(canonical_name) LIKE LOWER(?)",
                    (f'%{technique}%',)
                ).fetchone()
            if not tech_row:
                return []

            # Get writeups for this technique
            rows = conn.execute("""
                SELECT w.id as writeup_id, w.filename, w.title, w.writeup_type, w.difficulty, w.content_hash
                FROM technique_writeups tw
                JOIN writeups w ON tw.writeup_id = w.id
                WHERE tw.technique_id = ?
                ORDER BY w.filename
                LIMIT ?
            """, (tech_row['id'], limit)).fetchall()

            writeups = []
            for row in rows:
                # Get tools used in this writeup
                tools = conn.execute("""
                    SELECT DISTINCT t.name FROM commands c
                    JOIN tools t ON c.tool_id = t.id
                    WHERE c.writeup_id = ?
                    ORDER BY t.name
                """, (row['writeup_id'],)).fetchall()

                # Get tags
                tags = self._get_writeup_tags(conn, row['writeup_id'])

                writeups.append({
                    'document_id': row['writeup_id'],
                    'revision': row['content_hash'],
                    'filename': row['filename'],
                    'title': row['title'],
                    'type': row['writeup_type'],
                    'difficulty': row['difficulty'],
                    'tools': [t['name'] for t in tools],
                    'tags': tags,
                })

            return [{
                'technique': tech_row['canonical_name'],
                'type': tech_row['technique_type'],
                'writeup_count': len(writeups),
                'writeups': writeups
            }]

    def list_techniques(self, min_writeups: int = 1) -> list[dict]:
        """List all techniques with writeup counts."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT t.canonical_name, t.technique_type,
                       COUNT(tw.writeup_id) as writeup_count
                FROM techniques t
                LEFT JOIN technique_writeups tw ON t.id = tw.technique_id
                GROUP BY t.id
                HAVING writeup_count >= ?
                ORDER BY writeup_count DESC
            """, (min_writeups,)).fetchall()

            return [
                {
                    'technique': row['canonical_name'],
                    'type': row['technique_type'],
                    'writeup_count': row['writeup_count']
                }
                for row in rows
            ]

    # =========================================================================
    # HISTORY OPERATIONS
    # =========================================================================

    def get_history_hashes(self) -> set[str]:
        """Get all existing history command hashes for deduplication."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT command_hash FROM history_commands").fetchall()
            return {row['command_hash'] for row in rows}

    def insert_history_command(
        self,
        command_hash: str,
        raw_command: str,
        sanitized_command: str,
        command_template: Optional[str],
        tool_id: Optional[int],
        timestamp: Optional[str],
        source_file: str,
        shell_type: str = 'zsh',
        occurrence_count: int = 1,
        first_timestamp: Optional[str] = None
    ) -> tuple[int, bool]:
        """
        Insert a history command or update if exists.

        Returns:
            (command_id, is_new) - ID and whether it was newly inserted
        """
        with self._get_connection() as conn:
            # Check if exists
            first_timestamp = first_timestamp or timestamp
            existing = conn.execute(
                "SELECT id, occurrence_count FROM history_commands WHERE command_hash = ?",
                (command_hash,)
            ).fetchone()

            if existing:
                # Update occurrence count and last_seen
                conn.execute(
                    """UPDATE history_commands
                       SET occurrence_count = MAX(occurrence_count, ?),
                           first_seen = CASE WHEN first_seen IS NULL THEN ? WHEN ? IS NULL THEN first_seen ELSE MIN(first_seen, ?) END,
                           last_seen = CASE WHEN last_seen IS NULL THEN ? WHEN ? IS NULL THEN last_seen ELSE MAX(last_seen, ?) END
                       WHERE id = ?""",
                    (occurrence_count, first_timestamp, first_timestamp, first_timestamp, timestamp, timestamp, timestamp, existing['id'])
                )
                conn.commit()
                return existing['id'], False

            # Insert new
            cursor = conn.execute(
                """INSERT INTO history_commands
                   (command_hash, raw_command, sanitized_command, command_template,
                    tool_id, first_seen, last_seen, occurrence_count, source_file, shell_type)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (command_hash, raw_command, sanitized_command, command_template,
                 tool_id, first_timestamp, timestamp, occurrence_count, source_file, shell_type)
            )
            conn.commit()
            return cursor.lastrowid, True

    def search_history(
        self,
        query: Optional[str] = None,
        tool: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 20
    ) -> list[dict]:
        """Search history commands with AND-first, ranked-OR-fallback for FTS."""
        with self._get_connection() as conn:
            def _build_hist_query(fts_query: Optional[str], rank: bool = False):
                params = []
                where_clauses = []

                if fts_query:
                    base_query = """
                        SELECT h.id, h.sanitized_command, h.command_template,
                               h.first_seen, h.last_seen, h.occurrence_count,
                               t.name as tool_name
                        FROM history_fts fts
                        JOIN history_commands h ON fts.rowid = h.id
                        LEFT JOIN tools t ON h.tool_id = t.id
                        WHERE history_fts MATCH ?
                    """
                    params.append(fts_query)
                else:
                    base_query = """
                        SELECT h.id, h.sanitized_command, h.command_template,
                               h.first_seen, h.last_seen, h.occurrence_count,
                               t.name as tool_name
                        FROM history_commands h
                        LEFT JOIN tools t ON h.tool_id = t.id
                    """

                if tool:
                    where_clauses.append("t.name LIKE ? ESCAPE '\\'")
                    escaped_tool = tool.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                    params.append(f"%{escaped_tool}%")
                if since:
                    where_clauses.append("julianday(h.last_seen) >= julianday(?)")
                    params.append(since)

                if where_clauses:
                    joiner = " AND " if fts_query else " WHERE "
                    base_query += joiner + " AND ".join(where_clauses)

                if rank:
                    base_query += " ORDER BY bm25(history_fts)"
                else:
                    base_query += " ORDER BY h.last_seen DESC"
                base_query += " LIMIT ?"
                params.append(max(1, min(int(limit), 100)))
                return base_query, params

            # Try AND first (precise)
            and_q, and_p = _build_hist_query(
                _build_fts_query(query) if query else None
            )
            rows = conn.execute(and_q, and_p).fetchall()

            # Fallback to ranked OR if AND returned nothing and query is multi-word
            if not rows and query and len(_tokenize_fts(query)) > 1:
                or_q, or_p = _build_hist_query(
                    _build_fts_query_or(query), rank=True
                )
                rows = conn.execute(or_q, or_p).fetchall()

            return [
                {
                    'id': row['id'],
                    'tool': row['tool_name'],
                    'sanitized_command': row['sanitized_command'],
                    'template': row['command_template'],
                    'first_seen': row['first_seen'],
                    'last_seen': row['last_seen'],
                    'occurrence_count': row['occurrence_count'],
                    'source': 'history'
                }
                for row in rows
            ]

    def get_history_stats(self) -> dict:
        """Get statistics about indexed history commands."""
        with self._get_connection() as conn:
            # Total commands
            total = conn.execute("SELECT COUNT(*) FROM history_commands").fetchone()[0]

            # Unique tools
            unique_tools = conn.execute(
                "SELECT COUNT(DISTINCT tool_id) FROM history_commands WHERE tool_id IS NOT NULL"
            ).fetchone()[0]

            # Date range
            date_range = conn.execute(
                "SELECT MIN(first_seen) as first, MAX(last_seen) as last FROM history_commands"
            ).fetchone()

            # By source file
            by_source = {}
            for row in conn.execute(
                "SELECT source_file, COUNT(*) as cnt FROM history_commands GROUP BY source_file"
            ).fetchall():
                by_source[row['source_file']] = row['cnt']

            # Top tools
            top_tools = []
            for row in conn.execute("""
                SELECT t.name, COUNT(h.id) as cnt
                FROM history_commands h
                JOIN tools t ON h.tool_id = t.id
                GROUP BY t.id
                ORDER BY cnt DESC
                LIMIT 10
            """).fetchall():
                top_tools.append({'tool': row['name'], 'count': row['cnt']})

            return {
                'total_commands': total,
                'unique_tools': unique_tools,
                'date_range': {
                    'first': date_range['first'],
                    'last': date_range['last']
                },
                'by_source_file': by_source,
                'top_tools': top_tools
            }

    def clear_history(
        self,
        before: Optional[str] = None,
        source_file: Optional[str] = None
    ) -> int:
        """
        Clear history commands.

        Args:
            before: Clear commands before this datetime
            source_file: Clear commands from this specific file only

        Returns:
            Number of commands deleted
        """
        with self._get_connection() as conn:
            where_clauses = []
            params = []

            if before:
                where_clauses.append("last_seen < ?")
                params.append(before)

            if source_file:
                where_clauses.append("source_file = ?")
                params.append(source_file)

            if where_clauses:
                query = f"DELETE FROM history_commands WHERE {' AND '.join(where_clauses)}"
            else:
                query = "DELETE FROM history_commands"

            cursor = conn.execute(query, params)
            deleted = cursor.rowcount
            conn.commit()

            logger.info(f"Cleared {deleted} history commands")
            return deleted

    def maintain(
        self,
        vacuum: bool = False,
        analyze: bool = False,
        optimize_fts: bool = False
    ) -> dict:
        """
        Perform database maintenance tasks.

        Args:
            vacuum: Reclaim disk space and defragment
            analyze: Update query planner statistics
            optimize_fts: Optimize FTS5 indexes

        Returns:
            Dict with results of each operation
        """
        import os
        results = {
            'vacuum': None,
            'analyze': None,
            'optimize_fts': None,
            'size_before': None,
            'size_after': None
        }

        # Get size before
        if os.path.exists(self.db_path):
            results['size_before'] = os.path.getsize(self.db_path)

        with self._get_connection() as conn:
            # VACUUM - reclaim space (must be outside transaction)
            if vacuum:
                try:
                    conn.execute("VACUUM")
                    results['vacuum'] = 'ok'
                    logger.info("VACUUM completed")
                except Exception as e:
                    results['vacuum'] = f'error: {str(e)}'
                    logger.error(f"VACUUM failed: {e}")

            # ANALYZE - update statistics
            if analyze:
                try:
                    conn.execute("ANALYZE")
                    results['analyze'] = 'ok'
                    logger.info("ANALYZE completed")
                except Exception as e:
                    results['analyze'] = f'error: {str(e)}'
                    logger.error(f"ANALYZE failed: {e}")

            # Optimize FTS indexes
            if optimize_fts:
                try:
                    fts_tables = ['commands_fts', 'scripts_fts', 'writeup_chunks_fts', 'history_fts']
                    optimized = []
                    for table in fts_tables:
                        try:
                            conn.execute(f"INSERT INTO {table}({table}) VALUES('optimize')")
                            optimized.append(table)
                        except sqlite3.OperationalError:
                            pass  # Table might not exist
                    results['optimize_fts'] = f'ok: {", ".join(optimized)}'
                    logger.info(f"FTS optimization completed: {optimized}")
                except Exception as e:
                    results['optimize_fts'] = f'error: {str(e)}'
                    logger.error(f"FTS optimization failed: {e}")

        # Get size after
        if os.path.exists(self.db_path):
            results['size_after'] = os.path.getsize(self.db_path)

        # Calculate space saved
        if results['size_before'] and results['size_after']:
            saved = results['size_before'] - results['size_after']
            results['space_saved'] = saved
            results['space_saved_human'] = f"{saved / 1024:.1f} KB" if saved > 0 else "0 KB"

        return results
