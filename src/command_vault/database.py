"""SQLite database operations for Command Vault."""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from .models import (
    Writeup, Tool, Command, Script,
    CommandResult, ScriptResult, ToolInfo, CategoryInfo, VaultStats,
    WriteupType
)
from .categories import get_tool_category, get_category_description, CATEGORIES

logger = logging.getLogger(__name__)


def _build_fts_query(query: str) -> str:
    """Build an FTS5 query from user input.

    Tokenizes input and joins with OR so multi-word queries like
    "certipy ESC" match documents containing either word, not just
    the exact phrase.  Single-word queries pass through unchanged.
    FTS5 special characters are stripped to prevent syntax errors.
    """
    # Strip FTS5 operators/special chars that could cause syntax errors
    cleaned = query.replace('"', ' ').replace("'", ' ')
    tokens = cleaned.split()
    if not tokens:
        return '""'
    if len(tokens) == 1:
        # Single word: quote it for safe literal match
        return '"' + tokens[0] + '"'
    # Multi-word: each token quoted, joined with OR
    return ' OR '.join('"' + t + '"' for t in tokens)


SCHEMA = """
-- Writeup sources metadata
CREATE TABLE IF NOT EXISTS writeups (
    id INTEGER PRIMARY KEY,
    filename TEXT UNIQUE NOT NULL,
    filepath TEXT NOT NULL,
    writeup_type TEXT NOT NULL,
    challenge_type TEXT,
    difficulty TEXT,
    title TEXT,
    indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_commands_tool ON commands(tool_id);
CREATE INDEX IF NOT EXISTS idx_commands_writeup ON commands(writeup_id);
CREATE INDEX IF NOT EXISTS idx_scripts_writeup ON scripts(writeup_id);
CREATE INDEX IF NOT EXISTS idx_writeups_type ON writeups(writeup_type);
CREATE INDEX IF NOT EXISTS idx_writeups_challenge_type ON writeups(challenge_type);
CREATE INDEX IF NOT EXISTS idx_tools_category ON tools(category_id);
CREATE INDEX IF NOT EXISTS idx_history_hash ON history_commands(command_hash);
CREATE INDEX IF NOT EXISTS idx_history_tool ON history_commands(tool_id);
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


class Database:
    """SQLite database wrapper for Command Vault."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript(SCHEMA)
            conn.executescript(FTS_SCHEMA)
            self._seed_categories(conn)
            conn.commit()

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
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def reset(self):
        """Drop all tables and recreate schema."""
        with self._get_connection() as conn:
            # Drop FTS tables first (triggers depend on them)
            conn.execute("DROP TABLE IF EXISTS commands_fts")
            conn.execute("DROP TABLE IF EXISTS scripts_fts")
            conn.execute("DROP TABLE IF EXISTS history_fts")

            # Drop triggers
            for trigger in ['commands_ai', 'commands_ad', 'commands_au',
                           'scripts_ai', 'scripts_ad', 'scripts_au',
                           'history_ai', 'history_ad', 'history_au']:
                conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")

            # Drop main tables
            for table in ['command_tags', 'writeup_tags', 'commands', 'scripts',
                         'writeups', 'tools', 'tags', 'categories', 'history_commands']:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
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
                   ON CONFLICT(filename) DO UPDATE SET
                   filepath=excluded.filepath,
                   writeup_type=excluded.writeup_type,
                   challenge_type=excluded.challenge_type,
                   difficulty=excluded.difficulty,
                   title=excluded.title,
                   indexed_at=CURRENT_TIMESTAMP""",
                (writeup.filename, writeup.filepath, writeup.writeup_type.value,
                 writeup.challenge_type, writeup.difficulty, writeup.title)
            )
            conn.commit()

            # Get the ID (either inserted or existing)
            row = conn.execute(
                "SELECT id FROM writeups WHERE filename = ?",
                (writeup.filename,)
            ).fetchone()
            writeup_id = row['id']

            # Handle tags
            if writeup.tags:
                self._set_writeup_tags(conn, writeup_id, writeup.tags)
                conn.commit()

            return writeup_id

    def get_writeup_by_filename(self, filename: str) -> Optional[Writeup]:
        """Get writeup by filename."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM writeups WHERE filename = ?",
                (filename,)
            ).fetchone()

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
        """Search commands with various filters."""
        with self._get_connection() as conn:
            params = []
            where_clauses = []

            base_query = """
                SELECT c.id, c.raw_command, c.command_template, c.purpose,
                       c.source_section, t.name as tool_name, cat.name as category,
                       w.filename, w.writeup_type, w.challenge_type
                FROM commands c
                LEFT JOIN tools t ON c.tool_id = t.id
                LEFT JOIN categories cat ON t.category_id = cat.id
                LEFT JOIN writeups w ON c.writeup_id = w.id
            """

            # FTS search
            if query:
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
                params.append(_build_fts_query(query))

            # Tool filter
            if tool:
                where_clauses.append("t.name LIKE ?")
                params.append(f"%{tool}%")

            # Category filter
            if category:
                where_clauses.append("cat.name = ?")
                params.append(category)

            # Writeup type filter
            if writeup_type:
                where_clauses.append("w.writeup_type = ?")
                params.append(writeup_type)

            # Challenge type filter
            if challenge_type:
                where_clauses.append("w.challenge_type = ?")
                params.append(challenge_type)

            # Tag filter - filter by writeup tags (AND logic: all tags must match)
            if tags:
                tag_list = [t.lower() for t in tags]
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

            # Build final query
            if where_clauses:
                if query:
                    base_query += " AND " + " AND ".join(where_clauses)
                else:
                    base_query += " WHERE " + " AND ".join(where_clauses)

            base_query += " LIMIT ?"
            params.append(int(limit))

            rows = conn.execute(base_query, params).fetchall()

            results = []
            for row in rows:
                results.append(CommandResult(
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
                ))

            return results

    # =========================================================================
    # SCRIPT OPERATIONS
    # =========================================================================

    def insert_script(self, script: Script) -> int:
        """Insert a script and return its ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO scripts
                   (writeup_id, language, code, purpose, libraries_used, source_section)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (script.writeup_id, script.language, script.code,
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
        """Search scripts with various filters."""
        with self._get_connection() as conn:
            params = []
            where_clauses = []

            base_query = """
                SELECT s.id, s.language, s.code, s.purpose, s.libraries_used,
                       w.filename, w.writeup_type, w.challenge_type
                FROM scripts s
                LEFT JOIN writeups w ON s.writeup_id = w.id
            """

            # FTS search
            if query:
                base_query = """
                    SELECT s.id, s.language, s.code, s.purpose, s.libraries_used,
                           w.filename, w.writeup_type, w.challenge_type
                    FROM scripts_fts fts
                    JOIN scripts s ON fts.rowid = s.id
                    LEFT JOIN writeups w ON s.writeup_id = w.id
                    WHERE scripts_fts MATCH ?
                """
                params.append(_build_fts_query(query))

            # Language filter
            if language:
                where_clauses.append("s.language = ?")
                params.append(language)

            # Library filter (search in JSON array)
            if library:
                where_clauses.append("s.libraries_used LIKE ?")
                params.append(f'%"{library}"%')

            # Challenge type filter
            if challenge_type:
                where_clauses.append("w.challenge_type = ?")
                params.append(challenge_type)

            # Build final query
            if where_clauses:
                if query:
                    base_query += " AND " + " AND ".join(where_clauses)
                else:
                    base_query += " WHERE " + " AND ".join(where_clauses)

            base_query += " LIMIT ?"
            params.append(int(limit))

            rows = conn.execute(base_query, params).fetchall()

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
            writeup_stats = {'total': 0, 'boxes': 0, 'challenges': 0, 'sherlocks': 0}
            type_to_plural = {'box': 'boxes', 'challenge': 'challenges', 'sherlock': 'sherlocks'}
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
                history=history_stats
            )

    def clear_writeup_data(self, writeup_id: int):
        """Clear commands and scripts for a writeup (for re-indexing)."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM commands WHERE writeup_id = ?", (writeup_id,))
            conn.execute("DELETE FROM scripts WHERE writeup_id = ?", (writeup_id,))
            conn.commit()

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
        shell_type: str = 'zsh'
    ) -> tuple[int, bool]:
        """
        Insert a history command or update if exists.

        Returns:
            (command_id, is_new) - ID and whether it was newly inserted
        """
        with self._get_connection() as conn:
            # Check if exists
            existing = conn.execute(
                "SELECT id, occurrence_count FROM history_commands WHERE command_hash = ?",
                (command_hash,)
            ).fetchone()

            if existing:
                # Update occurrence count and last_seen
                conn.execute(
                    """UPDATE history_commands
                       SET occurrence_count = occurrence_count + 1,
                           last_seen = COALESCE(?, last_seen)
                       WHERE id = ?""",
                    (timestamp, existing['id'])
                )
                conn.commit()
                return existing['id'], False

            # Insert new
            cursor = conn.execute(
                """INSERT INTO history_commands
                   (command_hash, raw_command, sanitized_command, command_template,
                    tool_id, first_seen, last_seen, occurrence_count, source_file, shell_type)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (command_hash, raw_command, sanitized_command, command_template,
                 tool_id, timestamp, timestamp, source_file, shell_type)
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
        """Search history commands."""
        with self._get_connection() as conn:
            params = []
            where_clauses = []

            base_query = """
                SELECT h.id, h.sanitized_command, h.command_template,
                       h.first_seen, h.last_seen, h.occurrence_count,
                       t.name as tool_name
                FROM history_commands h
                LEFT JOIN tools t ON h.tool_id = t.id
            """

            # FTS search
            if query:
                base_query = """
                    SELECT h.id, h.sanitized_command, h.command_template,
                           h.first_seen, h.last_seen, h.occurrence_count,
                           t.name as tool_name
                    FROM history_fts fts
                    JOIN history_commands h ON fts.rowid = h.id
                    LEFT JOIN tools t ON h.tool_id = t.id
                    WHERE history_fts MATCH ?
                """
                params.append(_build_fts_query(query))

            # Tool filter
            if tool:
                where_clauses.append("t.name LIKE ?")
                params.append(f"%{tool}%")

            # Date filter
            if since:
                where_clauses.append("h.first_seen >= ?")
                params.append(since)

            # Build final query
            if where_clauses:
                if query:
                    base_query += " AND " + " AND ".join(where_clauses)
                else:
                    base_query += " WHERE " + " AND ".join(where_clauses)

            base_query += " ORDER BY h.last_seen DESC LIMIT ?"
            params.append(int(limit))

            rows = conn.execute(base_query, params).fetchall()

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
                    fts_tables = ['commands_fts', 'scripts_fts', 'history_fts']
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
