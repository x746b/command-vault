"""MCP tool definitions for Command Vault."""

import logging
import time
from pathlib import Path
from typing import Optional

from .database import Database
from .indexer import Indexer
from .security import SecurityFilter
from .history_parser import HistoryParser
from .models import (
    CommandResult, ScriptResult, ToolInfo, CategoryInfo,
    VaultStats, IndexResult, HistoryIndexResult
)

logger = logging.getLogger(__name__)


class VaultTools:
    """MCP tools for Command Vault."""

    def __init__(self, db: Database, writeup_dirs: dict[str, str]):
        self.db = db
        self.writeup_dirs = writeup_dirs
        self.security = SecurityFilter()
        self.indexer = Indexer(db, self.security)

    def search_commands(
        self,
        query: Optional[str] = None,
        tool: Optional[str] = None,
        category: Optional[str] = None,
        writeup_type: Optional[str] = None,
        challenge_type: Optional[str] = None,
        tags: Optional[list[str]] = None,
        limit: int = 10
    ) -> list[dict]:
        """
        Search for commands by keyword, tool, or category.

        Args:
            query: Free-text search query
            tool: Filter by tool name
            category: Filter by category (recon, web, ad, etc.)
            writeup_type: Filter by source type (box, challenge, sherlock)
            challenge_type: Filter by challenge type (web, pwn, crypto, etc.)
            tags: Filter by tags
            limit: Maximum results to return

        Returns:
            List of matching commands
        """
        results = self.db.search_commands(
            query=query,
            tool=tool,
            category=category,
            writeup_type=writeup_type,
            challenge_type=challenge_type,
            tags=tags,
            limit=limit
        )

        return [r.model_dump() for r in results]

    def search_scripts(
        self,
        query: Optional[str] = None,
        language: Optional[str] = None,
        library: Optional[str] = None,
        challenge_type: Optional[str] = None,
        limit: int = 10
    ) -> list[dict]:
        """
        Search for exploit scripts.

        Args:
            query: Free-text search in code/purpose
            language: Filter by language (python, javascript, etc.)
            library: Filter by library used (pwn, frida, requests, etc.)
            challenge_type: Filter by challenge type
            limit: Maximum results

        Returns:
            List of matching scripts with preview
        """
        results = self.db.search_scripts(
            query=query,
            language=language,
            library=library,
            challenge_type=challenge_type,
            limit=limit
        )

        return [r.model_dump() for r in results]

    def get_tool_examples(
        self,
        tool_name: str,
        purpose: Optional[str] = None,
        writeup_type: Optional[str] = None,
        limit: int = 20
    ) -> list[dict]:
        """
        Get usage examples for a specific tool.

        Args:
            tool_name: Name of the tool (nmap, bloodhound-python, etc.)
            purpose: Optional filter by purpose
            writeup_type: Filter by source type
            limit: Maximum results

        Returns:
            List of command examples
        """
        results = self.db.search_commands(
            query=purpose,
            tool=tool_name,
            writeup_type=writeup_type,
            limit=limit
        )

        return [r.model_dump() for r in results]

    def list_tools(
        self,
        category: Optional[str] = None,
        writeup_type: Optional[str] = None
    ) -> list[dict]:
        """
        List available tools.

        Args:
            category: Filter by category
            writeup_type: Filter by source type

        Returns:
            List of tools with command counts
        """
        results = self.db.list_tools(category=category, writeup_type=writeup_type)
        return [r.model_dump() for r in results]

    def list_categories(self) -> list[dict]:
        """
        List all categories with counts.

        Returns:
            List of categories with tool and command counts
        """
        results = self.db.list_categories()
        return [r.model_dump() for r in results]

    def list_tags(self, min_count: int = 1) -> list[dict]:
        """
        List all tags with usage counts.

        Args:
            min_count: Minimum writeup count to include a tag

        Returns:
            List of tags with writeup and command counts
        """
        return self.db.list_tags(min_count=min_count)

    def suggest_command(
        self,
        goal: str,
        context: Optional[dict] = None
    ) -> list[dict]:
        """
        Suggest commands based on a goal description.

        Args:
            goal: What you want to accomplish (e.g., "enumerate AD users")
            context: Optional context like {'os': 'windows', 'phase': 'privesc'}

        Returns:
            List of suggested commands with explanations
        """
        # Search for relevant commands
        results = self.db.search_commands(query=goal, limit=15)

        # Group by tool and deduplicate
        suggestions = {}
        for r in results:
            tool = r.tool or 'unknown'
            if tool not in suggestions:
                suggestions[tool] = {
                    'tool': tool,
                    'template': r.template,
                    'explanation': r.purpose,
                    'examples': [],
                    'sources': []
                }

            # Add example if unique
            if r.raw_command not in suggestions[tool]['examples']:
                suggestions[tool]['examples'].append(r.raw_command)

            # Add source
            source = r.source.get('file', '')
            if source and source not in suggestions[tool]['sources']:
                suggestions[tool]['sources'].append(source)

        # Limit examples per tool
        for tool in suggestions.values():
            tool['examples'] = tool['examples'][:3]
            tool['sources'] = tool['sources'][:3]

        return list(suggestions.values())[:5]

    def index_writeups(
        self,
        directories: Optional[list[str]] = None,
        force_rebuild: bool = False,
        add_new_only: bool = False,
        writeup_type: Optional[str] = None
    ) -> dict:
        """
        Index or re-index writeup directories.

        Args:
            directories: List of directories to index (defaults to configured)
            force_rebuild: Drop and recreate all data
            add_new_only: Only add new writeups (skip already indexed)
            writeup_type: Only index specific type (box, challenge, sherlock)

        Returns:
            Indexing statistics
        """
        if directories:
            dirs_to_index = {f"custom_{i}": d for i, d in enumerate(directories)}
        else:
            dirs_to_index = self.writeup_dirs.copy()

        # Filter by type if specified
        if writeup_type:
            type_map = {
                'box': 'boxes',
                'challenge': 'challenges',
                'sherlock': 'sherlocks'
            }
            key = type_map.get(writeup_type)
            if key and key in dirs_to_index:
                dirs_to_index = {key: dirs_to_index[key]}

        result = self.indexer.index_all(
            dirs_to_index,
            force_rebuild=force_rebuild,
            add_new_only=add_new_only
        )
        return result.model_dump()

    def get_stats(self) -> dict:
        """
        Get database statistics.

        Returns:
            Statistics about indexed content
        """
        stats = self.db.get_stats()
        return stats.model_dump()

    def get_writeup_summary(self, filename: str) -> dict:
        """
        Get summary of commands/scripts from a specific writeup.

        Args:
            filename: Writeup filename (e.g., "Authority.md")

        Returns:
            Summary with commands, scripts, and metadata
        """
        writeup = self.db.get_writeup_by_filename(filename)
        if not writeup:
            return {'error': f'Writeup not found: {filename}'}

        # Get commands for this writeup
        commands = self.db.search_commands(limit=100)
        writeup_commands = [c for c in commands if c.source.get('file') == filename]

        # Get scripts
        scripts = self.db.search_scripts(limit=50)
        writeup_scripts = [s for s in scripts if s.source.get('file') == filename]

        return {
            'writeup': writeup.model_dump(),
            'commands': [c.model_dump() for c in writeup_commands],
            'scripts': [s.model_dump() for s in writeup_scripts],
            'summary': {
                'command_count': len(writeup_commands),
                'script_count': len(writeup_scripts),
                'tools_used': list(set(c.tool for c in writeup_commands if c.tool))
            }
        }

    # =========================================================================
    # HISTORY TOOLS
    # =========================================================================

    def index_history(
        self,
        path: str,
        since: Optional[str] = None
    ) -> dict:
        """
        Index shell history file - ALWAYS ADDS, never rebuilds.

        Deduplication happens automatically via command_hash.
        Running multiple times on same file is safe (idempotent).

        Args:
            path: Path to history file (e.g., ~/.zsh_history)
            since: Only index commands after this ISO datetime

        Returns:
            Indexing statistics
        """
        start_time = time.time()

        # Expand path
        filepath = Path(path).expanduser()
        if not filepath.exists():
            return {'error': f'History file not found: {path}'}

        # Initialize parser
        parser = HistoryParser(self.security)

        # Get existing hashes for deduplication
        existing_hashes = self.db.get_history_hashes()

        # Parse history file
        try:
            commands = parser.parse_file(str(filepath))
        except Exception as e:
            return {'error': f'Failed to parse history: {str(e)}'}

        # Process commands
        stats = {
            'path': str(filepath),
            'commands_processed': 0,
            'commands_added': 0,
            'commands_skipped_blocklist': 0,
            'commands_skipped_duplicate': 0,
            'commands_skipped_short': 0,
            'sensitive_redacted': 0,
            'tools_identified': set(),
        }

        for entry in commands:
            stats['commands_processed'] += 1
            cmd = entry['command']
            timestamp = entry['timestamp'].isoformat() if entry['timestamp'] else None

            # Filter by date if specified
            if since and timestamp and timestamp < since:
                continue

            # Check blocklist
            should_skip, reason = parser.should_skip_command(cmd)
            if should_skip:
                if reason == 'blocklist':
                    stats['commands_skipped_blocklist'] += 1
                elif reason == 'short':
                    stats['commands_skipped_short'] += 1
                continue

            # Generate hash for deduplication
            cmd_hash = parser.get_command_hash(cmd)
            if cmd_hash in existing_hashes:
                stats['commands_skipped_duplicate'] += 1
                # Still update occurrence count
                self.db.insert_history_command(
                    command_hash=cmd_hash,
                    raw_command=cmd,
                    sanitized_command=cmd,  # Will be ignored on update
                    command_template=None,
                    tool_id=None,
                    timestamp=timestamp,
                    source_file=str(filepath),
                    shell_type=entry['shell_type']
                )
                continue

            # Sanitize command
            sanitized = parser.sanitize_command(cmd, str(filepath))
            if sanitized != cmd:
                stats['sensitive_redacted'] += 1

            # Templatize
            template = parser.templatize_command(sanitized)

            # Identify tool
            tool_name = parser.identify_tool(cmd)
            tool_id = None
            if tool_name:
                tool_id = self.db.get_or_create_tool(tool_name)
                stats['tools_identified'].add(tool_name)

            # Insert
            cmd_id, is_new = self.db.insert_history_command(
                command_hash=cmd_hash,
                raw_command=cmd,
                sanitized_command=sanitized,
                command_template=template,
                tool_id=tool_id,
                timestamp=timestamp,
                source_file=str(filepath),
                shell_type=entry['shell_type']
            )

            if is_new:
                stats['commands_added'] += 1
                existing_hashes.add(cmd_hash)

        duration = time.time() - start_time

        return {
            'path': stats['path'],
            'commands_processed': stats['commands_processed'],
            'commands_added': stats['commands_added'],
            'commands_skipped_blocklist': stats['commands_skipped_blocklist'],
            'commands_skipped_duplicate': stats['commands_skipped_duplicate'],
            'commands_skipped_short': stats['commands_skipped_short'],
            'sensitive_redacted': stats['sensitive_redacted'],
            'tools_identified': len(stats['tools_identified']),
            'duration_seconds': round(duration, 2)
        }

    def search_history(
        self,
        query: Optional[str] = None,
        tool: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 20
    ) -> list[dict]:
        """
        Search indexed history commands.

        Args:
            query: Free-text search query
            tool: Filter by tool name
            since: Filter by date (ISO format)
            limit: Maximum results

        Returns:
            List of matching history commands
        """
        return self.db.search_history(
            query=query,
            tool=tool,
            since=since,
            limit=limit
        )

    def history_stats(self) -> dict:
        """
        Get statistics about indexed history.

        Returns:
            Statistics including total commands, tools, date range
        """
        return self.db.get_history_stats()

    def clear_history(
        self,
        before: Optional[str] = None,
        source_file: Optional[str] = None,
        confirm: bool = False
    ) -> dict:
        """
        Clear indexed history commands.

        Args:
            before: Clear commands before this ISO datetime
            source_file: Clear commands from this specific file only
            confirm: Safety flag - must be True to execute

        Returns:
            Result with number of commands deleted
        """
        if not confirm:
            return {
                'error': 'Safety check: set confirm=True to delete history commands',
                'would_affect': 'all' if not before and not source_file else 'filtered'
            }

        deleted = self.db.clear_history(before=before, source_file=source_file)
        return {
            'deleted': deleted,
            'filters': {
                'before': before,
                'source_file': source_file
            }
        }
