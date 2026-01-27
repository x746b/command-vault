"""MCP tool definitions for Command Vault."""

import logging
from typing import Optional

from .database import Database
from .indexer import Indexer
from .security import SecurityFilter
from .models import (
    CommandResult, ScriptResult, ToolInfo, CategoryInfo,
    VaultStats, IndexResult
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
