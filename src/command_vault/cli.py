#!/usr/bin/env python3
"""Command-line interface for Command Vault (standalone usage)."""

import argparse
import json
import sys
import os
from pathlib import Path

from .database import Database
from .tools import VaultTools


def get_default_config():
    """Get default configuration.

    Supports both unified (WRITEUPS) and legacy (WRITEUPS_BOXES, etc.) env vars.
    - WRITEUPS: Single directory with full tag-based categorization
    - WRITEUPS_BOXES, WRITEUPS_CHALLENGES, WRITEUPS_SHERLOCKS: Legacy dirs (directory-based type)

    When WRITEUPS is set, writeups in that directory use content-based type detection
    and full #hashtag extraction. Legacy directories use directory-based type detection.
    """
    writeup_dirs = {}

    # Check for unified WRITEUPS env var (takes priority)
    unified_dir = os.environ.get('WRITEUPS', '')
    if unified_dir:
        writeup_dirs['unified'] = unified_dir

    # Also include legacy env vars for backward compatibility
    # These work alongside unified dir
    legacy_dirs = {
        'boxes': os.environ.get('WRITEUPS_BOXES', ''),
        'challenges': os.environ.get('WRITEUPS_CHALLENGES', ''),
        'sherlocks': os.environ.get('WRITEUPS_SHERLOCKS', ''),
    }
    for key, value in legacy_dirs.items():
        if value:
            writeup_dirs[key] = value

    return {
        'db_path': os.environ.get(
            'VAULT_DB',
            str(Path.home() / '.local/share/command-vault/vault.db')
        ),
        'writeup_dirs': writeup_dirs
    }


def main():
    parser = argparse.ArgumentParser(
        description='Command Vault - Search security commands from penetration testing writeups',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vault search "bloodhound enumerate"
  vault search --tool nmap --category recon
  vault search --tag windows --tag ad   # Filter by tags
  vault prose "NTLM relay"            # Search writeup prose
  vault suggest "crack NTLM hash"
  vault tools --category ad
  vault tags                            # List all tags
  vault tags --min-count 5              # List tags with 5+ writeups
  vault index --add          # Add new writeups only
  vault index --rebuild      # Full database rebuild
  vault stats

  # History commands
  vault history index ~/.zsh_history    # Index history (always adds)
  vault history search nmap             # Search history
  vault history search --tool ffuf      # Filter by tool
  vault history stats                   # Show history stats
  vault history clear --confirm         # Clear all history

  # Maintenance
  vault maintain --all                  # Run all maintenance tasks
  vault maintain --vacuum               # Reclaim disk space
  vault maintain --analyze              # Update query statistics
  vault maintain --optimize             # Optimize FTS indexes

Environment Variables:
  WRITEUPS             Unified writeup directory (full tag-based categorization)
  WRITEUPS_BOXES       Legacy: boxes directory (type detected from path)
  WRITEUPS_CHALLENGES  Legacy: challenges directory (type detected from path)
  WRITEUPS_SHERLOCKS   Legacy: sherlocks directory (type detected from path)
  VAULT_DB             Database path (default: ~/.local/share/command-vault/vault.db)
        """
    )

    parser.add_argument('--db', help='Database path', default=None)
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Search command
    search_parser = subparsers.add_parser('search', help='Search for commands')
    search_parser.add_argument('query', nargs='?', help='Search query')
    search_parser.add_argument('--tool', '-t', help='Filter by tool')
    search_parser.add_argument('--category', '-c', help='Filter by category')
    search_parser.add_argument('--tag', '-g', action='append', dest='tags',
                               help='Filter by tag (repeatable, e.g., -g windows -g ad)')
    search_parser.add_argument('--type', '-T', choices=['box', 'challenge', 'sherlock'],
                               help='[Deprecated: use --tag] Filter by writeup type')
    search_parser.add_argument('--limit', '-n', type=int, default=10, help='Max results')

    # Scripts command
    scripts_parser = subparsers.add_parser('scripts', help='Search for scripts')
    scripts_parser.add_argument('query', nargs='?', help='Search query')
    scripts_parser.add_argument('--language', '-l', help='Filter by language')
    scripts_parser.add_argument('--library', help='Filter by library')
    scripts_parser.add_argument('--limit', '-n', type=int, default=10, help='Max results')

    # Suggest command
    suggest_parser = subparsers.add_parser('suggest', help='Suggest commands for a goal')
    suggest_parser.add_argument('goal', help='What you want to accomplish')

    # Tools command
    tools_parser = subparsers.add_parser('tools', help='List available tools')
    tools_parser.add_argument('--category', '-c', help='Filter by category')

    # Categories command
    subparsers.add_parser('categories', help='List categories')

    # Tags command
    tags_parser = subparsers.add_parser('tags', help='List all tags')
    tags_parser.add_argument('--min-count', '-m', type=int, default=1,
                             help='Minimum writeup count to include a tag')

    # Prose command
    prose_parser = subparsers.add_parser('prose', help='Search writeup prose/methodology')
    prose_parser.add_argument('query', help='Search query (e.g., "NTLM relay")')
    prose_parser.add_argument('--type', '-T', choices=['box', 'challenge', 'sherlock'],
                               help='Filter by writeup type')
    prose_parser.add_argument('--tag', '-g', action='append', dest='tags',
                               help='Filter by tag (repeatable)')
    prose_parser.add_argument('--limit', '-n', type=int, default=10, help='Max results')
    prose_parser.add_argument('--chars', '-l', type=int, default=300, help='Max chars per passage (0 for full text)')

    # Index command
    index_parser = subparsers.add_parser('index', help='Index writeups')
    index_group = index_parser.add_mutually_exclusive_group()
    index_group.add_argument('--add', '-a', action='store_true',
                             help='Add new writeups only (skip already indexed)')
    index_group.add_argument('--rebuild', '-r', action='store_true',
                             help='Full rebuild (drop and recreate database)')
    index_parser.add_argument('--type', '-T', choices=['box', 'challenge', 'sherlock'],
                              help='Only index specific type')
    index_parser.add_argument('directories', nargs='*', help='Directories to index')

    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')

    # History command with subcommands
    history_parser = subparsers.add_parser('history', help='Shell history commands')
    history_subparsers = history_parser.add_subparsers(dest='history_command', help='History commands')

    # history index
    history_index = history_subparsers.add_parser('index', help='Index shell history file (always adds)')
    history_index.add_argument('path', help='Path to history file (e.g., ~/.zsh_history)')
    history_index.add_argument('--since', help='Only index commands after this ISO datetime')

    # history search
    history_search = history_subparsers.add_parser('search', help='Search indexed history')
    history_search.add_argument('query', nargs='?', help='Search query')
    history_search.add_argument('--tool', '-t', help='Filter by tool')
    history_search.add_argument('--since', help='Filter by date (ISO format)')
    history_search.add_argument('--limit', '-n', type=int, default=20, help='Max results')

    # history stats
    history_subparsers.add_parser('stats', help='Show history statistics')

    # history clear
    history_clear = history_subparsers.add_parser('clear', help='Clear indexed history')
    history_clear.add_argument('--before', help='Clear commands before this ISO datetime')
    history_clear.add_argument('--source', help='Clear commands from this file only')
    history_clear.add_argument('--confirm', action='store_true', required=True,
                               help='Required safety flag to confirm deletion')

    # Maintain command
    maintain_parser = subparsers.add_parser('maintain', help='Database maintenance')
    maintain_parser.add_argument('--vacuum', action='store_true',
                                 help='Reclaim disk space and defragment')
    maintain_parser.add_argument('--analyze', action='store_true',
                                 help='Update query planner statistics')
    maintain_parser.add_argument('--optimize', action='store_true',
                                 help='Optimize FTS indexes')
    maintain_parser.add_argument('--all', '-a', action='store_true',
                                 help='Run all maintenance tasks')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Initialize
    config = get_default_config()
    db_path = args.db or config['db_path']
    db = Database(db_path)

    writeup_dirs = {k: v for k, v in config['writeup_dirs'].items() if v and Path(v).exists()}
    vault = VaultTools(db, writeup_dirs)

    # Execute command
    result = None

    if args.command == 'search':
        result = vault.search_commands(
            query=args.query,
            tool=args.tool,
            category=args.category,
            writeup_type=args.type,
            tags=args.tags,
            limit=args.limit
        )

    elif args.command == 'scripts':
        result = vault.search_scripts(
            query=args.query,
            language=args.language,
            library=args.library,
            limit=args.limit
        )

    elif args.command == 'suggest':
        result = vault.suggest_command(goal=args.goal)

    elif args.command == 'tools':
        result = vault.list_tools(category=args.category)

    elif args.command == 'categories':
        result = vault.list_categories()

    elif args.command == 'tags':
        result = vault.list_tags(min_count=args.min_count)

    elif args.command == 'prose':
        result = vault.search_writeup_prose(
            query=args.query,
            writeup_type=args.type,
            tags=args.tags,
            limit=args.limit
        )

    elif args.command == 'index':
        directories = args.directories if args.directories else None
        result = vault.index_writeups(
            directories=directories,
            force_rebuild=args.rebuild,
            add_new_only=args.add,
            writeup_type=args.type
        )

    elif args.command == 'stats':
        result = vault.get_stats()

    elif args.command == 'history':
        if not args.history_command:
            history_parser.print_help()
            sys.exit(1)

        if args.history_command == 'index':
            result = vault.index_history(
                path=args.path,
                since=args.since
            )
        elif args.history_command == 'search':
            result = vault.search_history(
                query=args.query,
                tool=args.tool,
                since=args.since,
                limit=args.limit
            )
        elif args.history_command == 'stats':
            result = vault.history_stats()
        elif args.history_command == 'clear':
            result = vault.clear_history(
                before=args.before,
                source_file=args.source,
                confirm=args.confirm
            )

    elif args.command == 'maintain':
        do_all = args.all
        result = db.maintain(
            vacuum=args.vacuum or do_all,
            analyze=args.analyze or do_all,
            optimize_fts=args.optimize or do_all
        )

    # Output
    if args.json or args.command in ('stats', 'index', 'history', 'maintain', 'tags'):
        print(json.dumps(result, indent=2))
    else:
        format_output(args.command, result, args=args)


def format_output(command: str, result, args=None):
    """Format output for human readability."""
    if not result:
        print("No results found.")
        return

    if command == 'search':
        for item in result:
            print(f"\n{'='*60}")
            print(f"Tool: {item.get('tool', 'unknown')}")
            print(f"Source: {item['source'].get('file', '')} [{item['source'].get('section', '')}]")
            if item.get('purpose'):
                print(f"Purpose: {item['purpose'][:100]}...")
            print(f"\n  {item['raw_command']}")
            if item.get('template') and item['template'] != item['raw_command']:
                print(f"\n  Template: {item['template']}")

    elif command == 'scripts':
        for item in result:
            print(f"\n{'='*60}")
            print(f"Language: {item['language']}")
            print(f"Libraries: {', '.join(item.get('libraries', []))}")
            print(f"Source: {item['source'].get('file', '')}")
            if item.get('purpose'):
                print(f"Purpose: {item['purpose'][:100]}...")
            print(f"\nPreview:\n{item['code_preview']}")

    elif command == 'suggest':
        for item in result:
            print(f"\n{'='*60}")
            print(f"Tool: {item['tool']}")
            if item.get('explanation'):
                print(f"Purpose: {item['explanation'][:100]}...")
            print(f"Template: {item.get('template', 'N/A')}")
            print("Examples:")
            for ex in item.get('examples', []):
                print(f"  $ {ex}")

    elif command == 'tools':
        print(f"{'Tool':<30} {'Category':<15} {'Commands'}")
        print("-" * 55)
        for item in result:
            print(f"{item['name']:<30} {item.get('category', 'misc'):<15} {item['command_count']}")

    elif command == 'categories':
        print(f"{'Category':<20} {'Tools':<10} {'Commands'}")
        print("-" * 45)
        for item in result:
            print(f"{item['name']:<20} {item['tool_count']:<10} {item['command_count']}")

    elif command == 'prose':
        max_chars = getattr(args, 'chars', 300)
        for item in result:
            filename = item['source'].get('filename', '')
            section = item.get('section', '')
            content = item['content']
            if max_chars > 0 and len(content) > max_chars:
                content = content[:max_chars] + '...'
            print(f"\n{'='*60}")
            print(f"Source: {filename} [{section}]")
            print(f"\n  {content}")

    elif command == 'tags':
        print(f"{'Tag':<25} {'Writeups':<12} {'Commands'}")
        print("-" * 50)
        for item in result:
            print(f"{item['name']:<25} {item['writeup_count']:<12} {item['command_count']}")


if __name__ == '__main__':
    main()
