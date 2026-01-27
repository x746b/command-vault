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
    """Get default configuration."""
    return {
        'db_path': os.environ.get(
            'VAULT_DB',
            str(Path.home() / '.local/share/command-vault/vault.db')
        ),
        'writeup_dirs': {
            'boxes': os.environ.get('WRITEUPS_BOXES', '/home/xtk/labs/AI/boxes'),
            'challenges': os.environ.get('WRITEUPS_CHALLENGES', '/home/xtk/labs/AI/challenges'),
            'sherlocks': os.environ.get('WRITEUPS_SHERLOCKS', '/home/xtk/labs/AI/sherlocks'),
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description='Command Vault - Search security commands from penetration testing writeups',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vault search "bloodhound enumerate"
  vault search --tool nmap --category recon
  vault suggest "crack NTLM hash"
  vault tools --category ad
  vault index --add          # Add new writeups only
  vault index --rebuild      # Full database rebuild
  vault stats
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
    search_parser.add_argument('--type', '-T', choices=['box', 'challenge', 'sherlock'],
                               help='Filter by writeup type')
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

    # Output
    if args.json or args.command in ('stats', 'index'):
        print(json.dumps(result, indent=2))
    else:
        format_output(args.command, result)


def format_output(command: str, result):
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


if __name__ == '__main__':
    main()
