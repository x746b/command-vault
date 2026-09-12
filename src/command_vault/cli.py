#!/usr/bin/env python3
"""Command-line interface for Command Vault (standalone usage)."""

import argparse
import json
import sys
import os
import sqlite3
from pathlib import Path

from .database import Database
from .tools import VaultTools
from .config import get_config
from .knowledge import Knowledge
from .record_search import search_records, search_relations


def bounded_int(minimum, maximum=None):
    """Argparse validator matching the MCP parameter bounds."""
    def parse(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError('must be an integer') from exc
        if number < minimum or (maximum is not None and number > maximum):
            bounds = f'{minimum}..{maximum}' if maximum is not None else f'>= {minimum}'
            raise argparse.ArgumentTypeError(f'must be {bounds}')
        return number
    return parse


def run_knowledge_command(args, db_path):
    """Use the MCP retrieval service directly, with no server or index writes."""
    try:
        db = Database(db_path, readonly=True)
        knowledge = Knowledge(db)
        if args.command == 'knowledge':
            page = knowledge.search(query=args.query, writeup_type=args.type, tags=args.tags,
                                    required_terms=args.required_terms, limit=args.limit,
                                    max_chars=args.max_chars, cursor=args.cursor)
        elif args.command == 'context':
            page = knowledge.read_context(args.reference, offset=args.offset, max_chars=args.max_chars)
        elif args.command == 'related':
            page = search_relations(db,args.technique,limit=args.limit,
                                    max_chars=args.max_chars if args.max_chars is not None else 12000,cursor=args.cursor)
        else:
            options = dict(query=args.query, limit=args.limit,
                           max_chars=args.max_chars if args.max_chars is not None else 12000,
                           cursor=args.cursor)
            if args.command == 'search':
                page = search_records(db, 'command', **options, tool=args.tool, category=args.category,
                                      writeup_type=args.type, tags=args.tags)
            elif args.command == 'scripts':
                if args.list_libraries:
                    raise ValueError('--page is for script search, not --list-libraries')
                page = search_records(db, 'script', **options, language=args.language, library=args.library)
            else:
                page = search_records(db, 'history', **options, tool=args.tool, since=args.since)
    except (ValueError, OSError, sqlite3.Error) as exc:
        message = json.dumps({'error': str(exc)}) if args.json else f'Error: {exc}'
        print(message, file=sys.stderr)
        raise SystemExit(1) from exc
    result = page.model_dump()
    if args.json or args.command not in ('knowledge', 'context'):
        print(json.dumps(result, indent=2))
    else:
        format_output(args.command, result, args=args)


def get_default_config():
    """Compatibility alias for shared CLI/MCP configuration."""
    return get_config()


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
  vault knowledge "Security log cleared" --require-term 1102 --type sherlock
  vault context "<reference from knowledge>" --max-chars 8000
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
    search_parser.add_argument('--type', '-T', choices=['box', 'challenge', 'sherlock', 'research'],
                               help='[Deprecated: use --tag] Filter by writeup type')
    search_parser.add_argument('--limit', '-n', type=int, default=10, help='Max results')

    # Scripts command
    scripts_parser = subparsers.add_parser('scripts', help='Search for scripts')
    scripts_parser.add_argument('query', nargs='?', help='Search query')
    scripts_parser.add_argument('--language', '-l', help='Filter by language')
    scripts_parser.add_argument('--library', help='Filter by library')
    scripts_parser.add_argument('--list-libraries', action='store_true', help='List available libraries with counts')
    scripts_parser.add_argument('--limit', '-n', type=int, default=10, help='Max results')

    # Get script (full code)
    script_parser = subparsers.add_parser('script', help='Get full script code by ID')
    script_parser.add_argument('script_id', type=int, help='Script ID (from scripts search)')

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
    prose_parser.add_argument('--type', '-T', choices=['box', 'challenge', 'sherlock', 'research'],
                               help='Filter by writeup type')
    prose_parser.add_argument('--tag', '-g', action='append', dest='tags',
                               help='Filter by tag (repeatable)')
    prose_parser.add_argument('--limit', '-n', type=int, default=10, help='Max results')
    prose_parser.add_argument('--chars', '-l', type=int, default=300, help='Max chars per passage (0 for full text)')

    knowledge_parser = subparsers.add_parser('knowledge', help='Search explanatory evidence with MCP-equivalent controls')
    knowledge_parser.add_argument('query', help='Topic or information need to search')
    knowledge_parser.add_argument('--type', '-T', choices=['box', 'challenge', 'sherlock', 'research'], help='Filter by source type')
    knowledge_parser.add_argument('--tag', '-g', action='append', dest='tags', help='Required tag (repeatable; all must match)')
    knowledge_parser.add_argument('--require-term', '--require', action='append', dest='required_terms',
                                  help='Term that must match even on fallback (repeatable, at most 10)')
    knowledge_parser.add_argument('--limit', '-n', type=bounded_int(1, 100), default=5, help='Max results (1..100; default 5)')
    knowledge_parser.add_argument('--max-chars', type=bounded_int(500, 20000), default=10000,
                                  help='Result budget (500..20000; default 10000)')
    knowledge_parser.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='Output the structured MCP-equivalent page')
    knowledge_parser.add_argument('--cursor', help='Continue with next_cursor from the same query and filters')

    context_parser = subparsers.add_parser('context', help='Read the source section behind a search reference')
    context_parser.add_argument('reference', help='Copy the complete reference returned by knowledge')
    context_parser.add_argument('--offset', type=bounded_int(0), default=0, help='Character offset from next_offset (default 0)')
    context_parser.add_argument('--max-chars', type=bounded_int(500, 20000), default=8000,
                                help='Page size (500..20000; default 8000)')
    context_parser.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='Output the structured MCP-equivalent page')

    # Related command (technique linking)
    related_parser = subparsers.add_parser('related', help='Find writeups sharing a technique')
    related_parser.add_argument('technique', help='Technique name (e.g., "Kerberoasting", "ADCS ESC8")')
    related_parser.add_argument('--limit', '-n', type=int, default=20, help='Max results')

    # Techniques command
    techniques_parser = subparsers.add_parser('techniques', help='List all indexed techniques')
    techniques_parser.add_argument('--min-count', '-m', type=int, default=1,
                                    help='Minimum writeup count')

    # Enrich command
    subparsers.add_parser('enrich', help='Populate technique links from existing tags (no re-index)')

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

    # Preserve legacy list output; opt into the shared MCP page contract explicitly.
    for paged_parser in (search_parser, scripts_parser, history_search, related_parser):
        paged_parser.add_argument('--page', action='store_true', help='Return a structured JSON page with a continuation cursor')
        paged_parser.add_argument('--cursor', help='Continue the same search using its next_cursor')
        paged_parser.add_argument('--max-chars', type=bounded_int(500, 20000), help='Page record budget (enables --page; default 12000)')
        paged_parser.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='Output JSON')

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
    config = get_config()
    db_path = args.db or config['db_path']
    paged_records = args.command in ('search', 'scripts', 'related') or (args.command == 'history' and args.history_command == 'search')
    if args.command in ('knowledge', 'context') or (paged_records and
            (args.page or args.cursor is not None or args.max_chars is not None)):
        run_knowledge_command(args, db_path)
        return
    writing = args.command in ('index', 'enrich', 'maintain') or (args.command == 'history' and getattr(args, 'history_command', None) in ('index', 'clear'))
    db = Database(db_path, readonly=not writing)

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
        if args.list_libraries:
            result = vault.list_libraries()
        else:
            result = vault.search_scripts(
                query=args.query,
                language=args.language,
                library=args.library,
                limit=args.limit
            )

    elif args.command == 'script':
        result = vault.get_script(script_id=args.script_id)

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

    elif args.command == 'related':
        result = vault.search_related(
            technique=args.technique,
            limit=args.limit
        )

    elif args.command == 'techniques':
        result = vault.list_techniques(min_writeups=args.min_count)

    elif args.command == 'enrich':
        result = vault.enrich()

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

    if command == 'knowledge':
        print(f"Match mode: {result['match_mode']}")
        if result['unmatched_query_terms']:
            print(f"Unmatched query terms: {', '.join(result['unmatched_query_terms'])}")
        if result['unmatched_required_terms']:
            print(f"Unmatched required terms: {', '.join(result['unmatched_required_terms'])}")
        if result['notice']:
            print(result['notice'])
        if not result['results']:
            print('No results found.')
        for item in result['results']:
            print(f"\nReference: {item['reference']}")
            if item.get('source'):
                print(f"Source: {item['source']['filename']} [{item.get('section', '')}]")
            if item.get('question_only'):
                print('Question-only result; no answer established.')
            print(item.get('content') or item.get('notice', ''))
        if result['truncated']:
            print('\nResults truncated; use vault context with a returned reference for more.')
        if result['next_cursor']:
            print(f"\nNext cursor: {result['next_cursor']}")
            print('Repeat this search with --cursor and the same query/filters to continue.')

    elif command == 'context':
        source = result['source']
        print(f"Reference: {result['reference']}")
        print(f"Source: {source['filename']} [{source.get('section', '')}]")
        print(f"Source status: {result['source_status']}")
        print(f"Offset: {result['offset']}")
        if source.get('image_references_present'):
            print('Image references present; image content has not been extracted.')
        print(f"\n{result['content']}")
        if result['next_offset'] is not None:
            print(f"\nNext offset: {result['next_offset']} (use --offset {result['next_offset']})")

    elif command == 'search':
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
        if isinstance(result, list) and result and 'library' in result[0]:
            # --list-libraries output
            print(f"{'Library':<25} {'Scripts'}")
            print("-" * 35)
            for item in result:
                print(f"{item['library']:<25} {item['count']}")
        else:
            for item in result:
                print(f"\n{'='*60}")
                print(f"[ID: {item['id']}] Language: {item['language']}")
                print(f"Libraries: {', '.join(item.get('libraries', []))}")
                print(f"Source: {item['source'].get('file', '')}")
                if item.get('purpose'):
                    print(f"Purpose: {item['purpose'][:100]}...")
                print(f"\nPreview:\n{item['code_preview']}")

    elif command == 'script':
        if 'error' in result:
            print(result['error'])
        else:
            print(f"# {result['source'].get('file', 'unknown')} [{result.get('section', '')}]")
            print(f"# Language: {result['language']}  Libraries: {', '.join(result.get('libraries', []))}")
            if result.get('purpose'):
                print(f"# Purpose: {result['purpose']}")
            print()
            print(result['code'])

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

    elif command == 'related':
        if not result:
            print("No results found for this technique.")
            return
        for entry in result:
            print(f"\nTechnique: {entry['technique']} ({entry.get('type', '')})")
            print(f"Found in {entry['writeup_count']} writeup(s):\n")
            for wu in entry.get('writeups', []):
                diff = f" ({wu['difficulty']})" if wu.get('difficulty') else ""
                print(f"  {wu['filename']}{diff}")
                tools = wu.get('tools', [])
                if tools:
                    print(f"    Tools: {', '.join(tools[:10])}")
                tags = wu.get('tags', [])
                if tags:
                    print(f"    Tags: {' '.join('#' + t for t in tags)}")
                print()

    elif command == 'techniques':
        print(f"{'Technique':<35} {'Type':<15} {'Writeups'}")
        print("-" * 60)
        for item in result:
            print(f"{item['technique']:<35} {item.get('type', ''):<15} {item['writeup_count']}")

    elif command == 'enrich':
        print(f"Enrichment complete:")
        print(f"  Writeups enriched:  {result.get('writeups_enriched', 0)}")
        print(f"  Technique links:    {result.get('technique_links', 0)}")
        print(f"  Duration:           {result.get('duration_seconds', 0)}s")

    elif command == 'tags':
        print(f"{'Tag':<25} {'Writeups':<12} {'Commands'}")
        print("-" * 50)
        for item in result:
            print(f"{item['name']:<25} {item['writeup_count']:<12} {item['command_count']}")


if __name__ == '__main__':
    main()
