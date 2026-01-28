"""MCP Server for Command Vault."""

import os
import logging
import asyncio
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .database import Database
from .tools import VaultTools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_config() -> dict:
    """Get configuration from environment variables."""
    return {
        'db_path': os.environ.get(
            'VAULT_DB',
            str(Path.home() / '.local/share/command-vault/vault.db')
        ),
        'writeup_dirs': {
            'boxes': os.environ.get('WRITEUPS_BOXES', ''),
            'challenges': os.environ.get('WRITEUPS_CHALLENGES', ''),
            'sherlocks': os.environ.get('WRITEUPS_SHERLOCKS', ''),
        }
    }


def create_server() -> tuple[Server, VaultTools]:
    """Create and configure the MCP server."""
    config = get_config()

    # Initialize database
    db = Database(config['db_path'])

    # Filter out empty directories
    writeup_dirs = {k: v for k, v in config['writeup_dirs'].items() if v}

    # Initialize tools
    vault_tools = VaultTools(db, writeup_dirs)

    # Create MCP server
    server = Server("command-vault")

    return server, vault_tools


# Create global instances
server, vault_tools = create_server()


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="search_commands",
            description="Search for security commands by keyword, tool, or category. "
                       "Examples: 'bloodhound enumerate', 'nmap scan', 'hashcat crack'",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free-text search query"
                    },
                    "tool": {
                        "type": "string",
                        "description": "Filter by tool name (nmap, bloodhound-python, etc.)"
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by category (recon, web, ad, privesc, dfir, etc.)"
                    },
                    "writeup_type": {
                        "type": "string",
                        "enum": ["box", "challenge", "sherlock"],
                        "description": "Filter by writeup source type"
                    },
                    "challenge_type": {
                        "type": "string",
                        "description": "Filter by challenge type (web, pwn, crypto, mobile, etc.)"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 10,
                        "description": "Maximum results to return"
                    }
                }
            }
        ),
        Tool(
            name="search_scripts",
            description="Search for exploit scripts (Python, JavaScript/Frida, etc.)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free-text search in code/purpose"
                    },
                    "language": {
                        "type": "string",
                        "enum": ["python", "javascript", "powershell"],
                        "description": "Filter by programming language"
                    },
                    "library": {
                        "type": "string",
                        "description": "Filter by library (pwn, frida, requests, unicorn, etc.)"
                    },
                    "challenge_type": {
                        "type": "string",
                        "description": "Filter by challenge type"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 10,
                        "description": "Maximum results"
                    }
                }
            }
        ),
        Tool(
            name="get_tool_examples",
            description="Get usage examples for a specific security tool",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool (e.g., nmap, bloodhound-python, certipy)"
                    },
                    "purpose": {
                        "type": "string",
                        "description": "Optional filter by purpose"
                    },
                    "writeup_type": {
                        "type": "string",
                        "enum": ["box", "challenge", "sherlock"],
                        "description": "Filter by source type"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "description": "Maximum results"
                    }
                },
                "required": ["tool_name"]
            }
        ),
        Tool(
            name="list_tools",
            description="List available tools indexed in the vault",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Filter by category"
                    },
                    "writeup_type": {
                        "type": "string",
                        "enum": ["box", "challenge", "sherlock"],
                        "description": "Filter by source type"
                    }
                }
            }
        ),
        Tool(
            name="list_categories",
            description="List all tool categories with counts",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="suggest_command",
            description="Get command suggestions for a goal. "
                       "Example: 'enumerate AD users', 'crack NTLM hash', 'pivot through network'",
            inputSchema={
                "type": "object",
                "properties": {
                    "goal": {
                        "type": "string",
                        "description": "What you want to accomplish"
                    },
                    "context": {
                        "type": "object",
                        "description": "Optional context like {os: 'windows', phase: 'privesc'}"
                    }
                },
                "required": ["goal"]
            }
        ),
        Tool(
            name="index_writeups",
            description="Index or re-index writeup directories",
            inputSchema={
                "type": "object",
                "properties": {
                    "directories": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of directories to index (defaults to configured)"
                    },
                    "force_rebuild": {
                        "type": "boolean",
                        "default": False,
                        "description": "Drop and recreate all data"
                    },
                    "writeup_type": {
                        "type": "string",
                        "enum": ["box", "challenge", "sherlock"],
                        "description": "Only index specific type"
                    }
                }
            }
        ),
        Tool(
            name="vault_stats",
            description="Get statistics about indexed content",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_writeup_summary",
            description="Get summary of commands/scripts from a specific writeup",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Writeup filename (e.g., 'Authority.md')"
                    }
                },
                "required": ["filename"]
            }
        ),
        # History tools
        Tool(
            name="index_history",
            description="Index shell history file (zsh_history, bash_history). "
                       "ALWAYS ADDS commands, never rebuilds. Safe to run multiple times (idempotent). "
                       "Deduplicates, filters blocklisted commands, and sanitizes sensitive data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to history file (e.g., ~/.zsh_history, ~/.bash_history)"
                    },
                    "since": {
                        "type": "string",
                        "description": "Only index commands after this ISO datetime (optional)"
                    }
                },
                "required": ["path"]
            }
        ),
        Tool(
            name="search_history",
            description="Search indexed shell history commands",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free-text search query"
                    },
                    "tool": {
                        "type": "string",
                        "description": "Filter by tool name"
                    },
                    "since": {
                        "type": "string",
                        "description": "Filter by date (ISO format)"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "description": "Maximum results"
                    }
                }
            }
        ),
        Tool(
            name="history_stats",
            description="Get statistics about indexed shell history",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="clear_history",
            description="Clear indexed history commands. Requires confirm=true for safety.",
            inputSchema={
                "type": "object",
                "properties": {
                    "before": {
                        "type": "string",
                        "description": "Clear commands before this ISO datetime (optional)"
                    },
                    "source_file": {
                        "type": "string",
                        "description": "Clear commands from this specific file only (optional)"
                    },
                    "confirm": {
                        "type": "boolean",
                        "default": False,
                        "description": "Safety flag - must be true to execute deletion"
                    }
                }
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    import json

    try:
        if name == "search_commands":
            result = vault_tools.search_commands(
                query=arguments.get("query"),
                tool=arguments.get("tool"),
                category=arguments.get("category"),
                writeup_type=arguments.get("writeup_type"),
                challenge_type=arguments.get("challenge_type"),
                limit=arguments.get("limit", 10)
            )

        elif name == "search_scripts":
            result = vault_tools.search_scripts(
                query=arguments.get("query"),
                language=arguments.get("language"),
                library=arguments.get("library"),
                challenge_type=arguments.get("challenge_type"),
                limit=arguments.get("limit", 10)
            )

        elif name == "get_tool_examples":
            result = vault_tools.get_tool_examples(
                tool_name=arguments["tool_name"],
                purpose=arguments.get("purpose"),
                writeup_type=arguments.get("writeup_type"),
                limit=arguments.get("limit", 20)
            )

        elif name == "list_tools":
            result = vault_tools.list_tools(
                category=arguments.get("category"),
                writeup_type=arguments.get("writeup_type")
            )

        elif name == "list_categories":
            result = vault_tools.list_categories()

        elif name == "suggest_command":
            result = vault_tools.suggest_command(
                goal=arguments["goal"],
                context=arguments.get("context")
            )

        elif name == "index_writeups":
            result = vault_tools.index_writeups(
                directories=arguments.get("directories"),
                force_rebuild=arguments.get("force_rebuild", False),
                writeup_type=arguments.get("writeup_type")
            )

        elif name == "vault_stats":
            result = vault_tools.get_stats()

        elif name == "get_writeup_summary":
            result = vault_tools.get_writeup_summary(
                filename=arguments["filename"]
            )

        # History tools
        elif name == "index_history":
            result = vault_tools.index_history(
                path=arguments["path"],
                since=arguments.get("since")
            )

        elif name == "search_history":
            result = vault_tools.search_history(
                query=arguments.get("query"),
                tool=arguments.get("tool"),
                since=arguments.get("since"),
                limit=arguments.get("limit", 20)
            )

        elif name == "history_stats":
            result = vault_tools.history_stats()

        elif name == "clear_history":
            result = vault_tools.clear_history(
                before=arguments.get("before"),
                source_file=arguments.get("source_file"),
                confirm=arguments.get("confirm", False)
            )

        else:
            result = {"error": f"Unknown tool: {name}"}

        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]

    except Exception as e:
        logger.exception(f"Error in tool {name}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e)})
        )]


async def run_server():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


def main():
    """Entry point."""
    logger.info("Starting Command Vault MCP server")
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
