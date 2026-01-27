# Command Vault MCP

> *"What was that certipy command I used last week for ESC8?"*
> *"How did I exploit that shadow credentials thing again?"*

Ever found yourself digging through shell history, old notes, or writeups trying to recall that exact command you used before? Shell history is basic and lacks context. This tool solves that.

Command Vault indexes commands from your penetration testing writeups into a searchable database with full context - what tool, what technique, which box. It's also MCP-ready, so your AI assistant can search your command history for you.

## Features

- **Full-text search** across commands and scripts from your writeups
- **Smart categorization** - 200+ security tools mapped to categories (recon, AD, web, privesc, etc.)
- **Template generation** - Auto-replaces IPs, domains with placeholders
- **Security filtering** - Flags and credentials automatically redacted
- **Multiple writeup types** - Supports boxes, challenges, and Sherlocks

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Installation

```bash
# Clone the repository
git clone https://github.com/x746b/command-vault-mcp.git
cd command-vault-mcp

# Install with uv (recommended)
uv pip install -e .

# Or with pip
pip install -e .
```

## Quick Start

1. **Set up your writeup directories** (environment variables or defaults):

```bash
export WRITEUPS_BOXES="$HOME/writeups/boxes"
export WRITEUPS_CHALLENGES="$HOME/writeups/challenges"
export WRITEUPS_SHERLOCKS="$HOME/writeups/sherlocks"
```

2. **Index your writeups**:

```bash
vault index --rebuild
```

3. **Search for commands**:

```bash
vault search "kerberoasting"
vault search --tool nmap --category recon
```

## Indexing Writeups

### Initial Index

Run a full index on first setup:

```bash
vault index --rebuild
```

### Adding New Writeups

After adding new writeup files:

```bash
vault index --add
```

### Index Specific Type

```bash
vault index --add --type box        # Only boxes
vault index --add --type challenge  # Only challenges
vault index --add --type sherlock   # Only sherlocks
```

### Index Custom Directories

```bash
vault index --add /path/to/writeups /another/path
```

## CLI Usage

```bash
# Search commands
vault search "bloodhound enumerate"
vault search --tool certipy --category ad
vault search --type box "ADCS"

# Suggest commands for a goal
vault suggest "crack NTLM hash"
vault suggest "enumerate AD users"

# Search scripts
vault scripts --language python
vault scripts --library pwn

# List tools and categories
vault tools --category ad
vault categories

# Show statistics
vault stats
```

## MCP Server Configuration

Add to your Claude Code MCP configuration (`~/.claude/claude_code_config.json`):

```json
{
  "mcpServers": {
    "command-vault": {
      "command": "uv",
      "args": ["run", "command-vault"],
      "cwd": "/path/to/command-vault-mcp",
      "env": {
        "VAULT_DB": "~/.local/share/command-vault/vault.db",
        "WRITEUPS_BOXES": "~/writeups/boxes",
        "WRITEUPS_CHALLENGES": "~/writeups/challenges",
        "WRITEUPS_SHERLOCKS": "~/writeups/sherlocks"
      }
    }
  }
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_DB` | Path to SQLite database | `~/.local/share/command-vault/vault.db` |
| `WRITEUPS_BOXES` | Boxes writeups directory | None |
| `WRITEUPS_CHALLENGES` | Challenges writeups directory | None |
| `WRITEUPS_SHERLOCKS` | Sherlocks writeups directory | None |

## MCP Tools Reference

| Tool | Description |
|------|-------------|
| `search_commands` | Search commands by keyword, tool, or category |
| `search_scripts` | Search exploit scripts (Python, JS/Frida, PowerShell) |
| `get_tool_examples` | Get usage examples for a specific tool |
| `suggest_command` | Get command suggestions for a goal |
| `list_tools` | List indexed tools |
| `list_categories` | List categories with counts |
| `get_writeup_summary` | Get summary from a specific writeup |
| `index_writeups` | Index or re-index writeup directories |
| `vault_stats` | Get statistics about indexed content |

## Writeup Format

The parser expects markdown files with code blocks. Supported formats:

~~~markdown
## Enumeration

```bash
$ nmap -sC -sV 10.10.11.100
```

```powershell
PS> Get-ADUser -Filter *
```

```python
#!/usr/bin/env python3
from pwn import *
# exploit code...
```
~~~

### Writeup Types

- **Boxes**: Machine writeups (detected from `/boxes/` in path)
- **Challenges**: CTF challenges with type in filename, e.g., `Challenge (web).md`
- **Sherlocks**: DFIR investigations (detected from `/sherlocks/` in path)

## Troubleshooting

### "vault: command not found"

The CLI isn't in your PATH. Use one of these approaches:

```bash
# Option 1: Run via uv
cd /path/to/command-vault-mcp
uv run vault search "query"

# Option 2: Add to PATH after install
pip install -e .  # Creates vault in ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"
```

### "No results found"

1. Check if writeups are indexed: `vault stats`
2. If counts are 0, run: `vault index --rebuild`
3. Verify writeup directories exist and contain `.md` files

### MCP server not connecting

1. Verify the `cwd` path in your MCP config points to the project directory
2. Check that `uv` is installed and in PATH
3. Test manually: `cd /path/to/command-vault-mcp && uv run command-vault`

### Database errors

Reset the database:

```bash
rm ~/.local/share/command-vault/vault.db
vault index --rebuild
```

### Commands not being extracted

The parser looks for code blocks with `bash`, `sh`, `powershell`, or `ps` language tags. Commands should start with `$`, `#`, or `PS>` prompts, or be standalone tool invocations.

## License

MIT License - see [LICENSE](LICENSE) file.
