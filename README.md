# Command Vault (also MCP)

> *"What was that certipy command I used for ESC8?"*
> *"How did I exploit that shadow credentials thing again?"*

Command Vault indexes **commands**, **scripts**, and **prose** from your penetration testing writeups and shell history into a searchable database with full context — what tool, what technique, which box. MCP-ready for AI assistants.

## Features

- **Command search** — FTS across commands with AND-first, bm25-ranked OR fallback for multi-word queries
- **Prose search** — Search methodology text, attack explanations, and forensic analysis from writeups
- **Script search** — Find Python, PowerShell, and Frida exploit scripts by language or library
- **Ranked fallback** — Multi-word queries try AND (precise), then fall back to bm25-ranked OR (relevant)
- **Shell history** — Index `~/.zsh_history` or `~/.bash_history` with deduplication and security redaction
- **Tag filtering** — Search by `#hashtags` extracted from writeup content
- **Smart categorization** — 200+ security tools mapped to categories (recon, AD, web, privesc, etc.)
- **Template generation** — Auto-replaces IPs, domains, passwords with placeholders
- **Multiple writeup types** — Boxes, challenges, and Sherlocks with unified or legacy directory modes

## Installation

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/x746b/command-vault.git
cd command-vault
uv pip install -e .
```

## Quick Start

```bash
# Set writeup directory
export WRITEUPS="$HOME/writeups"

# Index everything
vault index --rebuild

# Search commands
vault search "kerberoasting"
vault search --tool nmap --category recon
vault search --tag windows --tag ad

# Search prose/methodology
vault prose "NTLM relay"
vault prose "ADCS ESC8" --type box
```

## CLI Reference

### Commands & Scripts

```bash
vault search "certipy ESC"              # AND match (both words required)
vault search "buffer overflow ROP chain" # AND first, bm25 OR fallback if no AND hits
vault search --tool bloodyAD --limit 5   # Filter by tool
vault search --category ad               # Filter by category
vault search --tag windows --tag ad      # Filter by tags (AND logic)
vault search --type box "ADCS"           # Filter by writeup type
vault search "ESC16" --json              # JSON output

vault scripts --language python          # Search scripts
vault scripts --library pwn

vault suggest "kerberoasting"            # Tool suggestions grouped by category
```

### Prose Search

Search the full text of writeup methodology, not just extracted commands:

```bash
vault prose "NTLM relay"                # Search writeup prose
vault prose "ADCS ESC8" --type box      # Filter by writeup type
vault prose "shadow credentials" --limit 20
vault prose "GenericWrite ADCS shadow"  # AND first, ranked OR fallback
```

### Indexing

```bash
vault index --rebuild                    # Full reindex (required first time)
vault index --add                        # Index new writeups only
vault index --add --type box             # Index specific type
vault index --add /path/to/writeups      # Index custom directory
```

### Shell History

```bash
vault history index ~/.zsh_history       # Index (additive, safe to re-run)
vault history index ~/.zsh_history --since "2024-01-01"
vault history search "kerberoast"        # Search history
vault history search --tool certipy
vault history stats                      # History statistics
vault history clear --confirm            # Clear all
```

### Other

```bash
vault tools --category ad                # List tools
vault categories                         # List categories
vault tags --min-count 5                 # List tags
vault stats                              # Database statistics
vault maintain --all                     # VACUUM + ANALYZE + FTS optimize
```

## MCP Server Setup

```bash
claude mcp add command-vault --scope user \
  -e VAULT_DB=~/.local/share/command-vault/vault.db \
  -e WRITEUPS=~/writeups \
  -- /path/to/command-vault/.venv/bin/python -m command_vault.server
```

Or in `~/.claude.json` / `.mcp.json`:

```json
{
  "mcpServers": {
    "command-vault": {
      "command": "/path/to/command-vault/.venv/bin/python",
      "args": ["-m", "command_vault.server"],
      "env": {
        "VAULT_DB": "~/.local/share/command-vault/vault.db",
        "WRITEUPS": "~/writeups"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_DB` | Path to SQLite database | `~/.local/share/command-vault/vault.db` |
| `WRITEUPS` | Unified writeup directory (recommended) | None |
| `WRITEUPS_BOXES` | Boxes directory (legacy, path-based type detection) | None |
| `WRITEUPS_CHALLENGES` | Challenges directory (legacy) | None |
| `WRITEUPS_SHERLOCKS` | Sherlocks directory (legacy) | None |

### MCP Tools

| Tool | Description |
|------|-------------|
| `search_commands` | Search commands by keyword, tool, category, or tags |
| `search_writeup_prose` | Search methodology text and explanations from writeups |
| `search_scripts` | Search exploit scripts by language or library |
| `get_tool_examples` | Get usage examples for a specific tool |
| `suggest_command` | Get command suggestions for a goal |
| `list_tools` | List indexed tools |
| `list_categories` | List categories with counts |
| `list_tags` | List all tags with usage counts |
| `get_writeup_summary` | Get summary from a specific writeup |
| `index_writeups` | Index or re-index writeup directories |
| `vault_stats` | Get statistics about indexed content |
| `index_history` | Index shell history file |
| `search_history` | Search indexed shell history |
| `history_stats` | Get history statistics |
| `clear_history` | Clear indexed history (requires `confirm=true`) |

## Writeup Format

The parser extracts commands from fenced code blocks (`bash`, `powershell`, `python`) and prose from paragraph text.

**Supported prompts:** `$`, `user@host$`, `➜ dir`, `PS C:\>`, `*Evil-WinRM*`, `PV >`, `C:\>`

**Example writeup:**

~~~markdown
# Machine Name

#box #windows #ad #easy

## Enumeration

We discover LDAP signing is not enforced, making NTLM relay possible.

```bash
$ nmap -sC -sV 10.10.11.100
```

```powershell
*Evil-WinRM* PS C:\Users\admin> Get-ADUser -Filter *
```

```python
#!/usr/bin/env python3
from pwn import *
# exploit code - detected as script
```
~~~

Tags (`#box`, `#windows`, `#ad`, `#easy`) are extracted and searchable. Prose paragraphs are chunked and indexed for `vault prose` / `search_writeup_prose` searches.

## Troubleshooting

- **"vault: command not found"** — Run via `uv run vault` from the project directory, or add `~/.local/bin` to PATH after `pip install -e .`
- **"No results found"** — Check `vault stats`, run `vault index --rebuild` if counts are 0. Multi-word queries try AND first, then fall back to bm25-ranked OR if AND returns nothing.
- **MCP not connecting** — Verify paths in MCP config, check `uv` is in PATH, test with `uv run command-vault`
- **Database errors** — Run `vault maintain --all`. If that fails: `rm ~/.local/share/command-vault/vault.db && vault index --rebuild`

## License

MIT License - see [LICENSE](LICENSE) file.
