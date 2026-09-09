# Command Vault (also MCP)

> *"What was that certipy command I used for ESC8?"*
> *"How did I exploit that shadow credentials thing again?"*

Command Vault indexes **commands**, **scripts**, and **prose** from your penetration testing writeups and shell history into a searchable database with full context — what tool, what technique, which box. MCP-ready for AI assistants.

## Features

- **Command search** — FTS across commands with AND-first, bm25-ranked OR fallback for multi-word queries
- **Prose search** — Search methodology text, attack explanations, and forensic analysis from writeups
- **Script search & retrieval** — Find exploit scripts by language/library, retrieve full code by ID
- **Ranked fallback** — Multi-word queries try AND (precise), then fall back to bm25-ranked OR (relevant)
- **Shell history** — Index `~/.zsh_history` or `~/.bash_history` with deduplication and security redaction
- **Tag filtering** — Search by `#hashtags` extracted from writeup content
- **Smart categorization** — 200+ security tools mapped to categories (recon, AD, web, privesc, etc.)
- **Template generation** — Auto-replaces IPs, domains, passwords with placeholders
- **Multiple writeup types** — Boxes, challenges, and Sherlocks with unified or legacy directory modes

## Installation

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
pip install command-vault-mcp
```

Or from source:

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
vault scripts --list-libraries           # List all libraries with counts
vault scripts "fmtstr printf" --library pwn  # Find format string exploits

vault script 147                         # Get full script code by ID

vault suggest "kerberoasting"            # Tool suggestions grouped by category
```

### Retrieving Full Exploit Scripts

Search returns a preview with the script ID, then use `vault script <ID>` to get the full code:

```
$ vault scripts "fmtstr printf" --library pwn
============================================================
[ID: 147] Language: python
Libraries: pwn
Source: What does the f say (pwn).md
Preview:
from pwn import *
context.arch = 'amd64'
...

$ vault script 147
# What does the f say (pwn).md
# Language: python  Libraries: pwn
from pwn import *
context.arch = 'amd64'
...
glibc_base = glibc_read - 0x110180
glibc_malloc_hook = glibc_base + 0x3ebc30
for i in range(0, 8):
    b = (glibc_one_gadget >> (i * 8)) & 0xff
    send_printf(fmtstr_payload(8, { glibc_malloc_hook + i: b }))
...
```

Same via MCP — AI calls `search_scripts` to find IDs, then `get_script` for full code:

```
search_scripts(query="RSA sage", library="Crypto")  ->  [ID: 239] 10-line preview
get_script(script_id=239)                           ->  full 193-line Sage solver
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

### Technique Linking

Find writeups that share the same attack technique — see all your approaches side by side:

```bash
vault techniques                         # List all indexed techniques
vault techniques --min-count 5           # Only techniques with 5+ writeups

vault related "RBCD"                     # All writeups using RBCD, with tools + tags
vault related "ADCS ESC1"               # All writeups using ESC1
vault related "SQL Injection"           # Works with canonical names

vault enrich                             # Populate technique links from tags (no re-index)
```

Techniques are extracted from your `#hashtag` tags — no prose scanning, no false positives. Tags like `#RBCD`, `#SQLi`, `#ESC1` are mapped to canonical names. Run `vault enrich` after re-indexing to update technique links.

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
        "WRITEUPS": "~/writeups",
        "VAULT_READONLY": "1"
      }
    }
  }
}
```

> The normal MCP profile is read-only. `VAULT_READONLY=1` is a supported legacy override;
> unset it before explicitly enabling administrative tools with `VAULT_ALLOW_ADMIN=1`.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_DB` | Path to SQLite database | `~/.local/share/command-vault/vault.db` |
| `WRITEUPS` | Unified writeup directory (recommended) | None |
| `WRITEUPS_BOXES` | Boxes directory (legacy, path-based type detection) | None |
| `WRITEUPS_CHALLENGES` | Challenges directory (legacy) | None |
| `WRITEUPS_SHERLOCKS` | Sherlocks directory (legacy) | None |
| `VAULT_READONLY` | Legacy override: force the MCP read-only profile (`1`, `true`, `yes`), even if admin tools were requested | Off; the normal profile is already read-only |

### MCP Tools

| Tool | Description |
|------|-------------|
| `search_commands` | Search commands by keyword, tool, category, or tags |
| `search_writeup_prose` | Search methodology text and explanations from writeups |
| `search_scripts` | Search exploit scripts by language or library |
| `get_script` | Get full script code by ID (from search_scripts results) |
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
| `search_related` | Find writeups sharing a technique (e.g., "RBCD", "ADCS ESC1") |
| `list_techniques` | List all indexed techniques with writeup counts |
| `enrich` | Populate technique links from tags (no re-indexing needed) |

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

## Changelog

### 0.9.1: search continuation and precise diagnostics

All MCP search tools (including related-writeup search and tool examples) accept `cursor` and
`max_chars`. Repeat the same query and filters with `next_cursor`; `limit` and `max_chars` may change
between pages. Cursors are stateless and bound to the query/filters and database file revision;
changed databases and mismatched/corrupt cursors require a new search. No index rebuild is needed.

`has_more` indicates additional records. `records_clipped` indicates shortened fields or a
`kind: reference` record whose content must be fetched with `read_context`/`get_script`. `truncated`
remains the compatibility signal for clipping or a result budget cutoff. The character budget
applies to serialized result records, excluding the page envelope; related search budgets its
nested writeup records. Result variants and context sources now have explicit validated schemas.

Knowledge search reports `unmatched_query_terms` and `unmatched_required_terms` separately. The latter
preserves the exact supplied required terms, including those absent from the query. `unmatched_terms`
is retained as their compatibility union. These fields report individual absence under source/tag
filters; terms that exist separately may still have no jointly matching document.

```sh
vault knowledge "audit logs" --require-term ZQXJ92814 --json
vault knowledge "windows" --limit 100 --max-chars 2000 --json
vault knowledge "windows" --cursor '<next_cursor>' --max-chars 4000 --json
vault search "file" --page --max-chars 2000
vault search "file" --cursor '<next_cursor>' --max-chars 2000
```

`vault knowledge` always returns the page contract. Existing CLI `search`, `scripts`, `history search`,
and `related` retain their legacy output unless `--page`, `--cursor`, or `--max-chars` is supplied;
these options enable structured JSON pagination. Related results retain the grouped `writeups` shape,
with page and total writeup counts. Document/history references support bounded context reads too.

Reconnect the MCP client to load the updated tool schemas. CLI changes are available immediately.

### 0.9: MCP 2.x and section-aware retrieval

Requires `mcp>=2.2,<3`; use the checked-in `uv.lock` with `uv sync --frozen` for reproducible installs.
The CLI remains available. The MCP API retains existing tool names, but search/list tools now return
a structured `SearchPage` object with `results`, `match_mode`, `next_cursor`, `truncated`, and `notice`.
Consumers expecting a bare array must read `results` instead.

The two new retrieval operations are available from the CLI as well:

```sh
vault knowledge "Security audit log" --type sherlock --require-term 1102 --limit 5
vault context '<complete reference from knowledge>' --max-chars 8000
vault context '<same reference>' --offset 8000 --max-chars 8000
vault knowledge "Security audit log" --require-term 1102 --json
```

Use the actual `next_offset` returned by a context page for subsequent reads. Repeat `--require-term`
(alias `--require`) or `--tag` for multiple constraints. Knowledge defaults to five results and a
10,000-character result budget; context defaults to 8,000 characters. Both accept `--max-chars`
from 500 to 20,000 and `--json` before or after the subcommand. Use the global `--db` before the
subcommand to select another database. Runtime errors go to stderr with exit status 1; with `--json`
they are JSON error objects. Invalid CLI arguments use argparse's standard exit status 2.

These commands open the database read-only and call the same `Knowledge` service as MCP. The older
`vault prose` command remains available with its existing output. Activate the installed environment
or invoke its `bin/vault` directly (this deployment uses `/opt/command-vault-mcp/.venv-v2/bin/vault`).

- Use `search_knowledge(query, required_terms=...)` for explanatory evidence. Required terms remain
  mandatory during fallback; unmatched terms and match mode are exposed. Scores are relative rankings,
  not confidence. `search_writeup_prose` is a compatibility name for this section-aware search.
- Follow a result's `reference` with `read_context(reference, offset, max_chars)` to read its source
  section, including XML/log/fenced text. Follow `next_offset` for more. Source status distinguishes
  current, changed, unverified, and unavailable content. Images are referenced, not OCR'd.
- `get_script(script_id, offset, max_chars)` returns exact indexed code in `content`; follow
  `next_offset` until null to retrieve a complete script. Stored material is never executed.
- Inventory tools default to 25 results and accept `limit`/`cursor`. `list_tools` excludes entries
  without writeup commands; `search_history` can still find history-only tools.
- `suggest_command.context` is explicitly rejected rather than silently ignored. Use explicit
  filters on search tools. History without execution timestamps reports unknown recency;
  date-filtered MCP queries fail clearly when all dates are unavailable.
- MCP startup opens the database read-only. Indexing/enrichment/deletion tools are absent by default;
  use the CLI, or explicitly set `VAULT_ALLOW_ADMIN=1` for an administrative server profile.
- Source identity is the canonical path. Schema migration preserves existing IDs. Changed files
  are detected by content hash and parser version, including with `--add`. Each document import
  is atomic. Structured collection directories determine source type in unified mode.
- Rebuilding writeups preserves indexed history. History reimports do not inflate occurrence
  counts; counts retain the maximum observed per-command multiplicity rather than claiming a
  complete multi-source execution ledger. Unknown dates stay unknown.

For a full refresh, prefer a candidate database using `scripts/build_candidate.py`, run the test
suite and retrieval evaluation, then promote the validated candidate. This preserves existing
records whose source files are unavailable. See [MIGRATION-0.9.md](MIGRATION-0.9.md).

## Troubleshooting

- **"vault: command not found"** — Run via `uv run vault` from the project directory, or add `~/.local/bin` to PATH after `pip install -e .`
- **"No results found"** — Check `vault stats`, run `vault index --rebuild` if counts are 0. Multi-word queries try AND first, then fall back to bm25-ranked OR if AND returns nothing.
- **MCP not connecting** — Verify paths in MCP config, check `uv` is in PATH, test with `uv run command-vault`
- **Database errors** — Preserve a SQLite backup before maintenance. Build and validate a separate
  candidate database if recovery requires reindexing; retain the original for rollback.

## License

MIT License - see [LICENSE](LICENSE) file.
