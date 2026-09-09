# Command Vault (also MCP)

> *"What was that certipy command I used for ESC8?"*
> *"How did I exploit that shadow credentials thing again?"*

Command Vault indexes **commands**, **scripts**, and **prose** from your penetration testing writeups and shell history into a searchable database with full context — what tool, what technique, which box. MCP-ready for AI assistants.

## Features

- **Command search** — Ranked FTS across command text and its context, with tool/category/tag filters
- **Prose search** — Search section-aware evidence, including methodology and fenced log/XML text; read source context by reference
- **Script search & retrieval** — Find detected scripts by language/library and retrieve their indexed code by ID
- **Ranked fallback** — Multi-word queries try AND first, then BM25-ranked OR if no AND matches exist; fallback is not a relevance guarantee
- **Shell history** — Index `~/.zsh_history` or `~/.bash_history` with deduplication and selected redaction patterns; dates stay unknown when absent
- **Tag filtering** — Search by extracted `#hashtags`; all requested tags must match
- **Smart categorization** — 200+ tool names mapped to categories (recon, AD, web, privesc, etc.); unknown names fall back to `misc`
- **Template generation** — Heuristic placeholders for recognized IPs, lab domains, and credential arguments; not comprehensive secret removal
- **Multiple writeup types** — Boxes, challenges, and Sherlocks with unified or legacy directory modes

## Installation

Requires Python 3.11+. [uv](https://docs.astral.sh/uv/guides/projects/) is recommended for the source
installation; it is not required by the installed runtime. To use the features documented here:

~~~bash
git clone https://github.com/x746b/command-vault.git
cd command-vault
uv sync --frozen
source .venv/bin/activate
~~~

If an existing checkout uses `.venv-v2`, use `UV_PROJECT_ENVIRONMENT=.venv-v2 uv sync --frozen` and
activate `.venv-v2/bin/activate` instead. The examples below assume the selected environment is active.

The [PyPI package](https://pypi.org/project/command-vault-mcp/) is published separately from GitHub.
As checked on 2026-09-09, PyPI provides **0.8.0**; use the source installation for **0.9.1**.
`python -m pip install command-vault-mcp` in an activated environment installs the published PyPI
package, which may not match this README.

## Quick Start

Point `WRITEUPS` at an existing directory containing your Markdown sources:

~~~bash
export WRITEUPS="$HOME/writeups"

# Create or incrementally update the index; a rebuild is not required
vault index
vault stats

# Search commands or explanatory evidence
vault search --tool file --limit 5
vault knowledge "Security audit log" --type sherlock --require-term 1102 --limit 5
vault context '<reference from knowledge>' --max-chars 8000
~~~

Replace the reference placeholder with the complete value returned by search. Initialize the database
through the CLI before registering MCP: the read-only server does not create or migrate it. Back up
an existing database before schema migration; see [MIGRATION-0.9.md](MIGRATION-0.9.md).

## CLI Reference

Use global `--db` and `--json` before the subcommand for consistent syntax across the CLI:

~~~bash
vault --db /absolute/path/vault.db --json stats
~~~

Some search commands also accept `--json` after their name. Use `vault <command> --help` for the
installed command's options.

### Commands & Scripts

~~~bash
vault search "certipy ESC"                # AND first; OR fallback if no AND matches
vault search --tool nmap --limit 5
vault search --category log_analysis
vault search --tag windows --tag ad       # All tags must match
vault --json search --type box "ADCS"

vault scripts --language python
vault scripts --library requests
vault scripts --list-libraries

vault suggest "audit logs"                # Keyword-based suggestions grouped by tool
~~~

Suggestions are keyword lookup rather than contextual planning. Extraction and categorization are
heuristic; confirm a command's purpose in its source context.

### Retrieving Indexed Scripts

Search returns a script ID and a preview of up to ten lines. Retrieve the stored code using an ID
from your own search results; numeric IDs are database-specific and can change after indexing.

~~~bash
vault scripts "parser" --language python
vault script 147                          # Replace 147 with a returned ID
vault --json script 147                   # The CLI returns the full indexed code
~~~

Over MCP, call `search_scripts`, select `results[i].id`, and call `get_script(script_id=...)`.
Read code from `content`. If `next_offset` is not null, call again with that offset until it is null.
The MCP default is 8,000 characters per page, with `max_chars` configurable from 500 to 20,000.
A final page means the indexed item is exhausted; it does not certify that the original source was
complete or that the script works.

### Evidence Search & Context

The legacy `prose` command searches indexed evidence chunks. It defaults to 10 passages and
300 displayed characters per passage; `--chars 0` displays each full indexed chunk:

~~~bash
vault prose "audit logs" --type sherlock
vault prose "file timestamps" --limit 20 --chars 0
~~~

Use `knowledge` for references, required terms, match diagnostics, and continuation:

~~~bash
vault knowledge "audit logs" --type sherlock --tag windows --require-term 1102 --json
vault knowledge "windows" --limit 100 --max-chars 2000 --json
vault knowledge "windows" --cursor '<next_cursor>' --max-chars 4000 --json
vault context '<reference>' --max-chars 500 --json
vault context '<same reference>' --offset 500 --max-chars 500 --json
~~~

Use the actual `next_cursor` or `next_offset` from the preceding response; stop when it is null.
Repeat the same query and filters for cursor searches; page size and budget may change.
`--require-term` (alias `--require`) and `--tag` are repeatable. Required terms remain mandatory on
OR fallback. `unmatched_query_terms` and `unmatched_required_terms` report individual absence under
the filters; otherwise-present terms may still have no jointly matching document.

Knowledge defaults to 5 results and a 10,000-character result budget. Context defaults to 8,000
characters; both budgets accept 500..20,000. These two commands accept `--json` before or after the
subcommand. Expected retrieval errors go to stderr with exit status 1 (JSON error objects in JSON
mode); invalid arguments use argparse's exit status 2.

Existing `search`, `scripts`, `history search`, and `related` retain their legacy output by default.
`--page`, `--cursor`, or `--max-chars` opts into structured JSON pagination:

~~~bash
vault search "file" --page --max-chars 2000
vault search "file" --cursor '<next_cursor>' --max-chars 2000
vault scripts --language python --page --limit 5
vault history search "curl" --page --limit 5
~~~

Paged searches accept limits from 1 to 100. `has_more`/`next_cursor` indicate additional records;
`records_clipped` means a field or record was shortened. Expand a `kind: reference` result with
`context`, or use `get_script` over MCP for exact indexed script code. Budgets cover serialized result
records, excluding the JSON envelope; related search budgets its nested writeup records. Legacy
unpaged searches are also capped internally; use page mode to enumerate beyond one result set.

### Indexing

~~~bash
vault index                              # Create/update; skip unchanged files
vault index --add                        # Compatibility incremental mode; changed files are updated too
vault index /path/to/writeups/boxes       # Import an explicit collection directory
vault index --rebuild                    # Clear all writeup data first; preserve history
~~~

Sources use canonical filepath identity, content hashes, and parser versions. Each document import
is atomic. Incremental indexing does not automatically prune deleted or moved sources.

`--rebuild` clears **all writeup content**, then imports the selected directories. It is not required
on first use and does not delete indexed history. Prefer the candidate-database workflow in
[MIGRATION-0.9.md](MIGRATION-0.9.md) for full refreshes and source relocation.

`--type` selects a matching configured **legacy collection** when that collection exists. It is not
a content-type filter over a unified `WRITEUPS` root or custom directory arguments. Pass the desired
collection directory explicitly in those cases. Explicit directory arguments use path-based
detection; use `WRITEUPS` for full tag scanning of flat unified sources.

### Shell History

~~~bash
vault history index "$HOME/.zsh_history"
vault history index "$HOME/.zsh_history" --since "2024-01-01"
vault history search "curl"
vault history search --tool ssh --page --limit 5
vault history stats
vault history clear --confirm            # Delete indexed history
~~~

Only recognized, non-blocklisted entries are imported. Raw history is retained alongside a sanitized
representation; search returns the sanitized field. Redaction uses selected patterns and does not
guarantee that all credentials are removed. Counts retain the maximum observed per-command
multiplicity rather than a complete execution ledger across sources.

Timestamped zsh/bash entries can provide first/last execution dates; plain history cannot.
`--since` filters known dates; unknown dates cannot qualify. MCP and paged CLI searches explicitly
reject date filtering when all history dates are unknown. Deleting indexed history does not modify
the original shell-history file.

### Technique Linking

~~~bash
vault techniques
vault techniques --min-count 5
vault related "RBCD"                     # Up to 20 linked writeups by default
vault related "ADCS ESC1" --page          # Follow next_cursor for additional writeups
vault related "SQL Injection"
vault enrich
~~~

Recognized hashtags such as `#RBCD`, `#SQLi`, and `#ESC1` map to canonical technique names. Links
depend on tag quality; they do not infer every technique mentioned in prose and are not guaranteed
free of false positives. Imported documents have their links refreshed automatically. `vault enrich`
refreshes existing tag-derived links without rereading source files.

### Other

~~~bash
vault tools --category log_analysis
vault categories
vault tags --min-count 5
vault stats
vault maintain --all                     # VACUUM + ANALYZE + FTS optimization
~~~

## MCP Server Setup

Use the interpreter from the environment where Command Vault is installed, and an existing
initialized database. For Claude Code, using its
[stdio registration syntax](https://code.claude.com/docs/en/mcp#option-3-add-a-local-stdio-server):

~~~bash
claude mcp add \
  --env "VAULT_DB=$HOME/.local/share/command-vault/vault.db" "WRITEUPS=$HOME/writeups" \
  --transport stdio --scope user command-vault \
  -- /absolute/path/to/command-vault/.venv/bin/python -m command_vault.server
~~~

For clients using `mcpServers` JSON configuration, add an entry such as:

~~~json
{
  "mcpServers": {
    "command-vault": {
      "command": "/absolute/path/to/command-vault/.venv/bin/python",
      "args": ["-m", "command_vault.server"],
      "env": {
        "VAULT_DB": "~/.local/share/command-vault/vault.db",
        "WRITEUPS": "~/writeups",
        "VAULT_ALLOW_ADMIN": "0"
      }
    }
  }
}
~~~

Replace the interpreter path, including `.venv-v2` if that is your chosen environment. Command Vault
expands `~` in its database/source settings. Other clients use their own configuration format.
Reconnect the client after changing the server environment or tool schemas.

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `VAULT_DB` | SQLite database path | `~/.local/share/command-vault/vault.db` |
| `WRITEUPS` | Unified source root, with full tag scanning | `~/writeups` if it exists and no source-directory variables are set |
| `WRITEUPS_BOXES` | Legacy boxes source directory | Unset |
| `WRITEUPS_CHALLENGES` | Legacy challenges source directory | Unset |
| `WRITEUPS_SHERLOCKS` | Legacy Sherlocks source directory | Unset |
| `VAULT_ALLOW_ADMIN` | Expose MCP write tools when exactly `1` | Disabled |
| `VAULT_READONLY` | Legacy MCP override: `1`, `true`, or `yes` forces the read-only profile even when admin was requested | Unset; the normal MCP profile is already read-only |

Explicit unified and legacy source settings can coexist. The two profile variables govern MCP;
they do not disable explicit CLI indexing or maintenance commands.

### MCP Tools

The normal profile exposes **18 read-only tools**:

| Tool | Description |
|---|---|
| `search_knowledge` | Search evidence with required terms, diagnostics, references, and cursors |
| `read_context` | Page through source sections/documents or indexed fallback content |
| `search_commands` | Search command text/context with tool, category, type, and tag filters |
| `search_writeup_prose` | Compatibility evidence search; use `search_knowledge` for required-term input |
| `search_scripts` | Search detected script previews by keyword, language, or library |
| `get_script` | Page through indexed code by script ID |
| `get_tool_examples` | Search examples for a tool, with an optional keyword-purpose filter |
| `suggest_command` | Bounded keyword suggestions grouped by tool; nonempty `context` is rejected |
| `list_tools` | Paged inventory of tools with writeup commands; history-only tools remain searchable through history |
| `list_categories` | Bounded category/count listing without a cursor |
| `list_tags` | Paged tags and usage counts |
| `list_libraries` | Paged libraries detected in scripts |
| `get_writeup_summary` | Bounded command/script inventory; use `read_context` for prose |
| `vault_stats` | Indexed corpus counts |
| `search_history` | Paged sanitized history; `since` filters last-seen execution dates |
| `history_stats` | History counts and timestamp coverage |
| `search_related` | Paged linked writeups grouped under the matched technique |
| `list_techniques` | Paged technique names and counts |

Search results use page envelopes with `results`, `match_mode`, clipping metadata, and continuation.
`list_tools`, `list_tags`, `list_libraries`, and `list_techniques` default to 25 items and accept
`limit`/`cursor`. Not every bounded tool supports continuation: categories, suggestions, and writeup
summaries are bounded listings, not cursor searches. Ranking scores are relative, not confidence.

The administrative profile adds **four write tools**. Enable it only with `VAULT_ALLOW_ADMIN=1` and
without a truthy `VAULT_READONLY` override:

| Tool | Description |
|---|---|
| `index_writeups` | Import/reindex configured or supplied source directories |
| `index_history` | Import shell history |
| `clear_history` | Delete indexed history; requires `confirm=true` |
| `enrich` | Refresh existing tag-derived technique relations |

## Writeup Format

Command extraction is heuristic and recognizes shell prompts such as `$`, `user@host$`, `➜ dir`,
`PS C:\>`, `*Evil-WinRM*`, `PV >`, and `C:\>` in supported code fences. Script detection currently
uses Python and JavaScript/Frida indicators; not every code block becomes a script record.

~~~markdown
# Example investigation

#sherlock #windows #easy

## Local inspection

```bash
$ file Security.evtx
```

```powershell
PS C:\> Get-Date
```

## Example script

```python
#!/usr/bin/env python3
import json

def main():
    print(json.dumps({"status": "ok"}))

if __name__ == "__main__":
    main()
```

## Audit evidence

A cleared Security log can be corroborated with this event:

```xml
<EventID>1102</EventID>
<Channel>Security</Channel>
```
~~~

The `boxes`, `challenges`, and `sherlocks` collection folders take precedence over type guesses from
prose or filenames. Tags are extracted from headers in legacy mode and scanned more broadly in
unified mode.

Evidence is grouped by section, including fenced text, with chunks of at most 3,000 characters and
within-section overlap. Small fragments can be skipped. `read_context` can fetch a larger source
section, reports source freshness/availability, and falls back to indexed text if the source is
unavailable. Images remain references; no OCR is performed. Retrieved material is data and is not
executed by the vault.

## Changelog

### 0.9.1: search continuation and precise diagnostics

All MCP search tools (including related-writeup search and tool examples) accept `cursor` and
`max_chars`. Repeat the same query and filters with `next_cursor`; `limit` and `max_chars` may change
between pages. Cursors are stateless and bound to the query/filters and database file revision;
changed databases and mismatched/corrupt cursors require a new search. No index rebuild is needed for the 0.9-to-0.9.1 update.

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
or invoke its `bin/vault` directly.

- Use `search_knowledge(query, required_terms=...)` for explanatory evidence. Required terms remain
  mandatory during fallback; unmatched terms and match mode are exposed. Scores are relative rankings,
  not confidence. `search_writeup_prose` is a compatibility name for this section-aware search.
- Follow a result's `reference` with `read_context(reference, offset, max_chars)` to read its source
  section, including XML/log/fenced text. Follow `next_offset` for more. Source status distinguishes
  current, changed, unverified, and unavailable content. Images are referenced, not OCR'd.
- `get_script(script_id, offset, max_chars)` returns exact indexed code in `content`; follow
  `next_offset` until null to retrieve a complete script. Stored material is never executed.
- `list_tools`, `list_tags`, `list_libraries`, and `list_techniques` default to 25 results and accept
  `limit`/`cursor`. `list_categories` is a bounded list without a cursor. `list_tools` excludes entries
  without writeup commands; `search_history` can still find history-only tools.
- Nonempty `suggest_command.context` is explicitly rejected rather than silently ignored. Use explicit
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

- **`vault: command not found`** — Activate the installed environment or invoke its `bin/vault`.
  From a source checkout, `uv run --frozen vault --help` uses uv's project environment; set
  `UV_PROJECT_ENVIRONMENT=.venv-v2` when that is the environment you intend to use.
- **Database not found** — Confirm `VAULT_DB` and source settings, then initialize through `vault index`.
  MCP startup is read-only and does not initialize the database.
- **No results found** — Check query terms, filters, required-term diagnostics, and corpus counts.
  OR fallback can return loosely related evidence. A missing hit alone is not a reason to rebuild.
- **MCP not connecting or showing old schemas** — Check the configured interpreter and installed
  dependencies, inspect client/server logs, and reconnect. Registering a different environment does
  not update an already-running server process.
- **Old schema or database errors** — Preserve a consistent SQLite backup. Use the
  [migration guide](MIGRATION-0.9.md) and validate a candidate database before replacing the live one.
- **Cursor rejected** — Repeat the original query/filters, or restart the search after a database
  change. Page size and budget may change; cursors are not intended to survive database updates.
- **Unknown history timestamps** — The source may lack execution dates. Do not substitute indexing
  time for execution time.

## License

MIT License — see [LICENSE](LICENSE).
