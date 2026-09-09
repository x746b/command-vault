# Migrating to 0.9

The server uses the high-level MCP 2.x `MCPServer`. No database is opened at module import time.
Search/list/context responses have explicit output schemas, and expected failures use tool errors.
Normal server instances use a SQLite read-only connection; administrative operations remain in the CLI.

## Compatibility

Existing retrieval tool names and principal input arguments remain. Search/list responses are now
`SearchPage` objects rather than bare arrays. Script retrieval returns `ContextPage.content` and
supports `offset`/`max_chars`; follow `next_offset` until null. `get_writeup_summary` is a bounded
inventory; source prose is available through `read_context`.

CLI parity is available through `vault knowledge` and `vault context`. They call the same retrieval
service directly without starting MCP, and support JSON pages, required terms, filtering, response
budgets, and context offsets. Both operations open the database read-only.

The new `search_knowledge` response includes match mode, unmatched query terms, excerpts, and
revision-bound references. `required_terms` are hard constraints. Legacy `chunk:ID`, `command:ID`,
and `script:ID` references remain accepted, but only new revision-bound references detect ID reuse
after reindexing. Existing numeric script IDs should not be cached across ingestion runs.

Protocol compatibility must be tested through stdio as well as the in-memory client. MCP 2.x supports
both modern and legacy clients. Generic dictionary return annotations need typed keys/values for
the SDK to emit structured content, which is covered by the regression tests.

## Database migration and ingestion

Schema version 1 replaces global filename uniqueness with canonical filepath uniqueness and adds
content hashes and parser versions. Existing IDs are retained during migration. A document's
commands, scripts, chunks, tags, and relations are replaced in a single transaction; failures roll
back. The read-only server does not migrate a database on startup.

Section-aware chunks retain fenced evidence, cap text at 3,000 characters, and overlap by 200
characters within a section. Source reading returns the original section with existing sanitization.
Images remain references and are not OCR'd. Invalid/fenced output is excluded from command extraction
where it is recognized, while remaining available as evidence. This is heuristic extraction and not
a guarantee that every stored item is correctly categorized.

Canonical collection folders (`boxes`, `challenges`, `sherlocks`) determine type before prose-based
fallback. This can correct old source-type counts. Existing lab credential treatment is retained.

`WRITEUPS` defaults to `~/writeups` when no source directories are configured and that folder exists.
Explicit source settings take precedence. Missing source directories fail before a destructive
rebuild. Rebuilding writeups does not clear history. A full refresh should use a separate candidate:

```sh
uv sync --frozen
uv run python scripts/build_candidate.py \
  --baseline /absolute/path/to/backup.db \
  --candidate /absolute/path/to/new-candidate.db \
  --writeups /absolute/path/to/writeups \
  --history /absolute/path/to/.zsh_history
uv run pytest -q
```

The builder refuses an existing candidate path and does not promote the candidate. It relocates
unambiguous filename matches into the provided source root and retains unavailable old records.
Review relocation, source counts, coverage, integrity, and retrieval results before replacement.

## Evaluation

`evals/retrieval-cases.json` contains eight defensive development tasks and four absence controls.
`scripts/evaluate_candidate.py` compares a baseline with a candidate using recorded live baseline
result IDs. It applies explicit concept checks to excerpts and source context. These are exploratory
regressions, not independent factual grading or blind agent performance. A held-out agent evaluation
and any semantic/reranking experiment remain future work.

## Rollback

Keep a consistent SQLite backup of the original database separately from the application backup.
Record the MCP interpreter/configuration used by the previous release. To roll back, stop/reconnect
only the affected MCP connection, restore the matching code/environment and database backup, then
verify the old server before resuming use. Do not mix a running old writer with a new database.
