# Migrating to 1.0

Version 1.0 introduces database schema 2 and optional managed research
collections while preserving existing command, script, prose, history, box,
challenge, and Sherlock functionality.

## Before migration

Keep a compatible application/database pair and create a SQLite-consistent
backup:

```bash
vault_db="$HOME/.local/share/command-vault/vault.db"
backup_db="$HOME/.local/share/command-vault/vault.pre-1.0-$(date +%Y%m%d-%H%M%S).db"

sqlite3 "$vault_db" ".backup '$backup_db'"
chmod 600 "$backup_db"
sqlite3 "file:$backup_db?mode=ro" \
  'PRAGMA integrity_check; PRAGMA foreign_key_check; PRAGMA user_version;'
```

The normal MCP server opens the database read-only and does not perform
migrations. Build and inspect a separate candidate using the
[`migration`](docs/research-knowledge/MIGRATION.md) and
[`evaluation`](docs/research-knowledge/EVALUATION.md) guidance before replacing
an existing database.

## Managed research

When a managed corpus is installed, configure:

```bash
export WRITEUPS="$HOME/writeups"
export WRITEUPS_RESEARCH="$HOME/writeups/research"
```

Managed research is adapter-owned. Do not index its `document.md` files through
the legacy Markdown indexer. Routine personal indexing safely auto-detects and
excludes the canonical managed subtree even if `WRITEUPS_RESEARCH` is omitted:

```bash
WRITEUPS="$HOME/writeups" vault --json index --add
```

See
[`docs/research-knowledge/SAFE-INDEXING.md`](docs/research-knowledge/SAFE-INDEXING.md)
for backups, integrity checks, explicit paths, idempotency, and rebuild
warnings.

## Candidate and release validation

The 1.0 source tree includes deterministic tools for:

- selective CyberGym text acquisition;
- CyberGym, ExploitGym, and ExploitBench bundle construction;
- multi-source candidate database construction;
- managed-path rebasing;
- read-only database/corpus release auditing.

Source contracts and pinned revisions are documented in
[`docs/research-knowledge/SOURCES.lock.json`](docs/research-knowledge/SOURCES.lock.json).
Do not commit upstream corpora, managed research documents, databases, or
release archives to Git.

Before promotion, require:

1. Full tests and `git diff --check`.
2. SQLite integrity and foreign-key checks.
3. Managed-file and embedded-snapshot hash parity.
4. Legacy and research retrieval regression checks.
5. A fresh production backup and explicit promotion approval.

Reusable guidance:

- [`MIGRATION.md`](docs/research-knowledge/MIGRATION.md)
- [`EVALUATION.md`](docs/research-knowledge/EVALUATION.md)
- [`SECURITY.md`](docs/research-knowledge/SECURITY.md)

## Rollback

Disconnect only affected command-vault clients, restore the matching old
application commit/tag and old database backup, verify integrity and retrieval,
then reconnect. Do not run an old application writer against schema 2.
