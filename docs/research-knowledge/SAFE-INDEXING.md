# Safe incremental writeup indexing

## Routine one-liner

After adding or editing personal Markdown beneath `~/writeups`, run:

```bash
WRITEUPS="$HOME/writeups" vault --json index --add
```

This is the recommended routine command. It uses the default database at
`~/.local/share/command-vault/vault.db`, processes new and changed personal
writeups, and skips unchanged files.

An existing canonical `$WRITEUPS/research` directory is detected and excluded
from legacy Markdown indexing even when `WRITEUPS_RESEARCH` is not exported.
Manifest-owned managed research documents are also rejected at the indexing
boundary. The managed framework corpus must be updated only through its
dedicated adapters and candidate workflow.

## Check the result

A successful first run reports the number of processed files and an empty
`errors` list. Run the same command again:

```bash
WRITEUPS="$HOME/writeups" vault --json index --add
```

With no further source changes, expect:

```json
{
  "files_processed": 0,
  "commands_extracted": 0,
  "scripts_extracted": 0,
  "chunks_extracted": 0,
  "errors": []
}
```

`--add` is incremental rather than strictly append-only: a modified existing
document is reindexed atomically, while an unchanged document is skipped.
Deleted or moved source files are not pruned automatically.

## Explicit paths

The equivalent fully explicit invocation is:

```bash
VAULT_DB="$HOME/.local/share/command-vault/vault.db" \
WRITEUPS="$HOME/writeups" \
WRITEUPS_RESEARCH="$HOME/writeups/research" \
vault --json index --add
```

Set `WRITEUPS_RESEARCH` explicitly when the managed research directory is not
the canonical `$WRITEUPS/research` child. Do not point a legacy/custom indexing
argument directly at a managed bundle or its `document.md` file.

Personal sources should normally live under:

```text
~/writeups/boxes/
~/writeups/challenges/
~/writeups/sherlocks/
```

Reserve `~/writeups/research/` for adapter-generated managed research.

## Optional backup for larger imports

For a large batch or parser upgrade, create a SQLite-consistent backup first:

```bash
vault_db="$HOME/.local/share/command-vault/vault.db"
backup_db="$HOME/.local/share/command-vault/vault.before-add-$(date +%Y%m%d-%H%M%S).db"

sqlite3 "$vault_db" ".backup '$backup_db'"
chmod 600 "$backup_db"
```

Then verify the database after indexing:

```bash
sqlite3 "file:$HOME/.local/share/command-vault/vault.db?mode=ro" \
  'PRAGMA integrity_check; PRAGMA foreign_key_check;'
```

The expected output is only:

```text
ok
```

Stop and inspect the source and backup if indexing reports any errors or the
integrity/foreign-key checks produce additional output.

## Full rebuild warning

Do not use `vault index --rebuild` for routine additions. A rebuild clears all
writeup-derived content before importing configured sources and requires the
separately validated candidate/migration workflow. Incremental `--add` keeps
history and managed research isolated.

## Regression contract

Automated CLI tests cover the canonical one-liner with managed research present.
They verify that only new or changed personal writeups are processed, research
documents and relations are preserved, and an immediate repeat processes zero
files.
