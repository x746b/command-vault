# Research knowledge schema migration

## Scope

Application schema version 2 adds the research-knowledge foundation without
removing or renaming any 0.9 retrieval table or interface. It performs no source
download, research import, or production promotion.

## Safety properties

- Migration runs only when `Database` is opened writable.
- Version 1 to 2 DDL executes inside one explicit SQLite transaction.
- Trigger bodies are executed as complete statements without `executescript`'s
  implicit-commit behavior.
- Pre-existing IDs, rows, FTS content, and relations are preserved.
- The deployed legacy `technique_aliases(id, alias, technique_id)` shape is
  upgraded without discarding IDs or aliases.
- Ambiguous normalized legacy aliases fail atomically for operator review.
- `PRAGMA user_version` changes to 2 only within the successful transaction.
- Newer schema versions are rejected without mutation.

## Candidate procedure

1. Create a consistent SQLite backup of the live database.
2. Verify `integrity_check`, `foreign_key_check`, size, mode, and SHA-256.
3. Copy the verified backup to a new candidate path under the recorded project
   root.
4. Open only the candidate with the schema-v2 application in writable mode.
5. Re-run integrity and foreign-key checks.
6. Compare all legacy table counts and stable IDs with the verified backup.
7. Run legacy retrieval and context tests against the candidate.
8. Keep the production DB and shared MCP process untouched.

The automated unit suite covers fresh creation, legacy v0/v1 migration,
deployed alias-table compatibility, DDL rollback, constraints, vulnerability FTS
insert/update/delete synchronization, reset behavior, and newer-version
rejection.

## Rollback

There is no in-place down-migration. Before production promotion, retain the
matching old application commit and verified old database backup. Rollback means
restoring that pair atomically after disconnecting only command-vault clients.
Never run an old writable application against schema v2.
