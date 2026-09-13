# Rollback runbook

Rollback restores a compatible application/database pair; there is no in-place
schema down-migration.

## Required anchors

- Pre-project application commit: `74710fe070ee8f3df6e242ca04c735d857c20d15`.
- Current live DB SHA-256 before promotion:
  `9e30b166c718941207b4d774fe7293bb90ff0086e626e6b8dddd763b628b0195`.
- Phase 0 consistent backup SHA-256:
  `8ca91bb13ddad000cb273430c9cf1be388c8d1a1fa9ffdeeaeba05ba6c62bccd`.
- A fresh, verified pre-promotion live backup and its durable external location
  must be recorded before any production replacement.

## Procedure

1. Disconnect only command-vault clients; do not terminate unrelated MCP or
   user sessions.
2. Preserve the failed/new DB and corpus for investigation.
3. Restore the approved old application commit/tag and its matching DB backup
   through same-filesystem temporary paths and atomic renames.
4. Restore the previous configuration/corpus state recorded immediately before
   promotion. Do not point old writable code at a schema-v2 DB.
5. Verify DB mode/owner/hash, `integrity_check`, foreign keys, application
   version, legacy stats/retrieval, and read-only MCP startup.
6. Reconnect clients only after validation and record the rollback outcome.

Minimum read-only validation after restoring the old pair:

```bash
git -C /opt/command-vault-mcp rev-parse HEAD
stat -c '%a %U %G %s %n' /home/xtk/.local/share/command-vault/vault.db
sha256sum /home/xtk/.local/share/command-vault/vault.db
sqlite3 'file:/home/xtk/.local/share/command-vault/vault.db?mode=ro' \
  'PRAGMA integrity_check; PRAGMA foreign_key_check; PRAGMA user_version;'
VAULT_READONLY=1 uv run command-vault
```

If rollback follows VM reversion, use the external protected bundle rather than
any `/tmp` path documented during development.
