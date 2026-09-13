# Restore runbook

This runbook is prepared but has not been executed. Replace every angle-bracket
placeholder from the approved release manifest before use.

1. Record and verify the external validated VM snapshot identifier and date.
2. Verify the durable release destination is outside the VM revert boundary.
3. Verify the protected bundle hashes before extracting anything.
4. Fetch/clone the approved Git tag or immutable commit into
   `/opt/command-vault-mcp`; require a clean worktree.
5. Recreate dependencies with `uv sync --frozen`. Do not restore a virtual
   environment archive or install system packages.
6. Restore the corpus archive into a new staging directory, verify every entry
   against `RESEARCH-CORPUS-MANIFEST.json`, reject links/nonregular files, then
   atomically install it as `/home/xtk/writeups/research`.
7. Restore `vault.db` through a same-filesystem temporary file, verify its
   SHA-256/integrity/foreign keys, set the recorded owner/group and mode `0600`,
   then atomically replace `/home/xtk/.local/share/command-vault/vault.db`.
8. Apply only the documented `WRITEUPS_RESEARCH=/home/xtk/writeups/research`
   configuration. Preserve unrelated configuration and verify the parent
   `WRITEUPS=/home/xtk/writeups` scanner excludes the managed subtree.
9. Start an isolated read-only process first and verify stats, legacy command
   search, research search/profile, C/syz retrieval, managed context, snapshot
   fallback, pagination, and unchanged DB bytes.
10. Reconnect only known command-vault clients. Record restored Git commit/tag,
    DB hash, corpus-manifest hash, test results, and client configuration.

Suggested verification commands, after substituting an approved release path:

```bash
sha256sum -c <release-dir>/vault.db.sha256
sha256sum -c <release-dir>/research-corpus.tar.sha256
sqlite3 'file:<release-dir>/vault.db?mode=ro' \
  'PRAGMA integrity_check; PRAGMA foreign_key_check; PRAGMA user_version;'
git -C /opt/command-vault-mcp status --short
uv sync --frozen
```

Use a newly created same-filesystem staging filename for DB/corpus installation;
never extract an archive directly over a live destination.

Do not clean the protected bundle after restoration. Keep the prior compatible
application/database pair until production validation is complete.
