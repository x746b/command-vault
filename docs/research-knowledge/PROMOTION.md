# Production promotion runbook

This procedure is prepared only. It requires explicit user approval and has not
been executed.

## Preconditions

- Feature branch/merge/tag is pushed and verified from the remote.
- External validated VM snapshot identifier/date is recorded.
- Protected release bundle is copied to and hash-verified at an approved
  durable destination outside the revert boundary.
- The p95 investigation disposition in `EVALUATION.md` is accepted.
- Exact production owner/group and every command-vault client are inventoried.

## Staging

Disconnect only known command-vault clients before the replacement window.
Create a fresh consistent live backup with SQLite's backup command and verify
its hash, mode, integrity, and foreign keys. Copy that backup to the protected
external destination before continuing.

Stage the approved path-rebased promotion DB on the live database filesystem
without replacing the live path. Do not use the development candidate with
`/tmp` managed paths:

```bash
install -m 0600 <release-dir>/vault.db \
  /home/xtk/.local/share/command-vault/.vault.db.release
sqlite3 'file:/home/xtk/.local/share/command-vault/.vault.db.release?mode=ro' \
  'PRAGMA integrity_check; PRAGMA foreign_key_check;'
sha256sum /home/xtk/.local/share/command-vault/.vault.db.release
```

Stage the verified managed corpus as a sibling beneath
`/home/xtk/writeups`; reject symlinks/nonregular files and verify the complete
corpus manifest before rename. The destination
`/home/xtk/writeups/research` must not already exist unless a separately
approved replacement/rollback path is recorded.

## Atomic replacement window

1. Recheck the live DB has not changed since the fresh backup.
2. Move the current live DB to the recorded rollback filename on the same
   filesystem; do not delete it.
3. Atomically rename `.vault.db.release` to `vault.db` and verify mode/owner.
4. Atomically rename the staged corpus directory to
   `/home/xtk/writeups/research`.
5. Add `WRITEUPS_RESEARCH=/home/xtk/writeups/research` only to inventoried
   command-vault client environments. Preserve `WRITEUPS=/home/xtk/writeups`
   and unrelated settings.

If any step fails, stop and use `ROLLBACK.md`; do not improvise a partial
mixed-version state.

## Post-promotion checks

Run the full release smoke set using a read-only process: schema/hash/stats,
legacy commands, exact research profiles, C/syz retrieval, managed context,
snapshot fallback, structured filters, pagination, and negative controls.
Confirm normal MCP calls do not change DB bytes, then reconnect only the known
clients. Record application tag/commit, DB/corpus/manifest hashes, client
configuration, checks, and timestamps.
