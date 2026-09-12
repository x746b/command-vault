# Research knowledge implementation baseline

Recorded: 2026-09-12 (Europe/Prague)

This ledger records the immutable starting point for development on
`feature/research-knowledge-v1`. It contains no database content, configuration
content, credentials, or temporary research artifacts.

## Application

- Repository: `/opt/command-vault-mcp`
- Baseline branch: `main`
- Baseline commit: `74710fe070ee8f3df6e242ca04c735d857c20d15`
- Baseline tree: `7cab648af81c07effa192c548c7ebad477b433a1`.
- Remote: `origin` (`git@github.com:x746b/command-vault.git`)
- Submodules: none.
- Worktree at start: clean.
- Application version: `0.9.1`.
- Python selected by `uv`: CPython 3.12.12.
- Baseline tests: 77 passed in 2.49 seconds.
- Baseline Git bundle: verified under the disposable project root; it is not a
  retained release artifact.

## Live database protection

- Path: `/home/xtk/.local/share/command-vault/vault.db`
- Mode/owner: `0600`, `xtk:xtk`
- Size: 69,836,800 bytes.
- SHA-256 at start and after read-only evaluation:
  `9e30b166c718941207b4d774fe7293bb90ff0086e626e6b8dddd763b628b0195`.
- Schema version: 1.
- `PRAGMA integrity_check`: `ok`.
- `PRAGMA foreign_key_check`: no rows.
- A consistent SQLite backup was created with SQLite's backup mechanism and
  independently passed both checks. Its SHA-256 is
  `8ca91bb13ddad000cb273430c9cf1be388c8d1a1fa9ffdeeaeba05ba6c62bccd`.

The backup differs byte-for-byte from the live file because SQLite backup
rewrites database pages into a consistent standalone image. All development
migrations and indexing must target a candidate derived from this backup, never
the live path.

## Retrieval baseline

The current eight-case suite was run in keyword and natural-language forms
against the backup, with up to five context reads per query:

- cases: 16;
- median search latency: 42.119 ms;
- maximum search latency: 122.004 ms;
- median context-read latency: 6.728 ms;
- maximum context-read latency: 13.628 ms.

The previously saved live-result IDs predated the current database and could
not be replayed against this baseline. The fresh, revision-bound result and
pytest XML are stored only in the recorded disposable project root.

## Host state relevant to this project

- Root filesystem: 59 GiB total, 26 GiB available at start.
- `/tmp`: 16 GiB tmpfs, 14 GiB available at start.
- Application tree: approximately 44 MiB before the new `uv` environment.
- ASLR: `kernel.randomize_va_space = 2`.
- Core pattern: systemd-coredump default recorded at start.
- Docker CLI: 28.5.2; daemon access denied to the current account. No Docker
  resources were created.
- Existing read-only command-vault MCP processes were left running and were not
  restarted or reconfigured.
- Primary MCP configuration mode: `0600`; its content is not copied here. Its
  starting SHA-256 is
  `0e69acf0bbf7f2b156b3e3608a4478565b662bcba59d23aa0ae3faefb63ef51a`.

## Disposable project root

The one allocated root is `/tmp/command-vault-research.j3Xal9`, with all
downloads, source clones, worktrees, normalized bundles, candidate databases,
test output, manifests, and backups beneath it.

This path is deliberately documented only as an implementation-run ledger. No
runtime code, database record, normalized source bundle, or release manifest may
depend on it.

## Unresolved preservation input

The identifier and location of the validated VM snapshot/revert checkpoint are
not visible inside the guest. The operator must record and verify that external
identifier before candidate promotion or cleanup. This does not block isolated
Phase 0/1 development.
