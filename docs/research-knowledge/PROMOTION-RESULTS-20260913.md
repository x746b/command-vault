# Production promotion results — 2026-09-13

Status: production database and managed research corpus promoted successfully; Git push and VM cleanup/revert remain pending.

## Application

- Branch: `feature/research-knowledge-v1`
- Promotion documentation commit before this record: `bb8700a`
- No remote push was performed during promotion.
- Full application suite: 1,181 tests passed.
- `git diff --check`, JSON validation, and Git integrity checks passed during release preparation.

## Persistent release unit

The complete release payload was copied out of tmpfs to:

```text
/home/xtk/.local/share/command-vault/releases/research-knowledge-20260913
```

- Directory mode: `0700`
- File mode: `0600`
- `PAYLOAD-MANIFEST.sha256`: `e14a2ae28b625229206071b0e6c9b9c4282fbbc6144ab06ec7910a8a93fc8fd0`
- All 23 payload files passed `sha256sum -c` after the persistent copy.
- The release unit remains local to this VM and must be copied to an approved durable destination outside the VM revert boundary before cleanup/revert.

## Pre-promotion backups

Two compatible rollback copies are retained:

```text
/home/xtk/.local/share/command-vault/vault.rollback-pre-research-20260913.db
/home/xtk/.local/share/command-vault/vault.pre-research-20260913.db
```

| Copy | SHA-256 | Size | Mode | Purpose |
|---|---|---:|---:|---|
| Exact-byte rollback | `9e30b166c718941207b4d774fe7293bb90ff0086e626e6b8dddd763b628b0195` | 69,836,800 | `0600` | Exact old live database bytes |
| SQLite backup API copy | `8ca91bb13ddad000cb273430c9cf1be388c8d1a1fa9ffdeeaeba05ba6c62bccd` | 69,836,800 | `0600` | Consistent logical backup |

Both backups passed SQLite integrity checks and contain the expected legacy counts. The differing physical hashes are expected because SQLite's backup API may produce different page bytes for a logically identical database.

## Managed research corpus

Installed atomically at:

```text
/home/xtk/writeups/research
```

- Root/directory mode: `0700`
- File mode: `0600`
- Regular files: 8,944
- Research documents: 1,753
- Manifest total content bytes: 149,256,948
- Archive SHA-256: `4b927324b919f964d22120a5b688874f3be21b22b696b2063ced54818905f4b0`
- Full staged release audit matched every managed file, bundle, database document path, and embedded snapshot before the atomic rename.

Sources:

- CyberGym: 1,507 documents
- ExploitGym: 204 documents
- ExploitBench: 42 documents

## Production database

Promoted atomically at:

```text
/home/xtk/.local/share/command-vault/vault.db
```

- SHA-256: `5d43797d22f45faeb7949e18dfe4ac28a3cc52a141c605ac3ffc1e2b8637fd2e`
- Size: 253,992,960 bytes
- Owner/group: `xtk:xtk`
- Mode: `0600`
- SQLite schema version: 2
- Integrity check: `ok`
- Foreign-key violations: 0
- Research paths mapped to `/home/xtk/writeups/research`: 1,753
- Research paths under `/tmp`: 0

Key counts:

| Record | Count |
|---|---:|
| Total documents | 2,612 |
| Research documents | 1,753 |
| Vulnerability profiles | 1,752 |
| Scripts | 623 |
| C scripts | 186 |
| Syzlang scripts | 159 |
| Chunks | 42,980 |
| Operational stages | 28 |
| Evidence links | 30,296 |

## Client configuration

Added only `WRITEUPS_RESEARCH=/home/xtk/writeups/research` to:

- `/home/xtk/.codex-htb/config.toml`
- `/home/xtk/.config/goose/config.yaml`
- `/home/xtk/.config/goose/recipes/pentest-win-hard/pentest-win-hard.yaml`

The dated pre-v2 configuration backup was not modified. TOML and YAML parsing succeeded after the edits.

Post-edit configuration hashes:

| Configuration | SHA-256 |
|---|---|
| Codex | `b80ad008ef1c7ea07cbd122013ed19ef489d5a49a9b859113a9ed9ae3c6049aa` |
| Goose | `510c5f578ae3c043ed8159ead84a53dd7c653b9eee281313a43bab04fd436f92` |
| Goose pentest recipe | `3e273dc8a1c864c04f85aad871237bcfced4a91dbcab19c842313eda3e62452a` |

Two command-vault server processes belonging to the already-running Codex parent predated this release. They were not terminated because this session's negotiated tool catalog cannot be refreshed in place. New Codex/Goose sessions will load the new code, schema, managed source root, and tool catalog.

## Production smoke verification

Read-only CLI checks passed for:

- additive research statistics;
- exact research/CVE knowledge search;
- managed source context;
- vulnerability profile with stages and mitigations;
- ExploitBench operational-stage profile;
- C and syzlang script retrieval.

A fresh in-process MCP server negotiated 20 read-only tools, including vulnerability and operational-stage profiles. Administrative tools were absent. Structured stats, profile, search, and managed context calls passed.

The production database SHA-256 remained unchanged after all read-only CLI and MCP smoke calls.

A second full release audit was run against the actually installed production DB and corpus. It verified all 8,944 files, 1,753 managed DB document mappings, and embedded snapshots. The production-audit release manifest SHA-256 is `38b6f7d63c81068d9d4f222cb44b011af9cdc1d68aa58b18708a51a08257962c`; its files are retained under the persistent release directory.

## Remaining work

Before VM cleanup or revert:

1. Review and push/merge/tag the feature branch.
2. Verify the pushed commit/tag from a fresh fetch or clone.
3. Copy the persistent release unit and both rollback databases to an approved protected destination outside the VM revert boundary.
4. Verify hashes after transfer and perform a restore test from that external copy.
5. Record the validated VM snapshot/checkpoint identifier and date.
6. Reconnect clients through a new session and perform a final user-facing MCP smoke test.
7. Request separate confirmation before removing the recorded `/tmp` project root or reverting the VM.

Do not clean `/tmp/command-vault-research.j3Xal9` until Git and external release preservation are independently verified.
