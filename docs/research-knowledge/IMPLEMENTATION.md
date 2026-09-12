# Research knowledge implementation record

## Governance

- Root orchestration and all cyber-domain, architecture, security, source-trust,
  integration, and acceptance decisions: `gpt-daybreak-blue-latest`.
- Bounded coding tasks only: `gpt-6-astra`.
- Production database writes, configuration changes, service restarts, Docker,
  and host security-setting changes are prohibited during development.
- Local implementation commits are allowed; pushing and database promotion are
  separate user checkpoints.

## Run log

### 2026-09-12 — Phase 0 started

- Created `feature/research-knowledge-v1` from
  `74710fe070ee8f3df6e242ca04c735d857c20d15`.
- Allocated `/tmp/command-vault-research.j3Xal9` as the sole disposable root.
- Verified the live database read-only, created a separate SQLite backup, and
  confirmed the live SHA-256 did not change during baseline tests or retrieval.
- Verified a Git bundle of the baseline commit.
- Ran 77 existing tests successfully.
- Captured the sixteen-query retrieval/latency baseline documented in
  `BASELINE.md`.
- Pinned the inspected framework revisions in `SOURCES.lock.json`.
- Added minimal sanitized source-shape fixtures. They contain metadata only—no
  PoCs, flags, credentials, callback endpoints, or executable material.

### 2026-09-12 — Phase 1 task allocation

Requested model: `gpt-6-astra`.

| Task | Reasoning | Owned files | Prohibited state |
|---|---|---|---|
| Additive schema-v2 migration | high | `database.py`, migration tests | live DB, services, config, dependencies |
| Research manifest models and JSON Schema | high | `models.py`, schema, model tests | DBs, services, config, dependencies |

Both task packets explicitly prohibit recursive delegation. The Daybreak Blue
orchestrator reviews and integrates all results before any commit.

### 2026-09-12 — Phase 1 foundation integrated

- Added schema version 2 with additive research, vulnerability, operational
  stage, evidence, mitigation, validation, snapshot, and artifact-fingerprint
  storage.
- Added strict Pydantic and JSON Schema bundle contracts.
- Added `research` to read-side MCP and CLI source filters while keeping the
  legacy Markdown indexer restricted to its existing three source types.
- Security review tightened artifact paths to reject traversal, backslashes,
  and all ASCII control characters, and source URLs to reject embedded
  credentials.
- The first real candidate migration found an existing deployed
  `technique_aliases(id, alias, technique_id)` table that was absent from the
  repository schema constant. The migration failed atomically and stayed at
  version 1. The revised migration preserves that legacy shape and fails
  atomically if conservative alias normalization collides.
- The revised real candidate reached schema 2 with `integrity_check = ok`, no
  foreign-key errors, and unchanged legacy counts: 859 writeups, 8,244
  commands, 278 scripts, 10,946 chunks, 26,740 history commands, and 104
  techniques.
- All 16 baseline retrievals retained identical IDs, ordering, match modes, and
  response sizes. Candidate median search latency was 42.530 ms versus 42.119
  ms in the baseline run; maximum was 122.325 ms versus 122.004 ms.
- Integrated foundation suite: 293 tests passed in 2.98 seconds.
- Live database SHA-256 remained
  `9e30b166c718941207b4d774fe7293bb90ff0086e626e6b8dddd763b628b0195`.

Requested coding model was `gpt-6-astra` with high reasoning. The runtime did
not expose a separate resolved model build identifier. No coding subagent
delegated further or created commits.

### 2026-09-12 — Phase 1 safe bundle vertical slice

- Added a common normalized-bundle loader that reads only declared files from
  an anchored directory descriptor.
- Added per-file/aggregate bounds, strict UTF-8 and manifest validation,
  duplicate-path rejection, symlink and non-regular-file rejection, and
  supplied SHA-256 verification.
- Loader consumers receive the verified artifact bytes; returned paths are
  provenance/display only and are not reopened after validation.
- Added a bounded zlib snapshot codec that rejects corrupt, truncated,
  concatenated, trailing, oversized, wrong-size, wrong-hash, and invalid-UTF-8
  snapshots.
- Coding-track report: 72 focused tests and 398 full-suite tests passed before
  orchestrator integration review.

### 2026-09-12 — Phase 2 ExploitGym kernelCTF adapter and storage slice

- Pinned and made read-only an ExploitGym checkout at
  `e4123d043774623b2274e6bbe0155a423d631f0a` beneath the recorded project root.
- Confirmed exactly 27 kernelCTF tasks and selected 138 UTF-8 text inputs
  totaling 989,087 bytes; compiled PoVs and Makefiles remain excluded.
- Added a deterministic adapter with source-metadata preservation, aggregate-only
  redaction auditing, fixed heading-to-stage annotations, bounded/symlink-safe
  reads, artifact hashes, and atomic no-overwrite publication.
- Real adapter run examined 186 kernel metadata records, selected 27 kernelCTF
  records, emitted 27 valid bundles with 78 artifacts, excluded 54 files, and
  recorded zero redactions. Bundles total approximately 1.6 MiB and contain no
  detected temporary paths, flags, keys, or token assignments.
- Added a minimum transactional research indexer for source collections, stable
  research identities, defense-in-depth sanitization, chunks, embedded
  snapshots, vulnerability records, idempotent cleanup, and rollback.
- Candidate `/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-v1.db`
  contains 27 research documents, 542 new chunks, 27 vulnerabilities, one source
  collection, and no temporary writeup paths. Legacy command/script/history
  counts remain unchanged.
- Exact research searches for `CVE-2023-3776`, `KASLR bypass`, and
  `core_pattern privilege escalation` returned relevant research records.
- Integrated adapter/storage suite: 554 tests passed in 3.28 seconds.

Follow-on Phase 2 slices still need to persist standalone C artifacts and stage
evidence, serve research context from embedded snapshots, and automate
create-only candidate construction. Until snapshot reads land, research
`read_context` correctly falls back to indexed content with source status
`unavailable`; it never follows the synthetic research identity as a file path.

## Acceptance notes

The implementation plan remains the governing contract. Passing a subagent's
targeted tests is necessary but not sufficient: integration requires diff
review, migration/data-preservation checks against a candidate copy, the full
suite, read-only byte preservation, and `git diff --check`.
