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

The follow-on slices now also persist all 27 standalone C PoVs, eight canonical
operational stages, 75 source-heading aliases, 238 evidence links, and 27
source-documented validation records. Script hashes distinguish verified source
bytes, stored sanitized bytes, and conservative normalized bytes.

Research `read_context` now verifies and serves the embedded snapshot with
source status `snapshot`; it never stats or opens the synthetic research
identity. The real CVE context and complete C script remain accessible from the
candidate after adapter staging is no longer required.

The combined suite passes 592 tests. The existing Sherlock development rubric
remains 15/16 supported cases at top five for both baseline and candidate, with
no relevant-evidence rank changes; three non-evidence result-order positions
changed because FTS corpus statistics changed. Candidate median search latency
was 45.017 ms versus 42.119 ms at baseline, and maximum was 131.557 ms versus
122.004 ms. This is recorded for later broader retrieval acceptance, not treated
as a benchmark score.

The enriched candidate is 27 research documents on top of the 859-document
baseline and has SHA-256
`717d7ae7823a67ed6425a1c3f1a38e2769bb104b3a91783effb28e04b74a375a`.
It was retained as the manually integrated comparison candidate; no live
database migration or promotion occurred.

Create-only automation is now implemented and tested. The offline adapter CLI
reproduced all 27 bundles byte-for-byte in a second output directory. The
candidate builder used SQLite's read-only backup API and exclusive `0600`
destination reservation to produce
`exploitgym-kernelctf-v1-built.db` from the protected baseline. Its report shows
schema 2, `integrity_check = ok`, zero foreign-key violations, the expected 27
documents/27 C scripts/542 chunks/238 evidence links, and candidate SHA-256
`690908b238cd6629329267fa3c4767ff58c1faf3f907075475e035e1aa22ddb2`.
The baseline backup hash remained
`8ca91bb13ddad000cb273430c9cf1be388c8d1a1fa9ffdeeaeba05ba6c62bccd`.

The final integrated Phase 2 suite passes 619 tests. Neither automation script
downloads data, executes an artifact, overwrites an existing destination, or
touches production configuration/services. No database has been promoted.

### 2026-09-12 — Phase 3 mitigation relations and profiles

- Added evidence-anchored mitigation annotations with explicit
  enabled/disabled/bypassed/required/discussed/unknown states.
- Reviewed kernel controls are detected only from exact source mentions;
  `original_capabilities`, user namespaces, io_uring, and BPF JIT remain raw
  source metadata rather than inferred mitigation state.
- Real-data review caught and fixed two deterministic-classification defects:
  an empty parent `KASLR Bypass` heading was initially omitted, and
  `Breaking KASLR under KPTI` initially attributed bypass to KPTI. The corrected
  result records KASLR as bypassed and KPTI as discussed.
- Persisted per-vulnerability mitigation relations, revision-bound source
  references, and deduplicated mitigation evidence. Global mitigation labels
  remain stable across sources.
- Corrected candidate
  `/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-phase3-corrected.db`
  has SHA-256
  `609123e8f82840b6abee010953ef0b30836b268efb64acafdf6705008cd19d16`,
  nine normalized mitigations, 27 vulnerability-mitigation relations, and 312
  total evidence links. Integrity is `ok` with no foreign-key violations.
- Added read-only exact vulnerability and operational-stage profile services.
  Profiles contain metadata, provenance, mitigation/stage summaries, and
  revision-bound evidence references—not stored content or generated exploit
  plans.
- Vulnerability profiles show only stage aliases evidenced within that
  vulnerability's documents. Stage alias queries prioritize evidence from the
  exact matched heading before applying response limits.

The hybrid authority policy is explicit in `ARCHITECTURE.md`. Research snapshot
export is intentionally out of scope: the managed normalized corpus, retained DB
fallback snapshots, pinned upstream URL/revision/hash, and deterministic
reacquisition are the preservation model.

Phase 3 then incorporated the durable managed-corpus requirement without writing
the production path. `WRITEUPS_RESEARCH` is routed separately, and a canonical
descendant exclusion prevents a parent `WRITEUPS` scan from parsing generated
research Markdown as personal material. Managed source/external identities
remain stable across path changes.

The simulation under `/tmp/command-vault-research.j3Xal9/managed-research/`
produced candidate `exploitgym-kernelctf-phase3-managed.db`, SHA-256
`ebe7be6e80260ee5776f4be365d035dc5815eb6a4d7e463cb7dc61680b290dbc`.
All 27 managed documents returned source status `managed` when hashes matched;
removing one document caused verified `snapshot` fallback without changing the
database. Changed, symlinked, nonregular, oversized, or unreadable managed input
is never returned and is reported as `snapshot_changed`.

Ten exact structured filters are available on knowledge search: source, domain,
external ID, CVE, project, vulnerability class, sanitizer, operational stage,
mitigation, and validation status. Applied filters are explicit and cursor-bound.
CLI/MCP vulnerability and stage profiles expose only structured metadata and
revision-bound references. The final integrated Phase 3 suite passes 836 tests.

Final promotion will retain the managed corpus under
`/home/xtk/writeups/research/{exploitgym,cybergym,exploitbench}`, the database
fallback snapshots, and a corpus manifest/hash inventory. No files have been
written to that production tree in this phase.

## Acceptance notes

The implementation plan remains the governing contract. Passing a subagent's
targeted tests is necessary but not sufficient: integration requires diff
review, migration/data-preservation checks against a candidate copy, the full
suite, read-only byte preservation, and `git diff --check`.
