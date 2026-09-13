# Changelog

## 1.0.1 — 2026-09-13

### Changed

- Reduced the public research-knowledge documentation to reusable architecture,
  source-selection, import, evaluation, migration, indexing, and security
  guidance.
- Removed private implementation diaries, host-specific promotion and restore
  records, temporary paths, database/corpus hashes, and model-orchestration
  notes from the public documentation tree.
- Simplified the public source lock to upstream revisions, source-file integrity
  values, and explicit import/exclusion scope.

## 1.0.0 — 2026-09-13

### Added

- Schema-v2 research source collections and embedded document snapshots.
- Source-backed vulnerability and operational-stage profiles over CLI and MCP.
- Structured research filters for source, domain, external ID, CVE, project,
  vulnerability class, sanitizer, stage, mitigation, and validation status.
- Managed research routing through `WRITEUPS_RESEARCH`, with safe fallback to
  verified database snapshots.
- C and syzlang reproducer retrieval with source/harness validation provenance.
- Deterministic, nonexecuting adapters and candidate builders for CyberGym,
  ExploitGym, and repository-only ExploitBench methodology/metadata.
- Release auditing, path rebasing, source locks, corpus manifests, and restore,
  rollback, and promotion runbooks.
- Safe automatic exclusion of canonical `$WRITEUPS/research` during routine
  `vault index --add`, even when `WRITEUPS_RESEARCH` is omitted.
- `syzlang` as an operator-facing alias for stored language `syz`.
- Stage-class navigation such as `trigger`, and `reproducer` navigation to
  source-linked crash-reproduction evidence.

### Compatibility

- Existing boxes, challenges, Sherlocks, history, commands, scripts, and
  evidence references remain supported.
- Schema-1 databases require a writable migration before the normal read-only
  MCP server can use schema-v2 research functionality.
- Old applications must not write to a schema-2 production database.
- The PyPI package remains at 0.9.1 until separately published.

Detailed design, source selection, validation, and production results are in
[`docs/research-knowledge/`](docs/research-knowledge/README.md).

## Earlier releases

Release notes through 0.9.1 remain available in the main
[`README.md`](README.md#changelog) and Git tags.
