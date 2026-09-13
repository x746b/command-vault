# Research knowledge extension

Command-vault can retain source-backed vulnerability, diagnostic, mitigation,
and exploit-development knowledge for authorized pentesting, CTF, and lab use.
This directory documents the reusable design and deliberately narrow import
scope. It does not contain private database manifests, host-specific deployment
records, model transcripts, or operator environment notes.

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — trust boundary, normalized bundles,
  managed-file routing, schema, and compatibility.
- [`FRAMEWORK-ASSESSMENT.md`](FRAMEWORK-ASSESSMENT.md) — what CyberGym,
  ExploitGym, and ExploitBench contribute and how to test them safely.
- [`INGESTION-SOURCES.md`](INGESTION-SOURCES.md) — selected upstream material,
  exclusions, and normalized record shape.
- [`CYBERGYM-IMPORT.md`](CYBERGYM-IMPORT.md) — selective description, crash,
  and patch ingestion.
- [`EXPLOITGYM-PILOT.md`](EXPLOITGYM-PILOT.md) and
  [`EXPLOITGYM-DIAGNOSTICS.md`](EXPLOITGYM-DIAGNOSTICS.md) — kernelCTF,
  syzbot, nofuzz, and CyberGym-enrichment contracts.
- [`EXPLOITBENCH-IMPORT.md`](EXPLOITBENCH-IMPORT.md) — methodology and
  metadata-only V8 target ingestion.
- [`EVALUATION.md`](EVALUATION.md) — release-independent acceptance checks.
- [`MIGRATION.md`](MIGRATION.md) — safe schema migration and rollback model.
- [`SAFE-INDEXING.md`](SAFE-INDEXING.md) — supported incremental personal
  writeup workflow.
- [`SECURITY.md`](SECURITY.md) — source trust, licensing, and publication rules.
- [`SOURCES.lock.json`](SOURCES.lock.json) — public upstream revisions and
  import/exclusion scope.

Normalized framework documents and their database are intentionally not stored
in Git. Users acquire source material under its original terms, generate bundles
with the adapters, and keep personal or license-unknown corpora private.
