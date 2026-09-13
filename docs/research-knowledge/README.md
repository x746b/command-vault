# Research knowledge extension

This directory contains the design and research material for extending command-vault with source-backed vulnerability, exploit-development, mitigation, and validation knowledge for authorized pentesting, CTF, and lab use.

## Documents

- [`IMPLEMENTATION-PLAN-RESEARCH-KNOWLEDGE.md`](IMPLEMENTATION-PLAN-RESEARCH-KNOWLEDGE.md) — product objective, proposed architecture and schema, ingestion adapters, retrieval changes, model orchestration, delivery phases, VM lifecycle, preservation, cleanup, and restoration.
- [`FRAMEWORK-ASSESSMENT.md`](FRAMEWORK-ASSESSMENT.md) — functional comparison, installation/testing findings, and reusable methodology from CyberGym, ExploitGym, and ExploitBench.
- [`INGESTION-SOURCES.md`](INGESTION-SOURCES.md) — inspected source revisions, corpus inventories, parsability findings, selective-download strategy, and normalized ingestion recommendations.
- [`EXPLOITBENCH-IMPORT.md`](EXPLOITBENCH-IMPORT.md) — repository-only V8 methodology/target metadata and excluded run-dataset contract.
- [`EXPLOITGYM-DIAGNOSTICS.md`](EXPLOITGYM-DIAGNOSTICS.md) — syzbot/nofuzz diagnostic-only selection and identity-preserving CyberGym enrichment contract.
- [`EVALUATION.md`](EVALUATION.md), [`SECURITY.md`](SECURITY.md), [`PROMOTION.md`](PROMOTION.md), [`RESTORE.md`](RESTORE.md), [`ROLLBACK.md`](ROLLBACK.md), and [`RELEASE-CANDIDATE.md`](RELEASE-CANDIDATE.md) — Phase 7 acceptance, retention, promotion, restoration, and approval gates.

These documents include the governing plan, source contracts, and living
implementation record. Development artifacts remain candidate-only; they do
not indicate that a production database migration or promotion has occurred.
