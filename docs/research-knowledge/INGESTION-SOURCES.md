# Reusable knowledge ingestion assessment

The source lock records the revisions used by the deterministic adapters.

## Source snapshots

| Source | Revision inspected | Principal value |
|---|---|---|
| ExploitGym code/data | `e4123d043774623b2274e6bbe0155a423d631f0a` | Detailed kernel/V8/userspace descriptions, PoVs, patches, traces, mitigation profiles |
| CyberGym code | `c6fe2027d39471375920b92cf1025e23a99ffda5` | Differential vulnerable/fixed server and task methodology |
| CyberGym dataset | `bde190ded494e52bc684b66073b436c9d992c7c6` | 1,507 task metadata records plus selectively downloadable descriptions, errors, and patches |
| ExploitBench code | `9d0173bcf8835b74a45f60450ae7f184e29e7607` | Sixteen-capability ontology, V8 task metadata, graders, audit and reproducibility rules |
| ExploitBench V8 runs | `41811977b3ce1b80f746fc510ae45ef9d7d3a2c9` | Excluded: license null and historical model-run content is outside accepted scope |

## CyberGym

`tasks.json` alone is an immediately useful, inexpensive source:

- 1,507 tasks: 1,368 ARVO and 139 OSS-Fuzz.
- 188 projects.
- 1,276 C++, 228 C, two Rust, and one Swift task.
- Every task has a vulnerability description, homepage, main repository, language, and files disclosed at Levels 0-3.

The Git LFS payload separates cleanly by value and cost:

| Artifact | Count | Declared total size |
|---|---:|---:|
| Patches | 1,507 | 24.91 MB |
| Descriptions + errors | 3,014 | 60.67 MB |
| Vulnerable/fixed repositories | 3,014 | 225,388 MB |

Therefore, download metadata plus `*.txt` and `*.diff`, not the repository archives. A representative task produced a concise vulnerability statement, a complete MemorySanitizer trace with source frames/origins/dedup tokens, and a focused fix diff.

### CyberGym record extraction

- Identity: task ID, family, project, repository, language.
- Vulnerability: normalized class plus original description.
- Runtime evidence: sanitizer, summary, signal/exit condition, top source frames, origin frames, dedup token, affected function/file/line.
- Fix evidence: changed files, hunk function, added/removed checks, initialization, bounds/ownership changes.
- Relationship: `description -> observed crash -> patch/fix`.
- Provenance: dataset revision and per-file hash.

The descriptions support broad vulnerability taxonomy; the error/fix pairs support diagnostic and remediation retrieval. No full source archive is required for the first ingestion version.

The dataset card does not state a dataset-wide license. Project URLs allow upstream attribution, but patches and source-derived artifacts must retain their upstream project licenses.

## ExploitBench

### Code repository

The repository provides 41 pinned V8 targets with CVE/Chromium IDs, patch commits, subsystems, JIT/sandbox annotations, evaluation flags and immutable image references. Its best reusable knowledge is:

- Capability definitions and verification semantics.
- Patch-location extraction from unified diffs.
- Differential, ASAN, coverage and primitive graders.
- Three-round randomized primitive verification.
- V8 sandbox, file-perimeter and grader-isolation design.
- Reward-hacking checks and replay methodology.
- Reproducible dependency/image/config pinning.
- Complete test JavaScript for crash, JSE primitives, general capabilities and ACE.

The existing command-vault Markdown parser processed 13 documents into 179 chunks and 25 commands without errors, but classified all as boxes and extracted no standalone scripts. A dedicated research-source adapter is required.

### Official V8 run dataset

The run dataset is not an ingestion source. Its card declares `license: null`,
and historical model runs are outside command-vault's accepted product scope.
No run rows, JavaScript, model/seed/image metadata, grade events, audit results,
transcripts, or tool calls enter normalized bundles, the managed corpus, or the
database. The pinned revision remains in the source lock only to make that
exclusion auditable and prevent accidental later scope expansion.

The code repository is MIT licensed, with some V8-derived files carrying
BSD-style notices. The adapter uses repository methodology and target metadata
only.

## Unified command-vault adapter

Add a source type such as `research` or `benchmark` instead of coercing these records into box/challenge/Sherlock. Minimum fields:

```text
source_project, source_revision, upstream_url, upstream_license
task_id, cve, project, domain, language, platform, subsystem
vulnerability_type, sanitizer, mitigation_profile
evidence_kind, capability, capability_stage, verification_status
artifact_hash, source_path, source_section
```

Use three adapters feeding one normalized intermediate record format:

- `ingest_exploitgym`: metadata plus Markdown, traces, PoV source and patches.
- `ingest_cybergym`: `tasks.json`, downloaded text artifacts and patches.
- `ingest_exploitbench`: repository capability definitions, methodology, and metadata-only V8 targets; no code artifacts or run dataset.

## Implemented import order

1. Add the research-source schema and normalized capability ontology.
2. Import ExploitBench's capability definitions and grader semantics.
3. Import the 27 high-quality ExploitGym kernelCTF tasks as the detailed pilot.
4. Import all CyberGym metadata and selectively fetch its roughly 86 MB text corpus.
5. Import one ExploitBench methodology document and 41 metadata-only V8 targets.
6. Expand to 159 syzbot diagnostics, 18 unique nofuzz records, and enrich 484
   existing CyberGym profiles without duplicate documents; defer all 181
   ExploitGym V8 tasks and exploit code.
7. Evaluate with pentest-style questions spanning vulnerability diagnosis, exploit primitives, mitigation effects and remediation.

This order gave the vault a stable ontology first, detailed technique
narratives second, broad vulnerable/crash/fix evidence third, and compact
repository-sourced target context without importing historical model traces.
