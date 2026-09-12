# Command-vault research knowledge extension: implementation plan

Date: 2026-09-12
Target: command-vault after the deployed 0.9 series
Status: implementation in progress on a feature branch; candidate-only, with no production database changes

## 1. Product objective

Extend command-vault into a stronger, source-backed operational knowledge base for:

- authorized penetration-testing sessions;
- Hack The Box and other authorized CTF play;
- lab training and exploit-development practice;
- rapid recall of commands, scripts, diagnostics, exploitation primitives, mitigation effects, and previous solutions.

CyberGym, ExploitGym, and ExploitBench are inputs, not the product model. Their datasets and validation methods supply high-quality vulnerability and exploitation evidence. Command-vault will not become an LLM benchmark runner, model leaderboard, agent grader, or training framework.

Project execution uses a single root orchestrator with optional bounded coding
delegation:

- `gpt-daybreak-blue-latest` is the root orchestrator for the entire project.
- The Daybreak root may directly implement cyber-adjacent or
  security-sensitive code.
- `gpt-5.6-terra` is the default for routine bounded coding, tests, and source
  adapters; `gpt-5.6-luna` may handle trivial mechanical fixtures or docs;
  `gpt-6-astra` is optional for genuinely complex pure coding.
- Cybersecurity interpretation, ontology decisions, source trust, authorization, safety, integration, acceptance, and production actions remain with the Daybreak Blue orchestrator.

The intended operator experience is:

```text
question or observed symptom
  -> find relevant vulnerability/technique evidence
  -> understand prerequisites and operational stage
  -> retrieve exact commands or scripts
  -> inspect original context and provenance
  -> adapt manually to the authorized target
  -> optionally record validation after the session
```

## 2. Explicit non-goals

- Do not run stored commands automatically.
- Do not expose administrative database writes through the normal MCP profile.
- Do not rank or compare LLMs.
- Do not reproduce the source frameworks' task servers, flags, cost accounting, or leaderboards.
- Do not index raw model reasoning as authoritative technical knowledge.
- Do not mark shell-history presence as proof that a command succeeded.
- Do not infer missing execution dates, target versions, licenses, or validation outcomes.
- Do not replace SQLite without measured evidence that SQLite is inadequate.
- Do not rename or discard the existing writeup, command, script, chunk, or history interfaces in the first release.

## 3. Current baseline to preserve

The deployed 0.9 implementation already provides valuable invariants:

- SQLite schema version 1 with canonical-path document identity.
- 858 indexed writeups, 8,244 commands, 278 scripts, 10,914 evidence chunks, and 26,740 history commands at deployment time.
- Atomic per-document replacement of commands, scripts, chunks, tags, and relations.
- Source hashes, parser versions, revision-bound references, and source freshness states.
- Section-aware chunks retaining fenced output, logs, and XML.
- Read-only MCP by default; administrative ingestion is CLI/explicit-profile only.
- Bounded, typed and paginated MCP responses.
- `search_knowledge -> read_context` for explanatory evidence.
- Dedicated command, script, history, technique, and related-writeup search paths.
- Explicit AND/OR fallback diagnostics, required identifiers, and question-only warnings.
- Candidate-database construction, integrity evaluation, backups, and rollback practice.

The extension must preserve these behaviors and their existing tests.

## 4. Operator use cases

### 4.1 Vulnerability and crash triage

Examples:

- Find similar ASAN, MSAN, UBSAN, or KASAN failures.
- Search by crash function, source file, sanitizer summary, dedup token, signal, or vulnerability class.
- Compare a crash report with historical patches and root-cause descriptions.
- Find examples of turning a crash into a useful exploit primitive.

### 4.2 Exploitation path recall

Examples:

- Find an `addrof` implementation and the prerequisites it assumes.
- Locate heap grooming patterns used with a particular kernel object cache.
- Move from UAF trigger to leak, arbitrary read/write, control-flow control, or privilege escalation.
- Compare approaches that work with and without PIE, ASLR, KASLR, SMEP, SMAP, RELRO, canaries, or a V8 sandbox.

### 4.3 Command and script retrieval

Examples:

- Retrieve exact GDB, pwndbg, checksec, sanitizer, compiler, QEMU, V8/d8, syzkaller, or kernel debugging syntax.
- Retrieve complete C, JavaScript, Python, shell, PowerShell, Go, or syzlang artifacts.
- Prefer examples observed or reproduced in an environment matching the current lab.
- Show the original source section before the operator adapts a command.

### 4.4 Cross-domain CTF and pentest support

External research content must complement—not displace—the existing AD, Windows, Linux, web, pwn, reversing, forensics, mobile, cloud, and cryptography material. Existing HTB writeups and personal history remain first-class sources.

## 5. Design principles

### 5.1 Evidence first

Every structured assertion must point to an original source record, section, trace, patch, code artifact, or observed validation. Search scores are ranking signals, not truth confidence.

### 5.2 Additive compatibility

Keep existing tables and MCP tools. Add fields, relations, adapters, filters, and two focused profile tools. Existing clients should continue to work without sending new parameters.

### 5.3 Separate source fact from derived interpretation

Store:

- verbatim source facts;
- deterministic parser output;
- derived normalization;
- curator annotations;
- validation observations;

as distinguishable provenance classes. Never present an inferred vulnerability class as if the upstream source explicitly supplied it.

### 5.4 Unknown is a valid state

Use explicit values such as `unknown`, `not_tested`, `source_documented`, `harness_observed`, `operator_confirmed`, `failed`, and `stale`. Avoid optimistic defaults.

### 5.5 Stable, recoverable source context

Development downloads, extraction trees, worktrees, staging bundles, and candidate builds remain in `/tmp`. Accepted sanitized normalized bundles are then installed under the managed tree `/home/xtk/writeups/research/{exploitgym,cybergym,exploitbench}/`. Generated research files are adapter-owned, hash-verified outputs and are not manually edited.

Store the sanitized normalized `document.md` snapshot inside the database as a verified fallback, bound to the same content hash and upstream provenance. `read_context` should prefer a current hash-matching managed research document, report changed managed content as an integrity problem, and use the embedded snapshot when the managed file is unavailable. Existing personal writeups retain their file-authoritative path/freshness behavior.

The retained production state therefore consists of the Git-tracked application/documentation, the database, and the managed normalized research tree. Full upstream repositories, benchmark downloads, extraction trees, raw traces outside normalized bundles, and `/tmp` staging are not retained.

### 5.6 Operational terminology

Internally, a generalized capability graph is useful. User-facing responses should call these `operational stages`, `primitives`, `outcomes`, and `prerequisites`, not benchmark scores.

## 6. Proposed architecture

```text
Pinned upstream sources
  -> source-specific adapters
  -> normalized research bundles in staging
  -> deterministic parsing and sanitization
  -> structured enrichment and relation building
  -> candidate SQLite database
  -> integrity/retrieval/operator acceptance tests
  -> managed normalized research tree + embedded fallback snapshots
  -> atomic DB promotion
  -> existing read-only MCP service
```

### 6.1 Normalized research bundle

Each upstream task or coherent methodology document becomes a directory such as:

```text
research/<source>/<external-id>/
  manifest.json
  document.md
  artifacts/
    reproducer.c
    poc.js
    patch.diff
    sanitizer-trace.txt
```

`document.md` gives `read_context` a durable, section-aware source. `manifest.json` retains structured metadata and maps raw artifacts to their roles. Raw binary targets, container images, and large vulnerable/fixed repositories are referenced by digest/URL rather than copied into command-vault.

### 6.2 Managed research routing

Use `WRITEUPS_RESEARCH=/home/xtk/writeups/research` as the dedicated managed-bundle root. Source adapters install accepted bundles beneath named children such as `exploitgym/`, `cybergym/`, and `exploitbench/`; the research indexer consumes manifests from those collections.

When `WRITEUPS=/home/xtk/writeups` contains the managed root, the legacy recursive Markdown scan must exclude the canonical `WRITEUPS_RESEARCH` subtree before discovering files. It must compare resolved paths, reject an exclusion outside the configured parent, and never depend on a simple string prefix. Managed research Markdown must not be parsed a second time as a box/challenge/Sherlock document. Dedicated research ingestion remains manifest-driven and hash-verified.

### 6.3 Manifest contract

Illustrative shape:

```json
{
  "schema_version": 1,
  "source": {
    "name": "cybergym",
    "revision": "bde190ded494e52bc684b66073b436c9d992c7c6",
    "upstream_url": "https://huggingface.co/datasets/sunblaze-ucb/cybergym",
    "license_expression": null
  },
  "external_id": "arvo:1065",
  "domain": "userspace",
  "project": "file",
  "language": "c++",
  "vulnerability": {
    "canonical_id": null,
    "class": "use-of-uninitialized-value",
    "class_provenance": "derived",
    "sanitizer": "msan"
  },
  "artifacts": [
    {
      "path": "artifacts/sanitizer-trace.txt",
      "kind": "runtime-evidence",
      "role": "trigger",
      "validation": "harness_observed"
    }
  ]
}
```

Validate manifests against JSON Schema before indexing.

## 7. Database extension

Use an additive schema migration. Do not replace `writeups` with a new generalized document table in the first release.

### 7.1 Source collections

Add `source_collections`:

```text
id
name                    unique stable identifier
source_kind             personal-writeup, history, benchmark, research
homepage
repository_url
revision
license_expression      nullable; unknown must stay null
fetched_at
manifest_hash
```

Extend `writeups` with nullable columns:

```text
source_collection_id
external_id
domain
document_kind
upstream_url
```

Add `research` to the Pydantic and MCP source-type literals. Keep current box/challenge/Sherlock collection behavior unchanged.

Add `document_snapshots` for self-contained research context:

```text
writeup_id               primary key / foreign key
content_blob             compressed sanitized normalized Markdown
compression              versioned value, initially zlib
content_hash             SHA-256 of uncompressed content
uncompressed_bytes
created_at
```

Use Python's standard-library zlib support to avoid an additional runtime dependency. The managed normalized document is the primary full-document source when its hash matches the indexed revision; the embedded snapshot is the verified fallback for that revision. Upstream freshness is represented by recorded revision/provenance rather than an implicit network check. Existing personal writeups continue to resolve current files and report current/changed/unavailable states. Research context should distinguish current managed content, fallback snapshot use, and changed managed content.

### 7.2 Vulnerability records

Add `vulnerabilities`:

```text
id
canonical_id            CVE when available
external_task_id
project_name
summary
summary_provenance
vulnerability_class
class_provenance
sanitizer
architecture
platform
subsystem
language
introduced_revision
fixed_revision
```

Add `writeup_vulnerabilities(writeup_id, vulnerability_id)` so one vulnerability can have several documents and one comparative document can reference several vulnerabilities.

Create `vulnerabilities_fts` over canonical ID, task ID, project, summary, class, sanitizer, subsystem, and affected symbols.

### 7.3 Techniques and aliases

Retain `techniques` and `technique_writeups`. Extend techniques with optional description and domain fields. Add:

```text
technique_aliases(
  technique_id,
  alias,
  alias_normalized,
  provenance,
  unique(alias_normalized)
)
```

Examples include:

```text
AAR -> arbitrary read
AAW -> arbitrary write
arb_read -> arbitrary read
addrof -> object address disclosure
UAF -> use-after-free
KASLR bypass -> kernel base disclosure
```

Alias expansion must be deterministic and reported in responses.

### 7.4 Operational stages and relations

Add `operational_stages`:

```text
id
canonical_name
domain
stage_class             reach, trigger, diagnose, primitive, control, objective, remediation
description
```

Add `stage_aliases` and `stage_edges`:

```text
stage_edges(
  source_stage_id,
  target_stage_id,
  relation               requires, enables, blocks, mitigates, subsumes
  domain
  evidence_reference
)
```

The graph is not required to be a single linear ladder. Web, AD, kernel, V8, Windows, cloud, and DFIR paths have different branches.

### 7.5 Evidence links

Add `evidence_links` with exactly one nullable target reference populated:

```text
id
writeup_id
command_id               nullable
script_id                nullable
chunk_id                 nullable
vulnerability_id         nullable
technique_id             nullable
stage_id                 nullable
evidence_role            prerequisite, procedure, signal, outcome, mitigation, remediation
assertion_provenance     source, deterministic, curated, inferred
validation_status
observed_outcome
environment_json
source_anchor_hash
```

Use a database `CHECK` constraint to require exactly one of `command_id`, `script_id`, or `chunk_id`. Rebuild these links inside the same per-document transaction as their parent artifacts.

### 7.6 Mitigations

Add:

```text
mitigations
vulnerability_mitigations
technique_mitigations
artifact_mitigation_observations
```

Normalize common controls while retaining raw upstream labels:

- ASLR/KASLR;
- PIE;
- stack canary;
- partial/full RELRO;
- NX/W^X;
- SMEP/SMAP;
- user namespaces;
- io_uring availability;
- V8 sandbox;
- sanitizer/instrumented builds;
- application-specific validation and patch state.

Record whether a mitigation was enabled, disabled, bypassed, required, or merely discussed.

### 7.7 Validation observations

Add `validation_records`:

```text
id
artifact_kind
artifact_id
validation_level
status
environment_json
expected_signal
observed_signal
validated_at
validator
source_reference
notes
```

Validation levels:

1. `source_documented` — described by an upstream source.
2. `syntax_checked` — structurally parsed or compiled without execution.
3. `harness_observed` — upstream harness recorded the outcome.
4. `reproduced_local` — reproduced in an authorized disposable environment.
5. `operator_confirmed` — operator explicitly recorded success during an authorized session.
6. `failed` or `stale` — known failure or invalidated environment.

History ingestion may record `observed_execution`, but never success without separate evidence.

### 7.8 Artifact fingerprints and deduplication

Add stable fingerprints to commands, scripts, and evidence artifacts:

```text
artifact_hash            hash of exact sanitized content
normalized_hash          hash after conservative placeholder/whitespace normalization
```

Do not delete duplicate source occurrences. Collapse duplicate display results while retaining every provenance link. Prefer a result with richer context or stronger validation, then show the other sources as corroboration.

## 8. Source adapters

All adapters emit the normalized manifest/bundle format. They must be independently testable and must not write directly to the production database.

### 8.1 ExploitGym adapter

Inputs:

- `src/cybergym/task/metadata.json`;
- `kernel_metadata.json`;
- `v8_metadata.json`;
- task directories under `data/tasks/`.

Extraction:

- 869 structured task identities.
- Userspace vulnerability type, project, sanitizer, architecture, language, binary, and mitigation images.
- Kernel CVE, release, category, original capabilities, vulnerability/exploit/novel-technique docs, C/syz PoVs, traces, and patches.
- V8 issue, revision, sandbox status, feature flags, descriptions, PoVs, reproduced output, and patches.
- Standalone `.c`, `.js`, `.syz`, `.py`, `.sh`, and Makefiles as typed artifacts.

First pilot: 27 kernelCTF tasks because their documentation explicitly identifies prerequisites, trigger, leak, primitive, mitigation bypass, control-flow, reliability, and privilege-escalation stages.

The approved initial follow-on is limited to 159 syzbot diagnostic records, 18
unique nofuzz records, and metadata enrichment of 484 already-imported
CyberGym profiles. Enrichment updates existing identities and must not create a
second document or vulnerability profile. All 181 ExploitGym V8 tasks and all
additional exploit code are deferred to optional later review.

For syzbot, import vulnerability prose, sanitizer trace, C and syzlang
reproducers, and declared patches. Reproducers remain non-executed, exact-hash,
license-null source-linked artifacts; use `harness_observed` only where the same
source record links the retained trace, and never claim `reproduced_local`.
Explicitly allow `c` and `syz` script retrieval. For nofuzz, import only
description, vulnerable runtime output, exit status, and patch. Exclude nofuzz
PoCs, Makefiles, binaries, images, and all V8 material.

For the 484 overlapping CyberGym records, enrich the existing normalized
identity rather than emitting an ExploitGym duplicate. Existing crash-derived
sanitizer/class fields take precedence; deterministic ExploitGym metadata fills
only null values. Mitigation image variants are `discussed` availability
metadata, never enabled/disabled/bypassed claims.

### 8.2 CyberGym adapter

Inputs:

- `tasks.json` metadata for all 1,507 tasks;
- selectively downloaded `description.txt`, `error.txt`, and `patch.diff` files.

Do not download repository archives in the first implementation. Current declared totals are roughly 24.9 MB of patches and 60.7 MB of descriptions/errors versus roughly 225 GB of source archives.

Extraction from error output:

- sanitizer and failure class;
- signal/exit behavior;
- summary line;
- dedup token;
- top crash frames;
- origin/allocation frames;
- affected files, functions, and line numbers.

Extraction from patches:

- changed paths;
- hunk function/context;
- added and removed conditions;
- bounds, initialization, ownership, lifetime, integer, and error-handling changes;
- relationship to observed crash functions.

Preserve whether classifications are source-provided or derived. Project repository URLs provide provenance anchors; upstream licensing must remain per record.

### 8.3 ExploitBench adapter

Use the MIT-licensed code repository only. Ingest:

- one methodology document covering the 16 precise capability definitions,
  deterministic grader/evidence semantics, isolation, reproducibility,
  provenance, and audit-as-review-prompt concepts;
- 41 metadata-only V8 target profiles with CVE/Chromium IDs, patch and
  depot-tools commits, subsystem/JIT/sandbox annotations, relevant evaluation
  flags, source-authored summaries, and stated years;
- zero code artifacts.

Translate capability names into operational-stage terms while retaining the
original names as aliases. Definitions are source-documented methodology, not
historical attainment evidence, and independently defined capabilities do not
create an inferred linear graph.

Completely exclude the license-null official run dataset from normalized
bundles, the managed research corpus, and the database. Do not import its
JavaScript, rows, run IDs, models, seeds, images, grade events, audit results,
transcripts, or tool calls. Retain only a source-lock exclusion record so later
review does not silently broaden the scope.

### 8.4 Temporal retention

There is no hard deletion cutoff for older exploitation patterns. Preserve all
accepted records with their explicit dates, affected versions, tool versions,
patch revisions, and source revisions. When a source does not state whether an
observation is current, fixed, superseded, or stale, store `temporal_status` as
`unknown` rather than inferring it from age.

Recency may become a modest ranking tie-breaker between otherwise comparable
results. It must never delete or hide older evidence, override validation or
source authority, or change exact identifier/filter behavior.

## 9. Ingestion and curation pipeline

### 9.1 Development staging

Use `/tmp` for all downloads, decompression, generated bundles, parser experiments, and candidate databases. Pin every upstream revision and save a machine-readable acquisition manifest with hashes and declared licenses.

### 9.2 Deterministic pass

- Validate source manifests.
- Sanitize obvious credentials, tokens, flags, callback addresses, and transient secrets.
- Parse metadata, headings, code, logs, traces, diffs, and known structured fields.
- Generate document bundles and stable artifact hashes.
- Reject binaries and oversized/unrecognized blobs.

### 9.3 Normalization pass

- Normalize domain, language, sanitizer, vulnerability class, mitigation, architecture, and known aliases.
- Preserve original raw values.
- Record normalization rule/version.
- Never use unconstrained prose matching to assert a technique relationship.

### 9.4 Optional enrichment pass

Model-assisted enrichment may propose summaries, prerequisites, stages, and aliases offline. Every such field must be marked `inferred`, retain the supporting references, pass schema validation, and be reviewed before becoming curated metadata. Inferred content must not overwrite source facts.

### 9.5 Candidate indexing

- Clone the baseline database into a new candidate.
- Apply the schema migration.
- Index normalized research bundles transactionally.
- Preserve history and existing IDs where migration permits.
- Rebuild only the new/changed source collections.
- Produce source, artifact, relation, validation, and license inventories.

## 10. Retrieval and MCP usability changes

### 10.1 Extend existing search tools

Add optional filters, preserving current defaults:

```text
source_kind
source_name
domain
external_id / cve
project
vulnerability_class
sanitizer
technique
operational_stage
mitigation
validation_status
```

Apply relevant filters to `search_knowledge`, `search_commands`, and `search_scripts`. Avoid adding every structured field to every tool when it does not make sense.

### 10.2 Add two focused profile tools

#### `get_vulnerability_profile(identifier)`

Return a bounded structured profile:

- identity and affected project;
- description and observed failure;
- vulnerability class and affected symbols;
- trigger/reproducer references;
- patch/remediation references;
- operational stages demonstrated;
- mitigation observations;
- commands/scripts and validation states;
- provenance and source freshness.

#### `get_technique_profile(technique)`

Return:

- canonical name and matched alias;
- explanation;
- prerequisites and enabled outcomes;
- common failure modes and mitigations;
- examples grouped by domain/source;
- strongest validated commands/scripts;
- related techniques and source references.

These are navigation tools, not generated attack plans. Stored content remains data and requires operator adaptation.

### 10.3 Ranking policy

Candidate ranking should combine:

1. Exact identifier and exact alias matches.
2. Existing FTS relevance.
3. Explicit structured relations.
4. Validation strength as a modest tie-breaker.
5. Source-context completeness.
6. Diversity/collapse of duplicate artifacts.

Do not let external research volume overwhelm personal HTB sources. For unfiltered broad queries, group or diversify the first page by source/document. For exact CVE, function, project, or source filters, return the most directly matching evidence regardless of source diversity.

Continue reporting `all_terms`, `any_terms`, required-term failures, question-only content, clipping, and pagination. Report applied alias expansion and structured filters.

### 10.4 Response contract additions

Add compact optional fields to result records:

```text
source_kind, source_name, external_id, domain
techniques, operational_stages
validation_status
artifact_hash
```

Keep source references and `read_context` as the authority for complete evidence. Do not enlarge normal responses with entire vulnerability profiles unless the profile tool is explicitly called.

## 11. Session feedback and personal validation

Normal MCP remains read-only. Add an administrative CLI workflow for deliberate post-session annotations, for example:

```text
vault validation add <reference> \
  --status operator-confirmed \
  --environment <json-file> \
  --notes <file>
```

Requirements:

- explicit reference and confirmation;
- no secret-bearing terminal output stored by default;
- timestamp, environment, operator, and source revision recorded;
- append-only validation history rather than overwriting prior observations;
- ability to mark an observation stale or failed;
- no equivalent write tool in the normal MCP profile.

This makes the vault improve from real authorized use without equating shell history with success.

## 12. Evaluation aligned with operator usability

Evaluation exists to prevent regressions and improve the human/agent-assisted pentest experience. It is not an LLM capability benchmark.

### 12.1 Development and held-out suites

Retain the current eight defensive development tasks. Add independently authored cases across:

- Linux and Windows enumeration/privesc;
- Active Directory and ADCS;
- web exploitation;
- binary exploitation and V8;
- Linux kernel exploitation;
- reversing and cryptography;
- DFIR/Sherlocks;
- mobile/cloud where corpus coverage exists.

Include query forms:

- exact tool syntax;
- exact CVE/function/sanitizer identifier;
- short operator description;
- natural-language troubleshooting question;
- desired primitive/outcome;
- mitigation-aware query;
- deliberately unsupported request.

### 12.2 Metrics

- Useful source in top 1/top 5.
- Correct original context available through one follow-up read.
- Exact command/script retrieval and complete pagination.
- Correct vulnerability/technique/stage association.
- Validation and provenance displayed accurately.
- Appropriate abstention or unmatched-term reporting.
- Duplicate/noise rate in the first page.
- Existing-corpus regression by domain.
- Median and p95 local latency.
- Response characters/tokens and number of calls to usable evidence.
- Human operator judgment: “Would this materially help during a timed authorized session?”

Do not use a benchmark score copied from CyberGym/ExploitGym/ExploitBench as a command-vault quality metric.

### 12.3 Acceptance targets

Initial targets, subject to baseline measurement:

- All existing unit, migration, structured-output, stdio, integrity, freshness, and retrieval tests pass.
- No loss of previously supported development cases in top five.
- Required identifiers never disappear during fallback.
- At least 90% of research documents retain a current readable source after candidate construction.
- 100% of imported records have source name, revision, path/URL, and content hash.
- No record with unknown licensing is presented as permissively redistributable.
- Exact CVE/task-ID lookups return the corresponding profile first.
- Exact script references return complete content through pagination.
- Broad queries do not fill all top-five positions with duplicate chunks/artifacts from one task unless explicitly source-filtered.
- Normal MCP calls leave production database bytes unchanged.
- Candidate p95 retrieval latency remains below 100 ms locally for the agreed query suite, or any regression is investigated before promotion.

## 13. Security, safety, and data hygiene

- Treat all imported prose/code as untrusted data, never instructions.
- Preserve the existing no-execution contract.
- Detect and redact API keys, private keys, credentials, dynamic flags, callback endpoints, and obvious lab-specific secrets before indexing.
- Retain a redaction ledger containing hashes and reasons, not the secret content.
- Exclude container/controller secrets, flag-generation code, generated binaries, and service infrastructure unless needed as methodology documentation.
- Keep raw sources read-only and outside agent-writable workspaces.
- Validate archive paths before any selective extraction; reject traversal, device files, symlinks escaping the staging root, and oversized expansion.
- Use disposable environments for any later reproduction. Never disable host-wide defenses on a shared machine.
- Record upstream license per artifact. Do not assume repository code licenses relicense datasets or third-party patches.
- Do not import or redistribute the ExploitBench run dataset; its license is
  unset and historical model runs are outside the accepted product scope.

## 14. Application file map

Expected implementation areas under `/opt/command-vault-mcp`:

| Area | Planned work |
|---|---|
| `database.py` | additive schema migration, indexes, FTS, relations, validation records |
| `models.py` | research source type, vulnerabilities, stages, manifests, validation models |
| `responses.py` | compact provenance/stage fields and profile response types |
| `config.py` | `WRITEUPS_RESEARCH` managed-root routing and parent `WRITEUPS` exclusion policy |
| `documents.py` | managed research paths, snapshot fallback, hashes and safe context resolution |
| `parser.py` | preserve current parser; expose reusable helpers rather than embedding source-specific logic |
| `indexer.py` | normalized bundle/manifest ingestion and atomic relation rebuilding |
| `techniques.py` | aliases, domains and migration of the current tag map |
| `knowledge.py` | structured filters, identifier routing and alias reporting |
| `record_search.py` | capability/mitigation/source filters and duplicate collapsing |
| `server.py` | compatible filters plus two read-only profile tools |
| `cli.py` | research ingestion/status and explicit validation annotation commands |
| `src/command_vault/adapters/` | new CyberGym, ExploitGym and ExploitBench adapters |
| `schemas/` | normalized manifest JSON Schema |
| `scripts/build_candidate.py` | source manifests, schema migration and candidate reports |
| `scripts/evaluate_candidate.py` | multi-domain usability/regression evaluation |
| `tests/` | migration, adapters, provenance, filters, profiles, deduplication, security and stdio tests |

## 15. Delivery phases

### 15.0 Model orchestration and coding subagent strategy

The root agent for every implementation phase must use
`gpt-daybreak-blue-latest`. It owns the plan, task graph, cyber-domain reasoning,
implementation decisions, delegation, review, integration, candidate
acceptance, and production handoff. It may implement any in-scope code directly.

Official OpenAI documentation describes [Daybreak Blue](https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest) as an alias with safeguards for defensive cybersecurity work and the [model catalog](https://developers.openai.com/api/docs/models) positions Astra for the hardest work, Terra for balanced intelligence/cost, and Luna for cost-sensitive workloads. The user-selected project routing applies those roles through a single delegation level.

#### Fixed hierarchy

```text
gpt-daybreak-blue-latest (root orchestrator)
  |- owns cyber-domain analysis and all project decisions
  |- defines exact coding contracts and sanitized fixtures
  |- may implement security-sensitive and integration code directly
  |- may delegate bounded coding tasks
  |- reviews and integrates every result
  `- Terra, Luna, or Astra coding subagent(s), selected by task complexity
       |- edit only assigned files
       |- implement only the fixed software contract
       |- run scoped tests
       `- do not spawn or delegate to additional agents
```

Rules:

- Do not automatically substitute another root model for `gpt-daybreak-blue-latest`.
- Do not delegate non-coding research, cyber interpretation, exploit analysis, source-policy decisions, security acceptance, or production operations.
- Use Terra for routine bounded adapters/tests, Luna for trivial mechanical
  changes, and Astra only when complex pure coding materially benefits from it.
- After one refusal or a time-box with no output, do not chase or repeatedly
  retry the same delegated task; narrow/reassign once or implement it at root.
- No subagent may spawn another subagent. All delegation remains visible to and
  controlled by Daybreak Blue.
- If a configured model is unavailable, report it rather than silently changing
  the requested role.
- Record the requested model ID, observed/resolved model identifier when available, reasoning effort, task packet, timestamps, changed files, and test results in the implementation report. This is especially important because `gpt-daybreak-blue-latest` is a moving alias.

#### Suitable delegated assignments

- Implement a pre-approved SQLite migration from an exact schema specification.
- Add Pydantic models and JSON Schema validation from an agreed manifest contract.
- Implement deterministic parsers for supplied, sanitized fixtures.
- Implement one source adapter in its own module after field mappings are fixed.
- Add typed response fields and mechanical CLI/MCP parameter plumbing.
- Implement artifact hashing, duplicate collapsing, pagination, and filtering utilities.
- Write migration, parser, serialization, property, pagination, and regression tests.
- Fix ordinary test failures, typing issues, lint findings, and compatibility defects.
- Produce fixture generators and deterministic candidate-reporting code.
- Review a bounded diff for correctness, edge cases, performance, or missing tests.

These tasks should describe data shapes and expected transformations without requiring the subagent to decide how an exploit works or whether a cyber action is appropriate.

#### Work retained by the Daybreak Blue orchestrator

- Decide the ontology, operational stages, aliases, and technique relationships.
- Interpret vulnerability, exploit, sanitizer, patch, mitigation, and grader evidence.
- Decide which trace milestones or exploit artifacts are authoritative enough to index.
- Define sanitization and credential/flag redaction policy.
- Resolve licensing and provenance policy.
- Approve source acquisition and any execution against vulnerable environments.
- Review security-sensitive parser behavior such as archive extraction and path handling.
- Integrate overlapping changes and resolve schema/API design conflicts.
- Evaluate retrieval quality against pentest/CTF operator needs.
- Build, audit, promote, or roll back the production database.
- Decide when work is sufficiently specified before delegating it and select
  Terra, Luna, or Astra according to the current routing policy.
- Receive all user steering and update the task graph without requiring coding
  subagents to reinterpret project intent.

#### Task-packet contract

Every delegated task should include:

```text
Objective
Exact input and output contract
Allowed files/directories
Files owned by other agents and therefore off limits
Sanitized fixtures
Required compatibility behavior
Required tests and commands
Explicit non-goals
Expected completion artifact: patch, tests, and concise handoff
```

Example:

```text
Implement the CyberGym metadata adapter in
src/command_vault/adapters/cybergym.py.

Input: the supplied tasks.json fixture and normalized-manifest schema.
Output: deterministic ResearchBundle objects. Do not download data,
execute artifacts, classify vulnerabilities beyond the supplied mapping,
edit database.py/server.py, or change the manifest contract.

Run the adapter unit tests and report changed files and results.
```

Use sanitized, minimal fixtures whenever full upstream artifacts could distract
from the coding contract. If a delegated task becomes dependent on cyber-domain
judgment, the subagent should stop at the typed boundary and return the
unresolved case to the Daybreak Blue orchestrator. Do not disguise intent or
ask an agent to bypass safeguards; isolate ordinary engineering from domain
decisions.

#### Parallel work policy

- Establish a clean, recorded application baseline before delegation.
- Prefer separate worktrees or, where all agents share one filesystem, strict non-overlapping file ownership.
- Do not assign two agents to edit `database.py`, `server.py`, or the same migration concurrently.
- Limit active coding branches to work the Daybreak Blue orchestrator can review and integrate promptly.
- Parallelize independent adapters, schemas, fixtures, and test modules.
- Serialize schema changes, shared response contracts, and final integration.
- Require each subagent to inspect current tests and local `AGENTS.md` instructions relevant to its owned files.
- Never let a subagent promote a candidate database, change MCP production configuration, restart shared services, or modify the live vault.

#### Suggested phase allocation

| Phase | `gpt-daybreak-blue-latest` orchestrator | Optional bounded coding delegation |
|---|---|---|
| Phase 0 | Freeze requirements, fixtures and acceptance gates | Fixture tooling, inventory/report utilities, test harness cleanup |
| Phase 1 | Own schema/API decisions and migration review | JSON Schema/Pydantic implementation, migration code from fixed DDL, migration tests |
| Phase 2 | Define ExploitGym mappings and review extracted meaning | Adapter implementation, code-language detection, manifest serialization, unit tests |
| Phase 3 | Define search behavior and inspect result quality | Filter plumbing, typed responses, duplicate collapsing, CLI parity, regression tests |
| Phase 4 | Define CyberGym derivation rules | Metadata/error/diff parsers in separate modules, fixtures and performance tests |
| Phase 5 | Define repository-only methodology and target semantics | Static metadata parsing, normalized bundle generation and deterministic tests |
| Phase 6 | Resolve syzbot/nofuzz and metadata-enrichment policy | Independent adapter expansion and mechanical normalization rules |
| Phase 7 | Own security review, acceptance and promotion | Candidate audit tooling, report generation and non-production test fixes |

#### Review and merge gate

No subagent result is complete merely because its local tests pass. The Daybreak Blue orchestrator must:

1. Inspect the full diff and confirm file ownership was respected.
2. Confirm the implementation matches the fixed contract without silent schema or behavior changes.
3. Check untrusted-input handling, path safety, response bounds, SQL parameterization, and source provenance.
4. Run targeted tests after integration.
5. Run the full existing suite plus new migration, stdio, candidate, integrity, and retrieval tests when the phase warrants it.
6. Compare candidate behavior and performance with the saved baseline.
7. Record the integrated commit/revision in the implementation report.

Recommended routing is `gpt-daybreak-blue-latest` for root orchestration and all
cyber/security-sensitive implementation; `gpt-5.6-terra` for routine bounded
coding/tests/adapters; `gpt-5.6-luna` for trivial mechanical fixtures/docs; and
`gpt-6-astra` only for complex pure coding. The Daybreak Blue orchestrator
performs cross-component integration review. Testing instructions should be
calibrated to the change: targeted meaningful tests first, followed by broader
checks when integration risk warrants them.

### Phase 0 — Baseline and fixtures

Deliverables:

- immutable baseline DB backup and application snapshot;
- current retrieval/latency results saved;
- pinned upstream acquisition manifests;
- representative fixtures from all three sources with secrets removed;
- agreed source/license inventory.

Exit gate: all current tests and byte-preservation checks reproduced from a clean environment.

### Phase 1 — Additive schema and normalized bundle contract

Deliverables:

- schema migration;
- Pydantic and JSON Schema models;
- research source type;
- source/vulnerability/stage/evidence/validation tables;
- migration and rollback tests.

Exit gate: baseline corpus migrates without data loss, normal MCP remains compatible and read-only.

### Phase 2 — ExploitGym kernelCTF pilot

Deliverables:

- ExploitGym adapter;
- normalized bundles for 27 kernelCTF tasks;
- vulnerability, exploit, novel-technique, trace, PoV, patch and mitigation relations;
- pilot search/profile tests.

Exit gate: representative kernel questions retrieve source-backed trigger, primitive, mitigation, script and remediation evidence without degrading existing retrieval cases.

### Phase 3 — Retrieval UX and operator profiles

Deliverables:

- new optional filters;
- deterministic aliases;
- vulnerability and technique profile tools;
- source-diverse/deduplicated result behavior;
- CLI parity and stdio compatibility tests.

Exit gate: timed manual walkthroughs demonstrate fewer query reformulations and direct access to complete artifacts/context.

### Phase 4 — CyberGym breadth import

Deliverables:

- CyberGym metadata adapter;
- selective text acquisition under `/tmp`;
- normalized description/error/patch records;
- sanitizer/stack/diff extraction;
- 1,507 structured vulnerability profiles where source data permits.

Exit gate: exact task/project/function/sanitizer queries work; licensing/provenance is complete; source archives remain excluded.

### Phase 5 — ExploitBench methodology and target metadata

Deliverables:

- operational-stage ontology seeded from deterministic grader semantics;
- one repository-sourced methodology document;
- 41 metadata-only V8 target profiles;
- zero imported scripts or run-dataset records.

Exit gate: V8 capability terminology and exact target metadata are retrievable
without run-dataset content, code artifacts, or incorrect attainment claims.

### Phase 6 — Remaining ExploitGym expansion

Deliverables:

- 159 syzbot diagnostic records;
- 18 unique nofuzz records;
- metadata-only enrichment of 484 existing CyberGym profiles without duplicate
  documents or vulnerability profiles;
- cross-source deduplication/corroboration and broader sanitizer coverage.

All 181 ExploitGym V8 tasks and exploit code outside the selected syzbot
reproducers are deferred to an optional later review.

Exit gate: corpus growth does not swamp personal writeups; broad-query diversity and latency remain acceptable.

### Phase 7 — Candidate acceptance and promotion

Deliverables:

- full candidate audit and retrieval report;
- multi-domain held-out evaluation;
- security/redaction/license report;
- database/snapshot and managed-research size report plus restore manifest;
- backup, promotion, reconnect, smoke-test and rollback runbook.

Exit gate: explicit user approval after reviewing candidate results. Promotion must be atomic and recoverable.

## 16. Risk register

| Risk | Mitigation |
|---|---|
| External corpus overwhelms personal material | source diversity, filters, duplicate collapse, regression cases |
| Noisy model traces pollute results | index only verified capability milestones; retain raw traces as attachments |
| Incorrect inferred technique relations | provenance classes, deterministic rules, curator review |
| IDs change after reindex | revision-bound references, stable hashes and atomic link rebuilding |
| Temporary sources break `read_context` | install accepted normalized bundles in the managed research tree and retain verified DB snapshots as fallback |
| Parent `WRITEUPS` scan duplicates research | canonical managed-root exclusion plus dedicated `WRITEUPS_RESEARCH` bundle routing |
| Licensing uncertainty | per-source/artifact license fields and redistribution status |
| Stored credentials or flags leak | deterministic scanning, redaction ledger and candidate audit |
| History mistaken for successful execution | separate `observed_execution` from success validation |
| Schema complexity harms reliability | additive migration, normalized bundle boundary, phased delivery |
| Retrieval slows with new joins | dedicated indexes, bounded queries and latency gates |
| Research assertions become stale | source revisions, freshness states and reproducible refresh adapters |

## 17. Recommended first implementation slice

The smallest slice that delivers real pentest/CTF value is:

1. Add `research` sources, source collections, vulnerability records, operational stages, aliases, evidence links, and validation status.
2. Implement the normalized manifest/bundle contract.
3. Build the ExploitGym adapter for the 27 kernelCTF tasks.
4. Seed stages from ExploitBench's definitions, translated into operational terminology.
5. Add domain/CVE/vulnerability/stage/mitigation/validation filters.
6. Add vulnerability and technique profile tools.
7. Test against existing cases plus 20 kernel/pwn/V8 operator questions.

This slice tests the architecture on high-quality, structured material before
the broader CyberGym and metadata-only diagnostic expansions. Historical model
traces are outside the accepted import scope.

## 18. Definition of done

The extension is complete when an operator in an authorized session can reliably:

- search an unfamiliar error, CVE, function, vulnerability class, primitive, or mitigation;
- retrieve concise source-backed explanation and original context;
- navigate prerequisites and plausible next operational stages;
- obtain exact, complete commands or scripts with environment and validation state;
- distinguish source-documented, harness-observed, locally reproduced, personally confirmed, failed, stale, and unknown evidence;
- find corroborating examples across personal HTB material and external research without losing provenance;
- receive an honest empty/unsupported result instead of loosely related content;
- use the normal MCP interface without granting it write or execution authority.

Success is improved usefulness, speed, grounding, and recall during real authorized pentesting and CTF/lab work—not performance on an AI cybersecurity benchmark.

## 19. VM execution, preservation, cleanup, and restoration

### 19.1 Desired retained state

After implementation and acceptance, retain only:

1. The reviewed command-vault application and documentation in Git.
2. The promoted `vault.db` and its protected release bundle.
3. The adapter-owned normalized tree under `/home/xtk/writeups/research/`.
4. Release, migration, evaluation, source, restore, and rollback documentation.

Do not retain virtual environments, cloned benchmark repositories, downloaded raw datasets, Docker images, extraction directories, worktrees, candidate databases, caches, test output, or temporary credentials. Recreate runtime dependencies from the lockfile after VM restoration. Do retain the normalized research bundles and their manifest/hash inventory.

The database may contain sensitive personal shell history and lab material. Never commit it to Git. Preserve it in a permission-restricted and preferably encrypted location outside the VM snapshot/revert boundary.

### 19.2 Current VM baseline

Baseline observed on 2026-09-12:

```text
Application:      /opt/command-vault-mcp
Git branch:       main
Git HEAD:         e2d4f3b
Git remote:       git@github.com:x746b/command-vault.git
Git worktree:     clean
Live database:    /home/xtk/.local/share/command-vault/vault.db
Live DB size:     approximately 67 MB
Application size: approximately 43 MB
Root free space:  approximately 26 GB
/tmp free space:  approximately 15 GB (tmpfs)
Primary config:   /home/xtk/.codex-htb/config.toml
Configured source:/home/xtk/writeups
```

Recheck and record these values at project start; this block is historical context, not a future assertion.

### 19.3 Before implementation

The Daybreak Blue orchestrator must create a baseline ledger before any changes:

- VM snapshot/checkpoint identifier and date.
- `git status --short`, branch, HEAD, remotes, tags, and submodule state.
- Application tree hash or reproducible file manifest excluding `.git`, virtual environments, and caches.
- Database path, mode, owner, size, SHA-256, schema version, `PRAGMA integrity_check`, and `PRAGMA foreign_key_check`.
- Current command-vault version and interpreter path.
- Current MCP configuration snippets and hashes, with secrets redacted.
- Current test results and saved retrieval/latency baseline.
- Disk usage, relevant running processes, Docker state, and host security settings that the project might otherwise affect.
- Exact temporary paths allocated for the project.

Create a consistent pre-project database backup outside the live path. Do not rely solely on copying a database while a writer may be active. Use SQLite's backup mechanism or a verified quiet/offline copy, then run integrity checks on the backup.

### 19.4 Git workflow and preservation anchor

Do not develop directly on `main`.

Recommended workflow:

```text
origin/main at recorded baseline
  -> feature/research-knowledge-v1
  -> phase commits with passing targeted tests
  -> integration and candidate acceptance commit
  -> reviewed merge to main
  -> annotated release tag after production validation
```

Requirements:

- Commit application code, schemas, fixtures that are safe to redistribute, tests, migrations, and operational documentation.
- Keep downloaded upstream corpora, generated candidate databases, raw traces, secrets, and the production DB out of Git.
- Update `.gitignore` before generating new local artifacts.
- Scan staged changes for secrets, flags, absolute temporary paths, database files, and oversized generated content.
- Push the accepted branch/merge and release tag to the configured remote before reverting the VM.
- Verify the remote contains the expected commit and tag from a fresh read-only fetch or clone.
- Do not include `Co-Authored-By`, `Signed-off-by`, or similar metadata unless explicitly requested.

Documentation that must survive the VM revert should live in the application repository, for example:

```text
docs/research-knowledge/
  ARCHITECTURE.md
  IMPLEMENTATION.md
  MIGRATION.md
  SOURCES.lock.json
  EVALUATION.md
  SECURITY.md
  RESTORE.md
  ROLLBACK.md
  RELEASE-MANIFEST.example.json
```

The planning documents currently under `/home/xtk/labs/HTB/NEW/reports/command-vault/` are not in a Git repository. Copy their reviewed final versions into the application documentation tree during Phase 0 so a VM revert does not lose them.

### 19.5 Temporary workspace layout

Allocate one explicit project root using `mktemp -d` under `/tmp`, record it in the baseline ledger, and keep all disposable state beneath it:

```text
/tmp/<recorded-project-root>/
  downloads/
  source-clones/
  worktrees/
  normalized-bundles/
  candidate-databases/
  test-output/
  manifests/
```

Rules:

- Never use `/tmp`, `/`, `$HOME`, `~`, or a workspace root as a recursive cleanup target.
- Use explicit, resolved paths from the ledger.
- Do not create system Python packages; use `uv` and project-local virtual environments/worktrees.
- Do not pull vulnerable Docker images unless a later approved validation specifically requires them.
- Do not change ASLR, KASLR, coredump, firewall, VPN, or shared service settings for ingestion/parser work.
- Check `/tmp` capacity before large selective downloads because it is a 16 GB tmpfs on this VM.
- Prefer metadata and selective text retrieval; do not download CyberGym's roughly 225 GB source archives.
- Store acquisition URLs, revisions, hashes, declared sizes, and license status in `SOURCES.lock.json`.

### 19.6 Candidate-only development

All migrations, imports, and retrieval experiments operate on candidate databases under the recorded temporary root.

- The normal MCP continues to use the live database read-only.
- Coding subagents receive candidate paths and sanitized fixtures only.
- No subagent receives authority to modify the live DB or production config.
- Candidate construction starts from the verified baseline backup.
- Every phase runs integrity, foreign-key, source-anchor, snapshot-hash, and retrieval checks.
- Test `read_context` against a hash-matching managed-tree fixture and after making that fixture unavailable; fallback snapshots must still resolve. Changed managed files must not silently override indexed snapshots.
- Record candidate size growth and confirm the retained DB remains practical to back up and restore.

### 19.7 Promotion checkpoint

Promotion is a material state change and requires an explicit checkpoint after the candidate is fully reviewable.

Before promotion:

1. All required tests and acceptance gates pass.
2. The application commit intended for production is pushed and recorded.
3. A consistent live-DB backup is created and verified.
4. The candidate DB passes integrity and foreign-key checks.
5. Candidate and baseline retrieval reports are reviewed.
6. Candidate research context works from a managed-tree fixture and from embedded fallback snapshots without `/tmp` staging.
7. The candidate contains no known temporary paths, secrets, dynamic flags, or unsupported license claims.
8. A rollback command/runbook identifies the exact old code commit and DB backup.

Promote with an atomic same-filesystem replacement strategy, retain mode `0600`, preserve the required owner/group, and reconnect only command-vault clients. Do not terminate unrelated MCP processes or shared sessions.

After promotion, verify:

- server version and Git commit;
- database schema/version/hash;
- read-only MCP startup;
- representative legacy and research queries;
- `read_context` for personal path-backed sources and managed research with snapshot fallback;
- command/script pagination;
- normal MCP operations do not change database bytes;
- all configured clients use the intended interpreter and DB.

### 19.8 Retention bundle outside the VM

Before VM revert, export a protected database release bundle to storage that will survive the revert. The exact destination must be chosen and verified before cleanup.

Bundle contents:

```text
vault.db
vault.db.sha256
research-corpus.tar
research-corpus.tar.sha256
RESEARCH-CORPUS-MANIFEST.json
DB-MANIFEST.json
integrity-check.txt
foreign-key-check.txt
application-commit.txt
application-tag.txt
schema-version.txt
SOURCES.lock.json
RESTORE.md
ROLLBACK.md
```

`DB-MANIFEST.json` should include database size, SHA-256, schema/application versions, creation time, baseline DB hash, source collection revisions, document/artifact counts, validation counts, and the compatible application commit/tag. `RESEARCH-CORPUS-MANIFEST.json` must enumerate every managed file with relative path, size, SHA-256, source/revision, and matching database collection/document hash.

Protection requirements:

- destination is outside the VM revert boundary;
- restrictive permissions;
- encryption appropriate for personal history and lab data;
- hash verification after transfer;
- a second independently verified copy when practical;
- restoration test from the exported copy before deleting temporary state.

### 19.9 Pre-revert cleanup

Cleanup occurs only after Git and database preservation are independently verified.

Use the baseline ledger to inventory and remove only project-created disposable paths. Prefer an explicit cleanup script that:

1. Prints every resolved target.
2. Refuses empty, root, home, workspace-root, or unresolved targets.
3. Confirms each target is beneath the recorded project root.
4. Reports sizes before removal.
5. Removes only downloads, clones, worktrees, normalized staging bundles, candidate DBs, caches, and test output created by this project.
6. Produces a cleanup report listing removed and retained items.

Do not remove existing `/tmp` content, unrelated Docker objects, shared tmux sessions, application backups, or other users' data. If Docker was used, remove only containers, networks, volumes, and images labeled/recorded as created by this project, and request confirmation before material cleanup.

Verify before reverting:

- `/opt/command-vault-mcp` is clean at the pushed/tagged accepted commit.
- No DB, archive, trace, credential, or generated corpus is untracked in Git.
- The live DB matches the exported bundle hash.
- Documentation exists in the pushed application repository.
- Temporary project root is gone or contains only an intentional cleanup report already copied into Git documentation.
- Host security settings and shared services match the baseline ledger.
- No project-specific listener, proxy, container, QEMU VM, or background process remains.
- System packages were not changed; project virtual environments and caches are disposable.

### 19.10 VM revert and restoration

After reverting the VM to the validated checkpoint:

1. Verify the VM matches the recorded validated baseline.
2. Fetch/clone `/opt/command-vault-mcp` from the accepted Git tag or immutable commit.
3. Recreate the application environment from the committed lockfile using `uv sync --frozen`; do not restore an old virtual environment archive.
4. Restore `vault.db` from the protected release bundle to `/home/xtk/.local/share/command-vault/vault.db`.
5. Set the recorded owner/group and mode `0600`.
6. Restore or manually apply the documented minimal MCP configuration; do not blindly overwrite unrelated current configuration.
7. Restore the normalized research corpus to `/home/xtk/writeups/research/`, verify its manifest/hashes, and configure `WRITEUPS_RESEARCH`.
8. Confirm configured personal writeup paths exist and the parent `WRITEUPS` scan excludes the managed research subtree.
9. Run database integrity and foreign-key checks.
10. Run the release smoke suite and representative legacy/research retrieval checks, including managed-file and snapshot-fallback context.
11. Verify normal MCP startup/search/context calls do not change database bytes.
12. Reconnect clients and record the restored application commit, DB hash, corpus-manifest hash, and validation results.

Only after the restored system passes these checks should the project be considered finished.

### 19.11 Rollback after restoration

Maintain compatibility pairs:

```text
old application commit/tag <-> old database backup
new application commit/tag <-> new promoted database
```

Do not run an old application writer against a new schema. To roll back, disconnect the affected command-vault clients, restore the matching old code and old database, verify integrity and MCP behavior, then reconnect. Preserve the failed/new pair until the cause is understood.

### 19.12 Recommended decision

Proceed on this VM with the following constraints:

- Begin with Phase 0 and the 27-task ExploitGym kernelCTF pilot rather than importing every source at once.
- Develop on a feature branch with Daybreak Blue root orchestration and the
  current task-appropriate optional delegation policy.
- Keep every disposable artifact beneath one recorded `/tmp` project root.
- Install accepted normalized research under `/home/xtk/writeups/research/` and retain DB snapshots as verified fallback.
- Commit and push all durable code and documentation before promotion.
- Export and test a protected database release bundle outside the VM before cleanup/revert.
- Revert the VM only after both Git and DB restoration have been proven.

This approach preserves the useful product state while returning the VM operating environment to a known, validated baseline.
