# Inspecting the research candidate

The current Phase 3 build is a separate candidate at:

```text
/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db
```

These commands select that database only for the invoked process. They do not
change the normal MCP configuration or production database.

## Reproduce the candidate

Build normalized bundles from the already pinned offline checkout:

```bash
uv run python scripts/build_exploitgym_bundles.py \
  --repository /tmp/command-vault-research.j3Xal9/source-clones/exploitgym \
  --revision e4123d043774623b2274e6bbe0155a423d631f0a \
  --output /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/exploitgym
```

Acquire and normalize CyberGym's text-only corpus; no repository archive is
selected:

```bash
uv run python scripts/download_cybergym_text.py \
  --pointer-root /tmp/command-vault-research.j3Xal9/source-clones/cybergym-pointers \
  --output /tmp/command-vault-research.j3Xal9/downloads/<new-cybergym-text> \
  --revision bde190ded494e52bc684b66073b436c9d992c7c6

uv run python scripts/build_cybergym_bundles.py \
  --dataset /tmp/command-vault-research.j3Xal9/downloads/<new-cybergym-text> \
  --revision bde190ded494e52bc684b66073b436c9d992c7c6 \
  --output /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/cybergym
```

Create a new candidate without modifying the baseline:

```bash
uv run python scripts/build_research_candidate.py \
  --baseline /tmp/command-vault-research.j3Xal9/baseline/vault-baseline.db \
  --candidate /tmp/command-vault-research.j3Xal9/candidate-databases/<new-candidate-name>.db \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/exploitgym \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/cybergym \
  --managed-root /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research
```

Both destinations are create-only. Choose new names for a rerun; existing
bundles and databases are never overwritten.

## See what was added

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
  uv run vault --json stats
```

The existing `writeups`, `commands`, `scripts`, `tools`, `chunks`, and `history`
keys remain. The additive `research` section reports source collections,
vulnerabilities, operational stages, mitigations, evidence links, validations, and
per-source/per-domain document counts. `writeups.research` exposes the research
document count alongside the existing box/challenge/Sherlock counts.

## Search research only

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
  uv run vault --json knowledge "KASAN use-after-free" --type research
```

Search by a precise identifier when available:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
  uv run vault --json knowledge "CVE-2023-3776" --type research \
  --require-term CVE-2023-3776
```

Combine exact structured filters without changing full-text ranking:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
  uv run vault --json knowledge "ctl_buf controlled data" --type research \
  --source-name exploitgym --domain linux-kernel --cve CVE-2023-3776 \
  --mitigation CONFIG_KMALLOC_SPLIT_VARSIZE
```

The page reports every applied filter. Available exact knowledge filters are
source name, domain, external ID, CVE, project, vulnerability class, sanitizer,
operational stage, mitigation, and validation status.

## Navigate structured profiles

Inspect one CVE or source task without retrieving all stored content:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
  uv run vault --json vulnerability CVE-2023-3776 --limit 12
```

Resolve a stage alias to its canonical operational stage and evidence:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
  uv run vault --json stage "KASLR Bypass" --domain linux-kernel --limit 5
```

Profiles contain source metadata, provenance, mitigation/stage relationships,
and revision-bound references. Follow a reference with `vault context`; profile
responses intentionally omit stored exploit/document content.

Read the complete source section using the returned reference:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
  uv run vault --json context 'chunk:<id>@<document>.<revision>'
```

This candidate points to the managed-tree simulation under the recorded `/tmp`
root. It reports `managed` for hash-matching adapter-owned documents and falls
back to the same verified embedded snapshot if a managed document is missing or
fails integrity checks. The final retained deployment uses the identical policy
under `WRITEUPS_RESEARCH`.

## Candidate-only MCP process

For an isolated client inspection, launch a separate stdio process with both the
candidate selection and read-only override:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase4-scoped.db \
VAULT_READONLY=1 \
  uv run command-vault
```

Then use `vault_stats`, `search_knowledge(writeup_type="research")`, and
`read_context(reference)`. Do not replace the shared MCP configuration during
candidate review.
