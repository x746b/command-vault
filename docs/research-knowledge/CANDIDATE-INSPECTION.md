# Inspecting the research candidate

The current Phase 5 build is separate from the live database:

```text
/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db
```

Commands below select it for one process only. They do not change shared MCP
configuration or the production database.

## Reproduce the candidate

Build the three normalized source collections from existing pinned offline
sources into a new managed fixture:

```bash
uv run python scripts/build_exploitgym_bundles.py \
  --repository /tmp/command-vault-research.j3Xal9/source-clones/exploitgym \
  --revision e4123d043774623b2274e6bbe0155a423d631f0a \
  --output /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/exploitgym

uv run python scripts/build_cybergym_bundles.py \
  --dataset /tmp/command-vault-research.j3Xal9/downloads/<verified-cybergym-text> \
  --revision bde190ded494e52bc684b66073b436c9d992c7c6 \
  --output /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/cybergym

uv run python scripts/build_exploitbench_bundles.py \
  --repository /tmp/command-vault-research.j3Xal9/source-clones/exploitbench \
  --revision 9d0173bcf8835b74a45f60450ae7f184e29e7607 \
  --output /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/exploitbench
```

The CyberGym downloader remains documented in `CYBERGYM-IMPORT.md`; it selects
only description/error/patch text and no repository archives. ExploitBench is
repository-only and emits no scripts.

Create a new candidate without modifying the baseline:

```bash
uv run python scripts/build_research_candidate.py \
  --baseline /tmp/command-vault-research.j3Xal9/baseline/vault-baseline.db \
  --candidate /tmp/command-vault-research.j3Xal9/candidate-databases/<new-candidate>.db \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/exploitgym \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/cybergym \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research/exploitbench \
  --managed-root /tmp/command-vault-research.j3Xal9/<new-managed-fixture>/research
```

Destinations are create-only. Use new names for reruns.

## Inspect counts and research

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json stats

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json knowledge "KASAN use-after-free" --type research

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json knowledge "StructuralOptimization ignored side-effects" \
  --type research --source-name exploitbench
```

The existing stats keys remain backward-compatible. The additive `research`
section reports sources, domains, vulnerabilities, stages, mitigations,
evidence, and validations.

## Navigate structured profiles

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json vulnerability CVE-2023-3776 --limit 12

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json stage "KASLR Bypass" --domain linux-kernel --limit 5

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json stage addrof --domain browser-engine

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json vulnerability CVE-2024-1939

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  uv run vault --json vulnerability v8-crbug-1509576
```

ExploitBench profiles contain repository methodology and target metadata only.
They contain no historical JavaScript, runs, models, seeds, grade/audit results,
transcripts, or tool calls.

Follow a returned reference with `vault context`. Hash-matching adapter-owned
documents report `managed`; a missing or changed managed document uses the
verified database snapshot fallback according to the documented integrity
policy.

## Candidate-only MCP process

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
VAULT_READONLY=1 \
  uv run command-vault
```

Use `vault_stats`, `search_knowledge(writeup_type="research")`, profiles, and
`read_context(reference)`. Do not replace the shared MCP configuration during
candidate review.
