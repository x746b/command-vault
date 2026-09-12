# Inspecting the research candidate

Phase 2 builds a separate candidate at:

```text
/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-v1-built.db
```

These commands select that database only for the invoked process. They do not
change the normal MCP configuration or production database.

## Reproduce the candidate

Build normalized bundles from the already pinned offline checkout:

```bash
uv run python scripts/build_exploitgym_bundles.py \
  --repository /tmp/command-vault-research.j3Xal9/source-clones/exploitgym \
  --revision e4123d043774623b2274e6bbe0155a423d631f0a \
  --output /tmp/command-vault-research.j3Xal9/normalized-bundles/<new-output-name>
```

Create a new candidate without modifying the baseline:

```bash
uv run python scripts/build_research_candidate.py \
  --baseline /tmp/command-vault-research.j3Xal9/baseline/vault-baseline.db \
  --candidate /tmp/command-vault-research.j3Xal9/candidate-databases/<new-candidate-name>.db \
  --bundles /tmp/command-vault-research.j3Xal9/normalized-bundles/<new-output-name>
```

Both destinations are create-only. Choose new names for a rerun; existing
bundles and databases are never overwritten.

## See what was added

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-v1-built.db \
  uv run vault --json stats
```

The existing `writeups`, `commands`, `scripts`, `tools`, `chunks`, and `history`
keys remain. The additive `research` section reports source collections,
vulnerabilities, operational stages, evidence links, validations, and
per-source/per-domain document counts. `writeups.research` exposes the research
document count alongside the existing box/challenge/Sherlock counts.

## Search research only

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-v1-built.db \
  uv run vault --json knowledge "KASAN use-after-free" --type research
```

Search by a precise identifier when available:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-v1-built.db \
  uv run vault --json knowledge "CVE-2023-3776" --type research \
  --require-term CVE-2023-3776
```

Read the complete source section using the returned reference:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-v1-built.db \
  uv run vault --json context 'chunk:<id>@<document>.<revision>'
```

Research context is served from the verified snapshot embedded in the candidate
database. It must continue to work when the normalized `/tmp` bundle is moved or
removed.

## Candidate-only MCP process

For an isolated client inspection, launch a separate stdio process with both the
candidate selection and read-only override:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/exploitgym-kernelctf-v1-built.db \
VAULT_READONLY=1 \
  uv run command-vault
```

Then use `vault_stats`, `search_knowledge(writeup_type="research")`, and
`read_context(reference)`. Do not replace the shared MCP configuration during
candidate review.
