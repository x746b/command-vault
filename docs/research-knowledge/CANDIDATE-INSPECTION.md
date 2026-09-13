# Inspecting the research candidate

The final data-phase candidate is separate from the live database:

```text
/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db
```

Commands below select it for one process only. They do not change shared MCP
configuration or the production database.

## Reproduce the source collections

Use new create-only destinations under the recorded `/tmp` root. Build the
ExploitGym kernelCTF and diagnostic collections separately, then assemble their
direct child bundles beneath one managed `exploitgym` source directory:

```bash
uv run python scripts/build_exploitgym_bundles.py \
  --repository /tmp/command-vault-research.j3Xal9/source-clones/exploitgym \
  --revision e4123d043774623b2274e6bbe0155a423d631f0a \
  --output /tmp/command-vault-research.j3Xal9/<new-staging>/kernelctf

uv run python scripts/build_exploitgym_diagnostics.py \
  --repository /tmp/command-vault-research.j3Xal9/source-clones/exploitgym \
  --revision e4123d043774623b2274e6bbe0155a423d631f0a \
  --output /tmp/command-vault-research.j3Xal9/<new-staging>/diagnostics

mkdir -p /tmp/command-vault-research.j3Xal9/<new-managed>/research/exploitgym
cp -a /tmp/command-vault-research.j3Xal9/<new-staging>/kernelctf/. \
  /tmp/command-vault-research.j3Xal9/<new-managed>/research/exploitgym/
cp -a /tmp/command-vault-research.j3Xal9/<new-staging>/diagnostics/. \
  /tmp/command-vault-research.j3Xal9/<new-managed>/research/exploitgym/
```

Rebuild the complete CyberGym collection with 484 stable-ID enrichments, and
build repository-only ExploitBench metadata:

```bash
uv run python scripts/enrich_cybergym_bundles.py \
  --bundles /tmp/command-vault-research.j3Xal9/managed-research-phase5/research/cybergym \
  --metadata /tmp/command-vault-research.j3Xal9/source-clones/exploitgym \
  --revision e4123d043774623b2274e6bbe0155a423d631f0a \
  --output /tmp/command-vault-research.j3Xal9/<new-managed>/research/cybergym

uv run python scripts/build_exploitbench_bundles.py \
  --repository /tmp/command-vault-research.j3Xal9/source-clones/exploitbench \
  --revision 9d0173bcf8835b74a45f60450ae7f184e29e7607 \
  --output /tmp/command-vault-research.j3Xal9/<new-managed>/research/exploitbench
```

Build a candidate from the prior accepted candidate to exercise in-place ID
preservation:

```bash
uv run python scripts/build_research_candidate.py \
  --baseline /tmp/command-vault-research.j3Xal9/candidate-databases/research-phase5.db \
  --candidate /tmp/command-vault-research.j3Xal9/candidate-databases/<new-candidate>.db \
  --managed-root /tmp/command-vault-research.j3Xal9/<new-managed>/research \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed>/research/exploitgym \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed>/research/cybergym \
  --bundles /tmp/command-vault-research.j3Xal9/<new-managed>/research/exploitbench
```

## Inspect counts and knowledge

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db \
  uv run vault --json stats

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db \
  uv run vault --json vulnerability kernel:472b20c73fdc

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db \
  uv run vault --json vulnerability CVE-2019-20503

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db \
  uv run vault --json vulnerability arvo:1461
```

The first profile demonstrates syzbot crash/trace/patch relationships, the
second a unique nofuzz diagnostic, and the third an existing CyberGym identity
enriched in place with source metadata and `discussed` mitigation variants.

Search exact non-executed reproducers by language:

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db \
  uv run vault --json scripts COMEDI_DEVCONFIG --language syz

VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db \
  uv run vault --json scripts __NR_io_uring_setup --language c
```

Follow returned references with `vault context`. Hash-matching adapter-owned
documents report `managed`; embedded snapshots remain the verified fallback.

## Candidate-only MCP process

```bash
VAULT_DB=/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db \
VAULT_READONLY=1 \
  uv run command-vault
```

Use `vault_stats`, research searches, profiles, script retrieval, and
`read_context`. Do not replace shared MCP configuration during review.
