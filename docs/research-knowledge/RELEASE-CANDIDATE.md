# Phase 7 pre-promotion release candidate

## Candidate unit

- Application branch: `feature/research-knowledge-v1`.
- Database: `research-phase6-final.db`, 253,992,960 bytes, mode `0600`,
  SHA-256 `c17c615aa1de5dba711ec8af1f508afea972f009517869e12bcb35ad5c63a166`.
- Managed corpus: 8,944 files, 149,256,948 bytes, tree SHA-256
  `2285567dc5d140a4f0c3ef04e67b16a3ded7518e628573d5f08d31908b690c75`.
- Sources: CyberGym 1,507 documents, ExploitGym 204, ExploitBench 42.
- Tests: 1,159 passing; SQLite integrity OK; zero foreign-key violations.

Machine-readable per-file/DB manifests and local Git/corpus bundles are prepared
under `/tmp/command-vault-research.j3Xal9/` during Phase 7. They are not durable
until copied to an approved destination outside the VM revert boundary and
verified there.

## Required user decisions

No production or external action is authorized until all are supplied:

1. External validated VM snapshot/checkpoint identifier and date.
2. Restrictive, preferably encrypted durable destination outside the revert
   boundary for the DB, corpus, manifests, Git bundle, and restore docs.
3. Explicit approval to push/merge/tag the Git branch.
4. Explicit approval to create `/home/xtk/writeups/research`, install the corpus,
   replace the live DB/config atomically, and reconnect command-vault clients.
5. Acceptance of the investigated p95 disposition in `EVALUATION.md`, or a
   request to optimize before promotion.

VM cleanup/reversion remains a later, separate confirmation after the Git
remote and external retention bundle have each been independently verified and
restored in a test location.
