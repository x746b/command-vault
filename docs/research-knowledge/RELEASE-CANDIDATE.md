# Phase 7 pre-promotion release candidate

## Candidate unit

- Application branch: `feature/research-knowledge-v1`.
- Compatible application/audit commit:
  `1ef23e459a21b58d3905aa800c2a68a6948fc945`.
- Development candidate: `research-phase6-final.db`, 253,992,960 bytes, mode
  `0600`, SHA-256
  `c17c615aa1de5dba711ec8af1f508afea972f009517869e12bcb35ad5c63a166`.
- Promotion DB: a create-only copy with all 1,753 managed paths rebased to
  `/home/xtk/writeups/research`, 253,992,960 bytes, mode `0600`, SHA-256
  `5d43797d22f45faeb7949e18dfe4ac28a3cc52a141c605ac3ffc1e2b8637fd2e`.
- Managed corpus: 8,944 files, 149,256,948 bytes, tree SHA-256
  `2285567dc5d140a4f0c3ef04e67b16a3ded7518e628573d5f08d31908b690c75`.
- Sources: CyberGym 1,507 documents, ExploitGym 204, ExploitBench 42.
- Tests: 1,159 passing; SQLite integrity OK; zero foreign-key violations.

The promotion DB was audited against both the original staging corpus and a
fresh extraction of the release tar using the future install root. Both audits
produced the identical per-file corpus manifest SHA-256
`bf38c2f8b45d06629a8a730bac18a25835955125df7fc8544b0ad80eab7a7b2e`.

Machine-readable per-file/DB manifests and local Git/corpus bundles are prepared
under `/tmp/command-vault-research.j3Xal9/` during Phase 7. They are not durable
until copied to an approved destination outside the VM revert boundary and
verified there.

Current local release hashes:

- release manifest:
  `b95571ee7da3f0ac92020287c3c8c5e9028f4fdf5b136d9969cd870156d906a3`;
- DB manifest:
  `d256147e9f609a2ce8164676e1b208048db8a698e496b2f1d60ce1dd7ff83bec`;
- per-file corpus manifest:
  `bf38c2f8b45d06629a8a730bac18a25835955125df7fc8544b0ad80eab7a7b2e`;
- corpus tar:
  `4b927324b919f964d22120a5b688874f3be21b22b696b2063ced54818905f4b0`.

The local payload and restored extraction were independently audited. Their DB
and corpus manifests are identical. The release manifest remains
`pre-promotion` and lists all five pending decisions.

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
