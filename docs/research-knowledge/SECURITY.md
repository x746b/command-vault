# Research release security, license, and provenance review

Date: 2026-09-13

## Trust boundary

All framework inputs are untrusted versioned data. Adapters use bounded,
nonsymlink, regular-file reads, strict manifests, hashes, aggregate-only
redaction reports, and create-only publication. No imported artifact is
executed. Normal MCP access remains read-only.

The final managed corpus contains 8,944 files and no symlink. All 1,753 managed
documents match their indexed content hash and embedded snapshot. All 318 new
C/syz scripts match the managed artifact, source-anchor, stored, and normalized
hashes and are `harness_observed`, never `reproduced_local`.

Aggregate research-corpus scans found zero private-key blocks, CTF flag values,
or recorded `/tmp/command-vault-research.*` paths. Generic words such as
`token`, `secret`, and `password` occur frequently inside source code, patches,
and diagnostic labels and are not credential findings. The reviewed security
filter performed two aggregate secret-shaped replacements during final import;
matched values were not logged.

Excluded data includes CyberGym source archives; nofuzz PoCs; syzbot
Makefiles/binaries/images; all ExploitGym V8 tasks; ExploitBench run JavaScript,
models, seeds, grades, audits, transcripts, and tool calls. The selected syzbot
C/syz files are retained only as non-executed source-linked reproducers.

## License disposition

| Source | Documents | Source license field | Artifact license field |
|---|---:|---|---|
| CyberGym dataset | 1,507 | null | 4,521 null |
| ExploitGym task material | 204 | null | 917 null |
| ExploitBench repository metadata | 42 | MIT | no artifacts |

Repository code licenses do not relicense dataset/task material. Null license
is preserved and the corpus is treated as local, provenance-preserved knowledge;
it must not be represented as permissively redistributable. The license-null
ExploitBench run dataset is excluded entirely.

## Git review

The feature branch contains no tracked database, archive, compressed corpus,
symlink, or file larger than 1 MB. Synthetic redaction strings in tests are
fixtures, not credentials. `git fsck`, the full test suite, JSON validation,
and `git diff --check` pass. The database and managed corpus remain outside Git.

## Sensitive release handling

The database contains personal writeup and shell-history material. Any release
bundle must use restrictive permissions and appropriate encryption outside the
VM revert boundary. Never publish the DB or managed corpus to the Git remote.
