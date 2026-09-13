# Research knowledge security and provenance

## Trust boundary

Framework repositories and datasets are untrusted, versioned inputs. Adapters
use bounded regular-file reads, reject symlinks and unsafe paths, validate strict
manifests, verify declared sizes and digests, and publish only normalized text.
No imported artifact is executed. Normal MCP access remains read-only.

C and syzlang reproducers are retained only as source-linked reference material.
`harness_observed` means an upstream record pairs the reproducer with crash
evidence; it never means command-vault ran it. Only a separately verified local
test may use `reproduced_local`.

## Included and excluded material

The selected corpus includes CyberGym descriptions, sanitizer reports, and
patches; selected ExploitGym kernelCTF documentation and reproducers; syzbot
diagnostics with C/syz reproducers; unique nofuzz diagnostics; and repository-
only ExploitBench methodology and target metadata.

Excluded material includes CyberGym source archives, nofuzz PoCs, build files,
binaries, images, historical ExploitGym V8 exploit code, and the ExploitBench
run dataset (JavaScript submissions, models, seeds, grades, audits, transcripts,
and tool calls).

## Licensing

A repository license does not automatically relicense embedded third-party task
material. Unknown dataset and artifact licenses remain null, retain upstream
provenance, and must not be presented as permissively redistributable. The
license-null ExploitBench run dataset is excluded entirely.

## Publication rules

Git may contain code, schemas, public source revisions, generalized import
contracts, and synthetic fixtures. Do not commit databases, generated corpora,
private writeups, shell history, credentials, local configuration, temporary
paths, host-specific deployment logs, or private release manifests and hashes.
Keep personal database backups and managed corpora outside the repository with
restrictive permissions and encryption appropriate to their sensitivity.
