# Pre-v1.0 research usability polish

Date: 2026-09-13
Status: corrected candidate accepted technically; production remains unchanged

## Approved scope

This checkpoint corrects four observed usability gaps without broadening the
accepted corpus:

- accept `syzlang` as a search alias while storing canonical `syz`;
- accept exact operational stage classes such as `trigger`, with exact domain
  filtering, and map `reproducer` to `crash reproduction`;
- link all retained C/syz reproducer scripts to the appropriate reproduction
  stage without changing their validation status;
- expose only deterministic source-backed fixed revisions, sanitizers, affected
  symbols, reviewed classes, and subsystems.

No source archive, historical V8 exploit, model trace, nofuzz PoC, Makefile,
binary, image, or container was added or executed.

## Model task ledger

| Task | Model | Boundary | Result |
|---|---|---|---|
| Script language alias | `gpt-5.6-luna` | database and paged search canonicalization plus focused tests; no source/corpus decisions | complete; 43 focused tests |
| Stage class lookup | `gpt-5.6-terra` | read-only exact class/domain lookup plus focused tests; no adapter/database writes | complete; 83 focused tests |
| Source enrichment, reproducer evidence, integration, candidate and release audit | `gpt-daybreak-blue-latest` | direct cyber/source interpretation and all acceptance decisions | complete; full suite and real candidate audit |

Neither delegated task spawned another agent, committed, used the network, or
changed production state. Daybreak reacquired the two pinned repositories into
a fresh disposable root and reviewed the real source behavior.

## Deterministic enrichment

The 27 kernelCTF records contain exactly one declared patch commit each and 24
retained trace files. Real-source inspection supports:

| Field | Populated | Basis |
|---|---:|---|
| `fixed_revision` | 27 | exactly one 40-hex `patch_commits` value |
| `sanitizer=kasan` | 22 | explicit `KASAN` token in retained trace |
| reviewed vulnerability class | 21 | exact supported KASAN fault headline |
| affected symbols | 21 | exact `KASAN: <fault> in <symbol>` target, deduplicated and bounded to 32 |
| subsystem | 27 | explicit safe leading Linux patch-title prefix |
| `introduced_revision` | 0 | not explicitly supplied |

The three remaining traces are not overinterpreted: one mentions KASAN without
a parseable fault headline, and two provide successful PoV text without an
explicit sanitizer marker. Unknown fields remain null.

All 41 ExploitBench target profiles now expose their declared patch commit as
`fixed_revision`; all 41 keep `introduced_revision` null. The repository-only
scope still contains zero ExploitBench scripts or run-dataset records.

## Reproducer and retrieval behavior

All 345 retained research reproducers link to `crash reproduction`:

- 318 syzbot C/syz scripts remain `harness_observed`;
- 27 kernelCTF C scripts remain `source_documented`;
- zero records claim `reproduced_local`.

`vault scripts --language syzlang --page` returns canonical `syz` records, and
its cursor can be continued with `--language syz` (or the reverse). Exact stage
class `trigger` returns four domain/canonical stage combinations in the current
corpus; a `linux-kernel` filter returns the two kernel trigger stages.
`reproducer` returns both canonical `crash reproduction` domain stages and
prioritizes evidence attached to the Linux-kernel stage.

## Candidate and acceptance evidence

The create-only candidate was built from the current production database and a
fresh 8,944-file managed-corpus staging tree:

```text
/tmp/command-vault-v1-polish.kEPVB4/candidate/v1-polish-stable-ids.db
```

- SHA-256: `191f6f19eb9c8ca03e7c315071d43f1546d7f1f914de0e1a62e6d2f4157bba4b`
- size: 253,992,960 bytes
- schema: 2
- SQLite integrity: `ok`
- foreign-key violations: 0
- release audit: 8,944 files and 1,753 research documents
- release-manifest SHA-256 before the final code commit:
  `572779c3f8279e4b5076b6e29f194fc24f1d5538a671dd447434504063db5476`
- full suite after the index-safety correction: 1,205 tests passed
- isolated MCP: 20 read-only tools; candidate bytes unchanged after smoke tests

After code checkpoint `36c0ba68ba3e4eb72c289f8df7719224ae611fe0`, a
create-only copy rebased all 1,753 research paths to the future install root
`/home/xtk/writeups/research`. That copy has SHA-256
`98743a3876771d11bdc3f46973bf7e41997f0c6ffa3c282a470170d2c0e06ca1` and
passed the full corpus/database release audit; the resulting release-manifest
SHA-256 is
`bc11e8f50f1ab2534f165246f04db99d56dd12b005ec0137baab3a4d855712a2`.

Every existing research document, vulnerability, chunk, and script ID is
preserved. The 12 sampled legacy command searches returned identical top-five
IDs between production and candidate. A warm 120-call comparative smoke run
measured production/candidate median 0.945/1.015 ms and p95 5.231/5.024 ms;
this targeted cached run is a relative regression check, not a replacement for
the broader historical Phase 7 latency measurement.

## Remaining checkpoint

The current production DB and managed corpus have not been replaced by this
polish. Before the v1.0 release push/tag, build the production-path release
copy from this accepted candidate, audit it against the corrected managed
corpus, create a new exact pre-replacement backup, atomically install the pair
only after explicit user approval, and repeat CLI/MCP/read-only byte checks.

## Release-blocking legacy-index safety correction

Post-polish testing reproduced a destructive candidate-only edge case when a
caller supplied the unified writeup root but omitted `WRITEUPS_RESEARCH`:

```bash
env -u WRITEUPS_RESEARCH \
  VAULT_DB=<candidate-copy.db> \
  WRITEUPS=/home/xtk/writeups \
  vault --json index --add
```

The corrected configuration auto-detects the existing canonical
`<WRITEUPS>/research` root. The legacy indexer also excludes the nested root on
its own, skips every Markdown document or artifact beneath a managed bundle
`manifest.json` under any unified or custom parent, and refuses direct legacy
indexing of a managed file. Explicit `WRITEUPS_RESEARCH`, equal-root refusal, symlink rejection,
custom directories, and roots without a research child retain their tested
behavior.

The exact subprocess regression builds a disposable schema-v2 database with a
structured research document/profile/chunk/C script/snapshot/stage/evidence
set. The first command adds only a new `Dump.md`; the repeated command processes
zero files. Every research ID, row, snapshot, evidence link, and validation row
is identical before and after both calls.

A separate real production-DB backup copy was tested against the current
`/home/xtk/writeups` tree. It preserved all 1,753 research records and every
SHA3 set for research documents, profiles, chunks, scripts, snapshots, stages,
aliases, evidence, and validations. It added two genuinely new personal files
currently absent from production (`Management.md` and `Dump-official.md`), then
processed zero files on repetition. SQLite integrity remained `ok` with no
foreign-key violations. The production database itself was not opened for
writing.
