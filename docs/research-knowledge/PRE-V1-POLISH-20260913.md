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
- full suite: 1,198 tests passed
- isolated MCP: 20 read-only tools; candidate bytes unchanged after smoke tests

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
