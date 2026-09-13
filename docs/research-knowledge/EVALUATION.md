# Research release evaluation

Date: 2026-09-13

Candidate: `/tmp/command-vault-research.j3Xal9/candidate-databases/research-phase6-final.db`

This is an operator-usability and regression review, not an LLM benchmark.
Nothing retrieved during evaluation was executed.

## Results

The integrated unit/regression suite passes 1,159 tests. SQLite reports
`integrity_check=ok` and no foreign-key violations. A second complete import
preserves all 1,753 research writeup IDs and counts.

Twelve sampled legacy command workflows returned useful evidence within five
results: nmap service enumeration, ffuf content discovery, BloodHound/AD
collection, Certipy/ADCS enumeration, Kerbrute user enumeration,
secretsdump-based Windows credential extraction, Linux and Windows privilege
escalation enumeration, MSSQL `xp_cmdshell`, sqlmap, John password cracking,
and Volatility process analysis.

Research acceptance checks passed for:

- ExploitBench `addrof` alias and exact V8 target/CVE profiles;
- kernelCTF CVE and mitigation profiles;
- syzbot external task, sanitizer/class/function, trace, C, syz, and patch
  retrieval;
- unique nofuzz CVE/GHSA diagnostics;
- CyberGym exact task profiles enriched without changing external identity;
- `discussed` canary/PIE/RELRO/hardened variant metadata;
- managed full-context reads and embedded snapshot verification;
- unsupported required-term negative controls.

The existing 24-query excerpt rubric remains 20/24 between Phase 5 and Phase 6.
Two of sixteen unrelated top-five result pages changed only among existing
personal results; no new diagnostic record entered them. This is the intended
effect of diagnostic-default scope.

## Latency disposition

Warm local measurements over 80 searches:

| Candidate | Median | p95 | Maximum |
|---|---:|---:|---:|
| Phase 5 | 47.925 ms | 140.738 ms | 141.373 ms |
| Phase 6 | 47.445 ms | 137.963 ms | 139.469 ms |

The aspirational absolute p95 target of 100 ms is not met. The plan's alternate
gate permits promotion after investigation. Investigation found no Phase 6
latency regression, no support loss, and no diagnostic-source leakage into
unrelated pages; p95 improved slightly. The exception is therefore acceptable
for a release candidate, but must be explicitly included in the user's final
promotion review. Further query-plan/FTS optimization is post-release work, not
a reason to discard the accepted corpus.

## Promotion acceptance

Pre-promotion evidence is complete. Production promotion remains blocked on the
external snapshot/durable-storage decisions and explicit push/promotion
approval listed in `RELEASE-CANDIDATE.md`.
