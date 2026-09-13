# Research knowledge evaluation

Evaluation checks retrieval quality, provenance, compatibility, and operator
usability. It is not an LLM benchmark, and imported artifacts are never executed
as part of the test suite.

## Acceptance checks

A candidate database should pass all of the following before it replaces an
existing database:

- `PRAGMA integrity_check` returns `ok` and `PRAGMA foreign_key_check` returns
  no rows.
- A repeated import is idempotent and preserves stable document, vulnerability,
  chunk, script, and evidence identifiers where identity is unambiguous.
- Exact CVE and external-task lookups resolve the intended vulnerability
  profile; invalid identifiers return clean empty results.
- Source, domain, project, vulnerability class, sanitizer, mitigation,
  operational-stage, language, and validation-status filters compose correctly.
- Canonical stage names and documented aliases resolve identically, including
  `trigger`, `reproducer`, and `syzlang` as the public alias for stored `syz`.
- Full-context reads prefer a hash-matching managed document and fall back to
  the verified embedded snapshot if that managed file is unavailable.
- Script pagination produces a stable continuation without duplicates or gaps.
- Legacy writeup, command, script, history, and context workflows retain their
  pre-migration results.
- Negative controls do not broaden into unrelated research results.

## Retrieval rubric

Use a fixed, versioned query set spanning diagnosis, trigger evidence,
mitigations, primitives, remediation, and exact identifiers. For each query,
record whether the expected source, section, artifact, and evidence reference
appear within a fixed result depth. Track median and p95 latency on the same
hardware, but treat a change from the previous candidate as more informative
than a universal millisecond threshold.

## Safety checks

Audit the generated corpus for symlinks, nonregular files, path traversal,
unexpected binaries, secret-shaped values, and untracked source types. Verify
every declared size and digest, confirm that no imported artifact was executed,
and retain unknown licenses as null. Database or corpus hashes belong in private
release manifests, not public documentation.
