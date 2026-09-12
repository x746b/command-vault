# CyberGym selective-text import contract

## Pinned source

- Dataset: `https://huggingface.co/datasets/sunblaze-ucb/cybergym`
- Revision: `bde190ded494e52bc684b66073b436c9d992c7c6`
- Tasks: 1,507 (`tasks.json`)
- Selected objects: `description.txt`, `error.txt`, and `patch.diff`
- Excluded objects: every `repo-vul.tar.gz` and `repo-fix.tar.gz`

At the pinned revision, the selected corpus is 4,521 Git-LFS objects with a
declared total of 89,741,551 bytes. Acquisition is content-addressed: every
download must match the pointer's declared size and SHA-256 before publication.
The acquisition manifest retains relative path, object ID, size, dataset URL,
and revision. Signed download URLs and authentication material are never logged.

## Source facts

The adapter preserves these upstream fields without reinterpretation:

- task ID and namespace (`arvo` or `oss-fuzz`);
- project name, homepage, main repository, and language;
- vulnerability description;
- declared difficulty-level file lists;
- exact description, sanitizer/error output, and patch text hashes.

Raw selected bytes retain SHA-256 and size. Normalized text is strict UTF-8 when
valid; otherwise invalid bytes are rendered with deterministic backslash escapes
and `utf8_valid=false` is recorded. The normalized runtime artifact is capped at
4 MiB with a visible head/omitted-byte-count/tail marker, because the pinned
corpus contains reports up to 37,140,428 bytes. The full raw object remains
content-addressed in the acquisition manifest but is not duplicated in the
operational database.

Dataset licensing is not inferred from the CyberGym repository license. The
bundle and artifacts retain a null license unless an upstream project/artifact
license is explicitly established.

## Deterministic error derivation

Crash/error parsing is navigation metadata, marked `deterministic`:

- canonical sanitizer: `asan`, `msan`, `ubsan`, `lsan`, `tsan`, or `hwasan`
  from explicit sanitizer names only;
- raw summary: the final `SUMMARY:` line when present;
- deduplication tokens: exact `DEDUP_TOKEN:` values in source order;
- frames: numbered sanitizer frames with function, path, line, and column when
  explicitly present;
- affected symbols: unique parsed frame functions in source order;
- normalized failure class only for an exact reviewed label.

Reviewed failure labels are:

- heap/stack/global buffer overflow;
- heap use-after-free;
- stack use-after-return or use-after-scope;
- use of uninitialized value;
- double free or invalid free;
- allocation/deallocation mismatch;
- null-pointer access;
- signed/unsigned integer overflow;
- shift out of bounds;
- division by zero;
- data race;
- leak;
- explicit segmentation fault/deadly signal.

Unknown or ambiguous labels remain null. The adapter does not derive
exploitability, impact, a CVE, introduced/fixed commits, or successful code
execution from a sanitizer crash.

Retained derived lists are bounded to 256 frames, 128 deduplication tokens, and
256 affected symbols, with total counts and truncation flags. This preserves
useful diagnostics without allowing a repetitive sanitizer report to dominate
manifest or profile responses.

## Patch derivation

Patch navigation extracts only explicit diff structure:

- changed paths from `diff --git` headers;
- hunk ranges and trailing hunk context/function text;
- counts of added and removed lines excluding diff headers.

It does not infer a root cause or remediation category from arbitrary added and
removed code. Patch text is retained as remediation evidence.

## Operational stages and validation

Each complete task emits:

- `crash reproduction` (`trigger`) anchored to runtime evidence;
- `crash diagnosis` (`diagnose`) anchored to the sanitizer/error section;
- `remediation` anchored to the patch section.

The runtime error artifact is `harness_observed`; description and patch are
`source_documented`. These statuses describe provenance, not exploit success.
No command or script is executed.

The manifest also records deterministic evidence completeness:
description/runtime/patch booleans, a complete-triple flag, and count `3`. The
value is a provenance/display and future ranking tie-breaker—not a confidence or
exploitability score. This selective import requires the full triple; incomplete
or low-information records are not silently promoted into ordinary personal
search results.

### Operator-value example: `arvo:10841`

The librawspeed record illustrates why a complete triple is useful even without
a CVE or exploit claim:

- the description identifies the violated invariant: PhaseOne strip rows were
  assumed valid;
- the MSAN report shows uninitialized image-row data flowing through
  `RawImageData::checkRowIsInitialized`;
- the patch adds `validateStrips()`, enforcing one strip per row, row bounds,
  and duplicate-row rejection.

This becomes reusable invariant-validation, sanitizer-triage, and remediation
knowledge for parser/decoder testing. It does not establish RCE, exploitability,
or a CVE, and the adapter must not manufacture those fields.

## Normalized document

One managed bundle per task contains:

```text
manifest.json
document.md
artifacts/description.txt
artifacts/error.txt
artifacts/patch.diff
```

The document includes source metadata, vulnerability description, a fenced
runtime report, parsed deterministic facts, and a fenced patch. It remains
searchable by task/project/sanitizer/summary/dedup token/function/path/patch
context. Generated files are adapter-owned and hash-verified.
