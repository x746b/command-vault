# Research knowledge architecture

## Boundary

Research sources are untrusted, versioned inputs. Source-specific adapters will
produce a normalized bundle; only the normalized bundle crosses into the common
indexer. No adapter writes the production database, and no read-side MCP tool
executes an imported artifact.

```text
pinned source -> adapter -> normalized bundle -> candidate database -> read-only MCP
```

The retained product state is Git-tracked code/documentation, `vault.db`, and
the managed normalized research tree. Downloaded repositories, raw datasets,
extraction trees, and generated candidate files remain disposable.

### Hybrid source authority

Command-vault intentionally uses three authority modes:

- Personal material beneath `~/writeups` remains file-authoritative and
  path-backed. Freshness compares the current file with its indexed revision.
- Imported framework research is adapter-owned under
  `$WRITEUPS_RESEARCH/{exploitgym,cybergym,exploitbench}`. A
  hash-matching managed document is the primary full-document source; the
  embedded database snapshot is its verified fallback. Upstream checkouts and
  `/tmp` staging can be removed after preservation gates pass.
- Project architecture, migration, source-lock, security, and import
  documentation is Git-authoritative in
  `docs/research-knowledge/`.

These modes must not be silently substituted. A missing personal file reports
unavailable; changed managed research fails integrity checks; a missing managed
research file falls back to its verified snapshot; and operational documentation
changes follow normal Git review.

### Managed routing and duplicate prevention

`WRITEUPS_RESEARCH="$WRITEUPS/research"` identifies the managed bundle
root. Dedicated manifest-driven research ingestion walks its source children.
If the general `WRITEUPS="$HOME/writeups"` root contains that tree, the legacy
Markdown scanner excludes the resolved managed subtree before recursive
discovery. This prevents the same generated `document.md` from being indexed a
second time and misclassified as a box/challenge/Sherlock writeup.

When `WRITEUPS_RESEARCH` is absent, an existing canonical `<WRITEUPS>/research`
directory is detected automatically. The legacy indexer independently excludes
that nested path and recognizes every Markdown path beneath a directory with a
bundle `manifest.json` before parsing, including documents and artifacts under
custom administrative roots. Direct legacy ingestion of a managed file is
refused. These layers prevent a
simple `vault index --add` from replacing structured research rows with legacy
writeup records.

The exclusion is path-aware: resolve both roots, require the managed root to be
inside the general root before excluding it, and do not use a textual-prefix
test. Generated managed files are updated only by reviewed adapters and verified
against their manifests; operators do not hand-edit them.

## Normalized bundle v1

A bundle is a directory containing:

```text
manifest.json
document.md
artifacts/<safe relative paths>
```

`schemas/research-bundle-v1.schema.json` and the strict Pydantic
`ResearchManifest` model define the same serialized contract. The contract:

- forbids unknown object fields;
- requires an explicit source revision, HTTP(S) provenance URL, external ID,
  and domain;
- keeps unknown licenses null;
- distinguishes source, deterministic, curated, and inferred assertions;
- distinguishes documentation, syntax, harness, local, and operator validation;
- rejects absolute paths, traversal segments, backslashes, NUL, and other ASCII
  control characters in artifact paths;
- permits only lowercase 64-character SHA-256 values when an artifact digest is
  supplied.

Adapters must not silently transform an upstream assertion into a source fact.
Raw labels and normalized values remain distinguishable through provenance.

The common loader anchors reads to the bundle directory, refuses symlinks and
non-regular files, bounds individual and aggregate content, validates supplied
digests, and returns the verified artifact bytes. Consumers use those retained
bytes instead of reopening a provenance path that may have changed after
validation. The snapshot codec bounds decompression and verifies the recorded
UTF-8 byte count and SHA-256 before returning context.

## SQLite schema v2

Schema v2 is additive to the 0.9 schema. Existing writeups, commands, scripts,
chunks, history, tools, tags, and explicit technique links remain first-class.
The extension adds:

- source collections and research document identity;
- compressed document snapshots;
- vulnerabilities and vulnerability FTS;
- operational stages, aliases, and directed relations;
- evidence links to exactly one command, script, or chunk;
- mitigation relations and validation observations;
- exact and conservative-normalized artifact hashes.

The graph is deliberately not a universal exploit ladder. `domain` allows a
kernel primitive, web precondition, AD control edge, and DFIR diagnostic stage
to coexist without claiming they have the same sequence.

`document_snapshots` is the verified fallback context mechanism for promoted
research records. The managed normalized document is preferred when its hash
matches the indexed revision. Personal writeups retain their path-backed
freshness behavior without snapshot fallback.

Research snapshot export is intentionally out of scope. Recovery retains the
managed normalized corpus and embedded database fallback, with public upstream
URL/revision metadata and deterministic adapters available for reacquisition.

Reindexing an existing managed identity preserves unambiguous public child IDs:
chunk identity is `(chunk_index, section)`, script identity is its declared
artifact source section, and a sole document vulnerability keeps its profile
ID. Evidence and validation rows are rebuilt transactionally around those
stable navigation IDs. Ambiguous old children are never guessed or reused.

## Compatibility

- Schema-v2 read-side clients may filter for `research`.
- The legacy Markdown indexer remains limited to box, challenge, and Sherlock
  sources. It cannot relabel arbitrary Markdown as research.
- A read-only application connection never migrates a database.
- A writable administrative/candidate connection migrates v0 to v1 and then v1
  to v2.
- A database newer than the application's current schema is rejected.
- The migration preserves a deployed legacy `technique_aliases` table by
  rebuilding it into the normalized v2 shape in the same transaction. A
  normalization collision aborts the migration instead of dropping an alias.

## Trust and authority

Validation strength is an evidence attribute, not a truth probability. Search
ranking may use it as a modest tie-breaker only. Shell-history presence is
`observed_execution`, never proof of success. Unknown versions, licenses,
mitigations, and outcomes remain unknown.

There is no age-based deletion cutoff for exploitation knowledge. Accepted
records retain explicit dates and source/tool/affected/patch versions; an absent
current/fixed/superseded/stale statement is `temporal_status: unknown`.
Recency-aware ranking may later break otherwise comparable ties, but it must not
hide older records, override provenance or validation strength, or affect exact
identifier and structured-filter retrieval.
