# Research knowledge architecture

## Boundary

Research sources are untrusted, versioned inputs. Source-specific adapters will
produce a normalized bundle; only the normalized bundle crosses into the common
indexer. No adapter writes the production database, and no read-side MCP tool
executes an imported artifact.

```text
pinned source -> adapter -> normalized bundle -> candidate database -> read-only MCP
```

The retained product state is Git-tracked code/documentation plus `vault.db`.
Downloaded repositories, datasets, extraction trees, and generated candidate
files remain disposable.

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

`document_snapshots` is the durable context mechanism for promoted research
records. Snapshot write/read and hash verification will be added with bundle
ingestion; the Phase 1 migration only establishes its constrained storage.
Personal writeups retain their path-backed freshness behavior.

## Compatibility

- Normal read-side clients may filter for `research` after Phase 1.
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
