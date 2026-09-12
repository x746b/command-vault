# Sanitized research source-shape fixtures

These fixtures preserve only representative metadata shapes observed at the
pinned revisions in `docs/research-knowledge/SOURCES.lock.json`. They contain no
exploit implementation, generated flag, credential, private endpoint, model
reasoning, or executable payload.

They are test inputs, not authoritative security classifications. Future source
adapters must preserve explicit upstream fields separately from deterministic or
curated derived fields.

The `exploitgym/` tree mirrors the relevant kernelCTF metadata/document layout
with a fictional CVE and nonfunctional C fixture. It is used for adapter and
candidate-ingestion tests without distributing an upstream exploit.

The `cybergym/` tree contains one fictional sanitizer report and patch in the
selective-text dataset layout. It contains no repository archive or executable
artifact.
