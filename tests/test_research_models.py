"""Validation and serialized-contract coverage for normalized research bundles."""

import json
from pathlib import Path
import re

import pytest
from pydantic import HttpUrl, TypeAdapter, ValidationError

from command_vault.models import (
    AssertionProvenance,
    EvidenceRole,
    OperationalStageClass,
    ResearchArtifact,
    ResearchManifest,
    ResearchSource,
    ResearchVulnerability,
    SourceCollectionKind,
    StageRelation,
    ValidationStatus,
    WriteupType,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/research-bundle-v1.schema.json"
ENUM_VALUES = {
    SourceCollectionKind: ["personal-writeup", "history", "benchmark", "research"],
    AssertionProvenance: ["source", "deterministic", "curated", "inferred"],
    ValidationStatus: [
        "unknown", "not_tested", "source_documented", "syntax_checked",
        "harness_observed", "reproduced_local", "operator_confirmed",
        "observed_execution", "failed", "stale",
    ],
    EvidenceRole: ["prerequisite", "procedure", "signal", "outcome", "mitigation", "remediation"],
    OperationalStageClass: ["reach", "trigger", "diagnose", "primitive", "control", "objective", "remediation"],
    StageRelation: ["requires", "enables", "blocks", "mitigates", "subsumes"],
}
UNSAFE_PATHS = [
    "", "/", "/report.md", "//host/report.md", "a//b", "a/", ".", "..",
    "./a", "../a", "a/./b", "a/../b", "a/.", "a/..", "a\\b",
    "C:\\report.md", "a\x00b", "a/\x00", "a\n/../b", "a/../b\n",
    "a\tb", "a\nb", "a\rb", "a\x7fb", "report.md\n", "..\n",
    "a/\t/b", "a/\r/b", "a/\x7f/b",
]
SAFE_PATHS = [
    "report.md", "notes/report.md", ".hidden", "a/.hidden", "..hidden",
    "...", "a/.../b", "a..", "two words/report.md", "résumé.md",
]


@pytest.fixture
def source_data():
    return {"name": "Example research", "revision": "rev-001", "upstream_url": "https://example.org/research"}


@pytest.fixture
def manifest_data(source_data):
    return {"schema_version": 1, "source": source_data, "external_id": "record-001", "domain": "software"}


def test_illustrative_manifest_round_trip(manifest_data):
    manifest_data.update({
        "project": "Example project", "language": "C", "document_kind": "research-note",
        "vulnerability": {
            "canonical_id": "CWE-125", "class": "out-of-bounds read",
            "class_provenance": "source", "sanitizer": "address",
            "architecture": "x86_64", "platform": "linux", "subsystem": "parser",
            "summary": "Illustrative source metadata.",
        },
        "artifacts": [{
            "path": "notes/analysis.md", "kind": "analysis", "role": "signal",
            "validation": "source_documented", "sha256": "a" * 64,
            "media_type": "text/markdown", "language": "markdown", "license_expression": None,
        }],
    })
    manifest = ResearchManifest.model_validate(manifest_data)
    dumped = manifest.model_dump()
    assert isinstance(dumped["source"]["upstream_url"], str)
    assert dumped["vulnerability"]["class"] == "out-of-bounds read"
    assert "vulnerability_class" not in dumped["vulnerability"]
    assert dumped == manifest.model_dump(by_alias=True)
    assert ResearchManifest.model_validate(dumped) == manifest
    assert ResearchManifest.model_validate_json(manifest.model_dump_json()) == manifest
    assert json.loads(manifest.model_dump_json())["artifacts"][0]["validation"] == "source_documented"
    assert dumped["source"]["license_expression"] is None
    assert dumped["artifacts"][0]["license_expression"] is None


def test_vulnerability_accepts_python_name_and_serializes_alias():
    model = ResearchVulnerability(vulnerability_class="example", class_provenance="curated")
    assert model.model_dump()["class"] == "example"
    assert model.model_dump(by_alias=False)["vulnerability_class"] == "example"
    assert json.loads(model.model_dump_json())["class"] == "example"


def test_research_writeup_type_preserves_current_values():
    assert [item.value for item in WriteupType] == ["box", "challenge", "sherlock", "research"]
    assert WriteupType("research") is WriteupType.RESEARCH


@pytest.mark.parametrize("enum_type,values", ENUM_VALUES.items())
def test_enum_values(enum_type, values):
    assert [item.value for item in enum_type] == values
    assert all(isinstance(item, str) for item in enum_type)


@pytest.mark.parametrize("path", UNSAFE_PATHS)
def test_unsafe_artifact_paths(path):
    with pytest.raises(ValidationError):
        ResearchArtifact(path=path, kind="note", role="signal")


@pytest.mark.parametrize("path", SAFE_PATHS)
def test_safe_artifact_paths(path):
    assert ResearchArtifact(path=path, kind="note", role="signal").path == path


@pytest.mark.parametrize("codepoint", [*range(32), 127])
def test_every_ascii_control_character_is_rejected(codepoint):
    pattern = json.loads(SCHEMA_PATH.read_text())["$defs"]["ResearchArtifact"]["properties"]["path"]["pattern"]
    for path in (chr(codepoint) + "note.md", "notes/" + chr(codepoint) + "/report.md", "note.md" + chr(codepoint)):
        with pytest.raises(ValidationError):
            ResearchArtifact(path=path, kind="note", role="signal")
        assert re.search(pattern, path) is None


@pytest.mark.parametrize("field", ["upstream_url", "homepage", "repository_url"])
@pytest.mark.parametrize("url", ["ftp://example.org/file", "file:///tmp/note", "javascript:alert(1)", "not-a-url", "https://", ""])
def test_bad_urls(source_data, field, url):
    with pytest.raises(ValidationError):
        ResearchSource(**{**source_data, field: url})


@pytest.mark.parametrize("field", ["upstream_url", "homepage", "repository_url"])
@pytest.mark.parametrize("url", [
    "http://example.org/notes", "https://example.org/notes",
    "https://example.org:8443/notes", "http://[::1]:8080/notes",
    "https://example.org/@notes?author=a@example.org#review@example.org",
])
def test_http_urls_are_serialized_strings(source_data, field, url):
    model = ResearchSource(**{**source_data, field: url})
    assert model.model_dump()[field] == url
    assert json.loads(model.model_dump_json())[field] == url
    properties = json.loads(SCHEMA_PATH.read_text())["$defs"]["ResearchSource"]["properties"]
    constraint = properties[field] if field == "upstream_url" else properties[field]["anyOf"][0]
    assert re.search(constraint["pattern"], url) is not None


@pytest.mark.parametrize("field", ["upstream_url", "homepage", "repository_url"])
@pytest.mark.parametrize("url", [
    "https://user:pass@example.org/x", "https://token@example.org/x",
    "http://user:pass@example.org/x", "https://:pass@example.org/x",
    "https://user:@example.org/x", "https://@example.org/x",
    "https://user%40mail:pass%3Aword@example.org/x",
])
def test_url_userinfo_rejected_by_model_and_schema(source_data, field, url):
    with pytest.raises(ValidationError, match="must not contain userinfo"):
        ResearchSource(**{**source_data, field: url})
    properties = json.loads(SCHEMA_PATH.read_text())["$defs"]["ResearchSource"]["properties"]
    constraint = properties[field] if field == "upstream_url" else properties[field]["anyOf"][0]
    assert re.search(constraint["pattern"], url) is None


@pytest.mark.parametrize("field", ["upstream_url", "homepage", "repository_url"])
def test_prevalidated_url_objects_cannot_bypass_userinfo_rejection(source_data, field):
    with pytest.raises(ValidationError, match="must not contain userinfo"):
        ResearchSource(**{**source_data, field: HttpUrl("https://token@example.org/x")})


@pytest.mark.parametrize("sha256", ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 64 + "\n"])
def test_bad_sha256(sha256):
    with pytest.raises(ValidationError):
        ResearchArtifact(path="note.md", kind="note", role="signal", sha256=sha256)


@pytest.mark.parametrize("version", [0, 2, -1, "1", None, 1.5])
def test_bad_schema_version(manifest_data, version):
    with pytest.raises(ValidationError):
        ResearchManifest.model_validate({**manifest_data, "schema_version": version})


@pytest.mark.parametrize("field", ["name", "revision"])
def test_source_requires_nonempty_fields(source_data, field):
    with pytest.raises(ValidationError):
        ResearchSource(**{**source_data, field: ""})


@pytest.mark.parametrize("field", ["external_id", "domain"])
def test_manifest_requires_nonempty_fields(manifest_data, field):
    with pytest.raises(ValidationError):
        ResearchManifest.model_validate({**manifest_data, field: ""})


def test_artifact_requires_nonempty_kind():
    with pytest.raises(ValidationError):
        ResearchArtifact(path="note.md", kind="", role="signal")


def test_extra_fields_forbidden_at_every_object(manifest_data, source_data):
    cases = [
        (ResearchManifest, manifest_data), (ResearchSource, source_data),
        (ResearchVulnerability, {}),
        (ResearchArtifact, {"path": "note.md", "kind": "note", "role": "signal"}),
    ]
    for model_type, data in cases:
        with pytest.raises(ValidationError, match="extra_forbidden"):
            model_type.model_validate({**data, "unexpected": "value"})
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ResearchManifest.model_validate({**manifest_data, "source": {**source_data, "unexpected": True}})


def test_defaults_are_independent_and_do_not_claim_validation_or_license(manifest_data):
    first = ResearchManifest.model_validate(manifest_data)
    second = ResearchManifest.model_validate(manifest_data)
    artifact = ResearchArtifact(path="note.md", kind="note", role="signal")
    first.artifacts.append(artifact)
    assert second.artifacts == []
    assert first.artifacts is not second.artifacts
    assert ResearchManifest.model_fields["artifacts"].default_factory is list
    assert artifact.validation is ValidationStatus.UNKNOWN
    assert artifact.sha256 is None
    assert artifact.license_expression is None
    assert first.source.license_expression is None
    assert first.vulnerability is None


def test_committed_schema_matches_pydantic_serialized_contract():
    committed = json.loads(SCHEMA_PATH.read_text())
    assert committed.pop("$schema") == "https://json-schema.org/draft/2020-12/schema"
    assert committed.pop("$id") == "urn:command-vault:research-bundle:v1"
    for enum_type in (SourceCollectionKind, OperationalStageClass, StageRelation):
        assert committed["$defs"].pop(enum_type.__name__) == TypeAdapter(enum_type).json_schema()
    assert committed == ResearchManifest.model_json_schema(mode="serialization", by_alias=True)


def test_schema_constraints_cover_paths_enums_urls_and_null_licenses():
    schema = json.loads(SCHEMA_PATH.read_text())
    for enum_type, values in ENUM_VALUES.items():
        assert schema["$defs"][enum_type.__name__]["enum"] == values
    for name in ("ResearchSource", "ResearchVulnerability", "ResearchArtifact"):
        assert schema["$defs"][name]["additionalProperties"] is False
    assert schema["additionalProperties"] is False
    artifact = schema["$defs"]["ResearchArtifact"]["properties"]
    for path in UNSAFE_PATHS:
        assert re.search(artifact["path"]["pattern"], path) is None
    for path in SAFE_PATHS:
        assert re.search(artifact["path"]["pattern"], path) is not None
    digest = artifact["sha256"]["anyOf"][0]
    assert digest["pattern"] == "^[0-9a-f]{64}$"
    assert digest["minLength"] == digest["maxLength"] == 64
    source = schema["$defs"]["ResearchSource"]["properties"]
    for field in ("upstream_url", "homepage", "repository_url"):
        url = source[field] if field == "upstream_url" else source[field]["anyOf"][0]
        assert url["format"] == "uri"
        assert url["pattern"] == r"^https?://[^/?#@]+(?:[/?#]|$)"
    for properties in (source, artifact):
        assert properties["license_expression"]["default"] is None
        assert {"type": "null"} in properties["license_expression"]["anyOf"]
