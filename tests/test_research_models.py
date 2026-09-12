"""Validation and serialized-contract coverage for normalized research bundles."""

import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path
import re

import pytest
from pydantic import HttpUrl, TypeAdapter, ValidationError

from command_vault.models import (
    AssertionProvenance,
    EvidenceRole,
    MitigationState,
    OperationalStageClass,
    ResearchArtifact,
    ResearchJsonValue,
    ResearchManifest,
    ResearchMitigation,
    ResearchOperationalStage,
    ResearchSource,
    ResearchVulnerability,
    SourceCollectionKind,
    StageRelation,
    ValidationStatus,
    VaultStats,
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
    MitigationState: ["enabled", "disabled", "bypassed", "required", "discussed", "unknown"],
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
            "summary_provenance": "source",
        },
        "artifacts": [{
            "path": "notes/analysis.md", "kind": "analysis", "role": "signal",
            "validation": "source_documented", "sha256": "a" * 64,
            "media_type": "text/markdown", "language": "markdown", "license_expression": None,
        }],
        "source_path": "records/example/task.json",
        "source_metadata": {"labels": ["example", None], "details": {"count": 1, "score": 0.5, "active": True}},
        "operational_stages": [{
            "canonical_name": "analysis", "stage_class": "diagnose",
            "assertion_provenance": "deterministic", "description": "A mapped heading.",
            "validation_status": "source_documented",
            "matched_alias": "Analysis", "evidence_sections": ["Overview", "Analysis"],
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
    assert dumped["source_path"] == manifest_data["source_path"]
    assert dumped["source_metadata"] == manifest_data["source_metadata"]
    assert dumped["operational_stages"] == manifest_data["operational_stages"]
    assert dumped["vulnerability"]["summary_provenance"] == "source"


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
    for enum_type in (SourceCollectionKind, StageRelation):
        assert committed["$defs"].pop(enum_type.__name__) == TypeAdapter(enum_type).json_schema()
    assert committed == ResearchManifest.model_json_schema(mode="serialization", by_alias=True)


def test_schema_constraints_cover_paths_enums_urls_and_null_licenses():
    schema = json.loads(SCHEMA_PATH.read_text())
    for enum_type, values in ENUM_VALUES.items():
        assert schema["$defs"][enum_type.__name__]["enum"] == values
    for name in ("ResearchSource", "ResearchVulnerability", "ResearchArtifact", "ResearchOperationalStage", "ResearchMitigation"):
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


@pytest.fixture
def stage_data():
    return {
        "canonical_name": "analysis", "stage_class": "diagnose", "matched_alias": "Analysis",
        "assertion_provenance": "deterministic",
    }


@pytest.mark.parametrize("sections", [[""], ["Overview", ""], ["Overview", "Overview"], [None], [1], "Overview"])
def test_invalid_evidence_sections(stage_data, sections):
    with pytest.raises(ValidationError):
        ResearchOperationalStage(**stage_data, evidence_sections=sections)


@pytest.mark.parametrize("field,value", [
    ("canonical_name", ""), ("matched_alias", ""), ("stage_class", "unknown"),
    ("assertion_provenance", "unknown"), ("assertion_provenance", None),
    ("unexpected", "value"),
])
def test_invalid_operational_stage_fields(stage_data, field, value):
    with pytest.raises(ValidationError):
        ResearchOperationalStage(**{**stage_data, field: value})


def test_operational_stage_requires_assertion_provenance(stage_data):
    del stage_data["assertion_provenance"]
    with pytest.raises(ValidationError, match="assertion_provenance"):
        ResearchOperationalStage(**stage_data)


def test_operational_stage_validation_default_round_trip_and_schema(stage_data, manifest_data):
    stage = ResearchOperationalStage(**stage_data)
    assert stage.validation_status is ValidationStatus.SOURCE_DOCUMENTED
    assert stage.model_dump(mode='json')['validation_status'] == 'source_documented'
    manifest = ResearchManifest(**manifest_data, operational_stages=[{**stage_data, 'validation_status': 'harness_observed'}])
    restored = ResearchManifest.model_validate_json(manifest.model_dump_json())
    assert restored.operational_stages[0].validation_status is ValidationStatus.HARNESS_OBSERVED
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema['$defs']['ResearchOperationalStage']['properties']['validation_status'] == {
        '$ref': '#/$defs/ValidationStatus', 'default': 'source_documented',
    }


@pytest.mark.parametrize('value', ['invented-success', None, 1])
def test_operational_stage_invalid_validation_status(stage_data, value):
    with pytest.raises(ValidationError, match='validation_status'):
        ResearchOperationalStage(**stage_data, validation_status=value)


@pytest.mark.parametrize("overrides", [{}, {"description": "Different description"}, {"evidence_sections": ["Different"]}, {"stage_class": "objective"}])
def test_duplicate_stage_pairs_rejected(manifest_data, stage_data, overrides):
    with pytest.raises(ValidationError, match="pairs must be unique"):
        ResearchManifest(**manifest_data, operational_stages=[stage_data, {**stage_data, **overrides}])


def test_evidence_sections_and_distinct_stage_pairs_preserve_order(manifest_data, stage_data):
    stages = [
        {**stage_data, "evidence_sections": ["Z", "A"]},
        {**stage_data, "matched_alias": "Review"},
        {**stage_data, "canonical_name": "review"},
    ]
    manifest = ResearchManifest(**manifest_data, operational_stages=stages)
    assert [(s.canonical_name, s.matched_alias) for s in manifest.operational_stages] == [
        ("analysis", "Analysis"), ("analysis", "Review"), ("review", "Analysis"),
    ]
    assert manifest.operational_stages[0].evidence_sections == ["Z", "A"]
    assert ResearchManifest.model_validate_json(manifest.model_dump_json()) == manifest


@pytest.mark.parametrize("path", UNSAFE_PATHS)
def test_unsafe_source_paths(manifest_data, path):
    with pytest.raises(ValidationError):
        ResearchManifest(**manifest_data, source_path=path)


@pytest.mark.parametrize("codepoint", [*range(32), 127])
def test_source_path_rejects_all_ascii_controls(manifest_data, codepoint):
    with pytest.raises(ValidationError):
        ResearchManifest(**manifest_data, source_path="notes/" + chr(codepoint) + "file.json")


@pytest.mark.parametrize("path", [None, *SAFE_PATHS])
def test_safe_source_paths(manifest_data, path):
    assert ResearchManifest(**manifest_data, source_path=path).source_path == path


@pytest.mark.parametrize("value", [
    (1, 2), {1, 2}, frozenset({1}), b"bytes", Decimal("1.5"), datetime(2026, 1, 1),
    Path("notes.md"), object(), float("nan"), float("inf"), float("-inf"),
    {1: "value"}, {b"key": "value"},
])
def test_source_metadata_rejects_non_json_recursive_values(manifest_data, value):
    for metadata in ({"value": value}, {"nested": [{"value": value}]}):
        with pytest.raises(ValidationError):
            ResearchManifest(**manifest_data, source_metadata=metadata)


@pytest.mark.parametrize("metadata", [None, [], [("key", "value")], {1: "value"}, {b"key": "value"}])
def test_source_metadata_requires_json_object(manifest_data, metadata):
    with pytest.raises(ValidationError):
        ResearchManifest(**manifest_data, source_metadata=metadata)


def test_new_collection_defaults_are_independent(manifest_data, stage_data):
    first = ResearchManifest(**manifest_data)
    second = ResearchManifest(**manifest_data)
    first.source_metadata["extra"] = {"values": [1]}
    first.operational_stages.append(ResearchOperationalStage(**stage_data))
    first.operational_stages[0].evidence_sections.append("Overview")
    other_stage = ResearchOperationalStage(**stage_data)
    assert second.source_metadata == {}
    assert second.operational_stages == []
    assert other_stage.evidence_sections == []
    assert second.source_path is None
    assert ResearchManifest.model_fields["source_metadata"].default_factory is dict
    assert ResearchManifest.model_fields["operational_stages"].default_factory is list
    assert ResearchOperationalStage.model_fields["evidence_sections"].default_factory is list


@pytest.mark.parametrize("provenance", [None, *AssertionProvenance])
def test_summary_provenance_round_trip(provenance):
    vulnerability = ResearchVulnerability(summary="Source summary", summary_provenance=provenance)
    assert ResearchVulnerability.model_validate_json(vulnerability.model_dump_json()) == vulnerability
    assert vulnerability.summary_provenance == provenance


def test_unknown_summary_provenance_is_rejected():
    with pytest.raises(ValidationError):
        ResearchVulnerability(summary_provenance="invented")


def test_extended_schema_constraints():
    schema = json.loads(SCHEMA_PATH.read_text())
    properties = schema["properties"]
    source_path = properties["source_path"]["anyOf"][0]
    artifact_path = schema["$defs"]["ResearchArtifact"]["properties"]["path"]
    assert source_path == {key: value for key, value in artifact_path.items() if key != "title"}
    assert properties["source_metadata"]["type"] == "object"
    assert properties["source_metadata"]["additionalProperties"] == {"$ref": "#/$defs/JsonValue"}
    stage = schema["$defs"]["ResearchOperationalStage"]
    assert stage["additionalProperties"] is False
    assert "assertion_provenance" in stage["required"]
    assert stage["properties"]["evidence_sections"]["uniqueItems"] is True
    assert stage["properties"]["evidence_sections"]["items"]["minLength"] == 1
    assert properties["operational_stages"]["uniqueItems"] is True
    assert "(canonical_name, matched_alias)" in properties["operational_stages"]["description"]
    assert properties["schema_version"]["const"] == 1


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_json_value_schema_is_explicit_recursive_and_reusable(mode):
    reference = {"$ref": "#/$defs/JsonValue"}
    expected = {
        "anyOf": [
            {"type": "null"}, {"type": "boolean"}, {"type": "integer"},
            {"type": "number"}, {"type": "string"},
            {"type": "array", "items": reference},
            {"type": "object", "additionalProperties": reference},
        ],
    }
    committed = json.loads(SCHEMA_PATH.read_text())
    assert committed["$defs"]["JsonValue"] == expected
    assert committed["$defs"]["JsonValue"] != {}
    model_schema = ResearchManifest.model_json_schema(mode=mode)
    assert model_schema["$defs"]["JsonValue"] == expected
    reusable_schema = TypeAdapter(dict[str, ResearchJsonValue]).json_schema(mode=mode)
    assert reusable_schema["$defs"]["JsonValue"] == expected
    assert reusable_schema["additionalProperties"] == reference


def test_vault_stats_optional_research_totals():
    base = {"writeups": {}, "commands": {}, "scripts": {}, "tools": {}}
    assert VaultStats(**base).research is None
    research = {"sources": 2, "records": 3}
    dumped = VaultStats(**base, research=research).model_dump()
    assert dumped["research"] == research
    assert all(dumped[key] == value for key, value in base.items())


@pytest.fixture
def mitigation_data():
    return {
        "canonical_name": "Example mitigation", "raw_label": "Example source label",
        "state": "discussed", "assertion_provenance": "source",
        "evidence_sections": ["Overview", "Source observations"],
    }


@pytest.mark.parametrize("state", list(MitigationState))
def test_mitigation_states_round_trip_with_evidence_and_provenance(manifest_data, mitigation_data, state):
    mitigation_data["state"] = state.value
    manifest = ResearchManifest(**manifest_data, mitigations=[mitigation_data])
    assert manifest.mitigations[0].state is state
    assert manifest.mitigations[0].assertion_provenance is AssertionProvenance.SOURCE
    assert manifest.model_dump(mode="json", by_alias=True)["mitigations"] == [mitigation_data]
    assert ResearchManifest.model_validate_json(manifest.model_dump_json()) == manifest


@pytest.mark.parametrize("field", ["canonical_name", "raw_label", "state", "assertion_provenance", "evidence_sections"])
def test_mitigation_requires_every_evidence_and_assertion_field(mitigation_data, field):
    del mitigation_data[field]
    with pytest.raises(ValidationError, match=field):
        ResearchMitigation(**mitigation_data)


@pytest.mark.parametrize("value", ["", " ", "\t\n", "\u2003", "\u00a0"])
@pytest.mark.parametrize("field", ["canonical_name", "raw_label", "evidence_sections"])
def test_mitigation_rejects_blank_labels_and_evidence(mitigation_data, field, value):
    mitigation_data[field] = [value] if field == "evidence_sections" else value
    with pytest.raises(ValidationError):
        ResearchMitigation(**mitigation_data)


@pytest.mark.parametrize("sections", [[], None, "Overview", [None], [1], ["Overview", "Overview"]])
def test_mitigation_rejects_missing_invalid_or_duplicate_evidence(mitigation_data, sections):
    with pytest.raises(ValidationError):
        ResearchMitigation(**{**mitigation_data, "evidence_sections": sections})


@pytest.mark.parametrize("field,value", [
    ("state", "unverified"), ("state", None), ("assertion_provenance", "assumed"),
    ("assertion_provenance", None), ("unexpected", "value"),
])
def test_mitigation_rejects_unknown_state_provenance_and_fields(mitigation_data, field, value):
    with pytest.raises(ValidationError):
        ResearchMitigation(**{**mitigation_data, field: value})


@pytest.mark.parametrize("name", ["Example mitigation", "EXAMPLE MITIGATION", " example   mitigation ", "Example\tmitigation"])
def test_mitigation_canonical_names_are_unique_after_normalization(manifest_data, mitigation_data, name):
    with pytest.raises(ValidationError, match="canonical names must be unique"):
        ResearchManifest(**manifest_data, mitigations=[
            mitigation_data, {**mitigation_data, "canonical_name": name, "raw_label": "Another label", "state": "unknown"},
        ])


def test_mitigation_preserves_original_text_order_and_other_fields(manifest_data, mitigation_data):
    first = {**mitigation_data, "canonical_name": " Zeta   mitigation ", "raw_label": " Label with spaces ",
             "evidence_sections": [" Z section ", "A section"]}
    second = {**mitigation_data, "canonical_name": "Alpha mitigation"}
    manifest = ResearchManifest(**{**manifest_data, "project": "  unchanged  "}, mitigations=[first, second])
    assert manifest.model_dump(mode="json")["mitigations"] == [first, second]
    assert manifest.project == "  unchanged  "


def test_mitigation_collection_defaults_are_independent(manifest_data, mitigation_data):
    first = ResearchManifest(**manifest_data)
    second = ResearchManifest(**manifest_data)
    first.mitigations.append(ResearchMitigation(**mitigation_data))
    assert second.mitigations == []
    assert ResearchManifest.model_fields["mitigations"].default_factory is list
    assert ResearchMitigation.model_fields["evidence_sections"].is_required()


def test_mitigation_schema_constraints_are_explicit():
    schema = json.loads(SCHEMA_PATH.read_text())
    model = schema["$defs"]["ResearchMitigation"]
    assert model["additionalProperties"] is False
    assert set(model["required"]) == {"canonical_name", "raw_label", "state", "assertion_provenance", "evidence_sections"}
    assert schema["$defs"]["MitigationState"]["enum"] == ENUM_VALUES[MitigationState]
    assert model["properties"]["state"] == {"$ref": "#/$defs/MitigationState"}
    assert model["properties"]["assertion_provenance"] == {"$ref": "#/$defs/AssertionProvenance"}
    evidence = model["properties"]["evidence_sections"]
    assert evidence["minItems"] == 1 and evidence["uniqueItems"] is True
    assert evidence["items"] == {"minLength": 1, "pattern": r"\S", "type": "string"}
    for field in ("canonical_name", "raw_label"):
        assert model["properties"][field]["minLength"] == 1
        assert model["properties"][field]["pattern"] == r"\S"
    mitigations = schema["properties"]["mitigations"]
    assert mitigations["uniqueItems"] is True
    assert "case folding" in mitigations["description"]
    assert schema["properties"]["schema_version"]["const"] == 1
