"""Pydantic models for Command Vault."""

from pydantic import (
    BaseModel, ConfigDict, Field, HttpUrl, JsonValue, TypeAdapter, WrapValidator,
    field_serializer, field_validator,
)
from typing import Annotated, Literal, Optional
from enum import Enum
import re
from urllib.parse import urlsplit


class WriteupType(str, Enum):
    BOX = "box"
    CHALLENGE = "challenge"
    SHERLOCK = "sherlock"
    RESEARCH = "research"


class SourceCollectionKind(str, Enum):
    PERSONAL_WRITEUP = "personal-writeup"
    HISTORY = "history"
    BENCHMARK = "benchmark"
    RESEARCH = "research"


class AssertionProvenance(str, Enum):
    SOURCE = "source"
    DETERMINISTIC = "deterministic"
    CURATED = "curated"
    INFERRED = "inferred"


class ValidationStatus(str, Enum):
    UNKNOWN = "unknown"
    NOT_TESTED = "not_tested"
    SOURCE_DOCUMENTED = "source_documented"
    SYNTAX_CHECKED = "syntax_checked"
    HARNESS_OBSERVED = "harness_observed"
    REPRODUCED_LOCAL = "reproduced_local"
    OPERATOR_CONFIRMED = "operator_confirmed"
    OBSERVED_EXECUTION = "observed_execution"
    FAILED = "failed"
    STALE = "stale"


class EvidenceRole(str, Enum):
    PREREQUISITE = "prerequisite"
    PROCEDURE = "procedure"
    SIGNAL = "signal"
    OUTCOME = "outcome"
    MITIGATION = "mitigation"
    REMEDIATION = "remediation"


class OperationalStageClass(str, Enum):
    REACH = "reach"
    TRIGGER = "trigger"
    DIAGNOSE = "diagnose"
    PRIMITIVE = "primitive"
    CONTROL = "control"
    OBJECTIVE = "objective"
    REMEDIATION = "remediation"


class StageRelation(str, Enum):
    REQUIRES = "requires"
    ENABLES = "enables"
    BLOCKS = "blocks"
    MITIGATES = "mitigates"
    SUBSUMES = "subsumes"


class MitigationState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    BYPASSED = "bypassed"
    REQUIRED = "required"
    DISCUSSED = "discussed"
    UNKNOWN = "unknown"


# Segments may start with a non-dot, one dot followed by a non-dot, or
# two dots followed by another character. Exclude traversal segments,
# backslashes, and ASCII control characters throughout each segment.
_RESEARCH_PATH_SEGMENT = (
    r"(?:[^./\\\u0000-\u001f\u007f][^/\\\u0000-\u001f\u007f]*"
    r"|\.[^./\\\u0000-\u001f\u007f][^/\\\u0000-\u001f\u007f]*"
    r"|\.\.[^/\\\u0000-\u001f\u007f]+)"
)
# A portable strict-end assertion avoids JSON Schema's '$' matching before
# a final newline. Compile with Python for Pydantic's lookaround support.
_RESEARCH_PATH_PATTERN = re.compile(
    rf"^{_RESEARCH_PATH_SEGMENT}(?:/{_RESEARCH_PATH_SEGMENT})*(?![\s\S])"
)
_ResearchRelativePath = Annotated[str, Field(min_length=1, pattern=_RESEARCH_PATH_PATTERN)]


class _ResearchJsonValueSchema:
    """Expose JsonValue's recursive types instead of its unconstrained JSON schema."""

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        reference = handler(core_schema)
        definition = handler.resolve_ref_schema(reference)
        # Use the handler's reference so Pydantic can resolve and rename $defs
        # consistently, including when this annotation is reused elsewhere.
        definition.update({
            "anyOf": [
                {"type": "null"},
                {"type": "boolean"},
                {"type": "integer"},
                {"type": "number"},
                {"type": "string"},
                {"type": "array", "items": dict(reference)},
                {"type": "object", "additionalProperties": dict(reference)},
            ]
        })
        return reference


ResearchJsonValue = Annotated[JsonValue, _ResearchJsonValueSchema]
_RESEARCH_JSON_METADATA = TypeAdapter(
    dict[str, ResearchJsonValue], config=ConfigDict(strict=True, allow_inf_nan=False)
)
_RESEARCH_URL_PATTERN = r"^https?://[^/?#@]+(?:[/?#]|$)"


def _research_url_without_userinfo(value, handler) -> HttpUrl:
    parsed = handler(value)
    # Check normalized URLs as well as raw strings: normalization discards
    # empty userinfo, but the bundle contract excludes that syntax too.
    if (
        parsed.username is not None or parsed.password is not None
        or (isinstance(value, str) and "@" in urlsplit(value).netloc)
    ):
        raise ValueError("Research source URLs must not contain userinfo")
    return parsed


_ResearchHttpUrl = Annotated[
    HttpUrl,
    WrapValidator(_research_url_without_userinfo),
    Field(json_schema_extra={"pattern": _RESEARCH_URL_PATTERN}),
]


class _ResearchContract(BaseModel):
    model_config = ConfigDict(
        extra="forbid", populate_by_name=True, serialize_by_alias=True
    )


class ResearchSource(_ResearchContract):
    name: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    upstream_url: _ResearchHttpUrl
    homepage: Optional[_ResearchHttpUrl] = None
    repository_url: Optional[_ResearchHttpUrl] = None
    license_expression: Optional[str] = None

    @field_serializer("upstream_url", "homepage", "repository_url")
    def serialize_url(self, value):
        return str(value) if value is not None else None


class ResearchVulnerability(_ResearchContract):
    canonical_id: Optional[str] = None
    vulnerability_class: Optional[str] = Field(default=None, alias="class")
    class_provenance: Optional[AssertionProvenance] = None
    sanitizer: Optional[str] = None
    architecture: Optional[str] = None
    platform: Optional[str] = None
    subsystem: Optional[str] = None
    summary: Optional[str] = None
    summary_provenance: Optional[AssertionProvenance] = None


class ResearchArtifact(_ResearchContract):
    path: _ResearchRelativePath
    kind: str = Field(min_length=1)
    role: EvidenceRole
    validation: ValidationStatus = ValidationStatus.UNKNOWN
    sha256: Optional[str] = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    media_type: Optional[str] = None
    language: Optional[str] = None
    license_expression: Optional[str] = None


class ResearchOperationalStage(_ResearchContract):
    canonical_name: str = Field(min_length=1)
    stage_class: OperationalStageClass
    assertion_provenance: AssertionProvenance
    description: Optional[str] = None
    matched_alias: str = Field(min_length=1)
    evidence_sections: list[Annotated[str, Field(min_length=1)]] = Field(
        default_factory=list, json_schema_extra={"uniqueItems": True}
    )

    @field_validator("evidence_sections")
    @classmethod
    def unique_evidence_sections(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("Evidence sections must not contain duplicates")
        return value


class ResearchMitigation(_ResearchContract):
    canonical_name: str = Field(min_length=1, json_schema_extra={"pattern": r"\S"})
    raw_label: str = Field(min_length=1, json_schema_extra={"pattern": r"\S"})
    state: MitigationState
    assertion_provenance: AssertionProvenance
    evidence_sections: list[Annotated[str, Field(min_length=1, json_schema_extra={"pattern": r"\S"})]] = Field(
        min_length=1, json_schema_extra={"uniqueItems": True}
    )

    @field_validator("canonical_name", "raw_label")
    @classmethod
    def nonblank_labels(cls, value):
        if not value.strip():
            raise ValueError("Mitigation labels must contain non-whitespace text")
        return value

    @field_validator("evidence_sections")
    @classmethod
    def nonblank_unique_evidence_sections(cls, value):
        if any(not section.strip() for section in value):
            raise ValueError("Mitigation evidence sections must contain non-whitespace text")
        if len(value) != len(set(value)):
            raise ValueError("Mitigation evidence sections must not contain duplicates")
        return value


class ResearchManifest(_ResearchContract):
    schema_version: Literal[1]
    source: ResearchSource
    external_id: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    project: Optional[str] = None
    language: Optional[str] = None
    document_kind: Optional[str] = None
    vulnerability: Optional[ResearchVulnerability] = None
    artifacts: list[ResearchArtifact] = Field(default_factory=list)
    source_path: Optional[_ResearchRelativePath] = None
    source_metadata: dict[str, ResearchJsonValue] = Field(default_factory=dict)
    operational_stages: list[ResearchOperationalStage] = Field(
        default_factory=list,
        description=(
            "Stages in source order; each (canonical_name, matched_alias) pair must be unique. "
            "Pair uniqueness is enforced by the manifest validator."
        ),
        json_schema_extra={"uniqueItems": True},
    )
    mitigations: list[ResearchMitigation] = Field(
        default_factory=list,
        description=(
            "Mitigations in source order; canonical_name must be unique after trimming, "
            "collapsing whitespace, and case folding. Normalized canonical-name uniqueness "
            "is enforced by the manifest validator."
        ),
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("source_metadata", mode="before")
    @classmethod
    def strict_json_metadata(cls, value):
        return _RESEARCH_JSON_METADATA.validate_python(value)

    @field_validator("operational_stages")
    @classmethod
    def unique_operational_stages(cls, value):
        pairs = [(stage.canonical_name, stage.matched_alias) for stage in value]
        if len(pairs) != len(set(pairs)):
            raise ValueError("Operational stage (canonical_name, matched_alias) pairs must be unique")
        return value

    @field_validator("mitigations")
    @classmethod
    def unique_mitigation_names(cls, value):
        names = [" ".join(mitigation.canonical_name.split()).casefold() for mitigation in value]
        if len(names) != len(set(names)):
            raise ValueError("Normalized mitigation canonical names must be unique")
        return value


class Difficulty(str, Enum):
    VERY_EASY = "VeryEasy"
    EASY = "Easy"
    MEDIUM = "Medium"
    HARD = "Hard"
    INSANE = "Insane"


class ShellType(str, Enum):
    BASH = "bash"
    POWERSHELL = "powershell"
    CMD = "cmd"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    SQL = "sql"
    HTTP = "http"


# Database models
class Writeup(BaseModel):
    id: Optional[int] = None
    filename: str
    filepath: str
    writeup_type: WriteupType
    challenge_type: Optional[str] = None
    difficulty: Optional[str] = None
    title: Optional[str] = None
    tags: list[str] = []


class Tool(BaseModel):
    id: Optional[int] = None
    name: str
    category: Optional[str] = None
    description: Optional[str] = None


class Command(BaseModel):
    id: Optional[int] = None
    tool_id: Optional[int] = None
    tool_name: Optional[str] = None
    writeup_id: Optional[int] = None
    raw_command: str
    command_template: Optional[str] = None
    flags_used: list[str] = []
    purpose: Optional[str] = None
    context: Optional[str] = None
    source_section: Optional[str] = None
    shell_type: ShellType = ShellType.BASH


class Script(BaseModel):
    id: Optional[int] = None
    writeup_id: Optional[int] = None
    language: str
    code: str
    purpose: Optional[str] = None
    libraries_used: list[str] = []
    source_section: Optional[str] = None


# Response models
class CommandResult(BaseModel):
    id: int
    tool: Optional[str] = None
    raw_command: str
    template: Optional[str] = None
    purpose: Optional[str] = None
    source: dict  # {file, type, section, challenge_type}
    match_mode: str = 'filtered'


class ScriptResult(BaseModel):
    id: int
    language: str
    purpose: Optional[str] = None
    libraries: list[str] = []
    code_preview: str  # First N lines
    source: dict
    match_mode: str = 'filtered'


class ToolInfo(BaseModel):
    name: str
    category: Optional[str] = None
    command_count: int = 0


class CategoryInfo(BaseModel):
    name: str
    description: Optional[str] = None
    tool_count: int = 0
    command_count: int = 0


class ChunkResult(BaseModel):
    id: int
    section: Optional[str] = None
    content: str
    source: dict  # {filename, writeup_type, title}


class VaultStats(BaseModel):
    writeups: dict  # {total, boxes, challenges, sherlocks}
    commands: dict  # {total, by_category}
    scripts: dict  # {total, by_language}
    tools: dict  # {total, top_10}
    chunks: Optional[dict] = None  # {total}
    history: Optional[dict] = None  # {total, unique_tools, top_tools, sources}
    research: Optional[dict] = None


class IndexResult(BaseModel):
    files_processed: int
    commands_extracted: int
    scripts_extracted: int
    chunks_extracted: int = 0
    errors: list[str] = []
    duration_seconds: float


# History models
class HistoryCommand(BaseModel):
    id: Optional[int] = None
    command_hash: str
    raw_command: str
    sanitized_command: str
    command_template: Optional[str] = None
    tool_id: Optional[int] = None
    tool_name: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    occurrence_count: int = 1
    source_file: Optional[str] = None
    shell_type: str = "zsh"


class HistoryCommandResult(BaseModel):
    id: int
    tool: Optional[str] = None
    sanitized_command: str
    template: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    occurrence_count: int = 1
    source: str = "history"


class HistoryIndexResult(BaseModel):
    path: str
    commands_processed: int
    commands_added: int
    commands_skipped_blocklist: int
    commands_skipped_duplicate: int
    commands_skipped_short: int
    sensitive_redacted: int
    tools_identified: int
    duration_seconds: float


class HistoryStats(BaseModel):
    total_commands: int
    unique_tools: int
    date_range: dict  # {first: datetime, last: datetime}
    by_source_file: dict  # {path: count}
    top_tools: list[dict]  # [{tool: str, count: int}]
