"""Pydantic models for Command Vault."""

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, WrapValidator, field_serializer
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


class ResearchArtifact(_ResearchContract):
    path: str = Field(min_length=1, pattern=_RESEARCH_PATH_PATTERN)
    kind: str = Field(min_length=1)
    role: EvidenceRole
    validation: ValidationStatus = ValidationStatus.UNKNOWN
    sha256: Optional[str] = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    media_type: Optional[str] = None
    language: Optional[str] = None
    license_expression: Optional[str] = None


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
