"""Validated result records for the public retrieval contract."""
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid')

    def __getitem__(self, key):
        # Keep read access compatible with callers of the former dictionary API.
        if key not in type(self).model_fields:
            raise KeyError(key)
        return getattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)


class ProfileSource(Record):
    document_id: int
    reference: str
    filename: str
    source_name: str | None = None
    domain: str | None = None
    upstream_url: str | None = None
    revision: str | None = None


class ProfileEvidence(Record):
    reference: str
    kind: Literal['chunk', 'command', 'script']
    evidence_role: str | None = None
    assertion_provenance: str | None = None
    validation_status: str | None = None
    observed_outcome: str | None = None
    stage: str | None = None
    section: str | None = None
    source: ProfileSource


class MitigationSummary(Record):
    canonical_name: str
    raw_label: str | None = None
    state: str | None = None
    source_reference: str | None = None


class StageSummary(Record):
    canonical_name: str
    domain: str
    stage_class: str
    description: str | None = None
    aliases: list[str] = Field(default_factory=list)
    evidence_count: int


class VulnerabilityRecord(Record):
    id: int
    canonical_id: str | None = None
    external_task_id: str | None = None
    project_name: str | None = None
    summary: str | None = None
    summary_provenance: str | None = None
    vulnerability_class: str | None = None
    class_provenance: str | None = None
    sanitizer: str | None = None
    architecture: str | None = None
    platform: str | None = None
    subsystem: str | None = None
    language: str | None = None
    affected_symbols: str | None = None
    introduced_revision: str | None = None
    fixed_revision: str | None = None
    sources: list[ProfileSource] = Field(default_factory=list)
    operational_stages: list[StageSummary] = Field(default_factory=list)
    mitigations: list[MitigationSummary] = Field(default_factory=list)
    evidence: list[ProfileEvidence] = Field(default_factory=list)


class VulnerabilityProfile(Record):
    identifier: str
    matches: list[VulnerabilityRecord] = Field(default_factory=list)
    total_matches: int
    truncated: bool


class StageEdgeSummary(Record):
    direction: Literal['incoming', 'outgoing']
    relation: str
    stage: str
    domain: str
    evidence_reference: str | None = None


class OperationalStageRecord(Record):
    id: int
    canonical_name: str
    domain: str
    stage_class: str
    description: str | None = None
    matched_alias: str | None = None
    aliases: list[str] = Field(default_factory=list)
    edges: list[StageEdgeSummary] = Field(default_factory=list)
    evidence: list[ProfileEvidence] = Field(default_factory=list)


class OperationalStageProfile(Record):
    identifier: str
    domain: str | None = None
    matches: list[OperationalStageRecord] = Field(default_factory=list)
    total_matches: int
    truncated: bool


class KnowledgeSource(Record):
    document_id: int
    filename: str
    writeup_type: str
    indexed_at: str | None = None
    revision: str | None = None


class CommandSource(Record):
    file: str | None
    type: str | None
    section: str | None = None
    challenge_type: str | None = None


class KnowledgeHit(Record):
    kind: Literal['knowledge'] = 'knowledge'
    reference: str
    id: int
    section: str | None
    content: str
    source: KnowledgeSource
    question_only: bool = False
    score: float
    has_more_context: bool = True
    truncated: bool = False


class CommandHit(Record):
    kind: Literal['command'] = 'command'
    reference: str
    id: int
    tool: str | None
    raw_command: str
    template: str | None
    purpose: str | None
    source: CommandSource
    match_mode: Literal['filtered', 'all_terms', 'any_terms']
    truncated: bool = False


class ScriptHit(Record):
    kind: Literal['script'] = 'script'
    reference: str
    id: int
    language: str
    purpose: str | None
    libraries: list[str]
    code_preview: str
    source: CommandSource
    match_mode: Literal['filtered', 'all_terms', 'any_terms']
    truncated: bool = False


class HistoryHit(Record):
    kind: Literal['history'] = 'history'
    reference: str
    id: int
    tool: str | None
    sanitized_command: str
    template: str | None
    first_seen: str | None
    last_seen: str | None
    occurrence_count: int
    source: Literal['history'] = 'history'
    truncated: bool = False


class ReferenceHit(Record):
    kind: Literal['reference'] = 'reference'
    reference: str
    id: int
    truncated: Literal[True] = True
    notice: str = 'Read this reference for content; the record exceeds the result budget.'


T = TypeVar('T')


class SearchPage(Record, Generic[T]):
    results: list[T] = Field(default_factory=list)
    query: str = ''
    match_mode: str = 'filtered'
    unmatched_terms: list[str] = Field(default_factory=list, description='Compatibility union of unmatched query and required terms.')
    unmatched_query_terms: list[str] = Field(default_factory=list, description='Query terms with no individual matches under the source/tag filters.')
    unmatched_required_terms: list[str] = Field(default_factory=list, description='Exact supplied required terms with no individual matches under the source/tag filters. An empty list does not prove they co-occur.')
    next_cursor: str | None = None
    has_more: bool = False
    truncated: bool = False
    records_clipped: bool = False
    notice: str | None = None
    applied_filters: dict[str, str] = Field(default_factory=dict)


KnowledgePage = SearchPage[KnowledgeHit | ReferenceHit]
CommandPage = SearchPage[CommandHit | ReferenceHit]
ScriptPage = SearchPage[ScriptHit | ReferenceHit]
HistoryPage = SearchPage[HistoryHit | ReferenceHit]


class RelatedWriteup(Record):
    kind: Literal['writeup'] = 'writeup'
    id: int
    reference: str
    revision: str | None = None
    filename: str
    title: str | None
    type: str
    difficulty: str | None
    tools: list[str]
    tags: list[str]
    truncated: bool = False


class RelatedGroup(Record):
    kind: Literal['related'] = 'related'
    technique: str
    type: str | None
    writeup_count: int
    total_writeup_count: int
    writeups: list[RelatedWriteup | ReferenceHit]


RelatedPage = SearchPage[RelatedGroup]


class DocumentContextSource(Record):
    document_id: int
    filename: str
    section: str | None
    indexed_revision: str | None
    current_revision: str | None = None
    line_start: int | None = None
    image_references_present: bool = False


class ScriptContextSource(CommandSource):
    language: str


class HistoryContextSource(Record):
    filename: str
    section: Literal['Indexed shell history'] = 'Indexed shell history'


class ContextPage(Record):
    reference: str
    source: DocumentContextSource | ScriptContextSource | HistoryContextSource
    content: str
    offset: int
    next_offset: int | None = None
    truncated: bool = False
    source_status: Literal['current','changed','unverified','unavailable','section_unavailable','indexed','snapshot','managed','snapshot_changed']
    evidence_only: bool = True
