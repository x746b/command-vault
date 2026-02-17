"""Pydantic models for Command Vault."""

from pydantic import BaseModel
from typing import Optional
from enum import Enum


class WriteupType(str, Enum):
    BOX = "box"
    CHALLENGE = "challenge"
    SHERLOCK = "sherlock"


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


class ScriptResult(BaseModel):
    id: int
    language: str
    purpose: Optional[str] = None
    libraries: list[str] = []
    code_preview: str  # First N lines
    source: dict


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
