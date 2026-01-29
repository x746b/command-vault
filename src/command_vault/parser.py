"""Markdown parser for extracting commands and scripts from writeups."""

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from .models import WriteupType, ShellType, Writeup, Command, Script
from .security import SecurityFilter
from .categories import TOOL_CATEGORIES, TOOL_ALIASES, TOOL_PREFIXES

logger = logging.getLogger(__name__)


# =============================================================================
# CODE BLOCK PATTERNS
# =============================================================================

# Fenced code blocks with language hint
FENCED_BLOCK_PATTERN = re.compile(
    r'```(bash|sh|shell|powershell|ps1|cmd|python|py|javascript|js|sql|http|c|asm|ruby|go|rust)?\s*\n'
    r'(.*?)'
    r'```',
    re.DOTALL
)

# Shell command lines with $ prompt (user shell)
# Note: We only use $ prompt, not # (root), because # in code blocks usually means comments
BASH_COMMAND_PATTERN = re.compile(r'^\s*\$\s+(.+)$', re.MULTILINE)
# Full prompt pattern: user@host:path$ command (common in writeups)
FULL_PROMPT_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+:[^\$]*\$\s+(.+)$', re.MULTILINE)
# Root shell prompt pattern - requires command to start with known tool (not comment-like text)
BASH_ROOT_PROMPT_PATTERN = re.compile(r'^\s*#\s+(\S+.*)$', re.MULTILINE)
# Zsh prompt pattern (➜  dirname command)
# Also handles git branch in prompt: ➜  dirname git:(branch) command
ZSH_PROMPT_PATTERN = re.compile(r'^➜\s+\S+\s+(?:git:\([^)]+\)\s+)?(.+)$', re.MULTILINE)
# Virtualenv prefix pattern: (venv) ➜  dirname command
VENV_ZSH_PROMPT_PATTERN = re.compile(r'^\([^)]+\)\s+➜\s+\S+\s+(?:git:\([^)]+\)\s+)?(.+)$', re.MULTILINE)
# PowerShell patterns
PS_COMMAND_PATTERN = re.compile(r'^PS [^>]*>\s*(.+)$', re.MULTILINE)
# Evil-WinRM prompt: *Evil-WinRM* PS C:\...>
EVIL_WINRM_PATTERN = re.compile(r'^\*Evil-WinRM\*\s+PS\s+[^>]+>\s*(.+)$', re.MULTILINE)
# PowerView prompt: PV > or (LDAPS)-[host]-[user]\nPV >
POWERVIEW_PATTERN = re.compile(r'^(?:\(LDAPS?\)-\[[^\]]+\]-\[[^\]]+\]\s*)?PV\s*>\s*(.+)$', re.MULTILINE)
# Windows cmd prompt
CMD_COMMAND_PATTERN = re.compile(r'^C:\\[^>]*>\s*(.+)$', re.MULTILINE)

# Output lines to skip (common output patterns that shouldn't be treated as commands)
OUTPUT_PATTERNS = [
    re.compile(r'^Owner:\s', re.IGNORECASE),
    re.compile(r'^Group:\s', re.IGNORECASE),
    re.compile(r'^(Allow|Deny)\s+\S+', re.IGNORECASE),
    re.compile(r'^Access list:', re.IGNORECASE),
    re.compile(r'^distinguishedName:', re.IGNORECASE),
    re.compile(r'^objectClass:', re.IGNORECASE),
    re.compile(r'^(SMB|LDAP|LDAPS)\s+\d+\.\d+\.\d+\.\d+', re.IGNORECASE),  # nxc output
    re.compile(r'^\[\*\]|\[\+\]|\[-\]'),  # Tool output markers
    re.compile(r'^Impacket v'),
    re.compile(r'^Certipy v'),
    re.compile(r'^INFO:'),
    re.compile(r'^\d{4}-\d{2}-\d{2}'),  # Timestamps
    re.compile(r'^Listening on'),
    re.compile(r'^Connection received'),
    re.compile(r'^PRIVILEGES INFORMATION'),
    re.compile(r'^Privilege Name'),
    re.compile(r'^={3,}'),  # Separator lines
    re.compile(r'^-{3,}'),
    re.compile(r'^\s*\d+:\s+HAZE\\'),  # RID brute output
]

# Section headers
SECTION_PATTERN = re.compile(r'^(#{1,3})\s+(.+)$', re.MULTILINE)

# Tags pattern (from header)
TAGS_PATTERN = re.compile(r'Tags?:\s*(.+)$', re.MULTILINE | re.IGNORECASE)
TAG_EXTRACT_PATTERN = re.compile(r'#(\w+)')

# Inline hashtag pattern for full-content scanning
# Matches #word but not code patterns like #include, #pragma, #define, etc.
INLINE_HASHTAG_PATTERN = re.compile(r'(?<![/\w])#([a-zA-Z][a-zA-Z0-9_-]*)\b')

# Tags to filter out (code/markdown artifacts, not real tags)
HASHTAG_BLOCKLIST = frozenset({
    # C/C++ preprocessor directives
    'include', 'define', 'ifdef', 'ifndef', 'endif', 'pragma', 'undef', 'error',
    'warning', 'line', 'elif', 'else', 'if',
    # Markdown anchors and common false positives
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'toc', 'top', 'bottom', 'section',
    # Python/shell comments that might look like tags
    'todo', 'fixme', 'note', 'hack', 'xxx',
    # Common HTML/CSS
    'id', 'class', 'style', 'href', 'src',
})

# Title pattern (first H1)
TITLE_PATTERN = re.compile(r'^#\s+(.+)$', re.MULTILINE)

# Difficulty in title or filename
DIFFICULTY_PATTERN = re.compile(r'\((Easy|Medium|Hard|Insane|VeryEasy|Very Easy)\)', re.IGNORECASE)


# =============================================================================
# TEMPLATIZATION PATTERNS
# =============================================================================

TEMPLATE_RULES = [
    # Lab IP range (10.10.x.x commonly used in lab environments)
    (re.compile(r'\b10\.10\.\d{1,3}\.\d{1,3}\b'), '{TARGET_IP}'),
    # General IP
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '{IP}'),
    # Common lab domains (.htb, .vl, .lab, .local, etc.)
    (re.compile(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.(htb|vl|lab|local)\b'), '{TARGET}'),
    # Ports after -p flag (but not passwords)
    (re.compile(r'(?<=-p\s)(\d{1,5})(?=\s|$)'), '{PORT}'),
]


# =============================================================================
# SCRIPT DETECTION
# =============================================================================

PYTHON_EXPLOIT_INDICATORS = [
    'from pwn import',
    'from pwnlib',
    'from Crypto',
    'from Cryptodome',
    'import requests',
    'import socket',
    'from unicorn import',
    'from capstone import',
    'from keystone import',
    'import angr',
    'import z3',
    'def exploit',
    'def main',
    'if __name__',
    'remote(',
    'process(',
    'ELF(',
]

FRIDA_INDICATORS = [
    'Java.perform',
    'Interceptor.attach',
    'Interceptor.replace',
    'Module.findExportByName',
    'Module.findBaseAddress',
    'ObjC.classes',
    'send(',
    'recv(',
]


@dataclass
class ParsedCodeBlock:
    """Represents a parsed code block."""
    language: str
    content: str
    section: str
    context: str  # Text before the block
    is_script: bool = False
    libraries: list[str] = field(default_factory=list)


@dataclass
class ExtractedCommand:
    """Represents an extracted command."""
    raw_command: str
    tool_name: Optional[str]
    shell_type: ShellType
    section: str
    context: str
    template: Optional[str] = None
    flags: list[str] = field(default_factory=list)


class WriteupParser:
    """Parser for extracting commands and scripts from writeups."""

    def __init__(self, security_filter: Optional[SecurityFilter] = None):
        self.security = security_filter or SecurityFilter()

    def detect_writeup_type(
        self,
        filepath: str,
        content: Optional[str] = None,
        source_dir: Optional[str] = None
    ) -> dict:
        """
        Detect writeup type from filepath and/or content.

        Args:
            filepath: Path to the writeup file
            content: File content (only used for unified dir)
            source_dir: 'unified' for WRITEUPS env var, None for legacy dirs

        Returns:
            dict with 'type', 'challenge_type', 'difficulty'
        """
        path = Path(filepath)
        filename = path.name

        # Legacy behavior: detect by directory path
        if source_dir != 'unified':
            if '/boxes/' in filepath or '\\boxes\\' in filepath:
                difficulty = self._extract_difficulty(filename)
                return {
                    'type': WriteupType.BOX,
                    'challenge_type': None,
                    'difficulty': difficulty
                }

            elif '/challenges/' in filepath or '\\challenges\\' in filepath:
                # Format: "Name (type).md"
                match = re.search(r'\(([^)]+)\)\.md$', filename, re.IGNORECASE)
                challenge_type = match.group(1).lower().strip() if match else 'misc'
                # Normalize challenge type
                challenge_type = challenge_type.replace(' - ', '_').replace(' ', '_')
                return {
                    'type': WriteupType.CHALLENGE,
                    'challenge_type': challenge_type,
                    'difficulty': None
                }

            elif '/sherlocks/' in filepath or '\\sherlocks\\' in filepath:
                # Format: "Name (Difficulty).md"
                match = re.search(r'\(([^)]+)\)\.md$', filename, re.IGNORECASE)
                difficulty = match.group(1) if match else None
                return {
                    'type': WriteupType.SHERLOCK,
                    'challenge_type': 'dfir',
                    'difficulty': difficulty
                }

            # Default for legacy (no matching directory)
            return {
                'type': WriteupType.BOX,
                'challenge_type': None,
                'difficulty': None
            }

        # Unified dir behavior: detect from content tags and filename
        detected_type = WriteupType.BOX
        challenge_type = None
        difficulty = self._extract_difficulty(filename)

        # 1. Check content tags (#sherlock, #challenge, #box)
        if content:
            content_lower = content.lower()
            # Extract inline tags for type detection
            content_tags = set()
            for match in INLINE_HASHTAG_PATTERN.finditer(content):
                content_tags.add(match.group(1).lower())

            if 'sherlock' in content_tags:
                detected_type = WriteupType.SHERLOCK
                challenge_type = 'dfir'
            elif 'challenge' in content_tags:
                detected_type = WriteupType.CHALLENGE
                # Try to find challenge type from tags
                challenge_types = {'web', 'pwn', 'crypto', 'forensics', 'reversing',
                                   'misc', 'mobile', 'hardware', 'blockchain', 'osint'}
                found_types = content_tags.intersection(challenge_types)
                if found_types:
                    challenge_type = sorted(found_types)[0]
                else:
                    challenge_type = 'misc'
            elif 'box' in content_tags:
                detected_type = WriteupType.BOX

        # 2. Fallback: check filename pattern "Name (type).md"
        if detected_type == WriteupType.BOX and not challenge_type:
            match = re.search(r'\(([^)]+)\)\.md$', filename, re.IGNORECASE)
            if match:
                type_hint = match.group(1).lower().strip()
                if type_hint in ('sherlock', 'dfir', 'forensics'):
                    detected_type = WriteupType.SHERLOCK
                    challenge_type = 'dfir'
                    difficulty = None
                elif type_hint in ('challenge', 'ctf'):
                    detected_type = WriteupType.CHALLENGE
                    challenge_type = 'misc'
                elif type_hint in ('web', 'pwn', 'crypto', 'mobile', 'reversing',
                                   'misc', 'hardware', 'blockchain', 'osint'):
                    detected_type = WriteupType.CHALLENGE
                    challenge_type = type_hint
                elif type_hint in ('easy', 'medium', 'hard', 'insane', 'veryeasy'):
                    difficulty = type_hint.title()

        return {
            'type': detected_type,
            'challenge_type': challenge_type,
            'difficulty': difficulty
        }

    def _extract_difficulty(self, text: str) -> Optional[str]:
        """Extract difficulty from text."""
        match = DIFFICULTY_PATTERN.search(text)
        if match:
            diff = match.group(1).replace(' ', '')
            return diff
        return None

    def _extract_all_tags(self, content: str, full_scan: bool = False) -> list[str]:
        """
        Extract tags from content.

        Args:
            content: Markdown content
            full_scan: If True, scan entire content for #hashtags.
                      If False (legacy), only extract from "Tags:" header line.

        Returns:
            List of lowercase tag names (deduplicated)
        """
        tags = set()

        # Always extract from "Tags:" header line (legacy behavior)
        tags_match = TAGS_PATTERN.search(content)
        if tags_match:
            tags_line = tags_match.group(1)
            for tag in TAG_EXTRACT_PATTERN.findall(tags_line):
                tag_lower = tag.lower()
                if tag_lower not in HASHTAG_BLOCKLIST:
                    tags.add(tag_lower)

        # If full_scan enabled, also scan entire content for #hashtags
        if full_scan:
            for match in INLINE_HASHTAG_PATTERN.finditer(content):
                tag = match.group(1).lower()
                if tag not in HASHTAG_BLOCKLIST and len(tag) >= 2:
                    tags.add(tag)

        return sorted(tags)

    def parse_writeup(
        self,
        filepath: str,
        content: str,
        full_scan: bool = False,
        source_dir: Optional[str] = None
    ) -> Writeup:
        """
        Parse writeup metadata.

        Args:
            filepath: Path to the writeup file
            content: File content
            full_scan: If True, extract #hashtags from entire content (unified dir mode)
            source_dir: Source directory type ('unified' for WRITEUPS env var, None for legacy)

        Returns:
            Writeup object with metadata
        """
        path = Path(filepath)
        filename = path.name

        # Detect type (uses content-based detection for unified dir)
        type_info = self.detect_writeup_type(
            filepath,
            content=content if source_dir == 'unified' else None,
            source_dir=source_dir
        )

        # Extract title
        title_match = TITLE_PATTERN.search(content)
        title = title_match.group(1).strip() if title_match else filename.replace('.md', '')

        # If difficulty not in filename, try title
        difficulty = type_info['difficulty']
        if not difficulty:
            difficulty = self._extract_difficulty(title)

        # Extract tags (full scan for unified dir)
        tags = self._extract_all_tags(content, full_scan=full_scan)

        # For unified dir, auto-add type as a tag
        if source_dir == 'unified':
            type_tag = type_info['type'].value  # 'box', 'challenge', 'sherlock'
            if type_tag not in tags:
                tags.append(type_tag)
                tags.sort()
            # Also add challenge_type as tag if present
            if type_info['challenge_type'] and type_info['challenge_type'] not in tags:
                tags.append(type_info['challenge_type'])
                tags.sort()

        return Writeup(
            filename=filename,
            filepath=filepath,
            writeup_type=type_info['type'],
            challenge_type=type_info['challenge_type'],
            difficulty=difficulty,
            title=title,
            tags=tags
        )

    def extract_code_blocks(self, content: str) -> list[ParsedCodeBlock]:
        """
        Extract all code blocks from content.

        Args:
            content: Markdown content

        Returns:
            List of parsed code blocks
        """
        blocks = []

        # Parse sections first
        sections = self._parse_sections(content)

        # Find all fenced code blocks
        for match in FENCED_BLOCK_PATTERN.finditer(content):
            language = match.group(1) or ''
            code = match.group(2).strip()

            if not code:
                continue

            # Determine section
            pos = match.start()
            section = self._get_section_at_position(sections, pos)

            # Get context (text before this block)
            context = self._get_context_before(content, pos)

            # Sanitize content
            code = self.security.sanitize_text(code)

            # Detect if it's a full script
            is_script, libraries = self._detect_script(code, language)

            blocks.append(ParsedCodeBlock(
                language=language.lower() if language else 'bash',
                content=code,
                section=section,
                context=context,
                is_script=is_script,
                libraries=libraries
            ))

        return blocks

    def _parse_sections(self, content: str) -> list[tuple[int, str]]:
        """Parse section headers with their positions."""
        sections = []
        for match in SECTION_PATTERN.finditer(content):
            level = len(match.group(1))
            title = match.group(2).strip()
            sections.append((match.start(), title))
        return sections

    def _get_section_at_position(self, sections: list[tuple[int, str]], pos: int) -> str:
        """Get the section name at a given position."""
        current_section = "Introduction"
        for section_pos, section_name in sections:
            if section_pos > pos:
                break
            current_section = section_name
        return current_section

    def _get_context_before(self, content: str, pos: int, max_chars: int = 500) -> str:
        """Get text context before a position."""
        start = max(0, pos - max_chars)
        text = content[start:pos]

        # Find last paragraph
        lines = text.split('\n')
        context_lines = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                if context_lines:
                    break
                continue
            if line.startswith('#'):
                break
            if line.startswith('```'):
                break
            context_lines.insert(0, line)

        context = ' '.join(context_lines)
        # Clean up
        context = re.sub(r'\s+', ' ', context).strip()
        return context[:300] if context else ""

    def _detect_script(self, code: str, language: str) -> tuple[bool, list[str]]:
        """
        Detect if code is a full script and extract libraries.

        Returns:
            (is_script, list of libraries)
        """
        libraries = []

        if language in ('python', 'py'):
            # Check for script indicators
            is_script = any(ind in code for ind in PYTHON_EXPLOIT_INDICATORS)

            # Extract imports
            import_pattern = re.compile(r'^(?:from|import)\s+(\w+)', re.MULTILINE)
            for match in import_pattern.finditer(code):
                lib = match.group(1)
                if lib not in ('os', 'sys', 're', 'json', 'time', 'struct'):
                    libraries.append(lib)

            # Check minimum length for script
            if is_script and len(code.split('\n')) >= 5:
                return True, list(set(libraries))

        elif language in ('javascript', 'js'):
            is_script = any(ind in code for ind in FRIDA_INDICATORS)
            if is_script:
                libraries.append('frida')
                return True, libraries

        return False, []

    def extract_commands(self, block: ParsedCodeBlock) -> list[ExtractedCommand]:
        """
        Extract individual commands from a code block.

        Args:
            block: Parsed code block

        Returns:
            List of extracted commands
        """
        commands = []
        content = block.content

        # Skip if it's a script
        if block.is_script:
            return commands

        # Determine shell type and pattern
        if block.language in ('powershell', 'ps1'):
            shell_type = ShellType.POWERSHELL
            # Try Evil-WinRM prompt first
            matches = EVIL_WINRM_PATTERN.findall(content)
            # Then standard PS prompt
            matches.extend(PS_COMMAND_PATTERN.findall(content))
            # Then PowerView prompt
            matches.extend(POWERVIEW_PATTERN.findall(content))
            if not matches:
                matches = [line.strip() for line in content.split('\n')
                          if line.strip() and not line.strip().startswith('#')]
        elif block.language in ('cmd',):
            shell_type = ShellType.CMD
            matches = CMD_COMMAND_PATTERN.findall(content)
            if not matches:
                matches = [line.strip() for line in content.split('\n')
                          if line.strip() and not line.strip().startswith('::')]
        elif block.language in ('python', 'py'):
            shell_type = ShellType.PYTHON
            # For python, look for one-liners or simple commands
            matches = [line.strip() for line in content.split('\n')
                      if line.strip().startswith('python') or line.strip().startswith('python3')]
        elif block.language in ('sql',):
            shell_type = ShellType.SQL
            matches = [content]  # Treat whole block as one command
        elif block.language in ('http',):
            shell_type = ShellType.HTTP
            matches = [content]  # Treat whole block as one command
        else:
            # Default bash
            shell_type = ShellType.BASH
            # First try $ prompts (most reliable)
            matches = BASH_COMMAND_PATTERN.findall(content)

            # Try full prompt pattern (user@host:path$ command)
            matches.extend(FULL_PROMPT_PATTERN.findall(content))

            # Try zsh prompts (➜  dirname command)
            matches.extend(ZSH_PROMPT_PATTERN.findall(content))
            # Try virtualenv zsh prompts ((venv) ➜  dirname command)
            matches.extend(VENV_ZSH_PROMPT_PATTERN.findall(content))

            # Also handle Evil-WinRM/PowerView prompts in bash blocks (mixed sessions)
            matches.extend(EVIL_WINRM_PATTERN.findall(content))
            matches.extend(POWERVIEW_PATTERN.findall(content))

            # Also try # prompts but validate they look like commands
            for candidate in BASH_ROOT_PROMPT_PATTERN.findall(content):
                if self._looks_like_command(candidate):
                    matches.append(candidate)

            # Fallback: try lines starting with known tools (no prompt)
            if not matches:
                for line in content.split('\n'):
                    line = line.strip()
                    if self._looks_like_command(line):
                        matches.append(line)

        for cmd in matches:
            cmd = cmd.strip()
            if not cmd:
                continue

            # Skip if looks like output (not a command)
            if self._is_output_line(cmd):
                continue

            # Skip if should be filtered
            if self.security.should_skip_command(cmd):
                continue
            if self.security.should_skip_line(cmd):
                continue

            # Identify tool
            tool_name = self._identify_tool(cmd)

            # Create template
            template = self._templatize(cmd)

            # Extract flags
            flags = self._extract_flags(cmd)

            commands.append(ExtractedCommand(
                raw_command=cmd,
                tool_name=tool_name,
                shell_type=shell_type,
                section=block.section,
                context=block.context,
                template=template,
                flags=flags
            ))

        return commands

    def _looks_like_command(self, line: str) -> bool:
        """Check if a line looks like a command."""
        if not line:
            return False

        # Skip comments
        if line.startswith('#') and not line.startswith('#!/'):
            return False

        # Skip output-like lines
        if line.startswith('[') or line.startswith('{') or line.startswith('('):
            return False

        # Skip lines that look like prose/sentences (capitalized word followed by space)
        # Commands typically start with lowercase tool names
        if line[0].isupper() and len(line) > 1 and ' ' in line:
            # Exception: Windows commands like 'Get-Process'
            if not line.split()[0].startswith('Get-') and not line.split()[0].startswith('Set-'):
                return False

        # Skip lines with common prose patterns
        prose_starts = ('the ', 'this ', 'that ', 'these ', 'a ', 'an ', 'in ', 'on ',
                       'for ', 'to ', 'and ', 'or ', 'if ', 'is ', 'are ', 'was ',
                       'note', 'output', 'result', 'example', 'usage', 'hint')
        if line.lower().startswith(prose_starts):
            return False

        # Skip lines that are mostly non-command characters
        if line.startswith('---') or line.startswith('===') or line.startswith('***'):
            return False

        # Check if starts with known tool
        parts = line.split()
        if not parts:
            return False

        first_word = parts[0].lower()

        # Remove path prefix
        if '/' in first_word:
            first_word = first_word.split('/')[-1]

        # Check against known tools
        if first_word in TOOL_CATEGORIES:
            return True

        # Check prefixes
        for prefix in TOOL_PREFIXES:
            if first_word.startswith(prefix.rstrip('-')):
                return True

        # Common shell commands (only if it looks like actual command usage)
        common_cmds = {'sudo', 'cd', 'ls', 'cat', 'echo', 'export', 'source', 'chmod', 'chown',
                      'mkdir', 'cp', 'mv', 'rm', 'grep', 'find', 'awk', 'sed', 'tar', 'unzip',
                      'wget', 'curl', 'ssh', 'scp', 'nc', 'python', 'python3', 'ruby', 'perl',
                      'php', 'java', 'node', 'npm', 'pip', 'pip3', 'git', 'docker', 'kubectl'}
        if first_word in common_cmds:
            return True

        return False

    def _is_output_line(self, line: str) -> bool:
        """Check if a line looks like command output (not a command itself)."""
        for pattern in OUTPUT_PATTERNS:
            if pattern.match(line):
                return True
        return False

    def _identify_tool(self, command: str) -> Optional[str]:
        """Identify the tool from a command."""
        # Handle sudo prefix
        cmd = command.strip()
        if cmd.startswith('sudo '):
            cmd = cmd[5:].strip()

        # Get first word
        parts = cmd.split()
        if not parts:
            return None

        first_word = parts[0].lower()

        # Remove path prefix
        if '/' in first_word:
            first_word = first_word.split('/')[-1]

        # Check aliases
        if first_word in TOOL_ALIASES:
            return TOOL_ALIASES[first_word]

        # For python/python3 commands, try to get the script/module first
        if first_word in ('python', 'python3'):
            if len(parts) > 1:
                second = parts[1]
                if second == '-m' and len(parts) > 2:
                    return parts[2]
                elif second == '-c':
                    return 'python'
                elif not second.startswith('-'):
                    # Script name
                    script = Path(second).stem
                    if script in TOOL_CATEGORIES:
                        return script
            return first_word

        # Check known tools
        if first_word in TOOL_CATEGORIES:
            return first_word

        # Check prefixes
        for prefix in TOOL_PREFIXES:
            if first_word.startswith(prefix.rstrip('-')):
                return first_word

        return first_word if first_word else None

    def _templatize(self, command: str) -> str:
        """Replace dynamic values with placeholders."""
        result = command
        for pattern, replacement in TEMPLATE_RULES:
            result = pattern.sub(replacement, result)
        return result

    def _extract_flags(self, command: str) -> list[str]:
        """Extract flags/options from a command."""
        flags = []
        # Match -x, --xxx patterns
        flag_pattern = re.compile(r'(?:^|\s)(-{1,2}[a-zA-Z][-a-zA-Z0-9]*)')
        for match in flag_pattern.finditer(command):
            flags.append(match.group(1))
        return flags

    def parse_file(
        self,
        filepath: str,
        full_scan: bool = False,
        source_dir: Optional[str] = None
    ) -> tuple[Writeup, list[ExtractedCommand], list[Script]]:
        """
        Parse a writeup file completely.

        Args:
            filepath: Path to the markdown file
            full_scan: If True, extract #hashtags from entire content (unified dir mode)
            source_dir: Source directory type ('unified' for WRITEUPS env var, None for legacy)

        Returns:
            Tuple of (Writeup, list of commands, list of scripts)
        """
        path = Path(filepath)
        content = path.read_text(encoding='utf-8', errors='ignore')

        # Sanitize entire content first
        content = self.security.sanitize_text(content, source_file=path.name)

        # Parse metadata
        writeup = self.parse_writeup(filepath, content, full_scan=full_scan, source_dir=source_dir)

        # Extract code blocks
        blocks = self.extract_code_blocks(content)

        commands = []
        scripts = []

        for block in blocks:
            if block.is_script:
                # Store as script
                scripts.append(Script(
                    language=block.language,
                    code=block.content,
                    purpose=block.context,
                    libraries_used=block.libraries,
                    source_section=block.section
                ))
            else:
                # Extract commands
                extracted = self.extract_commands(block)
                commands.extend(extracted)

        return writeup, commands, scripts
