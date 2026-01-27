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
# Root shell prompt pattern - requires command to start with known tool (not comment-like text)
BASH_ROOT_PROMPT_PATTERN = re.compile(r'^\s*#\s+(\S+.*)$', re.MULTILINE)
PS_COMMAND_PATTERN = re.compile(r'^PS [^>]*>\s*(.+)$', re.MULTILINE)
CMD_COMMAND_PATTERN = re.compile(r'^C:\\[^>]*>\s*(.+)$', re.MULTILINE)

# Section headers
SECTION_PATTERN = re.compile(r'^(#{1,3})\s+(.+)$', re.MULTILINE)

# Tags pattern (from header)
TAGS_PATTERN = re.compile(r'Tags?:\s*(.+)$', re.MULTILINE | re.IGNORECASE)
TAG_EXTRACT_PATTERN = re.compile(r'#(\w+)')

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

    def detect_writeup_type(self, filepath: str) -> dict:
        """
        Detect writeup type from filepath.

        Returns:
            dict with 'type', 'challenge_type', 'difficulty'
        """
        path = Path(filepath)
        filename = path.name

        # Detect by directory
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

        # Default
        return {
            'type': WriteupType.BOX,
            'challenge_type': None,
            'difficulty': None
        }

    def _extract_difficulty(self, text: str) -> Optional[str]:
        """Extract difficulty from text."""
        match = DIFFICULTY_PATTERN.search(text)
        if match:
            diff = match.group(1).replace(' ', '')
            return diff
        return None

    def parse_writeup(self, filepath: str, content: str) -> Writeup:
        """
        Parse writeup metadata.

        Args:
            filepath: Path to the writeup file
            content: File content

        Returns:
            Writeup object with metadata
        """
        path = Path(filepath)
        filename = path.name

        # Detect type
        type_info = self.detect_writeup_type(filepath)

        # Extract title
        title_match = TITLE_PATTERN.search(content)
        title = title_match.group(1).strip() if title_match else filename.replace('.md', '')

        # If difficulty not in filename, try title
        difficulty = type_info['difficulty']
        if not difficulty:
            difficulty = self._extract_difficulty(title)

        # Extract tags
        tags = []
        tags_match = TAGS_PATTERN.search(content)
        if tags_match:
            tags_line = tags_match.group(1)
            tags = TAG_EXTRACT_PATTERN.findall(tags_line)

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
            # Try PS prompt first, then raw lines
            matches = PS_COMMAND_PATTERN.findall(content)
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

        # Check known tools
        if first_word in TOOL_CATEGORIES:
            return first_word

        # Check prefixes
        for prefix in TOOL_PREFIXES:
            if first_word.startswith(prefix.rstrip('-')):
                return first_word

        # For python/python3 commands, try to get the script/module
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

    def parse_file(self, filepath: str) -> tuple[Writeup, list[ExtractedCommand], list[Script]]:
        """
        Parse a writeup file completely.

        Args:
            filepath: Path to the markdown file

        Returns:
            Tuple of (Writeup, list of commands, list of scripts)
        """
        path = Path(filepath)
        content = path.read_text(encoding='utf-8', errors='ignore')

        # Sanitize entire content first
        content = self.security.sanitize_text(content, source_file=path.name)

        # Parse metadata
        writeup = self.parse_writeup(filepath, content)

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
