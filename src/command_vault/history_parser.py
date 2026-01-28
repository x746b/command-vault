"""Shell history parser for Command Vault.

Parses zsh and bash history files, filters worthless commands,
applies security sanitization, and deduplicates entries.
"""

import re
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from .security import SecurityFilter
from .categories import TOOL_CATEGORIES

logger = logging.getLogger(__name__)


# =============================================================================
# HISTORY FORMAT PATTERNS
# =============================================================================

# Zsh extended history format: ": 1706000000:0;command"
ZSH_HISTORY_PATTERN = re.compile(r'^:\s*(\d+):\d+;(.+)$')

# Bash timestamp format: "#1706000000" followed by command on next line
BASH_TIMESTAMP_PATTERN = re.compile(r'^#(\d+)$')


# =============================================================================
# BLOCKLIST - Commands with no security/pentesting value
# =============================================================================

BLOCKLIST_EXACT = {
    # Navigation & basic file ops
    'ls', 'll', 'la', 'l', 'lr', 'cd', 'pwd', 'pushd', 'popd',
    'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'touch', 'ln',

    # File viewing (without specific targets)
    'cat', 'less', 'more', 'head', 'tail', 'view', 'bat',

    # Permissions
    'chmod', 'chown', 'chgrp',

    # Process management
    'ps', 'top', 'htop', 'btop', 'kill', 'killall', 'pkill', 'jobs', 'bg', 'fg',

    # Shell builtins
    'exit', 'logout', 'clear', 'c', 'reset', 'history', 'alias', 'unalias',
    'source', '.', 'export', 'set', 'unset', 'env', 'printenv', 'eval',

    # Editors
    'vim', 'vi', 'nvim', 'nano', 'emacs', 'code', 'subl', 'gedit', 'kate',

    # Help & docs
    'man', 'help', 'info', 'which', 'whereis', 'whatis', 'type', 'tldr',

    # Package managers (install commands rarely useful)
    'apt', 'apt-get', 'dpkg', 'yum', 'dnf', 'pacman', 'brew', 'pip', 'pip3',
    'npm', 'yarn', 'cargo', 'go',

    # System
    'sudo', 'su', 'doas', 'date', 'cal', 'uptime', 'who', 'w', 'id',
    'uname', 'hostname', 'whoami', 'groups', 'free', 'vmstat',

    # Disk & storage
    'df', 'du', 'mount', 'umount', 'lsblk', 'fdisk', 'blkid',

    # Network basics (without targets)
    'ifconfig', 'ip', 'netstat', 'ss', 'route', 'iwconfig',

    # Archives (generic)
    'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', '7z', 'rar',

    # Git basics
    'git', 'gitk', 'tig',

    # Misc
    'echo', 'printf', 'true', 'false', 'sleep', 'watch', 'time', 'timeout',
    'xclip', 'xsel', 'pbcopy', 'pbpaste', 'wl-copy', 'wl-paste',
    'tmux', 'screen', 'byobu', 'zsh', 'bash', 'sh', 'fish',
    'make', 'cmake', 'ninja', 'meson',
    'python', 'python3', 'python2', 'ruby', 'perl', 'node', 'java',
}

BLOCKLIST_PREFIXES = [
    'cd ',           # All directory changes
    'ls ',           # All ls variants
    'cat ',          # Plain cat without pipes
    'echo ',         # Simple echo
    'rm ',           # File deletion
    'mkdir ',        # Directory creation
    'cp ',           # File copy
    'mv ',           # File move
    'vim ', 'vi ', 'nvim ', 'nano ', 'code ', 'subl ',  # Editor opens
    'git ',          # All git commands (mostly noise)
    'apt ', 'apt-get ', 'pip ', 'pip3 ', 'npm ', 'yarn ',  # Package management
    'sudo apt', 'sudo pip', 'sudo npm',
    'man ',          # Manual pages
    'alias ',        # Alias definitions
    'export ',       # Variable exports
    'source ',       # Sourcing files
    'which ',        # Finding binaries
    'type ',         # Type checking
    'file ',         # File type checking
    'stat ',         # File stats
    'wc ',           # Word count
    'sort ',         # Sorting (usually piped)
    'uniq ',         # Dedup (usually piped)
    'cut ',          # Cut fields (usually piped)
    'awk ',          # Awk (usually scripting)
    'sed ',          # Sed (usually scripting)
    'grep ',         # Plain grep without context
    'find ',         # Find (too generic)
    'locate ',       # Locate files
    'docker ps', 'docker images', 'docker logs',  # Docker noise
    'kubectl get', 'kubectl describe',  # K8s noise
    'systemctl ',    # Service management
    'journalctl ',   # Log viewing
    'dmesg',         # Kernel logs
]

# Commands that should ALWAYS be indexed even if they match blocklist prefixes
ALLOWLIST_TOOLS = {
    # Recon
    'nmap', 'masscan', 'rustscan', 'autorecon',
    # Web
    'gobuster', 'ffuf', 'feroxbuster', 'dirsearch', 'wfuzz', 'nikto', 'sqlmap',
    'whatweb', 'wafw00f', 'nuclei', 'httpx', 'katana',
    # AD
    'bloodhound-python', 'crackmapexec', 'cme', 'nxc', 'netexec',
    'certipy', 'impacket', 'rubeus', 'mimikatz', 'pypykatz',
    'ldapsearch', 'ldapdomaindump', 'windapsearch', 'bloodyAD',
    'getTGT', 'getST', 'secretsdump', 'psexec', 'wmiexec', 'smbexec', 'atexec',
    'evil-winrm', 'kerbrute', 'GetUserSPNs', 'GetNPUsers',
    # Creds
    'hashcat', 'john', 'hydra', 'medusa', 'patator', 'cewl', 'crunch',
    # Shells
    'msfvenom', 'msfconsole', 'nc', 'netcat', 'ncat', 'socat', 'rlwrap',
    'pwncat', 'rcat', 'chisel', 'ligolo', 'sshuttle',
    # Privesc
    'linpeas', 'winpeas', 'pspy', 'sudo', 'getcap',
    # DFIR
    'volatility', 'volatility3', 'vol', 'vol3', 'chainsaw', 'hayabusa',
    'MFTECmd', 'PECmd', 'AmcacheParser', 'Timeline',
    # Reversing
    'gdb', 'pwndbg', 'gef', 'r2', 'radare2', 'ghidra', 'objdump', 'readelf',
    'strings', 'ltrace', 'strace', 'binwalk', 'upx',
    # Mobile
    'frida', 'objection', 'apktool', 'jadx', 'adb', 'aapt',
    # Misc security
    'curl', 'wget', 'proxychains', 'responder', 'mitm6', 'bettercap',
    'tcpdump', 'wireshark', 'tshark', 'scapy',
    'openssl', 'ssh-keygen', 'sshpass', 'scp', 'rsync',
    'xfreerdp', 'rdesktop', 'freerdp', 'xfreerdp3',
    'enum4linux', 'smbclient', 'smbmap', 'rpcclient', 'lookupsid',
    'wpscan', 'droopescan', 'joomscan',
    'searchsploit', 'msfconsole',
    'aws', 'az', 'gcloud',  # Cloud CLIs (when used for attacks)
}


# =============================================================================
# SENSITIVE PATTERNS FOR HISTORY
# =============================================================================

HISTORY_SENSITIVE_PATTERNS = [
    # Passwords in common flag formats
    (re.compile(r"(-p\s+)['\"]?[^\s'\"]+['\"]?"), r'\1{REDACTED}'),
    (re.compile(r"(--password[=\s]+)['\"]?[^\s'\"]+['\"]?"), r'\1{REDACTED}'),
    (re.compile(r"(-P\s+)['\"]?[^\s'\"]+['\"]?"), r'\1{REDACTED}'),

    # API keys and tokens
    (re.compile(r"([-_]?api[-_]?key[=:\s]+)[^\s]+", re.I), r'\1{REDACTED}'),
    (re.compile(r"([-_]?token[=:\s]+)[^\s]+", re.I), r'\1{REDACTED}'),
    (re.compile(r"([-_]?secret[=:\s]+)[^\s]+", re.I), r'\1{REDACTED}'),
    (re.compile(r"(Authorization:\s*Bearer\s+)[^\s]+", re.I), r'\1{REDACTED}'),

    # AWS credentials
    (re.compile(r"(AWS_SECRET_ACCESS_KEY=)[^\s]+", re.I), r'\1{REDACTED}'),
    (re.compile(r"(aws_secret_access_key\s*=\s*)[^\s]+", re.I), r'\1{REDACTED}'),

    # Private key files (redact path)
    (re.compile(r"(-i\s+)[^\s]+\.pem"), r'\1{KEY_FILE}'),
    (re.compile(r"(-i\s+)[^\s]+id_rsa[^\s]*"), r'\1{KEY_FILE}'),

    # Database connection strings
    (re.compile(r"(mysql://[^:]+:)[^@]+(@)"), r'\1{REDACTED}\2'),
    (re.compile(r"(postgres://[^:]+:)[^@]+(@)"), r'\1{REDACTED}\2'),
    (re.compile(r"(mongodb://[^:]+:)[^@]+(@)"), r'\1{REDACTED}\2'),
]


# =============================================================================
# TEMPLATIZATION RULES
# =============================================================================

TEMPLATE_RULES = [
    # IP addresses
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '{IP}'),
    # Common domains
    (re.compile(r'\b[\w-]+\.(htb|local|vl|thm)\b', re.I), '{DOMAIN}'),
    # User paths
    (re.compile(r'/home/\w+/'), '/home/{USER}/'),
    (re.compile(r'/tmp/[\w.-]+'), '/tmp/{FILE}'),
]


class HistoryParser:
    """Parser for shell history files."""

    def __init__(self, security_filter: Optional[SecurityFilter] = None):
        self.security = security_filter or SecurityFilter()
        self.stats = {
            'processed': 0,
            'skipped_blocklist': 0,
            'skipped_short': 0,
            'sensitive_redacted': 0,
        }

    def parse_file(self, filepath: str) -> list[dict]:
        """
        Parse a history file and return list of commands.

        Args:
            filepath: Path to history file

        Returns:
            List of dicts with {timestamp, command, shell_type}
        """
        path = Path(filepath).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"History file not found: {filepath}")

        # Detect shell type from filename
        shell_type = self._detect_shell_type(path)

        # Read and parse
        content = path.read_text(errors='replace')

        if shell_type == 'zsh':
            return self._parse_zsh_history(content, str(path))
        else:
            return self._parse_bash_history(content, str(path))

    def _detect_shell_type(self, path: Path) -> str:
        """Detect shell type from filename."""
        name = path.name.lower()
        if 'zsh' in name:
            return 'zsh'
        elif 'bash' in name:
            return 'bash'
        # Default to zsh for extended format detection
        return 'zsh'

    def _parse_zsh_history(self, content: str, source_file: str) -> list[dict]:
        """Parse zsh extended history format."""
        commands = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue

            match = ZSH_HISTORY_PATTERN.match(line)
            if match:
                timestamp = datetime.fromtimestamp(int(match.group(1)))
                command = match.group(2)
                commands.append({
                    'timestamp': timestamp,
                    'command': command,
                    'shell_type': 'zsh',
                    'source_file': source_file,
                })
            elif not line.startswith(':'):
                # Plain command without timestamp
                commands.append({
                    'timestamp': None,
                    'command': line,
                    'shell_type': 'zsh',
                    'source_file': source_file,
                })

        return commands

    def _parse_bash_history(self, content: str, source_file: str) -> list[dict]:
        """Parse bash history format (with optional timestamps)."""
        commands = []
        current_timestamp = None
        lines = content.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check for timestamp line
            ts_match = BASH_TIMESTAMP_PATTERN.match(line)
            if ts_match:
                current_timestamp = datetime.fromtimestamp(int(ts_match.group(1)))
                continue

            # Regular command line
            commands.append({
                'timestamp': current_timestamp,
                'command': line,
                'shell_type': 'bash',
                'source_file': source_file,
            })
            current_timestamp = None

        return commands

    def should_skip_command(self, cmd: str) -> tuple[bool, str]:
        """
        Check if command should be excluded from indexing.

        Returns:
            (should_skip, reason)
        """
        cmd_stripped = cmd.strip()
        cmd_lower = cmd_stripped.lower()

        # Too short
        if len(cmd_stripped) < 5:
            return True, 'short'

        # Get first word (the tool/command)
        parts = cmd_stripped.split()
        if not parts:
            return True, 'empty'

        first_word = parts[0].lower()
        # Handle sudo prefix
        if first_word == 'sudo' and len(parts) > 1:
            first_word = parts[1].lower()

        # Check allowlist first (takes priority)
        for tool in ALLOWLIST_TOOLS:
            if first_word == tool.lower() or first_word.endswith('/' + tool.lower()):
                return False, ''
            # Check if tool appears anywhere (for aliases like pxs nmap)
            if tool.lower() in cmd_lower:
                return False, ''

        # Check exact blocklist
        if first_word in BLOCKLIST_EXACT:
            return True, 'blocklist'

        # Check prefix blocklist
        for prefix in BLOCKLIST_PREFIXES:
            if cmd_lower.startswith(prefix):
                return True, 'blocklist'

        return False, ''

    def sanitize_command(self, cmd: str, source_file: str = "history") -> str:
        """
        Sanitize sensitive data from command.

        Returns:
            Sanitized command string
        """
        result = cmd

        # Apply history-specific patterns
        for pattern, replacement in HISTORY_SENSITIVE_PATTERNS:
            if pattern.search(result):
                self.stats['sensitive_redacted'] += 1
                result = pattern.sub(replacement, result)

        # Apply general security filter
        result = self.security.sanitize_text(result, source_file)

        return result

    def templatize_command(self, cmd: str) -> str:
        """
        Create a template from command by replacing variable parts.

        Returns:
            Templatized command string
        """
        result = cmd
        for pattern, replacement in TEMPLATE_RULES:
            result = pattern.sub(replacement, result)
        return result

    def get_command_hash(self, cmd: str) -> str:
        """
        Generate hash for deduplication.
        Uses normalized command to catch similar commands.
        """
        normalized = self.templatize_command(cmd.strip())
        # Normalize whitespace
        normalized = ' '.join(normalized.split())
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def identify_tool(self, cmd: str) -> Optional[str]:
        """
        Identify the primary tool used in a command.

        Returns:
            Tool name or None
        """
        parts = cmd.strip().split()
        if not parts:
            return None

        first_word = parts[0].lower()

        # Handle sudo prefix
        if first_word == 'sudo' and len(parts) > 1:
            first_word = parts[1].lower()

        # Handle proxychains prefix
        if first_word in ('proxychains', 'proxychains4', 'px', 'pxs', 'pxw'):
            if len(parts) > 1:
                # Check for -q flag
                idx = 1
                while idx < len(parts) and parts[idx].startswith('-'):
                    idx += 1
                if idx < len(parts):
                    first_word = parts[idx].lower()

        # Handle full paths
        if '/' in first_word:
            first_word = first_word.split('/')[-1]

        # Handle .py, .sh extensions
        if first_word.endswith('.py'):
            first_word = first_word[:-3]
        if first_word.endswith('.sh'):
            first_word = first_word[:-3]

        # Check against known tools
        for category, tools in TOOL_CATEGORIES.items():
            for tool in tools:
                if first_word == tool.lower():
                    return tool

        # Return as-is if not in known tools
        return first_word if first_word else None

    def reset_stats(self):
        """Reset parsing statistics."""
        self.stats = {
            'processed': 0,
            'skipped_blocklist': 0,
            'skipped_short': 0,
            'sensitive_redacted': 0,
        }
