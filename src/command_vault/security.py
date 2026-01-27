"""Security filters and sanitization for Command Vault."""

import re
from typing import Optional
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# CTF FLAG PATTERNS - These are completely redacted
# =============================================================================
FLAG_PATTERNS = [
    re.compile(r'HTB\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),
    re.compile(r'VL\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),
    re.compile(r'CTF\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),
    re.compile(r'FLAG\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),
    re.compile(r'flag\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),
    re.compile(r'picoCTF\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),
    re.compile(r'DEAD\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),
    re.compile(r'THM\{[A-Za-z0-9_!@#$%^&*()\-.,]{1,100}\}'),  # TryHackMe
    re.compile(r'FLAG-[A-Za-z0-9\-]{20,}'),
]

# Standalone hash that's likely a flag (user.txt/root.txt content)
STANDALONE_HASH_PATTERN = re.compile(r'^[a-f0-9]{32}$')


# =============================================================================
# SECRET PATTERNS - Redacted but structure preserved
# =============================================================================
SECRET_PATTERNS = [
    (re.compile(r'(api[_-]?key\s*[=:]\s*)[\'"]?[A-Za-z0-9_\-]{20,}[\'"]?', re.I), r'\1{API_KEY}'),
    (re.compile(r'(token\s*[=:]\s*)[\'"]?[A-Za-z0-9_.\-]{20,}[\'"]?', re.I), r'\1{TOKEN}'),
    (re.compile(r'(secret\s*[=:]\s*)[\'"]?[^\s\'"]{10,}[\'"]?', re.I), r'\1{SECRET}'),
    (re.compile(r'(aws_secret_access_key\s*[=:]\s*)[^\s]{20,}', re.I), r'\1{AWS_SECRET}'),
    (re.compile(r'(private_key\s*[=:]\s*)[^\s]+', re.I), r'\1{PRIVATE_KEY}'),
]

# SSH private key blocks
SSH_KEY_PATTERN = re.compile(
    r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'
)


# =============================================================================
# SKIP PATTERNS - Lines to completely exclude from indexing
# =============================================================================
SKIP_LINE_PATTERNS = [
    re.compile(r'cat\s+(user|root)\.txt', re.I),
    re.compile(r'type\s+(user|root)\.txt', re.I),
    re.compile(r'Get-Content\s+(user|root)\.txt', re.I),
    re.compile(r'^\s*[a-f0-9]{32}\s*$'),  # Standalone MD5-like hash
]


class SecurityFilter:
    """Handles sanitization and filtering of sensitive content."""

    def __init__(self, custom_flag_patterns: Optional[list[str]] = None):
        self.flag_patterns = FLAG_PATTERNS.copy()
        if custom_flag_patterns:
            for pattern in custom_flag_patterns:
                try:
                    self.flag_patterns.append(re.compile(pattern))
                except re.error as e:
                    logger.warning(f"Invalid custom flag pattern '{pattern}': {e}")

        self.redaction_log: list[dict] = []

    def sanitize_text(self, text: str, source_file: str = "unknown") -> str:
        """
        Remove or redact sensitive data from text.

        Args:
            text: The text to sanitize
            source_file: Source filename for logging

        Returns:
            Sanitized text safe for storage
        """
        original_text = text

        # Remove CTF flags
        for pattern in self.flag_patterns:
            matches = pattern.findall(text)
            if matches:
                for match in matches:
                    self._log_redaction(source_file, "flag", match[:20] + "...")
                text = pattern.sub('{FLAG_REDACTED}', text)

        # Remove SSH private keys
        if SSH_KEY_PATTERN.search(text):
            self._log_redaction(source_file, "ssh_key", "Private key block")
            text = SSH_KEY_PATTERN.sub('{PRIVATE_KEY_REDACTED}', text)

        # Redact secrets but keep structure
        for pattern, replacement in SECRET_PATTERNS:
            if pattern.search(text):
                self._log_redaction(source_file, "secret", pattern.pattern[:30])
                text = pattern.sub(replacement, text)

        return text

    def should_skip_line(self, line: str) -> bool:
        """
        Check if a line should be completely skipped (not indexed).

        Args:
            line: The line to check

        Returns:
            True if line should be skipped
        """
        line = line.strip()

        # Skip empty lines
        if not line:
            return True

        # Skip flag output lines
        for pattern in SKIP_LINE_PATTERNS:
            if pattern.search(line):
                return True

        # Skip standalone hashes (likely flags)
        if STANDALONE_HASH_PATTERN.match(line):
            return True

        return False

    def should_skip_command(self, command: str) -> bool:
        """
        Check if a command should be skipped entirely.

        Args:
            command: The command string

        Returns:
            True if command should not be indexed
        """
        command_lower = command.lower().strip()

        # Skip flag retrieval commands
        skip_commands = [
            'cat user.txt',
            'cat root.txt',
            'type user.txt',
            'type root.txt',
            'get-content user.txt',
            'get-content root.txt',
        ]

        for skip_cmd in skip_commands:
            if skip_cmd in command_lower:
                return True

        return False

    def _log_redaction(self, source: str, redaction_type: str, detail: str):
        """Log a redaction for audit purposes."""
        self.redaction_log.append({
            'source': source,
            'type': redaction_type,
            'detail': detail,
        })
        logger.debug(f"[REDACTED] {source} - {redaction_type}: {detail}")

    def get_redaction_summary(self) -> dict:
        """Get summary of redactions performed."""
        summary = {
            'total': len(self.redaction_log),
            'by_type': {},
            'by_source': {},
        }

        for entry in self.redaction_log:
            # Count by type
            rtype = entry['type']
            summary['by_type'][rtype] = summary['by_type'].get(rtype, 0) + 1

            # Count by source
            source = entry['source']
            summary['by_source'][source] = summary['by_source'].get(source, 0) + 1

        return summary

    def clear_log(self):
        """Clear the redaction log."""
        self.redaction_log = []
