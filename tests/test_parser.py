"""Tests for the writeup parser."""

import pytest
from command_vault.parser import WriteupParser
from command_vault.security import SecurityFilter
from command_vault.models import WriteupType


@pytest.fixture
def parser():
    return WriteupParser()


class TestWriteupTypeDetection:
    def test_detect_box(self, parser):
        result = parser.detect_writeup_type('/home/user/labs/AI/boxes/Authority.md')
        assert result['type'] == WriteupType.BOX
        assert result['challenge_type'] is None

    def test_detect_challenge(self, parser):
        result = parser.detect_writeup_type('/home/user/labs/AI/challenges/0xBOverchunked (web).md')
        assert result['type'] == WriteupType.CHALLENGE
        assert result['challenge_type'] == 'web'

    def test_detect_sherlock(self, parser):
        result = parser.detect_writeup_type('/home/user/labs/AI/sherlocks/Takedown (Easy).md')
        assert result['type'] == WriteupType.SHERLOCK
        assert result['difficulty'] == 'Easy'


class TestSecurityFilter:
    def test_flag_redaction(self):
        sf = SecurityFilter()
        text = "The flag is HTB{test_flag_123}"
        result = sf.sanitize_text(text)
        assert 'HTB{' not in result
        assert '{FLAG_REDACTED}' in result

    def test_vl_flag_redaction(self):
        sf = SecurityFilter()
        text = "Got the flag: VL{another_test_flag}"
        result = sf.sanitize_text(text)
        assert 'VL{' not in result

    def test_skip_flag_output(self):
        sf = SecurityFilter()
        assert sf.should_skip_line('cat user.txt')
        assert sf.should_skip_line('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4')
        assert not sf.should_skip_line('nmap -sC -sV target')


class TestCommandExtraction:
    def test_extract_bash_command(self, parser):
        content = '''
## Enumeration

```bash
$ nmap -sC -sV 10.10.11.222
PORT   STATE SERVICE
22/tcp open  ssh
```
'''
        blocks = parser.extract_code_blocks(content)
        assert len(blocks) == 1
        assert blocks[0].language == 'bash'

        commands = parser.extract_commands(blocks[0])
        assert len(commands) == 1
        assert 'nmap' in commands[0].raw_command
        assert commands[0].tool_name == 'nmap'

    def test_extract_powershell_command(self, parser):
        content = '''
```powershell
PS C:\\Users\\admin> Get-Process
```
'''
        blocks = parser.extract_code_blocks(content)
        commands = parser.extract_commands(blocks[0])
        assert len(commands) >= 1


class TestTemplatization:
    def test_ip_templatization(self, parser):
        template = parser._templatize('nmap -sC -sV 10.10.11.222')
        assert '{TARGET_IP}' in template

    def test_lab_domain_templatization(self, parser):
        template = parser._templatize('bloodhound-python -d authority.htb')
        assert '{TARGET}' in template

    def test_vl_domain_templatization(self, parser):
        template = parser._templatize('bloodhound-python -d target.vl')
        assert '{TARGET}' in template


class TestToolIdentification:
    def test_identify_impacket(self, parser):
        tool = parser._identify_tool('impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL')
        assert tool == 'impacket-secretsdump'

    def test_identify_with_sudo(self, parser):
        tool = parser._identify_tool('sudo nmap -sC -sV 10.10.10.10')
        assert tool == 'nmap'

    def test_identify_python_module(self, parser):
        tool = parser._identify_tool('python3 -m http.server 8000')
        assert tool == 'http.server'


class TestTagExtraction:
    """Tests for tag extraction functionality."""

    def test_extract_header_tags_legacy(self, parser):
        """Legacy mode: only extract tags from Tags: header line."""
        content = '''# TestBox

Tags: #windows #ad #easy

Some content with #inline tags that should be ignored.
'''
        tags = parser._extract_all_tags(content, full_scan=False)
        assert 'windows' in tags
        assert 'ad' in tags
        assert 'easy' in tags
        assert 'inline' not in tags

    def test_extract_tags_full_scan(self, parser):
        """Full scan mode: extract tags from entire content."""
        content = '''# TestBox

Tags: #windows

This is a #challenge for #web exploitation.

Also uses #crypto techniques.
'''
        tags = parser._extract_all_tags(content, full_scan=True)
        assert 'windows' in tags
        assert 'challenge' in tags
        assert 'web' in tags
        assert 'crypto' in tags

    def test_filter_false_positive_tags(self, parser):
        """Should filter out code-like patterns."""
        content = '''# TestBox

Tags: #windows #ad

```c
#include <stdio.h>
#define MAX_SIZE 100
#pragma once
```

Also check #if condition.
'''
        tags = parser._extract_all_tags(content, full_scan=True)
        assert 'windows' in tags
        assert 'ad' in tags
        assert 'include' not in tags
        assert 'define' not in tags
        assert 'pragma' not in tags
        # Note: #if at start of word should be filtered as it's in blocklist

    def test_tags_are_lowercase(self, parser):
        """All tags should be normalized to lowercase."""
        content = '''# TestBox
Tags: #Windows #ACTIVE_DIRECTORY #Easy
'''
        tags = parser._extract_all_tags(content, full_scan=False)
        assert 'windows' in tags
        assert 'active_directory' in tags
        assert 'easy' in tags
        assert 'Windows' not in tags


class TestUnifiedDirTypeDetection:
    """Tests for content-based type detection in unified dir mode."""

    def test_detect_sherlock_from_content_tag(self, parser):
        """Unified dir: detect sherlock type from #sherlock tag."""
        content = '''# Investigation Writeup

#sherlock #dfir #windows

Analyzing the log files...
'''
        result = parser.detect_writeup_type(
            '/home/user/writeups/Investigation.md',
            content=content,
            source_dir='unified'
        )
        assert result['type'] == WriteupType.SHERLOCK
        assert result['challenge_type'] == 'dfir'

    def test_detect_challenge_from_content_tag(self, parser):
        """Unified dir: detect challenge type from #challenge tag."""
        content = '''# Web Exploit

#challenge #web #sqli

This challenge involves SQL injection...
'''
        result = parser.detect_writeup_type(
            '/home/user/writeups/WebExploit.md',
            content=content,
            source_dir='unified'
        )
        assert result['type'] == WriteupType.CHALLENGE
        assert result['challenge_type'] == 'web'

    def test_detect_box_from_content_tag(self, parser):
        """Unified dir: detect box type from #box tag."""
        content = '''# HackBox

#box #linux #medium

Starting enumeration...
'''
        result = parser.detect_writeup_type(
            '/home/user/writeups/HackBox.md',
            content=content,
            source_dir='unified'
        )
        assert result['type'] == WriteupType.BOX

    def test_default_to_box_in_unified(self, parser):
        """Unified dir: default to box when no type tag present."""
        content = '''# Some Machine

#linux #easy

No explicit type tag.
'''
        result = parser.detect_writeup_type(
            '/home/user/writeups/SomeMachine.md',
            content=content,
            source_dir='unified'
        )
        assert result['type'] == WriteupType.BOX

    def test_legacy_dir_ignores_content(self, parser):
        """Legacy dir: should use path-based detection, ignore content tags."""
        content = '''# BoxName

#sherlock

This has sherlock tag but is in boxes directory.
'''
        result = parser.detect_writeup_type(
            '/home/user/labs/boxes/BoxName.md',
            content=content,
            source_dir='boxes'
        )
        assert result['type'] == WriteupType.BOX  # From path, not content


class TestWriteupParsing:
    """Tests for full writeup parsing with tags."""

    def test_parse_writeup_unified_auto_tags(self, parser):
        """Unified dir: auto-add type as tag."""
        content = '''# TestBox (Easy)

#windows #ad

Enumeration section...
'''
        writeup = parser.parse_writeup(
            '/home/user/writeups/TestBox.md',
            content,
            full_scan=True,
            source_dir='unified'
        )
        assert 'windows' in writeup.tags
        assert 'ad' in writeup.tags
        assert 'box' in writeup.tags  # Auto-added type tag

    def test_parse_writeup_legacy_no_auto_tags(self, parser):
        """Legacy dir: don't auto-add type as tag."""
        content = '''# TestBox

Tags: #windows #ad

Enumeration section...
'''
        writeup = parser.parse_writeup(
            '/home/user/labs/boxes/TestBox.md',
            content,
            full_scan=False,
            source_dir='boxes'
        )
        assert 'windows' in writeup.tags
        assert 'ad' in writeup.tags
        assert 'box' not in writeup.tags  # Legacy mode: no auto type tag
