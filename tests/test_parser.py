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
