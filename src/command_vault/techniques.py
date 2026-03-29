"""Technique extraction from writeup tags for cross-writeup linking.

Maps tags to canonical technique names. Tags are the single source of truth —
no prose scanning, no false positives from technique mentions in text.
"""

# Tag -> canonical technique name (lowercase tag keys)
TAG_TECHNIQUE_MAP: dict[str, str] = {
    # --- Active Directory ---
    'ad': 'Active Directory',
    'kerberos': 'Kerberos',
    'kerberoasting': 'Kerberoasting',
    'asreproasting': 'AS-REP Roasting',
    'adcs': 'ADCS',
    'esc1': 'ADCS ESC1',
    'esc4': 'ADCS ESC4',
    'esc7': 'ADCS ESC7',
    'esc8': 'ADCS ESC8',
    'esc9': 'ADCS ESC9',
    'esc16': 'ADCS ESC16',
    'adcs-esc1': 'ADCS ESC1',
    'adcs-esc4': 'ADCS ESC4',
    'adcs-esc6': 'ADCS ESC6',
    'adcs-esc7': 'ADCS ESC7',
    'adcs-esc8': 'ADCS ESC8',
    'adcs-esc9': 'ADCS ESC9',
    'adcs-esc16': 'ADCS ESC16',
    'esc3': 'ADCS ESC3',
    'esc6': 'ADCS ESC6',
    'esc10': 'ADCS ESC10',
    'esc13': 'ADCS ESC13',
    'esc14': 'ADCS ESC14',
    'esc15': 'ADCS ESC15',
    'adcs_domain_escalation': 'ADCS Domain Escalation',
    'adcs_domain_esc': 'ADCS Domain Escalation',
    'rbcd': 'RBCD',
    'dcsync': 'DCSync',
    'shadow_credential': 'Shadow Credentials',
    'shadow_credentials': 'Shadow Credentials',
    'gpo_abuse': 'GPO Abuse',
    'dacl': 'DACL Abuse',
    'genericall': 'GenericAll Abuse',
    'genericwrite': 'GenericWrite Abuse',
    'writedacl': 'WriteDACL Abuse',
    'writeowner': 'WriteOwner Abuse',
    'dpapi_extracting_passwords': 'DPAPI Credential Extraction',
    'dpapi': 'DPAPI Credential Extraction',
    'golden_ticket': 'Golden Ticket',
    'silver_ticket': 'Silver Ticket',
    'ntlm_relay': 'NTLM Relay',
    'constrained_delegation': 'Constrained Delegation',
    'unconstrained_delegation': 'Unconstrained Delegation',
    'kerberos_delegation': 'Kerberos Delegation',
    'kerberos_relay': 'Kerberos Relay',
    'coerced_authentication': 'Coerced Authentication',
    'petitpotam': 'PetitPotam',
    'gmsa': 'gMSA Abuse',
    'laps': 'LAPS',
    'domain_trust': 'Domain Trust Abuse',
    'password_spray': 'Password Spray',
    'logon_script_tampering': 'Logon Script Tampering',
    'wsus_abuse': 'WSUS Abuse',
    'sccm': 'SCCM Abuse',

    # --- Web ---
    'sqli': 'SQL Injection',
    'lfi': 'LFI',
    'rfi': 'RFI',
    'xss': 'XSS',
    'ssti': 'SSTI',
    'ssrf': 'SSRF',
    'ssrf-lfi': 'SSRF to LFI',
    'idor': 'IDOR',
    'csrf': 'CSRF',
    'xxe': 'XXE',
    'jwt': 'JWT Attack',
    'command_injection': 'Command Injection',
    'code_injection': 'Code Injection',
    'bash_command_injection': 'Bash Command Injection',
    'deserialization': 'Deserialization',
    'java_deserialization': 'Java Deserialization',
    'php_filter_chain': 'PHP Filter Chain',
    'websocket': 'WebSocket Attack',
    'nosql': 'NoSQL Injection',
    'nosql-injection': 'NoSQL Injection',
    'prototype_pollution': 'Prototype Pollution',
    'path_traversal': 'Path Traversal',
    'file_upload': 'File Upload Bypass',
    'authentication_bypass': 'Authentication Bypass',
    'saml_bypass': 'SAML Bypass',
    '2fa_bypass': '2FA Bypass',
    'rce': 'RCE',
    'flask_rce': 'RCE',
    'git_rce': 'RCE',
    'go_rce': 'RCE',
    'postgresql_rce': 'RCE',
    'pearcmd_rce': 'RCE',
    'maltrail_rce': 'RCE',
    'custom_code_rce': 'RCE',
    'dijango_secret_key_rce': 'RCE',
    'meta-git-rce': 'RCE',
    'preauthrce': 'RCE',
    'h2_rce': 'RCE',

    # --- Privilege Escalation ---
    'suid': 'SUID Abuse',
    'gtfobins': 'GTFOBins',
    'sudo_abuse': 'Sudo Abuse',
    'path_hijack': 'Path Hijack',
    'dll_hijacking': 'DLL Hijacking',
    'docker_escape': 'Docker Escape',
    'docker_privesc': 'Docker Privilege Escalation',
    'seimpersonateprivilege': 'SeImpersonate Abuse',
    'sebackupprivilege': 'SeBackupPrivilege Abuse',
    'custom_exploitation': 'Custom Exploitation',
    'binary_exploitation': 'Binary Exploitation',
    'buffer_overflow': 'Buffer Overflow',
    'seh_overwrite': 'SEH Overwrite',
    'rop': 'ROP Chain',
    'format_string': 'Format String',
    'race_condition': 'Race Condition',
    'applocker_bypass': 'AppLocker Bypass',
    'driver_exploit': 'Driver Exploit',

    # --- Credential ---
    'password_reuse': 'Password Reuse',
    'password-reuse': 'Password Reuse',
    'responder': 'Responder/LLMNR Poisoning',
    'ntlm_steal': 'NTLM Hash Stealing',
    'keepass': 'KeePass Exploitation',
    'mimikatz': 'Mimikatz',
    'phishing': 'Phishing',
    'macro': 'Malicious Macro',

    # --- Crypto ---
    'rsa': 'RSA',
    'aes': 'AES',

    # --- DFIR ---
    'memory_forensics': 'Memory Forensics',
    'network_forensics': 'Network Forensics',
    'disk_forensics': 'Disk Forensics',
    'log_analysis': 'Log Analysis',
    'malware': 'Malware Analysis',
    'malware_analysis': 'Malware Analysis',
    'ransomware': 'Ransomware',
    'windows_eventlog': 'Windows Event Log Analysis',
}

# Technique -> type classification
TECHNIQUE_TYPE: dict[str, str] = {
    # AD
    'Active Directory': 'ad', 'Kerberos': 'ad', 'Kerberoasting': 'ad',
    'AS-REP Roasting': 'ad', 'ADCS': 'ad', 'ADCS ESC1': 'ad',
    'ADCS ESC4': 'ad', 'ADCS ESC7': 'ad', 'ADCS ESC8': 'ad',
    'ADCS ESC3': 'ad', 'ADCS ESC6': 'ad',
    'ADCS ESC9': 'ad', 'ADCS ESC10': 'ad', 'ADCS ESC13': 'ad',
    'ADCS ESC14': 'ad', 'ADCS ESC15': 'ad', 'ADCS ESC16': 'ad',
    'ADCS Domain Escalation': 'ad',
    'RBCD': 'ad', 'DCSync': 'ad', 'Shadow Credentials': 'ad',
    'GPO Abuse': 'ad', 'DACL Abuse': 'ad', 'GenericAll Abuse': 'ad',
    'GenericWrite Abuse': 'ad', 'WriteDACL Abuse': 'ad', 'WriteOwner Abuse': 'ad',
    'DPAPI Credential Extraction': 'ad', 'Golden Ticket': 'ad', 'Silver Ticket': 'ad',
    'NTLM Relay': 'ad', 'Constrained Delegation': 'ad',
    'Unconstrained Delegation': 'ad', 'Kerberos Delegation': 'ad',
    'Kerberos Relay': 'ad', 'Coerced Authentication': 'ad',
    'PetitPotam': 'ad', 'gMSA Abuse': 'ad', 'LAPS': 'ad',
    'Domain Trust Abuse': 'ad', 'Password Spray': 'ad',
    'Logon Script Tampering': 'ad', 'WSUS Abuse': 'ad', 'SCCM Abuse': 'ad',
    # Web
    'SQL Injection': 'web', 'LFI': 'web', 'RFI': 'web', 'XSS': 'web',
    'SSTI': 'web', 'SSRF': 'web', 'SSRF to LFI': 'web', 'IDOR': 'web',
    'CSRF': 'web', 'XXE': 'web', 'JWT Attack': 'web',
    'Command Injection': 'web', 'Code Injection': 'web',
    'Bash Command Injection': 'web', 'Deserialization': 'web',
    'Java Deserialization': 'web', 'PHP Filter Chain': 'web',
    'WebSocket Attack': 'web', 'NoSQL Injection': 'web',
    'Prototype Pollution': 'web', 'Path Traversal': 'web',
    'File Upload Bypass': 'web', 'Authentication Bypass': 'web',
    'SAML Bypass': 'web', '2FA Bypass': 'web', 'RCE': 'web',
    # Privesc
    'SUID Abuse': 'privesc', 'GTFOBins': 'privesc', 'Sudo Abuse': 'privesc',
    'Path Hijack': 'privesc', 'DLL Hijacking': 'privesc',
    'Docker Escape': 'privesc', 'Docker Privilege Escalation': 'privesc',
    'SeImpersonate Abuse': 'privesc', 'SeBackupPrivilege Abuse': 'privesc',
    'Custom Exploitation': 'privesc', 'Binary Exploitation': 'privesc',
    'Buffer Overflow': 'privesc', 'SEH Overwrite': 'privesc',
    'ROP Chain': 'privesc', 'Format String': 'privesc',
    'Race Condition': 'privesc', 'AppLocker Bypass': 'privesc',
    'Driver Exploit': 'privesc',
    # Credential
    'Password Reuse': 'credential', 'Responder/LLMNR Poisoning': 'credential',
    'NTLM Hash Stealing': 'credential', 'KeePass Exploitation': 'credential',
    'Mimikatz': 'credential', 'Phishing': 'credential',
    'Malicious Macro': 'credential',
    # Crypto
    'RSA': 'crypto', 'AES': 'crypto',
    # DFIR
    'Memory Forensics': 'dfir', 'Network Forensics': 'dfir',
    'Disk Forensics': 'dfir', 'Log Analysis': 'dfir',
    'Malware Analysis': 'dfir', 'Ransomware': 'dfir',
    'Windows Event Log Analysis': 'dfir',
}


def extract_techniques_from_tags(tags: list[str]) -> list[dict]:
    """
    Map writeup tags to canonical technique names.

    Args:
        tags: List of tag names (any case)

    Returns:
        List of {'canonical': str, 'type': str}
        Deduplicated by canonical name.
    """
    found: dict[str, dict] = {}

    for tag in tags:
        tag_lower = tag.lower()
        canonical = TAG_TECHNIQUE_MAP.get(tag_lower)
        if canonical and canonical not in found:
            found[canonical] = {
                'canonical': canonical,
                'type': TECHNIQUE_TYPE.get(canonical, 'misc'),
            }

    return list(found.values())
