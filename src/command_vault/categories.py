"""Pre-defined categories and tool mappings for Command Vault."""

# =============================================================================
# CATEGORIES
# =============================================================================
CATEGORIES = {
    # Core categories (Boxes)
    "recon": "Reconnaissance & Scanning",
    "web": "Web Application Testing",
    "ad": "Active Directory",
    "smb": "SMB/File Shares",
    "wifi": "Wireless Attacks",
    "privesc": "Privilege Escalation",
    "creds": "Credential Attacks",
    "shells": "Shells & Payloads",
    "pivot": "Pivoting & Tunneling",
    "database": "Database Access",

    # Challenge-specific
    "pwn": "Binary Exploitation",
    "reversing": "Reverse Engineering",
    "crypto_tools": "Cryptographic Analysis",
    "mobile": "Mobile Security",
    "emulation": "CPU Emulation",
    "blockchain": "Smart Contract Analysis",
    "hardware": "Hardware Hacking",

    # DFIR/Sherlock
    "dfir": "Digital Forensics",
    "log_analysis": "Log Analysis (SIEM)",
    "network_forensics": "Network Forensics",
    "disk_forensics": "Disk Artifact Analysis",
    "memory_forensics": "Memory Forensics",
    "malware": "Malware Analysis",
    "cloud_forensics": "Cloud Investigation",

    # General
    "osint": "Open Source Intelligence",
    "misc": "Miscellaneous",
}


# =============================================================================
# TOOL TO CATEGORY MAPPING
# =============================================================================
TOOL_CATEGORIES = {
    # Recon
    "nmap": "recon",
    "masscan": "recon",
    "rustscan": "recon",
    "ping": "recon",
    "traceroute": "recon",
    "whatweb": "recon",
    "wafw00f": "recon",

    # Web
    "gobuster": "web",
    "ffuf": "web",
    "feroxbuster": "web",
    "dirb": "web",
    "dirsearch": "web",
    "wfuzz": "web",
    "nikto": "web",
    "sqlmap": "web",
    "curl": "web",
    "wget": "web",
    "httpx": "web",
    "nuclei": "web",
    "burpsuite": "web",
    "wpscan": "web",
    "droopescan": "web",
    "joomscan": "web",

    # Active Directory
    "bloodhound-python": "ad",
    "bloodhound": "ad",
    "crackmapexec": "ad",
    "cme": "ad",
    "netexec": "ad",
    "nxc": "ad",
    "certipy": "ad",
    "certipy-ad": "ad",
    "rubeus": "ad",
    "mimikatz": "ad",
    "pypykatz": "ad",
    "ldapsearch": "ad",
    "ldapdomaindump": "ad",
    "windapsearch": "ad",
    "adidnsdump": "ad",
    "bloodyad": "ad",
    "ldeep": "ad",
    "petitpotam": "ad",
    "coercer": "ad",
    "krbrelayx": "ad",
    "targetedkerberoast": "ad",
    "gettgtpkinit": "ad",
    "getnthash": "ad",
    "dacledit": "ad",
    "owneredit": "ad",
    "addcomputer": "ad",

    # Impacket tools
    "impacket-psexec": "ad",
    "impacket-wmiexec": "ad",
    "impacket-smbexec": "ad",
    "impacket-atexec": "ad",
    "impacket-dcomexec": "ad",
    "impacket-secretsdump": "ad",
    "impacket-getTGT": "ad",
    "impacket-getST": "ad",
    "impacket-GetNPUsers": "ad",
    "impacket-GetUserSPNs": "ad",
    "impacket-ticketer": "ad",
    "impacket-ntlmrelayx": "ad",
    "impacket-smbserver": "smb",
    "impacket-mssqlclient": "database",
    "impacket-reg": "ad",
    "impacket-addcomputer": "ad",
    "impacket-rbcd": "ad",
    "impacket-describeTicket": "ad",
    "impacket-changepasswd": "ad",
    "impacket-lookupsid": "ad",
    "impacket-samrdump": "ad",

    # SMB
    "smbmap": "smb",
    "smbclient": "smb",
    "enum4linux": "smb",
    "enum4linux-ng": "smb",
    "smbget": "smb",
    "rpcclient": "smb",
    "nbtstat": "smb",
    "nbtscan": "smb",

    # WiFi
    "aircrack-ng": "wifi",
    "airodump-ng": "wifi",
    "aireplay-ng": "wifi",
    "airmon-ng": "wifi",
    "airdecap-ng": "wifi",
    "eaphammer": "wifi",
    "hostapd": "wifi",
    "wpa_supplicant": "wifi",
    "bettercap": "wifi",
    "hcxdumptool": "wifi",
    "hcxpcapngtool": "wifi",

    # Privilege Escalation
    "linpeas": "privesc",
    "winpeas": "privesc",
    "pspy": "privesc",
    "linux-exploit-suggester": "privesc",
    "windows-exploit-suggester": "privesc",
    "seatbelt": "privesc",
    "sharphound": "privesc",
    "powerup": "privesc",
    "privesccheck": "privesc",
    "sudo": "privesc",

    # Credentials
    "hashcat": "creds",
    "john": "creds",
    "hydra": "creds",
    "medusa": "creds",
    "patator": "creds",
    "cewl": "creds",
    "crunch": "creds",
    "hash-identifier": "creds",
    "nth": "creds",
    "name-that-hash": "creds",
    "secretsdump": "creds",
    "ansible2john": "creds",
    "ssh2john": "creds",
    "zip2john": "creds",
    "rar2john": "creds",
    "keepass2john": "creds",
    "pfx2john": "creds",
    "office2john": "creds",

    # Shells & Payloads
    "msfvenom": "shells",
    "msfconsole": "shells",
    "nc": "shells",
    "netcat": "shells",
    "ncat": "shells",
    "socat": "shells",
    "rlwrap": "shells",
    "pwncat": "shells",
    "powercat": "shells",

    # Pivoting
    "chisel": "pivot",
    "ligolo-ng": "pivot",
    "ligolo": "pivot",
    "sshuttle": "pivot",
    "proxychains": "pivot",
    "proxychains4": "pivot",
    "ssh": "pivot",
    "plink": "pivot",
    "ngrok": "pivot",
    "bore": "pivot",

    # Database
    "mysql": "database",
    "psql": "database",
    "mssqlclient.py": "database",
    "odat": "database",
    "sqlplus": "database",
    "mongo": "database",
    "redis-cli": "database",

    # PWN / Binary Exploitation
    "gdb": "pwn",
    "pwndbg": "pwn",
    "gef": "pwn",
    "peda": "pwn",
    "ropper": "pwn",
    "ROPgadget": "pwn",
    "one_gadget": "pwn",
    "checksec": "pwn",
    "patchelf": "pwn",
    "pwn": "pwn",
    "pwntools": "pwn",

    # Reversing
    "ghidra": "reversing",
    "ida": "reversing",
    "radare2": "reversing",
    "r2": "reversing",
    "rizin": "reversing",
    "cutter": "reversing",
    "strings": "reversing",
    "file": "reversing",
    "objdump": "reversing",
    "readelf": "reversing",
    "nm": "reversing",
    "ltrace": "reversing",
    "strace": "reversing",
    "binwalk": "reversing",
    "upx": "reversing",
    "uncompyle6": "reversing",
    "pycdc": "reversing",
    "dnspy": "reversing",
    "ilspy": "reversing",
    "jd-gui": "reversing",
    "jadx": "reversing",
    "jadx-gui": "reversing",
    "dex2jar": "reversing",
    "apktool": "mobile",
    "die": "reversing",

    # Mobile
    "frida": "mobile",
    "objection": "mobile",
    "adb": "mobile",
    "aapt": "mobile",

    # Emulation
    "unicorn": "emulation",
    "keystone": "emulation",
    "capstone": "emulation",
    "qemu": "emulation",

    # Crypto Tools
    "openssl": "crypto_tools",
    "gpg": "crypto_tools",
    "ansible-vault": "crypto_tools",
    "cyberchef": "crypto_tools",
    "hashpump": "crypto_tools",
    "rsactftool": "crypto_tools",

    # DFIR
    "volatility": "memory_forensics",
    "volatility3": "memory_forensics",
    "vol": "memory_forensics",
    "vol3": "memory_forensics",
    "rekall": "memory_forensics",
    "aeskeyfind": "memory_forensics",

    # Disk Forensics
    "autopsy": "disk_forensics",
    "sleuthkit": "disk_forensics",
    "fls": "disk_forensics",
    "icat": "disk_forensics",
    "mmls": "disk_forensics",
    "MFTECmd": "disk_forensics",
    "PECmd": "disk_forensics",
    "AmcacheParser": "disk_forensics",
    "AppCompatCacheParser": "disk_forensics",
    "ShellBagsExplorer": "disk_forensics",
    "RegistryExplorer": "disk_forensics",
    "KAPE": "disk_forensics",
    "plaso": "disk_forensics",
    "log2timeline": "disk_forensics",

    # Network Forensics
    "wireshark": "network_forensics",
    "tshark": "network_forensics",
    "tcpdump": "network_forensics",
    "NetworkMiner": "network_forensics",
    "zeek": "network_forensics",
    "bro": "network_forensics",
    "snort": "network_forensics",

    # Log Analysis
    "splunk": "log_analysis",
    "chainsaw": "log_analysis",
    "hayabusa": "log_analysis",
    "evtxecmd": "log_analysis",
    "logparser": "log_analysis",
    "zircolite": "log_analysis",

    # Malware Analysis
    "pestudio": "malware",
    "peview": "malware",
    "x64dbg": "malware",
    "x32dbg": "malware",
    "ollydbg": "malware",
    "procmon": "malware",
    "process-monitor": "malware",
    "yara": "malware",
    "capa": "malware",
    "floss": "malware",

    # Cloud
    "aws": "cloud_forensics",
    "az": "cloud_forensics",
    "gcloud": "cloud_forensics",
    "kubectl": "cloud_forensics",

    # OSINT
    "theHarvester": "osint",
    "sherlock": "osint",
    "maltego": "osint",
    "spiderfoot": "osint",
    "recon-ng": "osint",
    "amass": "osint",
    "subfinder": "osint",
    "assetfinder": "osint",
    "sublist3r": "osint",

    # Misc
    "git": "misc",
    "docker": "misc",
    "python": "misc",
    "python3": "misc",
    "php": "misc",
    "base64": "misc",
    "xxd": "misc",
    "hexdump": "misc",
    "exiftool": "misc",
    "steghide": "misc",
    "stegseek": "misc",
    "zsteg": "misc",
    "foremost": "misc",
    "evil-winrm": "shells",
    "xfreerdp": "misc",
    "rdesktop": "misc",
    "vncviewer": "misc",
}


# =============================================================================
# TOOL ALIASES
# =============================================================================
TOOL_ALIASES = {
    "cme": "crackmapexec",
    "nxc": "netexec",
    "bh": "bloodhound-python",
    "vol": "volatility",
    "vol3": "volatility3",
    "r2": "radare2",
    "nc": "netcat",
    "ncat": "netcat",
}


# =============================================================================
# IMPACKET PREFIX DETECTION
# =============================================================================
TOOL_PREFIXES = [
    "impacket-",
    "aircrack-",
    "airodump-",
    "aireplay-",
    "airmon-",
]


def get_tool_category(tool_name: str) -> str:
    """
    Get category for a tool, handling aliases and prefixes.

    Args:
        tool_name: The tool name (e.g., 'nmap', 'impacket-psexec')

    Returns:
        Category name or 'misc' if unknown
    """
    # Normalize
    tool_lower = tool_name.lower().strip()

    # Check aliases first
    if tool_lower in TOOL_ALIASES:
        tool_lower = TOOL_ALIASES[tool_lower]

    # Direct lookup
    if tool_lower in TOOL_CATEGORIES:
        return TOOL_CATEGORIES[tool_lower]

    # Check prefixes
    for prefix in TOOL_PREFIXES:
        if tool_lower.startswith(prefix):
            # Try full name first
            if tool_lower in TOOL_CATEGORIES:
                return TOOL_CATEGORIES[tool_lower]
            # Otherwise use prefix category
            prefix_tool = prefix.rstrip("-")
            if prefix_tool in TOOL_CATEGORIES:
                return TOOL_CATEGORIES[prefix_tool]

    return "misc"


def get_category_description(category: str) -> str:
    """Get description for a category."""
    return CATEGORIES.get(category, "Miscellaneous")
