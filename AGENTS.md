# AGENTS.md - AI Assistant Usage Guide

## When to Use Command Vault

Use the vault MCP tools when the user needs:

### Specific Tool Syntax
- Exact command flags and options from real-world usage
- Examples: `certipy`, `bloodyAD`, `MSOLSpray`, `targetedKerberoast`

### Technique-Specific Commands
- Attack techniques with specific tool combinations
- Examples: "ESC13 exploitation", "kerberoasting", "ADCS abuse", "shadow credentials"

### Past Solutions
- How similar problems were solved before
- Commands from specific writeups (boxes, challenges, sherlocks)

### Shell History Recall
- Commands the user has run before
- "What was that sliver command I used?"
- "How did I run neo4j last time?"

### Exploit Scripts
- Python exploits using `pwntools`, `requests`, `impacket`
- Frida scripts for mobile
- PowerShell payloads

## When to Use LLM Knowledge

Rely on built-in knowledge for:

### Concepts and Theory
- "What is Kerberos delegation?"
- "How does NTLM relay work?"
- "Explain ADCS certificate templates"

### General Tool Usage
- Common tools with well-known syntax (nmap, gobuster, ffuf)
- Basic flag explanations

### Troubleshooting
- Error interpretation
- Debugging failed exploits
- Alternative approaches

### Attack Planning
- Methodology and attack chains
- Combining techniques
- Prioritizing attack vectors

## Tool Selection Guide

| User Request | Use |
|--------------|-----|
| "Find certipy commands" | `search_commands` |
| "How did I exploit ESC8?" | `search_commands` |
| "Show me kerberoasting examples" | `search_commands` |
| "Python script for buffer overflow" | `search_scripts` |
| "What tools for AD enumeration?" | `suggest_command` |
| "List all nmap examples" | `get_tool_examples` |
| "What sliver command did I use?" | `search_history` |
| "How did I run hashcat last time?" | `search_history` |
| "Show my recent bloodhound commands" | `search_history` |
| "What is kerberoasting?" | LLM knowledge |
| "Why is my exploit failing?" | LLM knowledge |

## Best Practice: Hybrid Approach

1. **Search vault first** for real-world examples with context
2. **Check history** for user's own past commands
3. **Use LLM** to explain, adapt, or troubleshoot the commands
4. **Combine all** when building attack chains

## Example Interactions

### Writeup Search
```
User: "I need to exploit ESC1"

Good approach:
1. search_commands(query="ESC1") → Get real commands from past labs
2. Explain the ESC1 vulnerability context
3. Adapt commands to user's current target
```

### History Recall
```
User: "What was the command for running sliver?"

Good approach:
1. search_history(query="sliver") → Find user's actual past commands
2. Return the exact command they used before
```

### Combined Search
```
User: "Show me certipy examples"

Good approach:
1. search_commands(query="certipy") → Writeup examples with context
2. search_history(query="certipy") → User's own usage
3. Present both for complete picture
```
