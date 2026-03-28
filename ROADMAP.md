# Command Vault — Roadmap

Development priorities for command-vault beyond the current FTS5 search.

**Current state (v1):** 657 writeups, 9,180 commands, 252 scripts, 20,371 prose chunks, 24,729 history entries. SQLite FTS5 with BM25 ranking. MCP integration for Claude Code.

**Design principle:** The search backend serves structured data to frontier models (Opus) that do the reasoning. Don't add a dumber intelligence layer (embeddings, RAG) in front of a smarter one. Instead, improve the **structure and relationships** in the data.

---

## 1. Cross-Writeup Technique Linking

**Problem:** The same technique (e.g., ADCS ESC8) appears across multiple writeups as isolated instances. No way to see all approaches for the same technique side by side.

**Solution:** Build a technique index that links writeups sharing the same attack technique, then surface consolidated views.

### CLI
```bash
vault related "ADCS ESC8"
→ Box A (Certified, 2024): certipy + petitpotam + ntlmrelayx
→ Box B (Escape, 2025): certipy + coercer + LDAP relay
→ Box C (Authority, 2025): certipy + printerbug + shadow creds
→ Common pattern: coercion → relay → cert request → auth
→ Variations: coercion method (3 different), relay target (LDAP vs HTTP)

vault related "kerberoasting" --diff
→ Shows what varied across instances (tools, flags, targets)
→ Shows what stayed constant (the core technique)
```

### MCP
```
search_related(technique="ADCS ESC8")
→ Returns grouped results with common patterns and variations
```

### Implementation notes
- Extract technique identifiers from tags, commands, and prose (MITRE ATT&CK IDs, tool names, known technique names like "ESC1-16", "kerberoasting", "shadow credentials")
- Build a `technique_writeups` junction table: technique → [writeup_id, commands_used, tools_used, date]
- Technique extraction can be rule-based (pattern matching on known technique names) — no ML needed
- The "common pattern" summary could be computed at index time (intersect tool sets across instances) or generated on-the-fly by the LLM from the grouped results

### Effort: Medium
- New table schema + indexer changes
- Technique name extraction (regex + known patterns list)
- New CLI command + MCP tool

---

## 2. Attack Chain Extraction

**Problem:** Writeups contain implicit multi-step attack chains (foothold → privesc → lateral → DA) but they're buried in prose and sequential commands. No way to search by attack pattern.

**Solution:** Extract ordered attack chains from writeups and make them queryable.

### CLI
```bash
vault chains --from "foothold" --to "domain admin"
→ 12 chains found across 47 box writeups
→ Most common path (7 boxes): foothold → kerberoast → hash crack → lateral → DCSync
→ Fastest (3 steps): foothold → ADCS ESC1 → DA cert → DCSync
→ Most creative: foothold → GenericWrite → shadow creds → RBCD → silver ticket → DA

vault chains --technique "RBCD"
→ Shows all chains that include Resource-Based Constrained Delegation
→ What came before (how RBCD was set up), what came after (how it was leveraged)

vault chains --box "Certified"
→ Shows the extracted chain for a specific writeup
→ foothold (HTTP) → SQL injection → creds → ADCS ESC1 → DA cert → DCSync
```

### MCP
```
search_chains(from_phase="foothold", to_phase="domain admin", limit=5)
get_chain(writeup="Certified")
```

### Implementation notes
- Writeups already have `## Enumeration`, `## Foothold`, `## Privilege Escalation`, `## Lateral Movement` etc. as section headers — use these as chain phase markers
- Map each section to a phase enum: `recon → foothold → privesc → lateral → persistence → objective`
- Extract the key technique per phase from commands + prose (e.g., "kerberoasting" from impacket-GetUserSPNs in the lateral section)
- Store as: `chain_steps(writeup_id, phase_order, phase_name, technique, tools[], commands[])`
- "Most common path" = frequency analysis across all extracted chains

### Effort: Medium-High
- Phase detection from section headers (mostly rule-based, writeup format is consistent)
- Technique-per-phase extraction (harder — needs tool→technique mapping + some heuristics)
- New query interface for chain search
- Aggregation logic for "most common path"

---

## 3. Temporal Awareness

**Problem:** All search results are equal regardless of when the writeup was written. A 2022 approach might be outdated (tool deprecated, technique patched), but it ranks the same as a 2025 approach.

**Solution:** Add date awareness to search ranking and filtering.

### CLI
```bash
vault search "certipy" --recent           # boost recent results
vault search "certipy" --after 2025-01    # only 2025+ results
vault search "certipy" --sort date        # sort by date (default: relevance)
vault search "kerberoasting" --evolution  # show how your approach evolved over time
```

### MCP
```
search_commands(query="certipy", sort="recent")    # recency-weighted
search_commands(query="certipy", after="2025-01")  # date filter
```

### Implementation notes
- Writeup dates can be extracted from: file modification time, git commit date, front-matter metadata, or the HTB machine/challenge release date
- Add `date` column to commands/scripts/chunks tables
- For `--recent` mode: multiply BM25 score by a recency decay factor (e.g., `score * exp(-age_days / 365)`)
- For `--evolution`: group by year/quarter, show technique/tool changes over time
- Store date as ISO string, index for range queries

### Effort: Low-Medium
- Date extraction (parse from filenames, git log, or HTB API)
- Schema change (add date column)
- Ranking adjustment (simple math on existing BM25 scores)
- New CLI flags

---

## 4. Success/Failure Annotation

**Problem:** Writeups contain both successful and unsuccessful approaches. A dead-end rabbit hole gets indexed alongside the actual solution. Currently no way to distinguish them.

**Solution:** Annotate commands and prose as "worked" vs "dead end" and allow filtering.

### CLI
```bash
vault search "SSTI" --worked              # only commands that led to progress
vault search "SSTI" --dead-ends           # see what didn't work (learn from failures)
vault search "SSTI" --annotated           # show annotations inline
```

### Writeup format extension
```markdown
## Foothold

Tried SQL injection but the input was sanitized:

```bash
# [dead-end]
$ sqlmap -u "http://target/login" --forms --batch
→ all parameters appear to be not injectable
```

Found SSTI in the template engine:

```bash
# [worked]
$ curl "http://target/" -d "name={{7*7}}"
→ 49
```
```

### Implementation notes
- **Explicit annotation** (preferred): add `# [worked]` / `# [dead-end]` / `# [rabbit-hole]` markers in code blocks. Parser extracts these during indexing
- **Implicit detection** (supplementary): heuristics based on writeup structure — commands after "this didn't work" / "no results" are likely dead ends; commands in the section that leads to the next phase header are likely successful
- Add `outcome` column to commands table: `null` (unknown), `worked`, `dead_end`
- Default search behavior unchanged; `--worked` filters to `outcome = 'worked'`
- Retroactive annotation of 657 existing writeups is the hard part — could be done incrementally, or with LLM assistance (Opus reads writeup, annotates commands)

### Effort: Medium
- Parser changes for annotation markers
- Schema change (outcome column)
- Heuristic detector for implicit annotation
- The real effort is annotating existing writeups (ongoing, not blocking)

---

## 5. Playbook Generation

**Problem:** Before starting a box, you manually recall "what do I usually do against Windows AD with MSSQL?" The vault has the data across 314 box writeups but no way to aggregate it into a prioritized attack plan.

**Solution:** Given a target profile, generate a prioritized attack playbook from historical data.

### CLI
```bash
vault playbook --os windows --services ldap,smb,mssql --domain-joined
→ Playbook based on 47 matching box writeups:
→
→ Phase 1: Enumeration (used in 47/47 boxes)
→   nxc smb $IP -u '' -p ''                    # null session (worked 12/47)
→   nxc smb $IP -u $USER -p $PASS --shares     # share enum (worked 38/47)
→   nxc ldap $IP -u $USER -p $PASS -M laps     # LAPS check (worked 8/47)
→   certipy find -u $USER -p $PASS -dc-ip $IP  # ADCS enum (worked 15/47)
→
→ Phase 2: Quick Wins (ordered by historical success rate)
→   kerberoasting  (succeeded 23/47, avg time to DA: 4 steps)
→   ADCS ESC1-4    (succeeded 15/47, avg time to DA: 3 steps)
→   MSSQL xp_cmdshell (succeeded 9/47, direct shell)
→
→ Phase 3: Lateral Movement
→   ...

vault playbook --os linux --services http,ssh --difficulty easy
→ Playbook based on 89 matching box writeups
→ ...

vault playbook --sherlock --category malware
→ Forensics playbook based on 28 matching Sherlocks
→ ...
```

### MCP
```
generate_playbook(os="windows", services=["ldap","smb","mssql"], domain_joined=true)
```

### Implementation notes
- Requires attack chain extraction (feature #2) as a prerequisite — need structured phase/technique data to aggregate
- Also benefits from success/failure annotation (feature #4) for success rate stats
- Target profile matching: filter writeups by OS tag, service presence in recon commands, difficulty tag
- Playbook is essentially: group matching writeups by phase → rank techniques by frequency → template the commands
- The `$IP`, `$USER`, `$PASS` templating already exists in command-vault (template generation feature)
- Could generate static playbooks at index time for common profiles, or compute on-the-fly

### Effort: High (depends on #2 and #4)
- Needs chain extraction and ideally success annotation first
- Profile matching logic
- Aggregation and ranking across writeups
- Template formatting
- New CLI command + MCP tool

---

## Priority Order

```
                    Low effort                    High effort
                    ─────────────────────────────────────────
High value     │  3. Temporal awareness    │  2. Attack chains     │
               │     (quick win)           │  5. Playbook gen      │
               ├───────────────────────────┼───────────────────────┤
Medium value   │  4. Success/failure       │  1. Technique linking │
               │     (incremental)         │                       │
                    ─────────────────────────────────────────
```

**Recommended order:**
1. **Temporal awareness** — lowest effort, immediate value. Just add dates and a `--recent` flag.
2. **Technique linking** — builds the technique index that #2 and #5 depend on.
3. **Attack chain extraction** — requires technique index from #1. Unlocks playbook generation.
4. **Success/failure annotation** — can be done incrementally alongside other work. Start with the annotation format, retroactively tag over time.
5. **Playbook generation** — the capstone feature. Needs #2 and benefits from #4.

---

## What We Explicitly Chose NOT to Build

### RAG / Semantic Search

Evaluated and rejected. Reasoning:

- **Opus already does the semantic reasoning.** FTS5 returns raw structured results; the frontier model interprets them. Adding an embedding layer puts a dumber intelligence (cosine similarity) in front of a smarter one (Opus reasoning).
- **Pentesting data is keyword-rich.** You search "certipy ESC8", not "that certificate thing." FTS5 with BM25 handles structured technical data better than embeddings.
- **Complexity cost.** Embedding model selection, chunking strategy, vector store, retrieval tuning, stale embeddings — all for marginal search improvement.
- **RAG may make sense for local models** where the model can't reason over 15 results well and needs pre-filtering to 3. But that's the local-llm use case, not the primary workflow. If needed, add it as a separate layer later without changing the core.

See `/opt/local-llms/doc/llm_internals_qa.md` for the full analysis.
