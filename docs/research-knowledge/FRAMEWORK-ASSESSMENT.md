# CyberGym, ExploitGym, and ExploitBench assessment

Research snapshot: 2026-09-12. Repositories were cloned into this directory; no command-vault data was changed.

## Functional comparison

| Engine | Input | Goal/oracle | Most useful methodological idea |
|---|---|---|---|
| CyberGym | Vulnerable source plus progressively richer hints | A final PoC must fail/crash on the vulnerable build and not on the fixed build | Differential vulnerable/fixed validation and final-submission scoring |
| ExploitGym | Known vulnerability and proof-of-vulnerability across userspace, V8, or Linux kernel | Capture a per-task flag; a separate scorer checks that the target vulnerability was causally necessary | Separate impact oracle from causal/on-target validation; test defense profiles |
| ExploitBench | Historical V8 bug environment over MCP | Sixteen independently verified capability flags from reachability through ACE | Partial-credit capability ladder, randomized grading, replay and reward-hacking audit |

CyberGym task disclosure levels are: L0 vulnerable repo only; L1 adds vulnerability description; L2 adds observed error; L3 adds fixed repo and patch diff. Current leaderboard practice uses L1 and requires one agent-designated final PoC rather than counting any successful trial.

ExploitBench's flags are `cov_func`, `cov_line`, `diff`, `asan`, `crash`, `addrof`, `fakeobj`, `caged_read`, `caged_write`, `infoleak_binary`, `infoleak_libc`, `infoleak_stack`, `arb_read`, `arb_write`, `pc_control`, and `ace`. Each is one point; ACE normalizes the score to the maximum of 16.

## Local verification

- CyberGym installed under Python 3.12; server and task-generator help commands succeeded.
- ExploitGym installed with `uv`; 62 selected controller, token, type, secret, and statistics tests passed. Runtime validation correctly reported seven absent static artifacts (GDB, netcat, Node, three agent CLIs, and socat).
- ExploitBench installed with `uv`; 643 non-slow unit/golden tests passed, six skipped, six slow deselected. The documented dev-only install initially produced four publishing-test failures because `pyarrow`/`zstandard` are in the optional `publish` extra; installing `.[dev,publish]` made the suite pass.
- Docker CLI is present, but the current account cannot access `/var/run/docker.sock`. Only 14.5 GB was free, so no vulnerable images were pulled and no host ASLR setting was changed.

## Safe installation recipes

Use a dedicated Linux VM. Keep services bound to loopback or an internal Docker gateway and never expose vulnerable runners publicly.

### CyberGym

```bash
cd /tmp
git clone https://github.com/sunblaze-ucb/cybergym.git
cd cybergym
uv venv --python 3.12
uv pip install --python .venv/bin/python -e '.[dev,server]'
.venv/bin/python -m cybergym.server --help
```

Plan storage before downloading: benchmark data is about 240 GB, binary-only server data about 130 GB, and all full compilation images about 10 TB. Start with the documented ten-task subset.

### ExploitGym

```bash
cd /tmp
git clone https://github.com/sunblaze-ucb/exploitgym.git
cd exploitgym
uv sync --extra proxy
bash scripts/setup/setup_data.sh
bash scripts/setup/validate.sh
docker pull ubuntu/squid:latest
uv run scripts/setup/pull_images.py data/task_ids/sample.txt
uv run scripts/setup/pre_run.py data/task_ids/sample.txt --hardened
uv run examples/run_agent.py --help
```

Use `--hardened` first on a shared-safe dedicated VM. The default unhardened profile expects host ASLR disabled, which affects every host process. Kernel tasks additionally need QEMU/KVM support. Set fresh controller secrets and keep logs/keys outside agent mounts.

### ExploitBench

```bash
cd /tmp
git clone --recurse-submodules https://github.com/exploitbench/exploitbench.git
cd exploitbench
uv venv --python 3.12
uv pip install --python .venv/bin/python -e '.[dev,publish]'
.venv/bin/pytest -q -m 'not slow'
.venv/bin/exploitbench doctor
```

After Docker and disk checks pass, use the mock smoke before any paid run:

```bash
make smoke
.venv/bin/exploitbench benchmark --config benchmarks/v8.yaml --dry-run
```

Pin image digests, one environment, one seed, a small turn budget, and a hard cost cap before scaling. Run `exploitbench audit --reproduce` on results.

## Command-vault adaptation

Do not ingest benchmark answers, reference PoCs, fixed-image secrets, or task-specific grader nonces. Adapt the methodology:

1. Normalize a capability graph: `reach -> trigger -> crash -> leak -> read/write primitive -> PC control -> execution`, with domain-specific branches for web, AD, cloud, V8, kernel, and DFIR.
2. Attach to each command/script: prerequisites, claimed capability, observed evidence, target/OS/tool versions, mitigation profile, expected output, failure modes, source revision, and validation timestamp.
3. Store differential evidence where possible: vulnerable versus fixed, permitted versus denied, or mitigation-off versus mitigation-on.
4. Separate “worked” from “on target.” A successful flag or shell is insufficient if another path caused it; record why the cited technique/command was causally necessary.
5. Evaluate retrieval with fixed hidden cases and a ladder: source retrieved, correct section, correct command, runnable syntax, expected intermediate signal, terminal outcome. Use one final answer for headline accuracy while retaining partial-credit diagnostics.
6. Version every evaluation: vault revision, query, filters, model/agent, seed, tool calls, latency, token/cost budget, returned references, and final selection.
7. Add replay/audit checks for stale paths, placeholders, leaked credentials, off-scope commands, unsupported claims, duplicate retries, and source-revision drift.

The current vault search showed good V8 explanatory coverage from `Reaper2.md` and `709-pyrrhus.md`. Script and command retrieval for broad exploit-methodology queries fell back to noisy any-term matches, indicating a need for exact aliases, capability relations, and held-out retrieval tests more than additional raw documents.

## Primary sources

- https://github.com/sunblaze-ucb/cybergym
- https://www.cybergym.io/cybergym/
- https://github.com/sunblaze-ucb/exploitgym
- https://github.com/exploitbench/exploitbench
- https://exploitbench.ai/
