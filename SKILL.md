---
name: project-memory
description: "Before starting or retrying any BIOS/UEFI, platform-hardware, or firmware engineering debug, recall verified cases + known-bad paths (negative knowledge) so a past failure isn't repeated. Load on ANY such debug or before concluding a root cause: the topic examples (S3/S4 sleep, ACPI, USB, power, GPU, EC/GPIO, SPI) only aid recall — they are NOT the gate."
version: 3.4.0
author: Barnet Wang
license: Apache-2.0
---

# Failure-Aware Episodic Engineering Memory Skill (v3.4.0 Dream-RSI)

This skill gives the agent a persistent, cross-conversation memory of **structured engineering decisions, exploration trees, and negative knowledge**. Inspired by **Google Dream-RSI** (*Recursive Self-Improvement through Evolving Worlds*), it transforms static ticket caching into an active exploration policy guide with risk-aware pruning and offline policy synthesis.

---

## Core Workflow & When to Use (Agent Workflow)

### 1. Before Starting / Debugging (Answer, Search & Similar — one-shot reasoning + dedupe)
* **Agent decision evidence card (`answer` / `card`)**: **the recommended first call when a session starts**.
  - Token-level hybrid retrieval with synonym / Traditional↔Simplified expansion (e.g. `蓝屏` ↔ `藍屏` ↔ `bsod`, `睡眠` ↔ `s3`).
  - `--platform` and `--env` matching filters are applied automatically.
  - **Risk-aware pruning & `[HARD VETO]`**: Fatal/high-risk attempts are sorted to the top and flagged with hard vetoes.
  - **Diagnostic Policy Sequence (`diagnostic_policy`)**: Returns ordered SOP steps, pruned branch histories, and verification checks.
  - One call returns: the best verified solution, applicability constraints (`conditions`), code commit, and the do-not-try list (`do_not_try`).
* **Retrieve verified solutions (`search --verified-only`)**:
  - Stage 1 output carries a **`decision` directive field** (`adopt` / `avoid` / `candidate` / `superseded`).
* **Retrieve negative knowledge (`search --negative-only` / `search-invalid`)**:
  - Token-split OR matching — use it to **prune reasoning and avoid repeating a known failure**.
* **Dedupe before opening a ticket (`similar`)**: **always** run `similar --subject "..."` **before** creating a new issue.

### 2. During Investigation & Trial-Error (Note & Reject-Path — build the exploration tree)
* Use `note` to record investigation steps and experimental observations.
* When an attempt fails, **immediately** record it with `reject-path`:
  - `--approach`, `--reason`, `--failure-mode`, `--side-effect`, `--scope`
  - **Exploration Tree (`--parent-id`, `--branch-type`)**: Link child attempts to parent hypotheses (`hypothesis`, `probe`, `workaround`, `fix_attempt`).
  - **Risk Level (`--risk-level`)**: Tag with `fatal` (hardware trip/RTC lost), `high` (crash/corruption), `medium`, or `low`.
  - **MANDATORY: `--risk-level` is never omitted** (standing user commitment, 2026-09-21).
    Classification: `fatal` = power trip / hardware damage / RTC loss / protection-circuit event;
    `high` = crash, data or flash corruption, boot-brick risk;
    `medium` = failed path needing a reboot or significant time;
    `low` = compile/log-level dead end, trivial cost. When in doubt, over-rate, not under-rate.

### 3. Resolution & Closure (Close & Verify — anchor to real evidence)
* Use `close` to record the **root cause** and the **solution** explicitly.
* If the fix is validated by tests or CI, use `verify` to bind the Git commit hash to the test/CI evidence and raise confidence to `Verified`.

### 4. Offline Dreaming & Meta-Policy Synthesis (`dream` / `synthesize-policy`)
* Run `dream --project <proj> --output-rules <path.md>` to distill exploration histories into actionable system rules and SOP heuristics for agents.

### 5. Deep Dive (Stage 2: `get --agent`)
* Low-token decision packet: strips verbose journal history and returns only the last 3 key notes, commit evidence, and do-not-try constraints with risk levels.

---

## Small-Model Decision Indicator (`decision`) Reference

| `decision` value | Trigger condition | Action guideline for 7B / 14B local models |
|---|---|---|
| `adopt` | `Verified` status with `verified` confidence, not superseded | **Highest priority.** Adopt directly as the standard solution. |
| `adopt_after_check` | `Closed`/`Resolved` with `high` confidence or attached commit/evidence | Adopt, but first check the applicability constraints (`conditions`). |
| `candidate` | `Closed`/`Resolved` with `medium` confidence | Reference only as a candidate direction; not a confirmed solution. |
| `avoid` | `Rejected`/`WontFix`/`Stale`, or a negative-knowledge hit | **Actively avoid.** Do not retry this path. |
| `superseded` | `superseded_by` field is non-empty | **This ticket is stale** — switch to the new ticket ID. |
| `reference_only` | `New` or `In Progress` draft | Debugging lead only. |

---

## CLI Reference

Script location: `scripts/memory_manager.py` (supports global `--db <path>`).

### 1. Agent decision evidence card (`answer` / `card`)
```bash
# One-shot: best solution, diagnostic policy, code evidence, hard veto list
python scripts/memory_manager.py answer --query "ACPI S3 Sleep Hang" --project "KernelDriver" --platform "Intel-ARL"
```

### 2. Append exploration branches with risk levels (`reject-path`)
```bash
# Record root hypothesis/probe
python scripts/memory_manager.py reject-path --id 1 --approach "Read EC register status" --reason "EC firmware timed out" --branch-type "probe" --risk-level "medium"

# Record child attempt with fatal risk (HARD VETO)
python scripts/memory_manager.py reject-path --id 1 --approach "Force reset EC controller" --reason "Tripped PMIC protection circuit" --side-effect "System power loss and lost RTC" --parent-id 1 --branch-type "fix_attempt" --risk-level "fatal"
```

### 3. Offline Dreaming & Policy Distillation (`dream`)
```bash
# Synthesize exploration policies and export agent rule file
python scripts/memory_manager.py dream --project "KernelDriver" --output-rules .gemini/rules/kerneldriver_policy.md
```

### 4. Dedupe & create ticket (`similar` / `create`)
```bash
python scripts/memory_manager.py similar --subject "ACPI S3 Sleep Hang"
python scripts/memory_manager.py create --project "KernelDriver" --subject "ACPI S3 sleep hang on Type-C attach" --tracker "Bug" --platform "Intel-ARL"
```

### 5. Closure & verification (`close` / `verify`)
```bash
python scripts/memory_manager.py close --id 1 --root-cause "race between Type-C PD firmware and the BIOS ACPI" --solution "add 50ms delay in _PTS" --commit-hash "9f8e7d6c5b4a"

# Promote to Verified — two pitfalls:
#   1. commit verification runs `git` in the CURRENT directory, so cd into
#      the repo that contains the commit first (VALIDATION_ERROR otherwise).
#   2. --db path is cwd-relative; pass an ABSOLUTE path when running from
#      outside the skills dir (NOT_FOUND otherwise).
cd /path/to/repo && python /abs/path/to/scripts/memory_manager.py verify \
  --db /abs/path/to/memory.db --id 1 \
  --commit-hash "9f8e7d6c5b4a" \
  --evidence-type "test" --evidence-ref "pytest tests/power/test_s3.py" \
  --evidence-note "passed 100 S3 stress cycles"
```

### 6. Two-stage retrieval & maintenance (`search-invalid` / `get --agent` / `doctor`)
```bash
python scripts/memory_manager.py search-invalid --query "I2C reset"
python scripts/memory_manager.py get --id 1 --agent
python scripts/memory_manager.py doctor
```
