---
name: project-memory
description: "Use for engineering debug: recall cases and reject-paths."
version: 3.2.2
author: Barnet Wang
license: Apache-2.0
---

# Failure-Aware Episodic Engineering Memory Skill (v3.2.2)

This skill gives the agent a persistent, cross-conversation memory of **structured engineering decisions and negative knowledge**. It is optimized for **open-source local small models (7B / 14B)** and for **environments mixing Traditional/Simplified Chinese, English, and ACPI underscore-named paths**.

---

## Core Workflow & When to Use (Agent Workflow)

### 1. Before Starting / Debugging (Answer, Search & Similar — one-shot reasoning + dedupe)
* **Agent decision evidence card (`answer` / `card`)**: **the recommended first call when a session starts**.
  - Token-level hybrid retrieval with synonym / Traditional↔Simplified expansion (e.g. `蓝屏` ↔ `藍屏` ↔ `bsod`, `睡眠` ↔ `s3`).
  - `--platform` and `--env` matching filters are applied automatically.
  - Tickets that have been superseded are flagged with a `superseded` warning and tracked.
  - One call returns: the best verified solution, its applicability constraints (`conditions`), the code commit, and the do-not-try list (`do_not_try`).
* **Retrieve verified solutions (`search --verified-only`)**:
  - Stage 1 output carries a **`decision` directive field** (`adopt` / `avoid` / `candidate` / `superseded`) — small models can act on it directly without reasoning through the state machine.
* **Retrieve negative knowledge (`search --negative-only` / `search-invalid`)**:
  - Token-split OR matching (e.g. `I2C reset` also matches `forced reset of the I2C controller register`; reversed word order still hits) — use it to **prune reasoning and avoid repeating a known failure**.
* **Dedupe before opening a ticket (`similar`)**: **always** run `similar --subject "..."` **before** creating a new issue.

### 2. During Investigation & Trial-Error (Note & Reject-Path — maintain the debug map)
* Use `note` to record investigation steps and experimental observations.
* When an attempt (Approach) fails, **immediately** record it with `reject-path`: the invalid path, the reason it failed, the failure mode, side effects, and the scope it applies to.

### 3. Resolution & Closure (Close & Verify — anchor to real evidence)
* Use `close` to record the **root cause** and the **solution** explicitly.
* If the fix is validated by tests or CI, use `verify` to bind the Git commit hash to the test/CI evidence and raise confidence to the highest level, `Verified`.

### 4. Deep Dive (Stage 2: `get --agent`)
* When reading a specific ticket, small models can add `--agent` / `--brief`: the system strips the voluminous history and returns only the last 3 key notes, commit evidence, and the do-not-try list — **saves 80%+ of tokens**.

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

Script location: `scripts/memory_manager.py` (supports the global `--db <path>` option).

### 1. Agent decision evidence card (`answer` / `card`)
```bash
# One-shot: best solution, applicability conditions, code evidence, do-not-try list
# (supports Traditional/Simplified Chinese, synonym, and abbreviation expansion)
python scripts/memory_manager.py answer --query "ACPI S3 Sleep Hang" --project "KernelDriver" --platform "Intel-ARL"
```

### 2. Dedupe & create ticket (`similar` / `create`)
```bash
# Dedupe first (prevents memory-store bloat)
python scripts/memory_manager.py similar --subject "ACPI S3 Sleep Hang"

# Create a new ticket
python scripts/memory_manager.py create --project "KernelDriver" --subject "ACPI S3 sleep hang on Type-C attach" --tracker "Bug" --module "power" --env "baremetal" --error-code "0x0000009F" --platform "Intel-ARL" --board "EVB-RVP" --bios-ver "v1.2.0" --scope "S3-resume"
```

### 3. Append investigation notes & fine-grained negative knowledge (`note` / `reject-path`)
```bash
# Record an investigation note
python scripts/memory_manager.py note --id 1 --notes "During S3 resume, the Type-C PD controller failed to release the I2C bus in time."

# Record fine-grained negative knowledge
python scripts/memory_manager.py reject-path --id 1 --approach "forced reset of the I2C controller register" --reason "put the power-management chip into protection mode" --failure-mode "system lost power and rebooted" --side-effect "fans spun at full speed and RTC time was lost" --scope "platform=Intel-ARL"
```

### 4. Closure & highest-confidence verification (`close` / `verify`)
```bash
# Close the ticket
python scripts/memory_manager.py close --id 1 --root-cause "race between Type-C PD firmware and the BIOS ACPI method" --solution "add a 50ms delay in _PTS and wait for the PD state to be ready" --conditions "only for PD firmware >= v2.0" --commit-hash "9f8e7d6c5b4a"

# Promote to Verified
python scripts/memory_manager.py verify --id 1 --commit-hash "9f8e7d6c5b4a" --evidence-type "test" --evidence-ref "pytest tests/power/test_s3.py" --evidence-note "passed 100 S3 stress cycles"
```

### 5. Two-stage retrieval (`search` / `search-invalid` / `get --agent`)
```bash
# Stage 1: verified solutions (returns results with the decision field)
python scripts/memory_manager.py search --project "KernelDriver" --query "睡眠 藍屏" --verified-only

# Stage 1: query negative-knowledge entries directly (reversed-word and sub-path matching)
python scripts/memory_manager.py search-invalid --query "I2C reset"

# Stage 2: low-token decision packet for small models
python scripts/memory_manager.py get --id 1 --agent
```

### 6. Redaction, backup & maintenance (`redact-issue` / `export` / `import` / `doctor`)
```bash
# Fully redact a sensitive ticket and wipe the WAL log
python scripts/memory_manager.py redact-issue --id 1 --reason "GDPR"

# Backup & import
python scripts/memory_manager.py export --file backup.jsonl
python scripts/memory_manager.py import --file backup.jsonl --dedupe

# Health check & project statistics
python scripts/memory_manager.py doctor
python scripts/memory_manager.py reindex
```
