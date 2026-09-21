[🇹🇼 繁體中文](#繁體中文) | [🇺🇸 English](#english)

---

<h1 id="繁體中文">Agent Episodic Engineering Memory (v3.4.0 - Dream-RSI Edition)</h1>

> **v3.4.0 (2026-09-21) Google Dream-RSI 架構深度升級**
> - **探索歷程樹 (Exploration Trees / DAG)**：負向知識全面支援樹狀推導結構 (`--parent-id` 與 `--branch-type`: hypothesis / probe / workaround / fix_attempt)，完整還原假說演變與追溯因果鏈。
> - **代價與風險感知剪枝 (Risk-Aware Pruning & Hard VETO)**：負向經驗導入四級風險評估 (`fatal` / `high` / `medium` / `low`)。在 `answer` 查詢中以 `[HARD VETO]` 標籤置頂呈現高危禁忌（如硬體損壞、死鎖），杜絕 Agent 重蹈毀滅性覆轍。
> - **排查決策策略流 (Diagnostic Policy)**：工單驗證與結案自動綜合推導排查狀態機步驟 (SOP Sequence)，引導 Agent 依循正規階梯式驗證歷程。
> - **離線做夢與元策略提煉 (Offline Dreaming & Meta-Policy Synthesis)**：全新 `dream` CLI 指令，聚合跨工單的探索樹、死胡同模式與解法，提煉為全域架構守則與除錯策略；預設輸出結構化 JSON，搭配 `--output-rules <path>.md` 另存一份 Agent 規則檔。
> - **資料庫結構升級 (Schema v4)**：自動無縫相容遷移，匯出/匯入具備階層 ID 重新映射機制，`doctor` 全面納入風險分佈統計與懸掛父節點健全性自檢。
> - **已知問題修正 (v3.4.0 hotfix, 2026-09-21)**：v4 遷移在既有 v3 資料庫上會因索引先於新欄位建立而中斷（`no such column: parent_path_id`，且 DB 停在半遷移狀態）；已修正建立順序並加入 v3→v4 遷移回歸測試。

> **v3.3.0 (2026-09-20) Project-Affinity Retrieval**
> - `--project` 過濾放鬆：完整字串相等 + 部分名包含（`FireRange` 可圈住 `FireRange-AM66ZJ`），三處入口（`search` / `answer` / `search-invalid`）。
> - `answer` ranking 將 project 命中置於 confidence 之前（≥3 字元 token），本專案工單優先、異域工單只補位。
> - Cross-project 誠實閘：查詢 token 指向某專案但最佳命中來自其他專案時，`decision` 降為 `candidate` 並附警示，避免跨專案 confident `adopt`。
> 建議 in-scope debug 一律帶 `--project`，確保證據卡鎖定本專案。
>

一個專為 AI Coding / Engineering Agent（特別針對 **7B / 14B 本地端開源小模型**、**硬體/韌體除錯** 與 **繁簡中文/英文/ACPI 路徑混合環境**）設計的 **Failure-Aware, Evidence-Grounded** 結構化專案長期記憶中樞。

---

## 本地端弱模型專屬四大革新 (Small-Model Innovations)

### 1. 零歧義決策指示 (`decision` 欄位)
- 7B/14B 弱模型往往無法可靠推理複雜的多狀態與置信度組合。本系統在 Stage 1 `search` 與 Stage 2 `get` 中直接計算並輸出 **`decision` 決策指示**：
  - `adopt`：最高置信度 Verified 解法，直接採納。
  - `adopt_after_check`：已結案且附帶 Commit/測試證據，確認條件後採納。
  - `candidate`：已結案但缺乏實體證據，僅供參考。
  - `avoid`：排除路徑 / 負向知識 / 廢棄方案，**主動避開**。
  - `superseded`：方案已過期被新單取代，提示改查新單。
  - `reference_only`：排查中草稿。

### 2. Token 級 Hybrid 檢索與同義詞/繁簡擴充
- **同義詞與縮寫映射**：查詢 `蓝屏` 自動擴充匹配 `藍屏` 與 `bsod`；`睡眠` 自動擴充 `s3` 與 `sleep`。
- **倒序詞與子路徑容錯**：查詢 `I2C 重設` 能完美召回 `強制重設 I2C 控制器暫存器`；查詢 `_PTS` 能命中 `\_SB.PCI0._PTS`。

### 3. 真正生效的環境與平台過濾 (`--platform` / `--env`)
- 在 `answer` 指令中精確過濾硬體平台與執行環境（檢查 `custom_values`、`scope` 與 `conditions`），杜絕硬體/BIOS Agent 誤用異質架構 Workaround。

### 4. 低 Token 決策封包 (`get --agent`)
- 專為小模型有限 Context Window 設計，自動剔除大量冗長歷史 Notes，僅回傳核心解法、Commit 證據與 Do Not Try 禁忌清單，節省 80% 以上 Token。

---

## 借鏡 Google Dream-RSI 架構新特性 (Dream-RSI Features)

### 5. 探索歷程樹 (Exploration Trees / DAG)
- 傳統記憶系統僅記錄扁平的「成功」或「失敗」，遺失了推導上下文。v3.4.0 支援將除錯嘗試記錄為樹狀結構：
  - `hypothesis`：主假設層級的嘗試或初步推斷。
  - `probe`：為驗證假設而採取的侦查性操作 (讀暫存器、抓 log、測訊號)。
  - `workaround`：繞過問題而非修正根因的臨時方案。
  - `fix_attempt`：直接指向根因修正方案的嘗試。
- 透過 `--parent-id` 將子分支掛到父分支下，並用 `branch_type` 標記分支性質；預設為 `attempt` (一般嘗試)。
- 完整保存 Agent 「思考—嘗試—受挫—轉向」的演化歷程。

### 6. 代價感知與高危剪枝 (Risk-Aware Hard VETO)
- 排查硬體或韌體時，不同失敗代價迥異（例如暫存器位元設錯僅需重開機，但供電晶片過壓可能燒毀主板）。
- 導入四級風險：`fatal`、`high`、`medium`、`low`。
- 在 `answer` 推理卡中，高危路徑以 `[HARD VETO]` 標註並**強制置頂**排於最前端，小模型即使發生注意力衰減也能第一時間看見致命禁忌。

### 7. 排查決策策略流 (Diagnostic Policy)
- 當工單結案並附帶驗證證據時，系統自動推導 Recommended SOP Sequence。
- 在調閱證據卡時，直接將多步驟排查 SOP 傳遞給 Agent，指引階梯式排查驗證。

### 8. 離線做夢與元策略提煉 (Offline Dreaming)
- 借鏡 Google Dream-RSI 核心概念，在沒有即時問題的空閒階段，執行 `dream` 提煉全局智慧：
  - 自動跨工單掃描失敗叢集，識別共同的系統性脆弱點與盲區。
  - 提煉黃金排查路徑與通用架構守則。
  - 預設輸出結構化 JSON (含 hard_veto_rules、risk_distribution、verified_fast_path_sops)；搭配 `--output-rules <path>.md` 另存一份 Markdown 規則檔，可被 Cursor / Claude / Antigravity 等工具直接載入為 System Rules。

---

## CLI 指令操作手冊 (CLI Quick Start)

### 1. Agent 專屬推理證據卡 (`answer` / `card`)
```bash
# 一站式取得最佳解法、適用條件、代碼證據、Do Not Try 禁忌 (含 [HARD VETO]) 與排查 SOP
python scripts/memory_manager.py answer --query "ACPI S3 Sleep Hang" --project "KernelDriver" --platform "Intel-ARL"
```

### 2. 查重與建立工單 (`similar` / `create`)
```bash
# 開立前先查重 (防記憶庫膨脹)
python scripts/memory_manager.py similar --subject "ACPI S3 Sleep Hang"

# 建立工單
python scripts/memory_manager.py create --project "KernelDriver" --subject "ACPI S3 Sleep Hang on Type-C Attach" --tracker "Bug" --module "power" --env "baremetal" --error-code "0x0000009F" --platform "Intel-ARL" --board "EVB-RVP" --bios-ver "v1.2.0" --scope "S3-resume"
```

### 3. 記錄排查歷程與無效路徑 (支援探索樹與風險評級)
```bash
# 記錄排查筆記
python scripts/memory_manager.py note --id 1 --notes "在 S3 喚醒過程中，Type-C PD 控制器未能及時釋放 I2C 匯流排。"

# 記錄細粒度負向知識 (失敗方法、失效模式、副作用、風險層級與父節點分支)
python scripts/memory_manager.py reject-path --id 1 \
  --approach "強制重設 I2C 控制器暫存器" \
  --reason "導致電源管理晶片進入保護模式" \
  --failure-mode "系統斷電重啟" \
  --side-effect "風扇全速運轉且遺失 RTC 時間" \
  --scope "platform=Intel-ARL" \
  --risk-level "fatal" \
  --branch-type "hypothesis"

# 記錄基於上一步嘗試的子分支 (fix_attempt)
python scripts/memory_manager.py reject-path --id 1 \
  --approach "降頻重送 I2C 重設命令" \
  --reason "PMIC 依然觸發保護" \
  --failure-mode "掛死" \
  --parent-id 1 \
  --branch-type "fix_attempt" \
  --risk-level "high"
```

### 4. 結案與驗證 (`close` / `verify`)
```bash
# 結案 (強制要求根因與解法)
python scripts/memory_manager.py close --id 1 --root-cause "Type-C PD 韌體與 BIOS ACPI 方法競態" --solution "在 _PTS 加入 50ms 延遲並等待 PD 狀態就緒" --conditions "僅適用於 PD 韌體 >= v2.0" --commit-hash "9f8e7d6c5b4a"

# 提升為 Verified (要求 Closed 狀態與真實 Commit 或 CI 證據)
python scripts/memory_manager.py verify --id 1 --commit-hash "9f8e7d6c5b4a" --evidence-type "test" --evidence-ref "pytest tests/power/test_s3.py" --evidence-note "通過 100 次 S3 壓力循環測試"
```

### 5. 兩階段檢索 (`search` / `search-invalid` / `get --agent`)
```bash
# 篩選最高置信度 Verified 解法 (回傳附帶 decision 決策欄位)
python scripts/memory_manager.py search --project "KernelDriver" --query "睡眠 藍屏" --verified-only

# 直接檢索具體失敗路徑條目 (支援倒序詞與風險/探索樹輸出)
python scripts/memory_manager.py search-invalid --query "I2C 重設"

# 小模型低 Token 深度調閱 (自動輸出 diagnostic_policy 與樹狀負向清單)
python scripts/memory_manager.py get --id 1 --agent
```

### 6. 離線做夢提煉策略 (`dream`)
```bash
# 離線做夢：從歷史探索樹與失敗模式提煉全局策略
#   --format json     (預設) 輸出結構化 JSON 到 stdout
#   --format markdown       輸出 Markdown 到 stdout
#   --output-rules <path>.md   另存一份 Agent 規則檔 (需搭配任一 format)
python scripts/memory_manager.py dream --project "KernelDriver"
python scripts/memory_manager.py dream --project "KernelDriver" --output-rules "rules/kerneldriver_policy.md"
```

### 7. 機密脫敏、備份與維運 (`redact-issue` / `export` / `import` / `doctor`)
```bash
# 敏感工單全表徹底脫敏並物理截斷 WAL 日誌
python scripts/memory_manager.py redact-issue --id 1 --reason "GDPR"

# 資料庫匯出與匯入 (支援冪等去重、狀態校驗與階層 parent_path_id 重新映射)
python scripts/memory_manager.py export --file backup.jsonl
python scripts/memory_manager.py import --file backup.jsonl --dedupe

# 系統健康檢查 (檢驗結構完整性、風險評估統計與懸掛探索節點)
python scripts/memory_manager.py doctor
python scripts/memory_manager.py reindex
```

---

<br><br>

---

<h1 id="english">Agent Episodic Engineering Memory (v3.4.0 - Dream-RSI Edition)</h1>

> **v3.4.0 (2026-09-21) Google Dream-RSI Architectural Upgrade**
> - **Exploration Trees / DAG**: Negative knowledge paths now support hierarchical hypothesis progression via `--parent-id` and `--branch-type` (`hypothesis`, `probe`, `workaround`, `fix_attempt`, `attempt`), preserving the chain of failure reasoning.
> - **Cost & Risk-Aware Pruning (Hard VETO)**: Negative knowledge tagged with 4 risk tiers (`fatal`, `high`, `medium`, `low`). Queries via `answer` enforce a `[HARD VETO]` policy placing dangerous dead-ends at the top of the prompt to prevent catastrophic debugging actions.
> - **Diagnostic Policy Flow**: Closed tickets synthesize SOP state machine sequences guiding agents along proven validation trajectories.
> - **Offline Dreaming & Meta-Policy Synthesis**: The new `dream` CLI command synthesizes architectural rules and anti-patterns across exploration trees. Outputs structured JSON by default; pass `--output-rules <path>.md` to additionally save an Agent rule file.
> - **Database Schema v4**: Seamless migration, parent-child ID remapping during export/import, and enhanced `doctor` diagnostics for risk distribution and dangling node audits.
> - **Known-fix (v3.4.0 hotfix, 2026-09-21)**: v4 migration aborted on pre-existing v3 databases because two indexes were created before the new columns existed (`no such column: parent_path_id`, leaving the DB half-migrated); build order fixed and a v3→v4 migration regression test added.

> **v3.3.0 (2026-09-20) Project-Affinity Retrieval**
> - Relaxed `--project` filter: exact match + substring containment (across `search` / `answer` / `search-invalid`).
> - `answer` ranking: project-token hits (>=3 chars) outrank content tokens, so same-project tickets stay on top.
> - Cross-project honesty gate: when query tokens name a project but the top hit comes from another one, `decision` degrades to `candidate` plus a warning.
> Recommended practice: pass `--project` on in-scope debugging to pin the evidence card to your project.
>

An industrial-grade, **Failure-Aware, Evidence-Grounded** episodic project memory hub designed specifically for local open-source models (7B / 14B), firmware/hardware engineering, and mixed Chinese/English/Hardware environments.

---

## Core Features for Small Models

1. **Unambiguous `decision` Field**: Eliminates reasoning overhead for 7B/14B models with direct action indicators (`adopt`, `adopt_after_check`, `candidate`, `avoid`, `superseded`).
2. **Token-Level Hybrid Search & Synonyms**: Automatic Simplified/Traditional Chinese mapping (`蓝屏` $\leftrightarrow$ `藍屏` $\leftrightarrow$ `bsod`), acronym expansion, and inverted word matching (`I2C 重設` $\rightarrow$ `強制重設 I2C 控制器暫存器`).
3. **True Platform & Environment Filtering**: Filters by `--platform` and `--env` in `answer` to prevent applying mismatched firmware/hardware workarounds.
4. **Low-Token Decision Packet (`get --agent`)**: Strips verbose journal history and provides concise 3-note summaries with commit proofs and Do Not Try constraints.

---

## Dream-RSI Enhancements

5. **Exploration Trees (DAG Reasoning)**: Replaces flat failure logs with hypothesis trees tracking parent-child links (`hypothesis`, `probe`, `workaround`, `fix_attempt`, `attempt`).
6. **Risk-Aware Pruning (`[HARD VETO]`)**: Fatal/high risk approaches are surfaced at the very top of context payloads with explicit veto warnings.
7. **Diagnostic Policy Flow**: Synthesizes verified issue sequences into actionable step-by-step diagnostic workflows.
8. **Offline Dreaming (`dream`)**: Synthesizes cross-ticket anti-patterns and rules; structured JSON by default, or a Markdown rule file via `--output-rules <path>.md` for AI-agent consumption.
