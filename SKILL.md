---
name: project-memory
description: "Use for engineering debug: recall cases and reject-paths."
version: 3.1.0
author: Barnet Wang
license: Apache-2.0
---

# Failure-Aware Episodic Engineering Memory Skill (v3.1.0)

本 Skill 賦予 Agent 跨對話的「結構化工程決策與負向知識記憶」能力。專門針對 **開源本地端弱模型（7B / 14B）** 與 **繁簡中文、英文、ACPI 底線路徑混合環境** 進行極致強化。

---

## 🎯 核心工作流與使用時機 (Agent Workflow)

### 1. 開工與除錯前 (Answer, Search & Similar - 一站式推理與查重)
* **Agent 專屬推理證據卡 (`answer` / `card`)**：**最推薦 Agent 開工時優先調用**。
  - 支援 Token 級混合檢索與同義詞/繁簡擴充（如 `蓝屏` $\leftrightarrow$ `藍屏` $\leftrightarrow$ `bsod`，`睡眠` $\leftrightarrow$ `s3`）。
  - 自動完成 `--platform` 與 `--env` 匹配過濾。
  - 遇到被取代工單自動追蹤標註 `superseded` 警告。
  - 一站式整合最佳已驗證解法、適用限制條件 (`conditions`)、代碼 Commit 與排查禁忌 (`do_not_try`)。
* **檢索已驗證解法 (`search --verified-only`)**：
  - Stage 1 輸出直接附帶 **`decision` 決策指示欄位**（`adopt` / `avoid` / `candidate` / `superseded`），小模型無需推理複雜狀態機即可直接裁決！
* **檢索負向知識 (`search --negative-only` / `search-invalid`)**：
  - 支援 Token 拆解 OR 匹配（如 `I2C 重設` 與 `強制重設 I2C 控制器暫存器` 倒序詞完美命中），**直接進行推理剪枝，避免重複試錯 (Repeated Failure)**。
* **開立新單前查重 (`similar`)**：在建立新 Issue 前，**務必先使用 `similar --subject "..."` 進行查重**。

### 2. 排查與試錯中 (Note & Reject-Path - 記錄排查地圖)
* 使用 `note` 記錄排查過程與實驗觀測。
* 當某個嘗試（Approach）失敗時，**立即使用 `reject-path` 記錄該無效路徑、失敗原因、失效模式、副作用與適用範疇**。

### 3. 解決與結案 (Close & Verify - 錨定真實證據)
* 使用 `close` 明確記錄「根因 (Root Cause)」與「解決方案 (Solution)」。
* 若已通過測試或 CI 驗證，使用 `verify` 綁定 Git Commit 雜湊碼與測試/CI 證據，將置信度提升為最高級別 `Verified`。

### 4. 深度調閱 (Stage 2: `get --agent`)
* 調閱特定工單時，小模型可加上 `--agent` / `--brief` 參數，系統自動剔除大量歷史冗長筆記，僅回傳最近 3 則關鍵 Notes、Commit 證據與 Do Not Try 禁忌清單，節省 80% 以上 Token！

---

## 🚦 小模型決策指標 (`decision`) 對照表

| `decision` 欄位值 | 觸發條件 | 7B / 14B 本地小模型行動準則 |
|---|---|---|
| `adopt` | `Verified` 狀態且置信度為 `verified`，未被取代 | **最高優先級**。直接採納為標準解法。 |
| `adopt_after_check` | `Closed`/`Resolved` 狀態且置信度為 `high` 或附帶 Commit/證據 | 可採納，但需先確認適用限制條件 (`conditions`)。 |
| `candidate` | `Closed`/`Resolved` 狀態，置信度為 `medium` | 作為候選方向參考，不可直接作為確定解法。 |
| `avoid` | `Rejected`/`WontFix`/`Stale` 或命中負向知識 | **主動避開**，嚴禁重複嘗試此路徑。 |
| `superseded` | `superseded_by` 欄位非空 | **本工單已過期**，應改查新工單 ID。 |
| `reference_only` | `New` 或 `In Progress` 排查中草稿 | 僅供排查線索參考。 |

---

## 🛠️ CLI 指令操作手冊

腳本位置：`scripts/memory_manager.py`（支援全域 `--db <path>` 參數）。

### 1. Agent 專屬推理證據卡 (`answer` / `card`)
```bash
# 一站式取得最佳解法、適用條件、代碼證據與 Do Not Try 禁忌清單 (支援繁簡/英文/同義詞擴充)
python scripts/memory_manager.py answer --query "ACPI S3 Sleep Hang" --project "KernelDriver" --platform "Intel-ARL"
```

### 2. 查重與建立工單 (`similar` / `create`)
```bash
# 開立前先查重 (防記憶庫膨脹)
python scripts/memory_manager.py similar --subject "ACPI S3 Sleep Hang"

# 建立新工單
python scripts/memory_manager.py create --project "KernelDriver" --subject "ACPI S3 Sleep Hang on Type-C Attach" --tracker "Bug" --module "power" --env "baremetal" --error-code "0x0000009F" --platform "Intel-ARL" --board "EVB-RVP" --bios-ver "v1.2.0" --scope "S3-resume"
```

### 3. 追加排查筆記與細粒度負向知識 (`note` / `reject-path`)
```bash
# 記錄排查筆記
python scripts/memory_manager.py note --id 1 --notes "在 S3 喚醒過程中，Type-C PD 控制器未能及時釋放 I2C 匯流排。"

# 記錄細粒度負向知識
python scripts/memory_manager.py reject-path --id 1 --approach "強制重設 I2C 控制器暫存器" --reason "導致電源管理晶片進入保護模式" --failure-mode "系統斷電重啟" --side-effect "風扇全速運轉且遺失 RTC 時間" --scope "platform=Intel-ARL"
```

### 4. 結案與最高置信度驗證 (`close` / `verify`)
```bash
# 結案
python scripts/memory_manager.py close --id 1 --root-cause "Type-C PD 韌體與 BIOS ACPI 方法競態" --solution "在 _PTS 加入 50ms 延遲並等待 PD 狀態就緒" --conditions "僅適用於 PD 韌體 >= v2.0" --commit-hash "9f8e7d6c5b4a"

# 提升為 Verified
python scripts/memory_manager.py verify --id 1 --commit-hash "9f8e7d6c5b4a" --evidence-type "test" --evidence-ref "pytest tests/power/test_s3.py" --evidence-note "通過 100 次 S3 壓力循環測試"
```

### 5. 兩階段檢索 (`search` / `search-invalid` / `get --agent`)
```bash
# 階段一：檢索已驗證解法 (回傳附帶 decision 欄位)
python scripts/memory_manager.py search --project "KernelDriver" --query "睡眠 藍屏" --verified-only

# 階段一：直接查詢負向知識條目 (支援倒序詞與子路徑匹配)
python scripts/memory_manager.py search-invalid --query "I2C 重設"

# 階段二：調閱小模型專屬低 Token 決策封包
python scripts/memory_manager.py get --id 1 --agent
```

### 6. 機密脫敏、備份與維運 (`redact-issue` / `export` / `import` / `doctor`)
```bash
# 敏感資料全表徹底脫敏並抹除 WAL 日誌
python scripts/memory_manager.py redact-issue --id 1 --reason "GDPR"

# 備份與匯入
python scripts/memory_manager.py export --file backup.jsonl
python scripts/memory_manager.py import --file backup.jsonl --dedupe

# 系統健康檢查與專案統計
python scripts/memory_manager.py doctor
python scripts/memory_manager.py reindex
```
