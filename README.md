[🇹🇼 繁體中文](#繁體中文) | [🇺🇸 English](#english)

---

<h1 id="繁體中文">Agent Episodic Engineering Memory (v3.1.0)</h1>

一個專為 AI Coding / Engineering Agent（特別針對 **7B / 14B 本地端開源小模型** 與 **繁簡中文/英文/ACPI 路徑混合環境**）設計的 **Failure-Aware, Evidence-Grounded** 結構化專案長期記憶中樞。

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

## CLI 指令操作手冊 (CLI Quick Start)

### 1. Agent 專屬推理證據卡 (`answer` / `card`)
```bash
# 一站式取得最佳解法、適用條件、代碼證據與 Do Not Try 禁忌清單
python scripts/memory_manager.py answer --query "ACPI S3 Sleep Hang" --project "KernelDriver" --platform "Intel-ARL"
```

### 2. 查重與建立工單 (`similar` / `create`)
```bash
# 開立前先查重 (防記憶庫膨脹)
python scripts/memory_manager.py similar --subject "ACPI S3 Sleep Hang"

# 建立工單
python scripts/memory_manager.py create --project "KernelDriver" --subject "ACPI S3 Sleep Hang on Type-C Attach" --tracker "Bug" --module "power" --env "baremetal" --error-code "0x0000009F" --platform "Intel-ARL" --board "EVB-RVP" --bios-ver "v1.2.0" --scope "S3-resume"
```

### 3. 記錄排查歷程與無效路徑 (`note` / `reject-path`)
```bash
# 記錄排查筆記
python scripts/memory_manager.py note --id 1 --notes "在 S3 喚醒過程中，Type-C PD 控制器未能及時釋放 I2C 匯流排。"

# 記錄細粒度負向知識 (失敗方法、失效模式與副作用)
python scripts/memory_manager.py reject-path --id 1 --approach "強制重設 I2C 控制器暫存器" --reason "導致電源管理晶片進入保護模式" --failure-mode "系統斷電重啟" --side-effect "風扇全速運轉且遺失 RTC 時間" --scope "platform=Intel-ARL"
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

# 直接檢索具體失敗路徑條目 (支援倒序詞)
python scripts/memory_manager.py search-invalid --query "I2C 重設"

# 小模型低 Token 深度調閱
python scripts/memory_manager.py get --id 1 --agent
```

### 6. 機密脫敏、備份與維運 (`redact-issue` / `export` / `import` / `doctor`)
```bash
# 敏感工單全表徹底脫敏並物理截斷 WAL 日誌
python scripts/memory_manager.py redact-issue --id 1 --reason "GDPR"

# 資料庫匯出與匯入 (支援冪等去重、狀態校驗與關聯 ID 重新映射)
python scripts/memory_manager.py export --file backup.jsonl
python scripts/memory_manager.py import --file backup.jsonl --dedupe

# 系統健康檢查與專案統計
python scripts/memory_manager.py doctor
python scripts/memory_manager.py reindex
```

---

<br><br>

---

<h1 id="english">Agent Episodic Engineering Memory (v3.1.0)</h1>

An industrial-grade, **Failure-Aware, Evidence-Grounded** episodic project memory hub designed specifically for local open-source models (7B / 14B) in mixed Chinese/English/Hardware environments.

---

## Core Features for Small Models

1. **Unambiguous `decision` Field**: Eliminates reasoning overhead for 7B/14B models with direct action indicators (`adopt`, `adopt_after_check`, `candidate`, `avoid`, `superseded`).
2. **Token-Level Hybrid Search & Synonyms**: Automatic Simplified/Traditional Chinese mapping (`蓝屏` $\leftrightarrow$ `藍屏` $\leftrightarrow$ `bsod`), acronym expansion, and inverted word matching (`I2C 重設` $\rightarrow$ `強制重設 I2C 控制器暫存器`).
3. **True Platform & Environment Filtering**: Filters by `--platform` and `--env` in `answer` to prevent applying mismatched firmware/hardware workarounds.
4. **Low-Token Decision Packet (`get --agent`)**: Strips verbose journal history and provides concise 3-note summaries with commit proofs and Do Not Try constraints.
