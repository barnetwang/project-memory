import unittest
import os
import tempfile
import json
import subprocess
import sys

class TestHardenedEpisodicMemoryManagerV31(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_episodic_memory.db")
        self.script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "memory_manager.py")
        )
        self.env = os.environ.copy()
        self.env["PROJECT_MEMORY_DB"] = self.db_path

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_cli(self, args, custom_env=None):
        cmd = [sys.executable, self.script_path] + args
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            env=custom_env or self.env
        )
        return result

    def test_verified_protection_and_status_machine(self):
        # 1. 直接以 Verified 建立應被禁止
        res_fail = self.run_cli(["create", "--project", "App", "--subject", "Test Verified", "--status", "Verified"])
        self.assertEqual(res_fail.returncode, 1)

        # 2. 建立新單
        res = self.run_cli(["create", "--project", "App", "--subject", "Auth Race Condition", "--status", "in_progress"])
        self.assertEqual(res.returncode, 0)
        issue_id = json.loads(res.stdout)["issue_id"]

        # 3. 在未結案前 (In Progress) 直接 verify 應被禁止
        res_ver_early = self.run_cli([
            "verify", "--id", str(issue_id),
            "--evidence-type", "ci",
            "--evidence-ref", "https://ci.example.com/build/100"
        ])
        self.assertEqual(res_ver_early.returncode, 1)

        # 4. 結案
        res_close = self.run_cli([
            "close", "--id", str(issue_id),
            "--root-cause", "並發鎖缺失",
            "--solution", "使用 Redis 分散式鎖",
            "--commit-hash", "abc1234def5678"
        ])
        self.assertEqual(res_close.returncode, 0)
        close_data = json.loads(res_close.stdout)
        self.assertEqual(close_data["issue_status"], "Closed")

        # 5. 正式使用 verify 升級
        res_ver = self.run_cli([
            "verify", "--id", str(issue_id),
            "--evidence-type", "ci",
            "--evidence-ref", "https://ci.example.com/build/100"
        ])
        self.assertEqual(res_ver.returncode, 0)
        ver_data = json.loads(res_ver.stdout)
        self.assertEqual(ver_data["issue_status"], "Verified")
        self.assertEqual(ver_data["confidence"], "verified")

        # 6. 嘗試以空泛字串假驗證應被拒絕
        res_fake_ver = self.run_cli([
            "verify", "--id", str(issue_id),
            "--evidence-ref", "Trust me, it works"
        ])
        self.assertEqual(res_fake_ver.returncode, 1)

        # 7. 重開 (Reopen) 已驗證工單，應自動降級置信度並清空 verified_by
        res_reopen = self.run_cli(["update", "--id", str(issue_id), "--status", "In Progress"])
        self.assertEqual(res_reopen.returncode, 0)
        res_get = self.run_cli(["get", "--id", str(issue_id)])
        reopened_data = json.loads(res_get.stdout)
        self.assertEqual(reopened_data["status"], "In Progress")
        self.assertEqual(reopened_data["confidence"], "unverified")
        self.assertEqual(reopened_data["verified_by"], "")

    def test_partial_update_invariant_drift_protection(self):
        # 1. 建立並結案一筆工單
        res = self.run_cli([
            "create", "--project", "App", "--subject", "DB Deadlock",
            "--status", "Closed", "--root-cause", "鎖順序相反", "--solution", "統一鎖順序"
        ])
        issue_id = json.loads(res.stdout)["issue_id"]

        # 2. 試圖不傳 --status 但將 root-cause 或 solution 洗為空字串，應被強制攔截
        res_drift = self.run_cli(["update", "--id", str(issue_id), "--root-cause", " ", "--solution", " "])
        self.assertEqual(res_drift.returncode, 1)

        # 3. 升級為 Verified
        self.run_cli([
            "verify", "--id", str(issue_id),
            "--evidence-ref", "https://ci.example.com/build/200"
        ])

        # 4. 在 Verified 狀態下修改 root-cause，應自動使 Verified 失效並降級為 In Progress
        res_mod_rc = self.run_cli(["update", "--id", str(issue_id), "--root-cause", "新發現的次要根因"])
        self.assertEqual(res_mod_rc.returncode, 0)

        res_get = self.run_cli(["get", "--id", str(issue_id)])
        data = json.loads(res_get.stdout)
        self.assertEqual(data["status"], "In Progress")
        self.assertEqual(data["confidence"], "unverified")
        self.assertEqual(data["verified_by"], "")

    def test_secret_scanner_expanded_coverage_including_keys(self):
        # 1. 自訂欄位鍵名中夾帶 OpenAI Secret Key 應被攔截
        res_key_leak = self.run_cli([
            "create", "--project", "Sec", "--subject", "Key Leak",
            "--cf", "sk-1234567890abcdef1234567890abcdef=innocent_value"
        ])
        self.assertEqual(res_key_leak.returncode, 1)

        # 2. 自訂欄位鍵值中夾帶 OpenAI Key 應被攔截
        res_val_leak = self.run_cli([
            "create", "--project", "Sec", "--subject", "Val Leak",
            "--cf", "api_key=sk-1234567890abcdef1234567890abcdef"
        ])
        self.assertEqual(res_val_leak.returncode, 1)

        # 3. JWT Token 應被攔截
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B1sR"
        res_jwt = self.run_cli(["create", "--project", "Sec", "--subject", "JWT Leak", "--description", fake_jwt])
        self.assertEqual(res_jwt.returncode, 1)

    def test_redact_issue_complete_scrub_and_purge(self):
        res = self.run_cli(["create", "--project", "Sec", "--subject", "Sensitive Issue", "--description", "Secret details"])
        issue_id = json.loads(res.stdout)["issue_id"]

        self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "Hardcode Token",
            "--reason", "Insecure",
            "--failure-mode", "leaked_failure_token_12345",
            "--side-effect", "leaked_side_effect_host",
            "--scope", "internal-net"
        ])
        self.run_cli(["note", "--id", str(issue_id), "--notes", "Secret journal notes"])

        # 執行徹底脫敏
        res_redact = self.run_cli(["redact-issue", "--id", str(issue_id), "--reason", "GDPR compliance"])
        self.assertEqual(res_redact.returncode, 0)

        # 檢查 get 詳情
        res_get = self.run_cli(["get", "--id", str(issue_id)])
        data = json.loads(res_get.stdout)
        self.assertEqual(data["subject"], "[REDACTED]")
        self.assertEqual(data["invalid_paths"][0]["failure_mode"], "[REDACTED]")
        self.assertEqual(data["invalid_paths"][0]["side_effect"], "[REDACTED]")
        self.assertEqual(data["journals"][0]["notes"], "[REDACTED]")

        # 檢查 FTS 全文索引中查不到已脫敏字串
        res_search = self.run_cli(["search-invalid", "--query", "leaked_failure_token_12345"])
        self.assertEqual(len(json.loads(res_search.stdout)), 0)

    def test_reject_stores_invalid_path(self):
        res = self.run_cli(["create", "--project", "Hardware", "--subject", "ACPI S3 Sleep Hang"])
        issue_id = json.loads(res.stdout)["issue_id"]

        res_rej = self.run_cli([
            "reject", "--id", str(issue_id),
            "--reason", "導致電源管理晶片重置逾時",
            "--side-effect", "風扇全速運轉",
            "--scope", "Intel-ARL"
        ])
        self.assertEqual(res_rej.returncode, 0)

        # 驗證 search-invalid 可以直接查到該副作用
        res_inv = self.run_cli(["search-invalid", "--query", "風扇全速運轉"])
        items = json.loads(res_inv.stdout)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["side_effect"], "風扇全速運轉")
        self.assertEqual(items[0]["scope"], "Intel-ARL")

    def test_cjk_search_and_confidence_ranking(self):
        # 建立兩筆工單：一筆 Verified (舊)，一筆 unverified (新)
        self.run_cli([
            "create", "--project", "Kernel", "--subject", "斷電藍屏修復",
            "--root-cause", "驅動衝突", "--solution", "更新補丁", "--status", "Resolved"
        ])
        self.run_cli(["verify", "--id", "1", "--evidence-ref", "https://ci.example.com/build/1"])
        
        self.run_cli(["create", "--project", "Kernel", "--subject", "斷電藍屏排查草稿", "--status", "New"])

        # 搜尋兩字中文「藍屏」，應依置信度 Verified 優先排序
        res = self.run_cli(["search", "--query", "藍屏"])
        items = json.loads(res.stdout)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["id"], 1)
        self.assertEqual(items[0]["confidence"], "verified")
        self.assertEqual(items[0]["decision"], "adopt")
        self.assertEqual(items[1]["id"], 2)
        self.assertEqual(items[1]["confidence"], "unverified")
        self.assertEqual(items[1]["decision"], "reference_only")

    def test_synonym_expansion_simplified_and_acronym(self):
        # 建立繁體中文工單
        self.run_cli([
            "create", "--project", "Kernel", "--subject", "斷電藍屏修復",
            "--root-cause", "驅動衝突", "--solution", "更新補丁", "--status", "Resolved"
        ])
        self.run_cli(["verify", "--id", "1", "--evidence-ref", "https://ci.example.com/build/1"])

        # 使用簡體中文「蓝屏」或英文「bsod」檢索，同義詞自動擴充應成功命中！
        res_simp = self.run_cli(["answer", "--query", "蓝屏"])
        self.assertEqual(res_simp.returncode, 0)
        card_simp = json.loads(res_simp.stdout)
        self.assertEqual(card_simp["confidence"], "verified")
        self.assertEqual(card_simp["best_solution"]["issue_id"], 1)

        res_bsod = self.run_cli(["search", "--query", "bsod"])
        items = json.loads(res_bsod.stdout)
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0]["id"], 1)

    def test_token_or_and_inverted_word_order_matching(self):
        # 建立工單並記錄負向知識
        self.run_cli(["create", "--project", "KernelDriver", "--subject", "ACPI S3 Sleep Hang on Type-C Attach"])
        self.run_cli([
            "reject-path", "--id", "1",
            "--approach", "強制重設 I2C 控制器暫存器",
            "--reason", "導致電源管理晶片進入保護模式",
            "--side-effect", "系統斷電重啟",
            "--scope", "platform=Intel-ARL"
        ])

        # 顛倒詞序與空格檢索：「I2C 重設」應成功命中！
        res = self.run_cli(["search-invalid", "--query", "I2C 重設"])
        self.assertEqual(res.returncode, 0)
        items = json.loads(res.stdout)
        self.assertGreaterEqual(len(items), 1)
        self.assertIn("I2C", items[0]["approach"])

    def test_platform_filter_in_answer(self):
        # 建立 Intel 平台工單
        self.run_cli([
            "create", "--project", "KernelDriver", "--subject", "S3 Hang Issue",
            "--root-cause", "Intel PD 韌體問題", "--solution", "加入 50ms 延遲",
            "--platform", "Intel-ARL", "--status", "Resolved"
        ])
        self.run_cli(["verify", "--id", "1", "--evidence-ref", "https://ci.example.com/test_s3"])

        # 檢索限定 AMD 平台：應被過濾或無最佳解
        res_amd = self.run_cli(["answer", "--query", "S3 Hang", "--platform", "AMD-Phoenix"])
        card_amd = json.loads(res_amd.stdout)
        self.assertIsNone(card_amd["best_solution"])

        # 檢索限定 Intel-ARL 平台：應成功匹配！
        res_intel = self.run_cli(["answer", "--query", "S3 Hang", "--platform", "Intel-ARL"])
        card_intel = json.loads(res_intel.stdout)
        self.assertIsNotNone(card_intel["best_solution"])
        self.assertEqual(card_intel["best_solution"]["issue_id"], 1)

    def test_superseded_tracking_and_warning(self):
        self.run_cli([
            "create", "--project", "App", "--subject", "Old Issue",
            "--root-cause", "Old RC", "--solution", "Old Sol",
            "--superseded-by", "2", "--status", "Resolved"
        ])
        self.run_cli(["verify", "--id", "1", "--evidence-ref", "https://ci.example.com/test1"])

        res = self.run_cli(["answer", "--query", "Old Issue"])
        card = json.loads(res.stdout)
        self.assertGreaterEqual(len(card["warnings"]), 1)
        self.assertIn("已被工單 #2 取代", card["warnings"][0])
        self.assertEqual(card["best_solution"]["decision"], "superseded")

    def test_get_agent_brief_mode(self):
        self.run_cli([
            "create", "--project", "App", "--subject", "Brief Mode Test",
            "--root-cause", "RC1", "--solution", "Sol1", "--status", "Resolved"
        ])
        self.run_cli(["verify", "--id", "1", "--evidence-ref", "https://ci.example.com/test_brief"])
        for i in range(10):
            self.run_cli(["note", "--id", "1", "--notes", f"Verbose note {i}"])

        # 執行 get --agent / --brief
        res = self.run_cli(["get", "--id", "1", "--agent"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["decision"], "adopt")
        self.assertEqual(data["solution"], "Sol1")
        # 僅保留最近 3 則筆記
        self.assertLessEqual(len(data["recent_notes"]), 3)

    def test_import_state_invariant_sanitization(self):
        bad_record = {
            "id": 1,
            "project": "PoisonApp",
            "subject": "Fake Verified Issue",
            "status": "Verified",
            "confidence": "unverified",
            "root_cause": "",
            "solution": ""
        }
        jsonl_path = os.path.join(self.temp_dir.name, "poison.jsonl")
        with open(jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(bad_record) + "\n")

        res_imp = self.run_cli(["import", "--file", jsonl_path])
        self.assertEqual(res_imp.returncode, 0)

        res_get = self.run_cli(["get", "--id", "1"])
        data = json.loads(res_get.stdout)
        self.assertEqual(data["status"], "In Progress")
        self.assertEqual(data["confidence"], "unverified")

    def test_doctor_and_stats(self):
        self.run_cli(["create", "--project", "DocTest", "--subject", "Doc Test Subject"])
        res_doc = self.run_cli(["doctor"])
        self.assertEqual(res_doc.returncode, 0)
        data = json.loads(res_doc.stdout)
        self.assertIn("projects_distribution", data)
        self.assertIn("status_distribution", data)
        self.assertIn("confidence_distribution", data)
        self.assertIn("risk_distribution", data)
        self.assertIn(data["status"], ["healthy", "warning"])

    def test_exploration_tree_and_risk_levels(self):
        res = self.run_cli(["create", "--project", "TreeTest", "--subject", "ACPI Sleep Hang"])
        self.assertEqual(res.returncode, 0)
        issue_id = json.loads(res.stdout)["issue_id"]

        # 1. 建立父節點 (Probe, Medium risk)
        res_p = self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "讀取 EC 暫存器狀態",
            "--reason", "EC 韌體未回傳 ACK",
            "--branch-type", "probe",
            "--risk-level", "medium"
        ])
        self.assertEqual(res_p.returncode, 0)
        p_data = json.loads(res_p.stdout)
        parent_path_id = p_data["invalid_path_id"]

        # 2. 建立子節點 (Fix Attempt, Fatal risk)
        res_c = self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "強制拉低 EC RESET 針腳",
            "--reason", "導致主機板 PMIC 進入保護模式斷電",
            "--side-effect", "系統斷電且遺失 RTC",
            "--parent-id", str(parent_path_id),
            "--branch-type", "fix_attempt",
            "--risk-level", "fatal"
        ])
        self.assertEqual(res_c.returncode, 0)
        c_data = json.loads(res_c.stdout)
        self.assertEqual(c_data["parent_path_id"], parent_path_id)
        self.assertEqual(c_data["risk_level"], "fatal")
        self.assertTrue(c_data["veto"])

        # 3. 測試指向不存在的 parent-id 應報錯
        res_bad_parent = self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "無效父節點測試",
            "--reason", "測試防呆",
            "--parent-id", "99999"
        ])
        self.assertEqual(res_bad_parent.returncode, 1)

        # 4. 驗證 get 包含完整探索樹屬性
        res_get = self.run_cli(["get", "--id", str(issue_id)])
        get_data = json.loads(res_get.stdout)
        invs = get_data["invalid_paths"]
        self.assertEqual(len(invs), 2)
        self.assertEqual(invs[1]["parent_path_id"], parent_path_id)
        self.assertEqual(invs[1]["branch_type"], "fix_attempt")
        self.assertEqual(invs[1]["risk_level"], "fatal")
        self.assertTrue(invs[1]["veto"])

        # 5. 驗證 search-invalid 結果 fatal 置頂且帶有 veto 標籤
        res_search_inv = self.run_cli(["search-invalid", "--query", "EC"])
        inv_results = json.loads(res_search_inv.stdout)
        self.assertGreaterEqual(len(inv_results), 2)
        self.assertEqual(inv_results[0]["risk_level"], "fatal")
        self.assertTrue(inv_results[0]["veto"])

    def test_answer_diagnostic_policy_and_veto_prioritization(self):
        res = self.run_cli([
            "create", "--project", "KernelPower", "--subject", "S3 Hang On Wakeup",
            "--root-cause", "PD 韌體競態", "--solution", "延遲 50ms 後重試",
            "--status", "Resolved"
        ])
        issue_id = json.loads(res.stdout)["issue_id"]
        self.run_cli(["verify", "--id", str(issue_id), "--evidence-ref", "https://ci.example.com/s3_pass"])
        self.run_cli(["note", "--id", str(issue_id), "--notes", "診斷步驟 1: 檢查 PD 狀態旗標"])
        self.run_cli(["note", "--id", str(issue_id), "--notes", "診斷步驟 2: 套用 50ms 延遲等待就緒"])

        # 加入一個 low risk 與一個 fatal risk 排除路徑
        self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "修改編譯器優化選項 -O0",
            "--reason", "代碼體積過大無法寫入 flash",
            "--risk-level", "low"
        ])
        self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "直寫 I2C 控制器暫存器",
            "--reason", "PMIC 觸發過流保護斷電",
            "--side-effect", "主機瞬間跳電",
            "--risk-level", "fatal"
        ])

        # 執行 answer
        res_ans = self.run_cli(["answer", "--query", "S3 Hang", "--project", "KernelPower"])
        self.assertEqual(res_ans.returncode, 0)
        card = json.loads(res_ans.stdout)

        # 檢查 do_not_try 中 fatal 項目優先置頂並標註 HARD VETO
        self.assertGreaterEqual(len(card["do_not_try"]), 2)
        top_inv = card["do_not_try"][0]
        self.assertEqual(top_inv["risk_level"], "fatal")
        self.assertTrue(top_inv["veto"])
        self.assertIn("[HARD VETO]", top_inv["warning_label"])

        # 檢查 diagnostic_policy 排查狀態機引導
        self.assertIn("diagnostic_policy", card)
        diag = card["diagnostic_policy"]
        self.assertIsNotNone(diag)
        self.assertEqual(diag["source_issue_id"], issue_id)
        self.assertEqual(len(diag["recommended_sop"]), 2)
        self.assertIn("診斷步驟 1", diag["recommended_sop"][0])
        self.assertGreaterEqual(len(diag["pruned_branches"]), 2)
        self.assertEqual(len(diag["verification_checks"]), 1)

    def test_dream_offline_policy_synthesis(self):
        res = self.run_cli([
            "create", "--project", "DreamProj", "--subject", "DRAM Timing Instability",
            "--root-cause", "記憶體訓練電壓不足", "--solution", "調高 VDDQ 50mV",
            "--status", "Resolved"
        ])
        issue_id = json.loads(res.stdout)["issue_id"]
        self.run_cli(["verify", "--id", str(issue_id), "--evidence-ref", "https://ci.example.com/mem_test_ok"])
        self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "直接關閉 ECC 檢查",
            "--reason", "導致靜默資料損壞 (Silent Data Corruption)",
            "--risk-level", "fatal"
        ])

        # 1. 執行 dream 產出 JSON
        res_dream = self.run_cli(["dream", "--project", "DreamProj"])
        self.assertEqual(res_dream.returncode, 0)
        data = json.loads(res_dream.stdout)
        self.assertEqual(data["status"], "success")
        self.assertIn("hard_veto_rules", data)
        self.assertEqual(len(data["hard_veto_rules"]), 1)
        self.assertEqual(data["hard_veto_rules"][0]["approach"], "直接關閉 ECC 檢查")
        self.assertEqual(data["risk_distribution"]["fatal"], 1)

        # 2. 測試 dream 輸出 Markdown 規則檔案
        rules_path = os.path.join(self.temp_dir.name, "dream_rules.md")
        res_md = self.run_cli(["dream", "--project", "DreamProj", "--output-rules", rules_path])
        self.assertEqual(res_md.returncode, 0)
        self.assertTrue(os.path.exists(rules_path))
        with open(rules_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Project Memory Exploration Policy", content)
        self.assertIn("HARD VETO Rules", content)
        self.assertIn("直接關閉 ECC 檢查", content)

    def test_v3_schema_migration_on_upgrade(self):
        # 模擬升級場景：手工建立一個 v3 形狀的資料庫 (invalid_paths 無
        # parent_path_id / branch_type / risk_level，user_version=3)，
        # 任一讀指令觸發 init_db 後必須完成 v4 遷移且資料不損。
        v3_path = os.path.join(self.temp_dir.name, "legacy_v3.db")
        import sqlite3
        conn = sqlite3.connect(v3_path)
        conn.executescript('''
            CREATE TABLE issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT NOT NULL,
                tracker TEXT NOT NULL DEFAULT 'Bug',
                status TEXT NOT NULL DEFAULT 'New',
                priority TEXT NOT NULL DEFAULT 'Normal',
                confidence TEXT NOT NULL DEFAULT 'unverified',
                subject TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                scope TEXT DEFAULT '', conditions TEXT DEFAULT '',
                root_cause TEXT DEFAULT '', solution TEXT DEFAULT '',
                ai_summary TEXT DEFAULT '', related_ids TEXT DEFAULT '',
                superseded_by INTEGER, created_by TEXT DEFAULT 'Agent',
                verified_by TEXT DEFAULT '', verified_at DATETIME,
                created_at DATETIME, updated_at DATETIME, closed_at DATETIME
            );
            CREATE TABLE journals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
                notes TEXT NOT NULL, author TEXT DEFAULT 'Agent', created_at DATETIME
            );
            CREATE TABLE invalid_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
                approach TEXT NOT NULL, failure_mode TEXT DEFAULT '',
                reason TEXT NOT NULL, side_effect TEXT DEFAULT '',
                scope TEXT DEFAULT '', created_at DATETIME
            );
            CREATE TABLE evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
                evidence_type TEXT NOT NULL, reference TEXT NOT NULL,
                note TEXT DEFAULT '', created_at DATETIME
            );
            CREATE TABLE custom_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL, field_type TEXT DEFAULT 'string'
            );
            CREATE TABLE custom_values (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
                custom_field_id INTEGER NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
                value TEXT NOT NULL, UNIQUE(issue_id, custom_field_id)
            );
            CREATE TABLE git_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
                commit_hash TEXT NOT NULL, repository TEXT DEFAULT '',
                diff_summary TEXT DEFAULT '', created_at DATETIME
            );
            INSERT INTO issues (project_name, subject, status, created_at, updated_at)
            VALUES ('LegacyProj', 'S3 sleep hang on legacy board', 'Closed',
                    '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z');
            INSERT INTO invalid_paths (issue_id, approach, reason, created_at)
            VALUES (1, 'force reset I2C controller', 'PMIC entered protection mode',
                    '2026-01-02T00:00:00Z');
            PRAGMA user_version = 3;
        ''')
        conn.close()

        v3_env = self.env.copy()
        v3_env["PROJECT_MEMORY_DB"] = v3_path

        # 1. doctor 必須在遷移後成功回傳 (舊版會噴 EXECUTION_ERROR:
        #    no such column: parent_path_id 且把 DB 留在半遷移狀態)
        res = self.run_cli(["doctor"], custom_env=v3_env)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertIn(data["status"], ["healthy", "warning"])

        # 2. 遷移完成：schema v4、新欄位到位且舊資料補預設值
        conn = sqlite3.connect(v3_path)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 4)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(invalid_paths)")}
        self.assertIn("parent_path_id", cols)
        self.assertIn("branch_type", cols)
        self.assertIn("risk_level", cols)
        risk, branch = conn.execute(
            "SELECT risk_level, branch_type FROM invalid_paths WHERE id = 1").fetchone()
        self.assertEqual(risk, "medium")
        self.assertEqual(branch, "attempt")
        # 3. 舊資料完整保留
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM issues").fetchone()[0], 1)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM invalid_paths").fetchone()[0], 1)
        conn.close()

        # 4. 遷移後檢索功能照常 (FTS 已重建)
        res_inv = self.run_cli(["search-invalid", "--query", "I2C"], custom_env=v3_env)
        self.assertEqual(res_inv.returncode, 0)
        items = json.loads(res_inv.stdout)
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0]["risk_level"], "medium")

    def test_export_import_with_exploration_tree(self):
        res = self.run_cli(["create", "--project", "ExportTreeProj", "--subject", "Tree Export Issue"])
        issue_id = json.loads(res.stdout)["issue_id"]
        res_p = self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "父方法",
            "--reason", "父原因",
            "--branch-type", "hypothesis",
            "--risk-level", "medium"
        ])
        parent_id = json.loads(res_p.stdout)["invalid_path_id"]

        res_c = self.run_cli([
            "reject-path", "--id", str(issue_id),
            "--approach", "子方法",
            "--reason", "子原因",
            "--parent-id", str(parent_id),
            "--branch-type", "fix_attempt",
            "--risk-level", "high"
        ])

        # 匯出到 jsonl
        export_file = os.path.join(self.temp_dir.name, "tree_export.jsonl")
        res_exp = self.run_cli(["export", "--file", export_file])
        self.assertEqual(res_exp.returncode, 0)

        # 建立全新的 test db 並匯入
        new_db_path = os.path.join(self.temp_dir.name, "new_tree.db")
        new_env = self.env.copy()
        new_env["PROJECT_MEMORY_DB"] = new_db_path

        res_imp = self.run_cli(["import", "--file", export_file], custom_env=new_env)
        self.assertEqual(res_imp.returncode, 0)

        # 檢查匯入後的新資料庫中，子節點的 parent_path_id 是否正確重映射
        res_get = self.run_cli(["get", "--id", "1"], custom_env=new_env)
        imported_issue = json.loads(res_get.stdout)
        invs = imported_issue["invalid_paths"]
        self.assertEqual(len(invs), 2)
        self.assertEqual(invs[1]["parent_path_id"], invs[0]["id"])
        self.assertEqual(invs[1]["risk_level"], "high")
        self.assertTrue(invs[1]["veto"])

if __name__ == '__main__':
    unittest.main()
