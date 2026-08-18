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
        self.assertIn(data["status"], ["healthy", "warning"])

if __name__ == '__main__':
    unittest.main()
