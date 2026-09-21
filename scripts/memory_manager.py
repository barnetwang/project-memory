#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Failure-Aware, Evidence-Grounded Episodic Engineering Memory for AI Agents
Version 3.4.0 (Dream-RSI: Exploration Trees, Risk-Aware Pruning, Offline Dreaming & Policy Guided Search)
"""

import sqlite3
import argparse
import os
import json
import sys
import re
import subprocess
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows
if sys.stdout.encoding is None or sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

SCHEMA_VERSION = 4

ALLOWED_BRANCH_TYPES = {"hypothesis", "probe", "workaround", "fix_attempt", "attempt"}
ALLOWED_RISK_LEVELS = {"fatal", "high", "medium", "low"}

STATUS_ALIASES = {
    "new": "New",
    "open": "New",
    "in progress": "In Progress",
    "in_progress": "In Progress",
    "reopened": "New",
    "resolved": "Resolved",
    "closed": "Closed",
    "verified": "Verified",
    "rejected": "Rejected",
    "wontfix": "WontFix",
    "wont fix": "WontFix",
    "duplicate": "Duplicate",
    "stale": "Stale",
}

ALLOWED_STATUSES = {
    "New", "In Progress", "Resolved", "Closed",
    "Verified", "Rejected", "WontFix", "Duplicate", "Stale"
}

ALLOWED_CONFIDENCE = {
    "unverified", "low", "medium", "high", "verified", "rejected"
}

TERMINAL_STATUSES = {"Closed", "Resolved", "Verified", "Rejected", "WontFix", "Duplicate", "Stale"}
OPEN_STATUSES = {"New", "In Progress", "Open", "Reopened"}

SECRET_PATTERNS = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "Private Key"),
    (r"\bsk-[a-zA-Z0-9_\-]{20,}\b", "OpenAI Secret Key"),
    (r"\bsk-ant-[a-zA-Z0-9_\-]{20,}\b", "Anthropic Secret Key"),
    (r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b", "GitHub Token"),
    (r"\bglpat-[a-zA-Z0-9_\-]{20,}\b", "GitLab Personal Token"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key"),
    (r"\beyJ[a-zA-Z0-9_\-]{8,}\.eyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{4,}\b", "JWT Token"),
    (r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", "API / Secret Key"),
    (r"(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:]+:[^@\s]+@[^\s]+", "Database Connection URI with Credentials"),
    (r"(?:bearer|token)\s+[A-Za-z0-9_\-\.]{20,}", "Auth / Bearer Token"),
    (r"(?:password|passwd|pwd|密碼)\s*[:=]\s*['\"]?[^ \r\n\t]{6,}['\"]?", "Plaintext Password"),
]

CUSTOM_VALUE_NORMALIZATION = {
    "framework": {"next.js": "nextjs", "next": "nextjs", "nextjs": "nextjs", "react.js": "react", "reactjs": "react"},
    "db": {"postgres": "postgresql", "postgresql": "postgresql", "pg": "postgresql"},
    "env": {"prod": "production", "production": "production", "stage": "staging", "staging": "staging", "dev": "development", "development": "development"}
}

def resolve_default_db_path(explicit_path=None):
    """
    決定資料庫路徑 (優先序：CLI參數 -> 環境變數 -> 本地Repo -> 全域中立路徑 -> 舊版相容路徑)
    """
    if explicit_path:
        return os.path.expanduser(explicit_path)

    if 'PROJECT_MEMORY_DB' in os.environ:
        return os.path.expanduser(os.environ['PROJECT_MEMORY_DB'])

    # 檢查當前是否位於 Git Repo，若是則直接預設使用 repo-local DB (.project-memory/memory.db)
    try:
        git_root = subprocess.check_output(
            ['git', 'rev-parse', '--show-toplevel'],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        if git_root:
            repo_local_dir = os.path.join(git_root, '.project-memory')
            return os.path.join(repo_local_dir, 'memory.db')
    except Exception:
        pass

    neutral_path = os.path.expanduser('~/.project-memory/memory.db')
    legacy_path = os.path.expanduser('~/.gemini/project_memory.db')
    
    if os.path.exists(neutral_path):
        return neutral_path
    if os.path.exists(legacy_path):
        return legacy_path
    return neutral_path

def utc_now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def normalize_status(status_str):
    if not status_str:
        return "New"
    key = status_str.strip().lower()
    norm = STATUS_ALIASES.get(key, status_str.strip().capitalize())
    if norm not in ALLOWED_STATUSES:
        raise ValueError(f"Invalid status: '{status_str}'. Allowed: {', '.join(sorted(ALLOWED_STATUSES))}")
    return norm

def normalize_confidence(conf_str):
    if not conf_str:
        return "unverified"
    val = conf_str.strip().lower()
    if val not in ALLOWED_CONFIDENCE:
        raise ValueError(f"Invalid confidence: '{conf_str}'. Allowed: {', '.join(sorted(ALLOWED_CONFIDENCE))}")
    return val

def normalize_custom_value(field_name, val_str):
    if not val_str:
        return ""
    field = field_name.strip().lower()
    val = str(val_str).strip()
    if field in CUSTOM_VALUE_NORMALIZATION:
        return CUSTOM_VALUE_NORMALIZATION[field].get(val.lower(), val)
    return val

def scan_for_secrets(text):
    if not text or not isinstance(text, str):
        return None
    for pattern, name in SECRET_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return name
    return None

def collect_and_scan_secrets(data_dict, allow_secret=False):
    """遞迴掃描字典或清單內的所有鍵名與字串型欄位"""
    if allow_secret:
        return
    
    def _scan_item(k, v):
        # 1. 鍵名掃描 (防止將機密藏於 custom_field 的鍵名中)
        if isinstance(k, str) and k:
            sec_k = scan_for_secrets(k)
            if sec_k:
                raise ValueError(f"Security Alert: Possible {sec_k} detected in field key '{k}'. Refusing to save.")
        # 2. 鍵值掃描
        if isinstance(v, str) and v:
            sec_v = scan_for_secrets(v)
            if sec_v:
                raise ValueError(f"Security Alert: Possible {sec_v} detected in field '{k}'. Refusing to save.")
        elif isinstance(v, dict):
            for sub_k, sub_v in v.items():
                _scan_item(f"{k}.{sub_k}", sub_v)
        elif isinstance(v, (list, tuple)):
            for idx, item in enumerate(v):
                _scan_item(f"{k}[{idx}]", item)

    for k, v in data_dict.items():
        _scan_item(k, v)

def escape_sql_like(text):
    if not text:
        return ""
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

def get_connection(db_path=None):
    path = resolve_default_db_path(db_path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn

def detect_best_tokenizer(conn):
    """檢查環境是否支援 trigram tokenizer，並將結果快取於 _schema_meta"""
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS _schema_meta (key TEXT PRIMARY KEY, value TEXT)")
    cursor.execute("SELECT value FROM _schema_meta WHERE key = 'fts_tokenizer'")
    row = cursor.fetchone()
    if row:
        return row[0]
    
    try:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _test_trigram USING fts5(x, tokenize='trigram')")
        conn.execute("DROP TABLE IF EXISTS _test_trigram")
        tokenizer = "trigram"
    except sqlite3.OperationalError:
        tokenizer = "unicode61"

    cursor.execute("INSERT OR REPLACE INTO _schema_meta (key, value) VALUES ('fts_tokenizer', ?)", (tokenizer,))
    conn.commit()
    return tokenizer

def create_fts_table(cursor, tokenizer="trigram"):
    cursor.execute(f'''
        CREATE VIRTUAL TABLE IF NOT EXISTS issues_fts USING fts5(
            issue_id UNINDEXED,
            project_name,
            tracker,
            status,
            subject,
            description,
            root_cause,
            solution,
            ai_summary,
            notes_aggregate,
            invalid_paths_aggregate,
            custom_fields_aggregate,
            tokenize='{tokenizer}'
        )
    ''')

def init_db(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # 1. Issues 主資料表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            tracker TEXT NOT NULL DEFAULT 'Bug',
            status TEXT NOT NULL DEFAULT 'New',
            priority TEXT NOT NULL DEFAULT 'Normal',
            confidence TEXT NOT NULL DEFAULT 'unverified',
            subject TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            scope TEXT DEFAULT '',
            conditions TEXT DEFAULT '',
            root_cause TEXT DEFAULT '',
            solution TEXT DEFAULT '',
            ai_summary TEXT DEFAULT '',
            related_ids TEXT DEFAULT '',
            superseded_by INTEGER,
            created_by TEXT DEFAULT 'Agent',
            verified_by TEXT DEFAULT '',
            verified_at DATETIME,
            created_at DATETIME,
            updated_at DATETIME,
            closed_at DATETIME
        )
    ''')

    # 2. Journals 表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS journals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
            notes TEXT NOT NULL,
            author TEXT DEFAULT 'Agent',
            created_at DATETIME
        )
    ''')

    # 3. 細粒度負向知識表 (Invalid Paths - 支援探索樹與風險權重)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS invalid_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
            approach TEXT NOT NULL,
            failure_mode TEXT DEFAULT '',
            reason TEXT NOT NULL,
            side_effect TEXT DEFAULT '',
            scope TEXT DEFAULT '',
            parent_path_id INTEGER DEFAULT NULL REFERENCES invalid_paths(id) ON DELETE SET NULL,
            branch_type TEXT DEFAULT 'attempt',
            risk_level TEXT DEFAULT 'medium',
            created_at DATETIME
        )
    ''')

    # 4. 可驗證證據表 (Evidence)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
            evidence_type TEXT NOT NULL,
            reference TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_at DATETIME
        )
    ''')

    # 5. 自定義欄位表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS custom_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            field_type TEXT DEFAULT 'string'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS custom_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
            custom_field_id INTEGER NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
            value TEXT NOT NULL,
            UNIQUE(issue_id, custom_field_id)
        )
    ''')

    # 6. Git Commit 關聯表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS git_revisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
            commit_hash TEXT NOT NULL,
            repository TEXT DEFAULT '',
            diff_summary TEXT DEFAULT '',
            created_at DATETIME
        )
    ''')

    # 索引 (含 journals issue_id 索引)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_project_status ON issues(project_name, status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_status_updated ON issues(status, updated_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_issues_confidence ON issues(confidence)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_journals_issue ON journals(issue_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_invalid_paths_issue ON invalid_paths(issue_id)")
    # v4: idx_invalid_paths_parent / idx_invalid_paths_risk are created AFTER the
    # ALTER TABLE migration below adds those columns; building them first would
    # throw "no such column" and abort the entire migration on v3 databases.
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_issue ON evidence(issue_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_custom_values_issue ON custom_values(issue_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_git_revisions_issue ON git_revisions(issue_id)")

    default_fields = ['module', 'env', 'tags', 'error_code', 'component', 'version', 'platform', 'board', 'bios_ver']
    for field_name in default_fields:
        cursor.execute("INSERT OR IGNORE INTO custom_fields (name) VALUES (?)", (field_name,))

    # Migration / Schema Version 管理
    cursor.execute("PRAGMA user_version")
    current_ver = cursor.fetchone()[0]
    best_tokenizer = detect_best_tokenizer(conn)

    # v4 migration: 確保既有 invalid_paths 表含有 parent_path_id, branch_type, risk_level 欄位
    cursor.execute("PRAGMA table_info(invalid_paths)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    if "parent_path_id" not in existing_cols:
        cursor.execute("ALTER TABLE invalid_paths ADD COLUMN parent_path_id INTEGER DEFAULT NULL REFERENCES invalid_paths(id) ON DELETE SET NULL")
    if "branch_type" not in existing_cols:
        cursor.execute("ALTER TABLE invalid_paths ADD COLUMN branch_type TEXT DEFAULT 'attempt'")
    if "risk_level" not in existing_cols:
        cursor.execute("ALTER TABLE invalid_paths ADD COLUMN risk_level TEXT DEFAULT 'medium'")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_invalid_paths_parent ON invalid_paths(parent_path_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_invalid_paths_risk ON invalid_paths(risk_level)")

    if current_ver < SCHEMA_VERSION:
        cursor.execute("DROP TABLE IF EXISTS issues_fts")
        create_fts_table(cursor, best_tokenizer)
        cursor.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
        cursor.execute("SELECT id FROM issues")
        for (i_id,) in cursor.fetchall():
            sync_fts_entry(conn, i_id)
        conn.commit()
    else:
        create_fts_table(cursor, best_tokenizer)

    conn.commit()
    return conn

def sync_fts_entry(conn, issue_id):
    """同步單筆 issue 到 FTS 表"""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT project_name, tracker, status, subject, description, root_cause, solution, ai_summary
        FROM issues WHERE id = ?
    ''', (issue_id,))
    issue = cursor.fetchone()
    
    if not issue:
        cursor.execute("DELETE FROM issues_fts WHERE issue_id = ?", (str(issue_id),))
        return
        
    project_name, tracker, status, subject, description, root_cause, solution, ai_summary = issue

    cursor.execute("SELECT notes FROM journals WHERE issue_id = ? ORDER BY id ASC", (issue_id,))
    notes_aggregate = "\n".join([row[0] for row in cursor.fetchall()])

    cursor.execute("SELECT approach, failure_mode, reason, side_effect, scope, branch_type, risk_level FROM invalid_paths WHERE issue_id = ? ORDER BY id ASC", (issue_id,))
    inv_list = [f"無效方法: {r[0]} | 失效模式: {r[1]} | 原因: {r[2]} | 副作用: {r[3]} | 範疇: {r[4]} | 分支: {r[5]} | 風險: {r[6]}" for r in cursor.fetchall()]
    invalid_paths_aggregate = "\n".join(inv_list)

    cursor.execute('''
        SELECT cf.name, cv.value
        FROM custom_values cv
        JOIN custom_fields cf ON cv.custom_field_id = cf.id
        WHERE cv.issue_id = ?
    ''', (issue_id,))
    cf_aggregate = ", ".join([f"{row[0]}: {row[1]}" for row in cursor.fetchall()])

    cursor.execute("DELETE FROM issues_fts WHERE issue_id = ?", (str(issue_id),))
    cursor.execute('''
        INSERT INTO issues_fts (
            issue_id, project_name, tracker, status, subject, description,
            root_cause, solution, ai_summary, notes_aggregate, invalid_paths_aggregate, custom_fields_aggregate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        str(issue_id), project_name, tracker, status, subject, description or '',
        root_cause or '', solution or '', ai_summary or '', notes_aggregate,
        invalid_paths_aggregate, cf_aggregate
    ))

def set_custom_value(cursor, issue_id, field_name, value):
    if value is None or str(value).strip() == "":
        return
    field_name = str(field_name).strip().lower()
    value = normalize_custom_value(field_name, str(value).strip())
    cursor.execute("INSERT OR IGNORE INTO custom_fields (name) VALUES (?)", (field_name,))
    cursor.execute("SELECT id FROM custom_fields WHERE name = ?", (field_name,))
    cf_id = cursor.fetchone()[0]
    cursor.execute('''
        INSERT INTO custom_values (issue_id, custom_field_id, value)
        VALUES (?, ?, ?)
        ON CONFLICT(issue_id, custom_field_id) DO UPDATE SET value = excluded.value
    ''', (issue_id, cf_id, value))

def add_git_revision(cursor, issue_id, commit_hash, repository="", diff_summary=""):
    if not commit_hash:
        return
    now = utc_now_iso()
    cursor.execute('''
        INSERT INTO git_revisions (issue_id, commit_hash, repository, diff_summary, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (issue_id, commit_hash.strip(), repository.strip() if repository else "", diff_summary.strip() if diff_summary else "", now))

def add_evidence_record(cursor, issue_id, evidence_type, reference, note=""):
    if not reference:
        return
    now = utc_now_iso()
    cursor.execute('''
        INSERT INTO evidence (issue_id, evidence_type, reference, note, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (issue_id, evidence_type.strip(), reference.strip(), note.strip() if note else "", now))

def verify_git_commit_exists(commit_hash):
    """若在 Git 倉庫內，使用 git cat-file 驗證 commit 雜湊是否真實存在"""
    if not commit_hash:
        return True
    try:
        res = subprocess.run(
            ['git', 'cat-file', '-e', f'{commit_hash.strip()}^{{commit}}'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return True  # 非 git 環境或未安裝 git 則寬鬆通過

def truncate_text(text, max_len=140):
    if not text:
        return ""
    cleaned = text.strip().replace("\n", " ")
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[:max_len] + "..."

def generate_ai_summary(subject, description, root_cause, solution, tracker="Bug", conditions=""):
    parts = [f"[{tracker}] {subject}"]
    if conditions and conditions.strip():
        parts.append(f"【條件】{conditions.strip()}")
    if root_cause and root_cause.strip():
        parts.append(f"【根因】{root_cause.strip()}")
    if solution and solution.strip():
        parts.append(f"【解法】{solution.strip()}")
    elif description and description.strip():
        parts.append(f"【情境】{description.strip()[:100]}")
    return " | ".join(parts)

TERM_SYNONYMS = {
    # 繁簡中文互通 & 軟硬體英文縮寫擴充
    "藍屏": ["蓝屏", "bsod", "blue screen"],
    "蓝屏": ["藍屏", "bsod", "blue screen"],
    "bsod": ["藍屏", "蓝屏", "blue screen"],
    "記憶體": ["内存", "memory", "ram"],
    "内存": ["記憶體", "memory", "ram"],
    "ram": ["記憶體", "内存", "memory"],
    "韌體": ["固件", "firmware", "fw"],
    "固件": ["韌體", "firmware", "fw"],
    "firmware": ["韌體", "固件", "fw"],
    "fw": ["韌體", "固件", "firmware"],
    "睡眠": ["sleep", "s3", "suspend"],
    "sleep": ["睡眠", "s3", "suspend"],
    "s3": ["睡眠", "sleep", "suspend"],
    "重設": ["重置", "reset", "restart"],
    "重置": ["重設", "reset", "restart"],
    "reset": ["重設", "重置"],
    "死鎖": ["死锁", "deadlock", "hang"],
    "死锁": ["死鎖", "deadlock", "hang"],
    "deadlock": ["死鎖", "死锁"],
    "掛死": ["卡死", "hang", "freeze"],
    "卡死": ["掛死", "hang", "freeze"],
    "hang": ["卡死", "掛死", "freeze"],
    "type-c": ["usb-c", "typec", "usbc"],
    "usb-c": ["type-c", "typec", "usbc"],
    "斷電": ["断电", "power off", "power loss"],
    "断电": ["斷電", "power off", "power loss"],
    "復位": ["复位", "reset"],
    "复位": ["復位", "reset"],
}

def extract_search_tokens(raw_query):
    """提取查詢中的關鍵詞、ACPI 路徑組件，並自動加入同義詞/繁簡擴充"""
    if not raw_query or not raw_query.strip():
        return []
    raw_tokens = re.findall(r"[\w\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff\-]+", raw_query.strip(), flags=re.UNICODE)
    expanded = set()
    for t in raw_tokens:
        t_clean = t.strip()
        if not t_clean:
            continue
        has_cjk = bool(re.search(r"[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]", t_clean))
        if (has_cjk and len(t_clean) >= 1) or (not has_cjk and len(t_clean) >= 2):
            expanded.add(t_clean)
            t_lower = t_clean.lower()
            if t_lower in TERM_SYNONYMS:
                for syn in TERM_SYNONYMS[t_lower]:
                    expanded.add(syn)
    return list(expanded)

def compute_decision(status, confidence, superseded_by=None, commit_hash="", evidence_count=0):
    """
    為小模型 (7B/14B) 提供明確零歧義的決策指標：
    - adopt: 最高置信度已驗證解法 (Verified 且未被取代)
    - adopt_after_check: 已結案且帶代碼 Commit 或測試證據 (High 且未被取代)
    - candidate: 已結案但無實體驗證 (Medium)
    - avoid: 排除路徑 / 負向知識 / 廢棄 (Rejected, WontFix, Stale)
    - superseded: 已被更新的工單取代 (需改查新工單)
    - reference_only: 排查中或草稿 (New, In Progress)
    """
    if superseded_by is not None:
        return "superseded"
    if status in {"Rejected", "WontFix", "Stale"}:
        return "avoid"
    if status == "Verified" and confidence == "verified":
        return "adopt"
    if status in {"Closed", "Resolved"}:
        if confidence == "high" or commit_hash or evidence_count > 0:
            return "adopt_after_check"
        return "candidate"
    return "reference_only"

def build_fts_query(raw_query, mode="AND"):
    """
    建構支援中英混合之 FTS 查詢字串：
    - 純 ASCII 詞彙：長度 >= 2 (如 S3, IP, 401, JWT)
    - 含有 CJK 漢字之詞彙：保留長度 >= 1 之詞元 (如 鎖, 睡眠, 斷電, 藍屏)
    """
    if not raw_query or not raw_query.strip():
        return ""
    tokens = re.findall(r"[\w\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff\-]+", raw_query.strip(), flags=re.UNICODE)
    
    fts_tokens = []
    for t in tokens:
        has_cjk = bool(re.search(r"[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]", t))
        if has_cjk and len(t) >= 1:
            fts_tokens.append(t)
        elif not has_cjk and len(t) >= 2:
            fts_tokens.append(t)

    if not fts_tokens:
        return ""
    safe_tokens = []
    for t in fts_tokens:
        escaped = t.replace('"', '""')
        safe_tokens.append(f'"{escaped}"')
    return f" {mode} ".join(safe_tokens)

def output_json(data, pretty=False):
    if pretty:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(data, ensure_ascii=False, separators=(',', ':')))

# --- Core Action Implementations ---

def create_issue(project, subject, description="", tracker="Bug", status="New", priority="Normal",
                 confidence="unverified", scope="", conditions="", root_cause="", solution="",
                 ai_summary="", related_ids="", superseded_by=None, created_by="Agent",
                 commit_hash="", repository="", diff_summary="", evidence_type="", evidence_ref="",
                 evidence_note="", custom_fields_dict=None, initial_note="", allow_secret=False,
                 db_path=None, pretty=False):
    if not subject or not subject.strip():
        raise ValueError("Subject cannot be empty.")
    if not project or not project.strip():
        raise ValueError("Project cannot be empty.")

    project = project.strip()
    status = normalize_status(status)
    confidence = normalize_confidence(confidence)

    if status == "Verified":
        raise ValueError("Status 'Verified' cannot be set on creation. Use 'verify' command with concrete evidence.")

    if status in {"Closed", "Resolved"}:
        if not root_cause or not root_cause.strip():
            raise ValueError(f"Status '{status}' requires a non-empty root_cause.")
        if not solution or not solution.strip():
            raise ValueError(f"Status '{status}' requires a non-empty solution.")
        if confidence == "unverified":
            confidence = "high" if (commit_hash or evidence_ref) else "medium"

    if status in {"Rejected", "WontFix"}:
        if not initial_note and not description:
            raise ValueError(f"Status '{status}' requires a reason in description or note.")
        confidence = "rejected"

    # 全面機密安全掃描
    collect_and_scan_secrets({
        "subject": subject, "description": description, "root_cause": root_cause,
        "solution": solution, "initial_note": initial_note, "diff_summary": diff_summary,
        "evidence_ref": evidence_ref, "evidence_note": evidence_note, "scope": scope,
        "conditions": conditions, "ai_summary": ai_summary, "custom_fields": custom_fields_dict
    }, allow_secret)

    now = utc_now_iso()
    conn = init_db(db_path)
    cursor = conn.cursor()
    
    closed_at = now if status in TERMINAL_STATUSES else None
    
    if not ai_summary and (root_cause or solution):
        ai_summary = generate_ai_summary(subject, description, root_cause, solution, tracker, conditions)

    cursor.execute('''
        INSERT INTO issues (
            project_name, tracker, status, priority, confidence, subject, description,
            scope, conditions, root_cause, solution, ai_summary, related_ids, superseded_by,
            created_by, created_at, updated_at, closed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (project, tracker, status, priority, confidence, subject.strip(), description, scope, conditions,
          root_cause, solution, ai_summary, related_ids, superseded_by, created_by, now, now, closed_at))
    
    issue_id = cursor.lastrowid

    if custom_fields_dict:
        for k, v in custom_fields_dict.items():
            set_custom_value(cursor, issue_id, k, v)

    if commit_hash:
        add_git_revision(cursor, issue_id, commit_hash, repository, diff_summary)
        add_evidence_record(cursor, issue_id, "git_commit", commit_hash, diff_summary)

    if evidence_ref:
        add_evidence_record(cursor, issue_id, evidence_type or "manual", evidence_ref, evidence_note)

    if initial_note:
        cursor.execute("INSERT INTO journals (issue_id, notes, author, created_at) VALUES (?, ?, ?, ?)", (issue_id, initial_note, created_by, now))

    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Issue #{issue_id} created successfully.",
        "issue_id": issue_id,
        "project": project,
        "subject": subject,
        "issue_status": status,
        "confidence": confidence,
        "secret_override": bool(allow_secret)
    }, pretty)

def add_journal(issue_id, notes, author="Agent", allow_secret=False, db_path=None, pretty=False):
    if not notes or not notes.strip():
        raise ValueError("Journal notes cannot be empty.")
    
    collect_and_scan_secrets({"notes": notes}, allow_secret)

    now = utc_now_iso()
    conn = init_db(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, subject FROM issues WHERE id = ?", (issue_id,))
    row = cursor.fetchone()
    if not row:
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        sys.exit(1)

    cursor.execute("INSERT INTO journals (issue_id, notes, author, created_at) VALUES (?, ?, ?, ?)", (issue_id, notes, author, now))
    cursor.execute("UPDATE issues SET updated_at = ? WHERE id = ?", (now, issue_id))
    
    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Added journal entry to Issue #{issue_id}.",
        "issue_id": issue_id
    }, pretty)

def add_invalid_path(issue_id, approach, reason, failure_mode="", side_effect="", scope="",
                     parent_path_id=None, branch_type="attempt", risk_level="medium",
                     allow_secret=False, db_path=None, pretty=False):
    """記錄細粒度負向知識與探索樹分支 (Invalid Path / Exploration Tree Node)"""
    if not approach or not approach.strip():
        raise ValueError("Approach cannot be empty.")
    if not reason or not reason.strip():
        raise ValueError("Reason cannot be empty.")

    branch_type = (branch_type or "attempt").strip().lower()
    if branch_type not in ALLOWED_BRANCH_TYPES:
        raise ValueError(f"Invalid branch_type: '{branch_type}'. Allowed: {', '.join(sorted(ALLOWED_BRANCH_TYPES))}")

    risk_level = (risk_level or "medium").strip().lower()
    if risk_level not in ALLOWED_RISK_LEVELS:
        raise ValueError(f"Invalid risk_level: '{risk_level}'. Allowed: {', '.join(sorted(ALLOWED_RISK_LEVELS))}")

    collect_and_scan_secrets({
        "approach": approach, "reason": reason, "failure_mode": failure_mode,
        "side_effect": side_effect, "scope": scope
    }, allow_secret)

    now = utc_now_iso()
    conn = init_db(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, subject FROM issues WHERE id = ?", (issue_id,))
    if not cursor.fetchone():
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        sys.exit(1)

    if parent_path_id is not None:
        cursor.execute("SELECT id FROM invalid_paths WHERE id = ? AND issue_id = ?", (parent_path_id, issue_id))
        if not cursor.fetchone():
            raise ValueError(f"Parent invalid path #{parent_path_id} not found for Issue #{issue_id}.")

    cursor.execute('''
        INSERT INTO invalid_paths (issue_id, approach, failure_mode, reason, side_effect, scope, parent_path_id, branch_type, risk_level, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (issue_id, approach.strip(), failure_mode.strip(), reason.strip(), side_effect.strip(), scope.strip(), parent_path_id, branch_type, risk_level, now))

    path_id = cursor.lastrowid
    cursor.execute("UPDATE issues SET updated_at = ? WHERE id = ?", (now, issue_id))
    
    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Recorded negative knowledge (invalid path #{path_id}) for Issue #{issue_id}.",
        "issue_id": issue_id,
        "invalid_path_id": path_id,
        "approach": approach,
        "parent_path_id": parent_path_id,
        "branch_type": branch_type,
        "risk_level": risk_level,
        "veto": risk_level in {"fatal", "high"}
    }, pretty)

def close_issue(issue_id, root_cause, solution, ai_summary="", status="Closed", confidence="",
                conditions="", commit_hash="", repository="", diff_summary="",
                evidence_type="", evidence_ref="", evidence_note="", notes="", allow_secret=False,
                db_path=None, pretty=False):
    if not root_cause or not root_cause.strip():
        raise ValueError("root_cause cannot be empty when closing an issue.")
    if not solution or not solution.strip():
        raise ValueError("solution cannot be empty when closing an issue.")

    status = normalize_status(status)
    if status == "Verified":
        raise ValueError("Cannot set status to 'Verified' via close. Use 'verify' command to attach verification evidence.")

    collect_and_scan_secrets({
        "root_cause": root_cause, "solution": solution, "notes": notes,
        "diff_summary": diff_summary, "evidence_ref": evidence_ref,
        "evidence_note": evidence_note, "conditions": conditions, "ai_summary": ai_summary
    }, allow_secret)

    if not confidence:
        confidence = "high" if (commit_hash or evidence_ref) else "medium"
    else:
        confidence = normalize_confidence(confidence)

    now = utc_now_iso()
    conn = init_db(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, subject, description, tracker, conditions FROM issues WHERE id = ?", (issue_id,))
    row = cursor.fetchone()
    if not row:
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        sys.exit(1)

    subject, description, tracker, existing_cond = row[1], row[2], row[3], row[4]
    final_cond = conditions if conditions else existing_cond
    
    if not ai_summary:
        ai_summary = generate_ai_summary(subject, description, root_cause, solution, tracker, final_cond)

    cursor.execute('''
        UPDATE issues SET 
            status = ?,
            confidence = ?,
            conditions = ?,
            root_cause = ?,
            solution = ?,
            ai_summary = ?,
            updated_at = ?,
            closed_at = ?
        WHERE id = ?
    ''', (status, confidence, final_cond, root_cause, solution, ai_summary, now, now, issue_id))

    if commit_hash:
        add_git_revision(cursor, issue_id, commit_hash, repository, diff_summary)
        add_evidence_record(cursor, issue_id, "git_commit", commit_hash, diff_summary)

    if evidence_ref:
        add_evidence_record(cursor, issue_id, evidence_type or "manual", evidence_ref, evidence_note)

    if notes:
        cursor.execute("INSERT INTO journals (issue_id, notes, author, created_at) VALUES (?, ?, ?, ?)", (issue_id, notes, "Agent", now))

    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Issue #{issue_id} has been closed/resolved successfully.",
        "issue_id": issue_id,
        "issue_status": status,
        "confidence": confidence,
        "ai_summary": truncate_text(ai_summary, 160)
    }, pretty)

def verify_issue(issue_id, commit_hash="", evidence_type="test", evidence_ref="",
                 evidence_note="", verified_by="Agent", allow_secret=False, db_path=None, pretty=False):
    """提升工單為 Verified 狀態，強制要求 commit_hash 或具體可驗證的 evidence_ref"""
    if not commit_hash and not evidence_ref:
        raise ValueError("Verification requires at least a commit_hash or a valid evidence_ref (e.g. CI link, test command, log).")

    # 1. 驗證 Git Commit Hash (格式與實體存在性)
    if commit_hash:
        commit_hash = commit_hash.strip()
        if not re.match(r"^[0-9a-fA-F]{7,40}$", commit_hash):
            raise ValueError(f"Invalid Git commit hash format: '{commit_hash}'. Must be 7-40 hex characters.")
        if not verify_git_commit_exists(commit_hash):
            raise ValueError(f"Git verification failed: commit '{commit_hash}' was not found in the repository.")

    # 2. 驗證 Evidence Reference (拒絕空泛/無效字串)
    if evidence_ref:
        ref_str = evidence_ref.strip()
        if len(ref_str) < 5 or ref_str.lower() in {"trust me", "it works", "verified", "done", "ok", "test"}:
            raise ValueError(f"Evidence reference '{evidence_ref}' is too vague. Provide a concrete URL, file path, test suite name or command.")
        if evidence_type in {"ci", "url"} and not (ref_str.startswith("http://") or ref_str.startswith("https://")):
            raise ValueError(f"Evidence reference for type '{evidence_type}' must be a valid URL starting with http:// or https://")

    collect_and_scan_secrets({"evidence_ref": evidence_ref, "evidence_note": evidence_note}, allow_secret)

    now = utc_now_iso()
    conn = init_db(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, subject, status, root_cause, solution, closed_at FROM issues WHERE id = ?", (issue_id,))
    row = cursor.fetchone()
    if not row:
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        sys.exit(1)

    curr_st = row[2]
    if curr_st not in {"Closed", "Resolved"}:
        raise ValueError(f"Cannot verify Issue #{issue_id}: Status must be 'Closed' or 'Resolved' prior to verification (currently '{curr_st}').")

    existing_root_cause, existing_solution = row[3], row[4]
    if not existing_root_cause or not existing_solution:
        raise ValueError(f"Cannot verify Issue #{issue_id}: Root cause and solution must be documented before verification.")

    closed_at = row[5] or now

    if commit_hash:
        add_git_revision(cursor, issue_id, commit_hash)
        add_evidence_record(cursor, issue_id, "git_commit", commit_hash, evidence_note)

    if evidence_ref:
        add_evidence_record(cursor, issue_id, evidence_type, evidence_ref, evidence_note)

    cursor.execute('''
        UPDATE issues SET
            status = 'Verified',
            confidence = 'verified',
            verified_by = ?,
            verified_at = ?,
            updated_at = ?,
            closed_at = ?
        WHERE id = ?
    ''', (verified_by, now, now, closed_at, issue_id))

    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Issue #{issue_id} has been verified with concrete evidence.",
        "issue_id": issue_id,
        "issue_status": "Verified",
        "confidence": "verified"
    }, pretty)

def reject_issue(issue_id, reason, status="Rejected", side_effect="", scope="",
                 risk_level="high", allow_secret=False, db_path=None, pretty=False):
    """工單級別拒絕 / 沉澱負向知識，並自動同步至 invalid_paths"""
    if not reason or not reason.strip():
        raise ValueError("Reason cannot be empty when rejecting an issue.")

    risk_level = (risk_level or "high").strip().lower()
    if risk_level not in ALLOWED_RISK_LEVELS:
        raise ValueError(f"Invalid risk_level: '{risk_level}'. Allowed: {', '.join(sorted(ALLOWED_RISK_LEVELS))}")

    collect_and_scan_secrets({"reason": reason, "side_effect": side_effect, "scope": scope}, allow_secret)

    status = normalize_status(status)
    now = utc_now_iso()
    conn = init_db(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, subject, tracker FROM issues WHERE id = ?", (issue_id,))
    row = cursor.fetchone()
    if not row:
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        sys.exit(1)

    subject, tracker = row[1], row[2]
    ai_summary = f"[{tracker}] {subject} | 【狀態】{status} (已排除路徑) | 【原因】{reason}"

    cursor.execute('''
        UPDATE issues SET
            status = ?,
            confidence = 'rejected',
            ai_summary = ?,
            updated_at = ?,
            closed_at = ?
        WHERE id = ?
    ''', (status, ai_summary, now, now, issue_id))

    cursor.execute('''
        INSERT INTO journals (issue_id, notes, author, created_at)
        VALUES (?, ?, ?, ?)
    ''', (issue_id, f"【排除/拒絕原因】{reason}", "Agent", now))

    # 自動將工單級別拒絕同步為 invalid_path 條目，確保 search-invalid 查得到
    cursor.execute('''
        INSERT INTO invalid_paths (issue_id, approach, failure_mode, reason, side_effect, scope, parent_path_id, branch_type, risk_level, created_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, 'hypothesis', ?, ?)
    ''', (issue_id, subject, f"{status} Solution", reason, side_effect, scope, risk_level, now))

    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Issue #{issue_id} marked as {status} (Negative Knowledge captured).",
        "issue_id": issue_id,
        "issue_status": status,
        "ai_summary": truncate_text(ai_summary, 160)
    }, pretty)

def update_issue(issue_id, status=None, tracker=None, priority=None, confidence=None,
                 subject=None, description=None, scope=None, conditions=None,
                 root_cause=None, solution=None, ai_summary=None, related_ids=None,
                 superseded_by=None, custom_fields_dict=None, note=None, allow_secret=False,
                 db_path=None, pretty=False):
    collect_and_scan_secrets({
        "subject": subject, "description": description, "root_cause": root_cause,
        "solution": solution, "note": note, "conditions": conditions, "scope": scope,
        "ai_summary": ai_summary, "custom_fields": custom_fields_dict
    }, allow_secret)

    now = utc_now_iso()
    conn = init_db(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, status, confidence, root_cause, solution, conditions FROM issues WHERE id = ?", (issue_id,))
    curr = cursor.fetchone()
    if not curr:
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        sys.exit(1)

    curr_status, curr_confidence, curr_rc, curr_sol, curr_cond = curr[1], curr[2], curr[3], curr[4], curr[5]
    updates = []
    params = []

    # 計算更新後的實質狀態與內容 (防止 Partial Update 繞過不變量)
    normalized_st = normalize_status(status) if status is not None else None
    effective_st = normalized_st if normalized_st is not None else curr_status
    effective_rc = root_cause if root_cause is not None else curr_rc
    effective_sol = solution if solution is not None else curr_sol

    if effective_st in {"Closed", "Resolved", "Verified"}:
        if not effective_rc or not str(effective_rc).strip():
            raise ValueError(f"Cannot maintain/update status to '{effective_st}': root_cause is required and cannot be empty.")
        if not effective_sol or not str(effective_sol).strip():
            raise ValueError(f"Cannot set/maintain status to '{effective_st}': solution is required and cannot be empty.")

    if status is not None:
        if normalized_st == "Verified":
            raise ValueError("Status cannot be updated to 'Verified' directly. Use 'verify' command with evidence.")
        
        # 離開 Verified 狀態時自動降級置信度並清空驗證者中繼資料
        if curr_status == "Verified" and normalized_st != "Verified":
            updates.extend(["confidence = ?", "verified_by = ''", "verified_at = NULL"])
            params.append("unverified" if normalized_st in OPEN_STATUSES else "high")
        elif normalized_st in TERMINAL_STATUSES:
            updates.append("closed_at = ?")
            params.append(now)
        elif normalized_st in OPEN_STATUSES:
            updates.append("closed_at = NULL")

        updates.append("status = ?")
        params.append(normalized_st)

    # 若工單原本處於 Verified 狀態，但未改狀態卻修改了根本原因或解法，原本驗證自動失效降級
    if curr_status == "Verified" and status is None:
        if (root_cause is not None and root_cause != curr_rc) or (solution is not None and solution != curr_sol):
            updates.extend(["status = 'In Progress'", "confidence = 'unverified'", "verified_by = ''", "verified_at = NULL"])

    if confidence is not None:
        normalized_conf = normalize_confidence(confidence)
        if normalized_conf == "verified" and effective_st != "Verified":
            raise ValueError("confidence='verified' strictly requires status='Verified'. Use 'verify' command.")
        updates.append("confidence = ?")
        params.append(normalized_conf)

    fields = [
        ('tracker', tracker), ('priority', priority), ('subject', subject.strip() if subject else None),
        ('description', description), ('scope', scope), ('conditions', conditions),
        ('root_cause', root_cause), ('solution', solution), ('ai_summary', ai_summary),
        ('related_ids', related_ids), ('superseded_by', superseded_by)
    ]
    for field_name, val in fields:
        if val is not None:
            updates.append(f"{field_name} = ?")
            params.append(val)

    if updates:
        updates.append("updated_at = ?")
        params.append(now)
        sql = f"UPDATE issues SET {', '.join(updates)} WHERE id = ?"
        params.append(issue_id)
        cursor.execute(sql, params)

    if custom_fields_dict:
        for k, v in custom_fields_dict.items():
            set_custom_value(cursor, issue_id, k, v)

    if note:
        cursor.execute("INSERT INTO journals (issue_id, notes, author, created_at) VALUES (?, ?, ?, ?)", (issue_id, note, "Agent", now))

    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Issue #{issue_id} updated successfully.",
        "issue_id": issue_id
    }, pretty)

def search_issues(project=None, query=None, status=None, tracker=None, confidence=None,
                  custom_filters=None, closed_only=False, verified_only=False,
                  rejected_only=False, negative_only=False, match_mode="AND", limit=10,
                  db_path=None, pretty=False):
    """
    通用混合檢索 (專案名稱容錯 + FTS5 + LIKE 轉義 + Token 級 OR 檢索 + 置信度加權排序)
    """
    limit = max(1, limit)
    conn = init_db(db_path)
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if project:
        # v3.3.0: relaxed project matching (exact > substring) so a partial
        # project name ('FireRange') still scopes to 'FireRange-AM66ZJ'.
        _pn = "LOWER(REPLACE(TRIM(i.project_name), ' ', ''))"
        _pv = "LOWER(REPLACE(TRIM(?), ' ', ''))"
        where_clauses.append(f"({_pn} = {_pv} OR {_pn} LIKE ?)")
        params.extend([project, "%" + project.strip().lower().replace(" ", "") + "%"])

    if status:
        where_clauses.append("LOWER(TRIM(i.status)) = LOWER(TRIM(?))")
        params.append(status)

    if tracker:
        where_clauses.append("LOWER(TRIM(i.tracker)) = LOWER(TRIM(?))")
        params.append(tracker)

    if confidence:
        where_clauses.append("LOWER(TRIM(i.confidence)) = LOWER(TRIM(?))")
        params.append(confidence)
    elif verified_only:
        where_clauses.append("i.status = 'Verified' AND i.confidence = 'verified'")
    elif closed_only:
        where_clauses.append("i.status IN ('Closed', 'Resolved', 'Verified')")
    elif rejected_only:
        where_clauses.append("i.status IN ('Rejected', 'WontFix')")
    elif negative_only:
        where_clauses.append('''
            (
                i.status IN ('Rejected', 'WontFix')
                OR EXISTS (SELECT 1 FROM invalid_paths ip WHERE ip.issue_id = i.id)
            )
        ''')

    if custom_filters:
        for cf_name, cf_val in custom_filters.items():
            if cf_val:
                norm_v = normalize_custom_value(cf_name, cf_val)
                where_clauses.append('''
                    EXISTS (
                        SELECT 1 FROM custom_values cv
                        JOIN custom_fields cf ON cv.custom_field_id = cf.id
                        WHERE cv.issue_id = i.id AND cf.name = ? AND cv.value LIKE ? ESCAPE '\\'
                    )
                ''')
                params.extend([cf_name.lower(), f"%{escape_sql_like(norm_v)}%"])

    like_pat = f"%{escape_sql_like(query.strip())}%" if (query and query.strip()) else ""

    if query and query.strip():
        fts_query = build_fts_query(query, mode=match_mode)
        tokens = extract_search_tokens(query)
        if not tokens:
            tokens = [query.strip()]
        
        token_likes = []
        token_params = []
        for t in tokens:
            t_pat = f"%{escape_sql_like(t)}%"
            token_likes.append('''
                (
                    i.subject LIKE ? ESCAPE '\\'
                    OR i.description LIKE ? ESCAPE '\\'
                    OR i.root_cause LIKE ? ESCAPE '\\'
                    OR i.solution LIKE ? ESCAPE '\\'
                    OR i.ai_summary LIKE ? ESCAPE '\\'
                    OR EXISTS (
                        SELECT 1 FROM invalid_paths ip 
                        WHERE ip.issue_id = i.id 
                          AND (ip.approach LIKE ? ESCAPE '\\' OR ip.failure_mode LIKE ? ESCAPE '\\' OR ip.reason LIKE ? ESCAPE '\\' OR ip.side_effect LIKE ? ESCAPE '\\' OR ip.scope LIKE ? ESCAPE '\\')
                    )
                    OR EXISTS (SELECT 1 FROM custom_values cv WHERE cv.issue_id = i.id AND cv.value LIKE ? ESCAPE '\\')
                )
            ''')
            token_params.extend([t_pat, t_pat, t_pat, t_pat, t_pat, t_pat, t_pat, t_pat, t_pat, t_pat, t_pat])

        token_clause_str = " OR ".join(token_likes)

        if fts_query:
            where_clauses.append(f'''
                (
                    i.id IN (
                        SELECT CAST(issue_id AS INTEGER)
                        FROM issues_fts
                        WHERE issues_fts MATCH ?
                    )
                    OR {token_clause_str}
                )
            ''')
            params.append(fts_query)
            params.extend(token_params)
        else:
            where_clauses.append(f'''
                (
                    {token_clause_str}
                )
            ''')
            params.extend(token_params)

    where_str = " AND ".join(where_clauses) if where_clauses else "1=1"
    
    # 排序核心原則：Verified/High 置信度優先 > 未被取代優先 > 標題/摘要精確匹配 > 最近更新
    order_params = []
    if query and query.strip():
        order_by_str = """
            ORDER BY
                CASE i.confidence
                    WHEN 'verified' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'unverified' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'rejected' THEN 5
                    ELSE 6
                END ASC,
                CASE WHEN i.superseded_by IS NOT NULL THEN 1 ELSE 0 END ASC,
                CASE WHEN i.subject LIKE ? ESCAPE '\\' THEN 0 WHEN i.ai_summary LIKE ? ESCAPE '\\' THEN 1 ELSE 2 END ASC,
                i.updated_at DESC
        """
        order_params.extend([like_pat, like_pat])
    else:
        order_by_str = """
            ORDER BY
                CASE i.confidence
                    WHEN 'verified' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'unverified' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'rejected' THEN 5
                    ELSE 6
                END ASC,
                CASE WHEN i.superseded_by IS NOT NULL THEN 1 ELSE 0 END ASC,
                i.updated_at DESC
        """

    sql = f'''
        SELECT i.id, i.project_name, i.tracker, i.status, i.confidence, i.priority,
               i.subject, i.conditions, i.superseded_by, i.ai_summary, i.root_cause, i.solution,
               i.created_at, i.updated_at,
               (SELECT commit_hash FROM git_revisions WHERE issue_id = i.id ORDER BY id DESC LIMIT 1) as commit_ref,
               (SELECT COUNT(*) FROM invalid_paths WHERE issue_id = i.id) as invalid_path_count
        FROM issues i
        WHERE {where_str}
        {order_by_str}
        LIMIT ?
    '''
    final_params = params + order_params + [limit]

    try:
        cursor.execute(sql, final_params)
        rows = cursor.fetchall()
    except sqlite3.OperationalError:
        # Fallback 到純 LIKE 查詢避免 FTS 異常中斷
        fallback_where = " AND ".join([c for c in where_clauses if "issues_fts" not in c]) if where_clauses else "1=1"
        fallback_sql = f'''
            SELECT i.id, i.project_name, i.tracker, i.status, i.confidence, i.priority,
                   i.subject, i.conditions, i.superseded_by, i.ai_summary, i.root_cause, i.solution,
                   i.created_at, i.updated_at,
                   (SELECT commit_hash FROM git_revisions WHERE issue_id = i.id ORDER BY id DESC LIMIT 1) as commit_ref,
                   (SELECT COUNT(*) FROM invalid_paths WHERE issue_id = i.id) as invalid_path_count
            FROM issues i
            WHERE {fallback_where}
            ORDER BY i.updated_at DESC
            LIMIT ?
        '''
        cursor.execute(fallback_sql, [limit])
        rows = cursor.fetchall()

    results = []
    for r in rows:
        raw_summary = r[9] if r[9] else (f"根因: {r[10]} | 解法: {r[11]}" if (r[10] or r[11]) else "")
        dec = compute_decision(r[3], r[4], r[8], commit_hash=r[14] or "", evidence_count=0)
        results.append({
            "id": r[0],
            "project": r[1],
            "decision": dec,
            "tracker": r[2],
            "status": r[3],
            "confidence": r[4],
            "priority": r[5],
            "subject": r[6],
            "conditions": r[7] or "",
            "is_superseded": (r[8] is not None),
            "superseded_by": r[8],
            "ai_summary": truncate_text(raw_summary, 120),
            "commit_hash": r[14] or "",
            "has_negative_knowledge": (r[15] > 0),
            "invalid_path_count": r[15],
            "updated_at": r[13]
        })

    conn.close()
    output_json(results, pretty)

def search_invalid_paths(query=None, project=None, limit=10, db_path=None, pretty=False):
    """直接檢索細粒度負向知識條目 (Invalid Paths，支援 Token 拆解 OR 與同義詞擴充)"""
    limit = max(1, limit)
    conn = init_db(db_path)
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if project:
        # v3.3.0: relaxed project matching (exact > substring) so a partial
        # project name ('FireRange') still scopes to 'FireRange-AM66ZJ'.
        _pn = "LOWER(REPLACE(TRIM(i.project_name), ' ', ''))"
        _pv = "LOWER(REPLACE(TRIM(?), ' ', ''))"
        where_clauses.append(f"({_pn} = {_pv} OR {_pn} LIKE ?)")
        params.extend([project, "%" + project.strip().lower().replace(" ", "") + "%"])

    if query and query.strip():
        tokens = extract_search_tokens(query)
        if not tokens:
            tokens = [query.strip()]
        
        raw_like = f"%{escape_sql_like(query.strip())}%"
        or_clauses = [
            "(ip.approach LIKE ? ESCAPE '\\' OR ip.failure_mode LIKE ? ESCAPE '\\' OR ip.reason LIKE ? ESCAPE '\\' OR ip.side_effect LIKE ? ESCAPE '\\' OR ip.scope LIKE ? ESCAPE '\\' OR i.subject LIKE ? ESCAPE '\\')"
        ]
        params.extend([raw_like, raw_like, raw_like, raw_like, raw_like, raw_like])

        for t in tokens:
            t_like = f"%{escape_sql_like(t)}%"
            or_clauses.append("""
                (
                    ip.approach LIKE ? ESCAPE '\\'
                    OR ip.failure_mode LIKE ? ESCAPE '\\'
                    OR ip.reason LIKE ? ESCAPE '\\'
                    OR ip.side_effect LIKE ? ESCAPE '\\'
                    OR ip.scope LIKE ? ESCAPE '\\'
                    OR i.subject LIKE ? ESCAPE '\\'
                )
            """)
            params.extend([t_like, t_like, t_like, t_like, t_like, t_like])

        where_clauses.append(f"({' OR '.join(or_clauses)})")

    where_str = " AND ".join(where_clauses) if where_clauses else "1=1"
    sql = f'''
        SELECT ip.id, ip.issue_id, i.project_name, i.subject as issue_subject,
               ip.approach, ip.failure_mode, ip.reason, ip.side_effect, ip.scope,
               ip.parent_path_id, ip.branch_type, ip.risk_level, ip.created_at
        FROM invalid_paths ip
        JOIN issues i ON ip.issue_id = i.id
        WHERE {where_str}
        ORDER BY
            CASE ip.risk_level
                WHEN 'fatal' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
            END ASC,
            ip.created_at DESC
        LIMIT ?
    '''
    params.append(limit)

    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()

    results = []
    seen_ids = set()
    for r in rows:
        if r[0] not in seen_ids:
            seen_ids.add(r[0])
            r_risk = (r[11] or "medium").lower()
            results.append({
                "invalid_path_id": r[0],
                "issue_id": r[1],
                "project": r[2],
                "issue_subject": r[3],
                "approach": r[4],
                "failure_mode": r[5],
                "reason": r[6],
                "side_effect": r[7],
                "scope": r[8],
                "parent_path_id": r[9],
                "branch_type": r[10] or "attempt",
                "risk_level": r_risk,
                "veto": r_risk in {"fatal", "high"},
                "created_at": r[12]
            })
    output_json(results, pretty)

def find_similar_issues(subject, project=None, limit=5, db_path=None, pretty=False):
    """建立 Issue 前的查重指令 (Similar Check，採 OR 檢索模式)"""
    if not subject or not subject.strip():
        output_json([], pretty)
        return
    search_issues(project=project, query=subject.strip(), match_mode="OR", limit=limit, db_path=db_path, pretty=pretty)

def get_issue(issue_id, agent_mode=False, db_path=None, pretty=False):
    """Stage 2: 提取單筆工單完整詳情 (若啟用 agent_mode 則輸出低 Token 決策卡)"""
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, project_name, tracker, status, confidence, priority, subject, description,
               scope, conditions, root_cause, solution, ai_summary, related_ids, superseded_by,
               created_by, verified_by, verified_at, created_at, updated_at, closed_at
        FROM issues WHERE id = ?
    ''', (issue_id,))
    row = cursor.fetchone()

    if not row:
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        conn.close()
        sys.exit(1)

    cursor.execute('''
        SELECT cf.name, cv.value
        FROM custom_values cv
        JOIN custom_fields cf ON cv.custom_field_id = cf.id
        WHERE cv.issue_id = ?
    ''', (issue_id,))
    custom_fields = {r["name"]: r["value"] for r in cursor.fetchall()}

    cursor.execute('''
        SELECT commit_hash, repository, diff_summary, created_at
        FROM git_revisions WHERE issue_id = ? ORDER BY id ASC
    ''', (issue_id,))
    git_revisions = [
        {
            "commit_hash": r["commit_hash"],
            "repository": r["repository"],
            "diff_summary": r["diff_summary"],
            "created_at": r["created_at"]
        }
        for r in cursor.fetchall()
    ]

    cursor.execute('''
        SELECT evidence_type, reference, note, created_at
        FROM evidence WHERE issue_id = ? ORDER BY id ASC
    ''', (issue_id,))
    evidence_list = [
        {
            "type": r["evidence_type"],
            "reference": r["reference"],
            "note": r["note"],
            "created_at": r["created_at"]
        }
        for r in cursor.fetchall()
    ]

    cursor.execute('''
        SELECT id, approach, failure_mode, reason, side_effect, scope, parent_path_id, branch_type, risk_level, created_at
        FROM invalid_paths WHERE issue_id = ? ORDER BY id ASC
    ''', (issue_id,))
    invalid_paths = [
        {
            "id": r["id"],
            "approach": r["approach"],
            "failure_mode": r["failure_mode"],
            "reason": r["reason"],
            "side_effect": r["side_effect"],
            "scope": r["scope"],
            "parent_path_id": r["parent_path_id"],
            "branch_type": r["branch_type"] or "attempt",
            "risk_level": r["risk_level"] or "medium",
            "veto": (r["risk_level"] or "medium").lower() in {"fatal", "high"},
            "created_at": r["created_at"]
        }
        for r in cursor.fetchall()
    ]

    cursor.execute('''
        SELECT id, notes, author, created_at
        FROM journals WHERE issue_id = ? ORDER BY id ASC
    ''', (issue_id,))
    journals = [
        {"journal_id": r["id"], "notes": r["notes"], "author": r["author"], "created_at": r["created_at"]}
        for r in cursor.fetchall()
    ]

    conn.close()

    decision = compute_decision(
        row["status"],
        row["confidence"],
        row["superseded_by"],
        commit_hash=git_revisions[0]["commit_hash"] if git_revisions else "",
        evidence_count=len(evidence_list)
    )

    if agent_mode:
        recent_notes = [j["notes"] for j in journals[-3:]] if journals else []
        compact_output = {
            "id": row["id"],
            "project": row["project_name"],
            "decision": decision,
            "status": row["status"],
            "confidence": row["confidence"],
            "subject": row["subject"],
            "conditions": row["conditions"] or "無特定限制",
            "scope": row["scope"] or "",
            "root_cause": row["root_cause"] or "",
            "solution": row["solution"] or "",
            "commit_hashes": [r["commit_hash"] for r in git_revisions],
            "evidence": evidence_list,
            "do_not_try": [
                {
                    "path_id": inv["id"],
                    "approach": inv["approach"],
                    "reason": inv["reason"],
                    "side_effect": inv["side_effect"],
                    "scope": inv["scope"],
                    "parent_path_id": inv["parent_path_id"],
                    "branch_type": inv["branch_type"],
                    "risk_level": inv["risk_level"],
                    "veto": inv["veto"]
                }
                for inv in invalid_paths
            ],
            "recent_notes": recent_notes,
            "superseded_by": row["superseded_by"]
        }
        output_json(compact_output, pretty)
        return

    output = {
        "id": row["id"],
        "project": row["project_name"],
        "tracker": row["tracker"],
        "status": row["status"],
        "confidence": row["confidence"],
        "decision": decision,
        "priority": row["priority"],
        "subject": row["subject"],
        "description": row["description"],
        "scope": row["scope"] or "",
        "conditions": row["conditions"] or "",
        "root_cause": row["root_cause"] or "",
        "solution": row["solution"] or "",
        "ai_summary": row["ai_summary"] or "",
        "related_ids": row["related_ids"] or "",
        "superseded_by": row["superseded_by"],
        "created_by": row["created_by"] or "Agent",
        "verified_by": row["verified_by"] or "",
        "verified_at": row["verified_at"] or "",
        "custom_fields": custom_fields,
        "git_revisions": git_revisions,
        "evidence": evidence_list,
        "invalid_paths": invalid_paths,
        "journals": journals,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "closed_at": row["closed_at"]
    }
    output_json(output, pretty)

def redact_issue(issue_id, reason="Security Redaction", db_path=None, pretty=False):
    """
    全面脫敏並抹除特定工單所有敏感文字（涵蓋主表與所有子表，並執行 WAL Checkpoint 與 FTS 優化）
    """
    collect_and_scan_secrets({"reason": reason})

    conn = init_db(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM issues WHERE id = ?", (issue_id,))
    if not cursor.fetchone():
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        conn.close()
        sys.exit(1)

    now = utc_now_iso()
    cursor.execute('''
        UPDATE issues SET
            subject = '[REDACTED]',
            description = '[REDACTED: ' || ? || ']',
            scope = '[REDACTED]',
            conditions = '[REDACTED]',
            root_cause = '[REDACTED]',
            solution = '[REDACTED]',
            ai_summary = '[REDACTED]',
            status = 'Stale',
            confidence = 'rejected',
            verified_by = '',
            verified_at = NULL,
            updated_at = ?,
            closed_at = ?
        WHERE id = ?
    ''', (reason, now, now, issue_id))

    cursor.execute("UPDATE journals SET notes = '[REDACTED]', author = '[REDACTED]' WHERE issue_id = ?", (issue_id,))
    cursor.execute('''
        UPDATE invalid_paths SET
            approach = '[REDACTED]',
            failure_mode = '[REDACTED]',
            reason = '[REDACTED]',
            side_effect = '[REDACTED]',
            scope = '[REDACTED]'
        WHERE issue_id = ?
    ''', (issue_id,))
    cursor.execute("UPDATE evidence SET reference = '[REDACTED]', note = '[REDACTED]' WHERE issue_id = ?", (issue_id,))
    cursor.execute("UPDATE git_revisions SET commit_hash = '[REDACTED]', diff_summary = '[REDACTED]' WHERE issue_id = ?", (issue_id,))
    cursor.execute("UPDATE custom_values SET value = '[REDACTED]' WHERE issue_id = ?", (issue_id,))
    
    conn.commit()
    sync_fts_entry(conn, issue_id)
    conn.commit()

    # 執行 FTS 影子表重組與 WAL Checkpoint 物理抹除日誌
    try:
        cursor.execute("INSERT INTO issues_fts(issues_fts) VALUES('optimize')")
        cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
    except Exception:
        pass

    conn.close()
    output_json({"status": "success", "message": f"Issue #{issue_id} and all related child records have been thoroughly redacted and physical WAL purged."}, pretty)

def delete_issue(issue_id, confirm=False, db_path=None, pretty=False):
    """物理刪除特定工單及其關聯資料並抹除 WAL"""
    if not confirm:
        output_json({"status": "error", "error_code": "CONFIRM_REQUIRED", "message": "Physical deletion requires --confirm flag."}, pretty)
        sys.exit(1)

    conn = init_db(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM issues WHERE id = ?", (issue_id,))
    if not cursor.fetchone():
        output_json({"status": "error", "error_code": "NOT_FOUND", "message": f"Issue #{issue_id} not found."}, pretty)
        conn.close()
        sys.exit(1)

    cursor.execute("DELETE FROM issues WHERE id = ?", (issue_id,))
    cursor.execute("DELETE FROM issues_fts WHERE issue_id = ?", (str(issue_id),))
    conn.commit()

    try:
        cursor.execute("INSERT INTO issues_fts(issues_fts) VALUES('optimize')")
        cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
    except Exception:
        pass

    conn.close()
    output_json({"status": "success", "message": f"Issue #{issue_id} permanently deleted and WAL purged."}, pretty)

def export_data(file_path, project=None, db_path=None, pretty=False):
    """高效匯出記憶庫資料為 JSONL 備份檔 (單一連線避免 N+1)"""
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    where_clause = "WHERE LOWER(TRIM(project_name)) = LOWER(TRIM(?))" if project else ""
    params = (project,) if project else ()
    
    cursor.execute(f"SELECT * FROM issues {where_clause} ORDER BY id ASC", params)
    issues_rows = cursor.fetchall()

    count = 0
    with open(file_path, 'w', encoding='utf-8') as f:
        for row in issues_rows:
            i_id = row["id"]

            cursor.execute('''
                SELECT cf.name, cv.value FROM custom_values cv
                JOIN custom_fields cf ON cv.custom_field_id = cf.id WHERE cv.issue_id = ?
            ''', (i_id,))
            custom_fields = {r["name"]: r["value"] for r in cursor.fetchall()}

            cursor.execute('SELECT commit_hash, repository, diff_summary, created_at FROM git_revisions WHERE issue_id = ?', (i_id,))
            git_revisions = [{"commit_hash": r["commit_hash"], "repository": r["repository"], "diff_summary": r["diff_summary"], "created_at": r["created_at"]} for r in cursor.fetchall()]

            cursor.execute('SELECT evidence_type, reference, note, created_at FROM evidence WHERE issue_id = ?', (i_id,))
            evidence_list = [{"type": r["evidence_type"], "reference": r["reference"], "note": r["note"], "created_at": r["created_at"]} for r in cursor.fetchall()]

            cursor.execute('SELECT id, approach, failure_mode, reason, side_effect, scope, parent_path_id, branch_type, risk_level, created_at FROM invalid_paths WHERE issue_id = ?', (i_id,))
            invalid_paths = [
                {
                    "id": r["id"],
                    "approach": r["approach"],
                    "failure_mode": r["failure_mode"],
                    "reason": r["reason"],
                    "side_effect": r["side_effect"],
                    "scope": r["scope"],
                    "parent_path_id": r["parent_path_id"],
                    "branch_type": r["branch_type"] or "attempt",
                    "risk_level": r["risk_level"] or "medium",
                    "created_at": r["created_at"]
                }
                for r in cursor.fetchall()
            ]

            cursor.execute('SELECT notes, author, created_at FROM journals WHERE issue_id = ?', (i_id,))
            journals = [{"notes": r["notes"], "author": r["author"], "created_at": r["created_at"]} for r in cursor.fetchall()]

            record = {
                "id": row["id"], "project": row["project_name"], "tracker": row["tracker"], "status": row["status"],
                "confidence": row["confidence"], "priority": row["priority"], "subject": row["subject"], "description": row["description"],
                "scope": row["scope"], "conditions": row["conditions"], "root_cause": row["root_cause"], "solution": row["solution"],
                "ai_summary": row["ai_summary"], "related_ids": row["related_ids"], "superseded_by": row["superseded_by"],
                "created_by": row["created_by"], "verified_by": row["verified_by"], "verified_at": row["verified_at"],
                "created_at": row["created_at"], "updated_at": row["updated_at"], "closed_at": row["closed_at"],
                "custom_fields": custom_fields, "git_revisions": git_revisions,
                "evidence": evidence_list, "invalid_paths": invalid_paths, "journals": journals
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    conn.close()
    output_json({"status": "success", "message": f"Exported {count} issues to {file_path}."}, pretty)

def import_data(file_path, dedupe=False, allow_secret=False, db_path=None, pretty=False):
    """從 JSONL 檔案匯入記憶庫 (支援冪等去重、狀態不變量校驗與關聯 ID 重新映射)"""
    file_path = os.path.abspath(os.path.expanduser(file_path))
    if not os.path.exists(file_path):
        output_json({"status": "error", "error_code": "FILE_NOT_FOUND", "message": f"File not found: {file_path}"}, pretty)
        sys.exit(1)

    conn = init_db(db_path)
    cursor = conn.cursor()
    
    imported_count = 0
    skipped_count = 0
    id_mapping = {}  # 舊 ID -> 新 ID
    path_id_mapping = {}  # 舊 Path ID -> 新 Path ID
    pending_updates = []
    pending_path_updates = []

    try:
        cursor.execute("BEGIN TRANSACTION")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                item = json.loads(line)
                
                # 掃描機密
                collect_and_scan_secrets(item, allow_secret=allow_secret)

                project = item.get('project', '').strip()
                subject = item.get('subject', '').strip()
                old_id = item.get('id')

                if dedupe and project and subject:
                    cursor.execute("SELECT id FROM issues WHERE LOWER(TRIM(project_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(subject)) = LOWER(TRIM(?))", (project, subject))
                    if cursor.fetchone():
                        skipped_count += 1
                        continue

                raw_st = item.get('status', 'New')
                norm_st = normalize_status(raw_st)
                raw_conf = item.get('confidence', 'unverified')
                norm_conf = normalize_confidence(raw_conf)
                rc = (item.get('root_cause') or '').strip()
                sol = (item.get('solution') or '').strip()

                # 狀態機不變量校驗 (防止損毀/惡意備份檔注入偽造狀態)
                if norm_st == 'Verified':
                    if norm_conf != 'verified' or not rc or not sol:
                        norm_st = 'In Progress'
                        norm_conf = 'unverified'
                elif norm_st in {'Closed', 'Resolved'}:
                    if not rc or not sol:
                        norm_st = 'In Progress'
                        norm_conf = 'unverified'

                cursor.execute('''
                    INSERT INTO issues (
                        project_name, tracker, status, priority, confidence, subject, description,
                        scope, conditions, root_cause, solution, ai_summary, related_ids, superseded_by,
                        created_by, verified_by, verified_at, created_at, updated_at, closed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    project, item.get('tracker', 'Bug'), norm_st,
                    item.get('priority', 'Normal'), norm_conf,
                    subject, item.get('description', ''), item.get('scope', ''),
                    item.get('conditions', ''), rc, sol,
                    item.get('ai_summary', ''), item.get('related_ids', ''), item.get('superseded_by'),
                    item.get('created_by', 'Agent'), item.get('verified_by', '') if norm_st == 'Verified' else '',
                    item.get('verified_at') if norm_st == 'Verified' else None,
                    item.get('created_at', utc_now_iso()), item.get('updated_at', utc_now_iso()),
                    item.get('closed_at')
                ))
                new_id = cursor.lastrowid
                if old_id:
                    id_mapping[old_id] = new_id

                for k, v in item.get('custom_fields', {}).items():
                    set_custom_value(cursor, new_id, k, v)

                for rev in item.get('git_revisions', []):
                    add_git_revision(cursor, new_id, rev.get('commit_hash', ''), rev.get('repository', ''), rev.get('diff_summary', ''))

                for ev in item.get('evidence', []):
                    add_evidence_record(cursor, new_id, ev.get('type', 'manual'), ev.get('reference', ''), ev.get('note', ''))

                for inv in item.get('invalid_paths', []):
                    cursor.execute('''
                        INSERT INTO invalid_paths (issue_id, approach, failure_mode, reason, side_effect, scope, parent_path_id, branch_type, risk_level, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                    ''', (
                        new_id,
                        inv.get('approach', ''),
                        inv.get('failure_mode', ''),
                        inv.get('reason', ''),
                        inv.get('side_effect', ''),
                        inv.get('scope', ''),
                        inv.get('branch_type', 'attempt'),
                        inv.get('risk_level', 'medium'),
                        inv.get('created_at', utc_now_iso())
                    ))
                    new_path_id = cursor.lastrowid
                    old_path_id = inv.get('id')
                    if old_path_id is not None:
                        path_id_mapping[old_path_id] = new_path_id
                    if inv.get('parent_path_id') is not None:
                        pending_path_updates.append((new_path_id, inv.get('parent_path_id')))

                for j in item.get('journals', []):
                    cursor.execute('INSERT INTO journals (issue_id, notes, author, created_at) VALUES (?, ?, ?, ?)',
                                   (new_id, j.get('notes', ''), j.get('author', 'Agent'), j.get('created_at', utc_now_iso())))

                pending_updates.append((new_id, item.get('related_ids', ''), item.get('superseded_by')))
                imported_count += 1

        # 重新映射 related_ids 與 superseded_by
        for new_id, rel_str, sup_id in pending_updates:
            updates = []
            params = []
            if rel_str:
                new_rel_list = []
                for p in str(rel_str).split(','):
                    p = p.strip()
                    if p.isdigit():
                        old_p_id = int(p)
                        new_rel_list.append(str(id_mapping.get(old_p_id, old_p_id)))
                    elif p:
                        new_rel_list.append(p)
                updates.append("related_ids = ?")
                params.append(",".join(new_rel_list))
            
            if sup_id and isinstance(sup_id, int):
                new_sup_id = id_mapping.get(sup_id, sup_id)
                updates.append("superseded_by = ?")
                params.append(new_sup_id)
            
            if updates:
                params.append(new_id)
                cursor.execute(f"UPDATE issues SET {', '.join(updates)} WHERE id = ?", params)

        # 重新映射 invalid_paths 的 parent_path_id
        for new_pid, old_parent_pid in pending_path_updates:
            if old_parent_pid in path_id_mapping:
                cursor.execute("UPDATE invalid_paths SET parent_path_id = ? WHERE id = ?", (path_id_mapping[old_parent_pid], new_pid))

        conn.commit()

        # 重建 FTS
        cursor.execute("SELECT id FROM issues")
        for (i_id,) in cursor.fetchall():
            sync_fts_entry(conn, i_id)
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        output_json({"status": "error", "error_code": "IMPORT_FAILED", "message": f"Import failed: {str(e)}"}, pretty)
        sys.exit(1)

    conn.close()
    output_json({
        "status": "success",
        "message": f"Successfully imported {imported_count} issues ({skipped_count} skipped by dedupe) from {file_path}."
    }, pretty)

def answer_query(query, project=None, platform=None, env=None, limit=3, db_path=None, pretty=False):
    """
    Agent 專屬推理證據卡生成器 (Synthesized Evidence Card for LLM Context)
    使用 Token 級混合檢索 (Token-OR + FTS5 + LIKE) 並支援 Platform/Env/Superseded 完整過濾。
    """
    if not query or not query.strip():
        output_json({"status": "error", "message": "Query cannot be empty."}, pretty)
        return

    conn = init_db(db_path)
    cursor = conn.cursor()

    search_tokens = extract_search_tokens(query)
    if not search_tokens:
        search_tokens = [query.strip()]

    # 1. 建立工單候選集查詢條件
    where_clauses = ["(i.status IN ('Verified', 'Closed', 'Resolved') OR i.confidence IN ('verified', 'high', 'medium'))"]
    params = []

    if project:
        # v3.3.0: relaxed project matching (exact > substring) so a partial
        # project name ('FireRange') still scopes to 'FireRange-AM66ZJ'.
        _pn = "LOWER(REPLACE(TRIM(i.project_name), ' ', ''))"
        _pv = "LOWER(REPLACE(TRIM(?), ' ', ''))"
        where_clauses.append(f"({_pn} = {_pv} OR {_pn} LIKE ?)")
        params.extend([project, "%" + project.strip().lower().replace(" ", "") + "%"])

    # Platform 過濾
    if platform:
        p_clean = platform.strip()
        where_clauses.append("""
            (
                i.scope LIKE ? ESCAPE '\\'
                OR i.conditions LIKE ? ESCAPE '\\'
                OR EXISTS (
                    SELECT 1 FROM custom_values cv
                    JOIN custom_fields cf ON cv.custom_field_id = cf.id
                    WHERE cv.issue_id = i.id AND cf.name = 'platform' AND cv.value LIKE ? ESCAPE '\\'
                )
            )
        """)
        params.extend([f"%{escape_sql_like(p_clean)}%", f"%{escape_sql_like(p_clean)}%", f"%{escape_sql_like(p_clean)}%"])

    # Env 過濾
    if env:
        e_clean = env.strip()
        where_clauses.append("""
            (
                i.scope LIKE ? ESCAPE '\\'
                OR i.conditions LIKE ? ESCAPE '\\'
                OR EXISTS (
                    SELECT 1 FROM custom_values cv
                    JOIN custom_fields cf ON cv.custom_field_id = cf.id
                    WHERE cv.issue_id = i.id AND cf.name = 'env' AND cv.value LIKE ? ESCAPE '\\'
                )
            )
        """)
        params.extend([f"%{escape_sql_like(e_clean)}%", f"%{escape_sql_like(e_clean)}%", f"%{escape_sql_like(e_clean)}%"])

    # Token-based 匹配
    token_or_clauses = []
    token_params = []
    raw_like = f"%{escape_sql_like(query.strip())}%"

    # 精確整體匹配
    token_or_clauses.append("""
        (
            i.subject LIKE ? ESCAPE '\\'
            OR i.root_cause LIKE ? ESCAPE '\\'
            OR i.solution LIKE ? ESCAPE '\\'
            OR i.ai_summary LIKE ? ESCAPE '\\'
        )
    """)
    token_params.extend([raw_like, raw_like, raw_like, raw_like])

    # 個別 Token 拆解 OR 匹配 (支援 ACPI 子路徑、繁簡中文與倒序詞)
    for token in search_tokens:
        t_like = f"%{escape_sql_like(token)}%"
        token_or_clauses.append("""
            (
                i.subject LIKE ? ESCAPE '\\'
                OR i.root_cause LIKE ? ESCAPE '\\'
                OR i.solution LIKE ? ESCAPE '\\'
                OR i.ai_summary LIKE ? ESCAPE '\\'
                OR EXISTS (
                    SELECT 1 FROM invalid_paths ip 
                    WHERE ip.issue_id = i.id AND (ip.approach LIKE ? ESCAPE '\\' OR ip.reason LIKE ? ESCAPE '\\')
                )
            )
        """)
        token_params.extend([t_like, t_like, t_like, t_like, t_like, t_like])

    # 3. Rank by token hit-count first: a ticket matching MORE query tokens
    #    outranks one matching fewer. Previously ties fell through to
    #    updated_at, letting a newer-but-unrelated issue win the evidence card.
    rank_clauses = []
    rank_params = []
    _rlike = "%" + escape_sql_like(query.strip()) + "%"
    rank_clauses.append(
        "(i.subject LIKE ? ESCAPE '\\' OR i.root_cause LIKE ? ESCAPE '\\' "
        "OR i.solution LIKE ? ESCAPE '\\' OR i.ai_summary LIKE ? ESCAPE '\\')"
    )
    rank_params.extend([_rlike, _rlike, _rlike, _rlike])
    for token in search_tokens:
        _tl = "%" + escape_sql_like(token) + "%"
        rank_clauses.append(
            "(i.subject LIKE ? ESCAPE '\\' OR i.root_cause LIKE ? ESCAPE '\\' "
            "OR i.solution LIKE ? ESCAPE '\\' OR i.ai_summary LIKE ? ESCAPE '\\' "
            "OR EXISTS (SELECT 1 FROM invalid_paths ip WHERE ip.issue_id = i.id "
            "AND (ip.approach LIKE ? ESCAPE '\\' OR ip.reason LIKE ? ESCAPE '\\')))"
        )
        rank_params.extend([_tl] * 6)
    rank_sum = " + ".join(
        "CASE WHEN " + c + " THEN 1 ELSE 0 END" for c in rank_clauses
    )

    # v3.3.0: project affinity — a query token hitting a ticket's project_name
    # outranks pure content hits, so same-project tickets stay on top while
    # cross-project results only fill the gaps. Single-char tokens are skipped
    # to prevent false project matches.
    project_rank_clauses = []
    project_rank_params = []
    for token in search_tokens:
        if len(token) < 3:
            continue
        project_rank_clauses.append("(i.project_name LIKE ? ESCAPE '\\')")
        project_rank_params.append("%" + escape_sql_like(token) + "%")
    project_sum = (
        " + ".join(
            "CASE WHEN " + c + " THEN 1 ELSE 0 END"
            for c in project_rank_clauses
        ) if project_rank_clauses else "0"
    )

    where_clauses.append(f"({' OR '.join(token_or_clauses)})")
    params.extend(token_params)

    where_str = " AND ".join(where_clauses)
    sql = f'''
        SELECT i.id, i.project_name, i.subject, i.status, i.confidence, i.conditions,
               i.root_cause, i.solution, i.ai_summary, i.superseded_by,
               (SELECT commit_hash FROM git_revisions WHERE issue_id = i.id ORDER BY id DESC LIMIT 1) as commit_ref,
               (SELECT COUNT(*) FROM evidence WHERE issue_id = i.id) as ev_count
        FROM issues i
        WHERE {where_str}
        ORDER BY
            CASE WHEN i.superseded_by IS NOT NULL THEN 1 ELSE 0 END ASC,
            ({project_sum}) DESC,
            CASE i.confidence WHEN 'verified' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END ASC,
            ({rank_sum}) DESC,
            CASE WHEN i.subject LIKE ? ESCAPE '\\' THEN 0 ELSE 1 END ASC,
            i.updated_at DESC
        LIMIT ?
    '''
    params.extend(project_rank_params + rank_params + [raw_like, limit])
    cursor.execute(sql, params)
    candidate_rows = cursor.fetchall()

    # v3.3.0: project probe for the cross-project honesty warning (below).
    probe_tokens = [t for t in search_tokens if len(t) >= 3]
    probe_projects = set()
    if probe_tokens:
        _pph = " OR ".join(["i2.project_name LIKE ? ESCAPE '\\'" for _ in probe_tokens])
        _plt = ["%" + escape_sql_like(t) + "%" for t in probe_tokens]
        cursor.execute(f"SELECT DISTINCT project_name FROM issues i2 WHERE {_pph}", _plt)
        probe_projects = {r[0].strip().lower().replace(" ", "") for r in cursor.fetchall()}

    # 2. 檢索相關負向知識 (Invalid Paths: 採用 Token 拆解 OR 匹配)
    inv_or_clauses = [
        "(ip.approach LIKE ? ESCAPE '\\' OR ip.reason LIKE ? ESCAPE '\\' OR ip.side_effect LIKE ? ESCAPE '\\' OR i.subject LIKE ? ESCAPE '\\')"
    ]
    inv_params = [raw_like, raw_like, raw_like, raw_like]

    for token in search_tokens:
        t_like = f"%{escape_sql_like(token)}%"
        inv_or_clauses.append("""
            (
                ip.approach LIKE ? ESCAPE '\\'
                OR ip.reason LIKE ? ESCAPE '\\'
                OR ip.side_effect LIKE ? ESCAPE '\\'
                OR ip.scope LIKE ? ESCAPE '\\'
                OR i.subject LIKE ? ESCAPE '\\'
            )
        """)
        inv_params.extend([t_like, t_like, t_like, t_like, t_like])

    inv_sql = f'''
        SELECT ip.id, ip.approach, ip.reason, ip.side_effect, ip.scope, ip.issue_id, i.subject,
               ip.parent_path_id, ip.branch_type, ip.risk_level
        FROM invalid_paths ip
        JOIN issues i ON ip.issue_id = i.id
        WHERE ({' OR '.join(inv_or_clauses)})
        ORDER BY
            CASE ip.risk_level
                WHEN 'fatal' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
            END ASC,
            ip.created_at DESC
        LIMIT 10
    '''
    cursor.execute(inv_sql, inv_params)
    inv_rows = cursor.fetchall()

    solutions = []
    for r in candidate_rows:
        dec = compute_decision(r[3], r[4], r[9], commit_hash=r[10] or "", evidence_count=r[11])
        solutions.append({
            "issue_id": r[0],
            "project": r[1],
            "decision": dec,
            "subject": r[2],
            "status": r[3],
            "confidence": r[4],
            "conditions": r[5] or "無特定限制",
            "root_cause": r[6],
            "solution": r[7],
            "summary": r[8],
            "superseded_by": r[9],
            "commit_hash": r[10] or ""
        })

    do_not_try = []
    seen_approaches = set()
    for ir in inv_rows:
        app_key = ir[1].strip().lower()
        if app_key not in seen_approaches:
            seen_approaches.add(app_key)
            ir_risk = (ir[9] or "medium").lower()
            is_veto = ir_risk in {"fatal", "high"}
            do_not_try.append({
                "path_id": ir[0],
                "approach": ir[1],
                "reason": ir[2],
                "side_effect": ir[3] or "",
                "scope": ir[4] or "",
                "source_issue_id": ir[5],
                "parent_path_id": ir[7],
                "branch_type": ir[8] or "attempt",
                "risk_level": ir_risk,
                "veto": is_veto,
                "warning_label": f"[HARD VETO] {ir[1]}" if is_veto else ir[1]
            })

    best_sol = solutions[0] if solutions else None
    diagnostic_policy = None
    if best_sol:
        b_id = best_sol["issue_id"]
        cursor.execute("SELECT id, notes, author, created_at FROM journals WHERE issue_id = ? ORDER BY id ASC", (b_id,))
        b_journals = cursor.fetchall()
        cursor.execute("SELECT id, approach, failure_mode, reason, side_effect, scope, parent_path_id, branch_type, risk_level FROM invalid_paths WHERE issue_id = ? ORDER BY id ASC", (b_id,))
        b_invs = cursor.fetchall()
        cursor.execute("SELECT evidence_type, reference, note FROM evidence WHERE issue_id = ? ORDER BY id ASC", (b_id,))
        b_evidence = cursor.fetchall()

        sop_steps = []
        if b_journals:
            for idx, jr in enumerate(b_journals, 1):
                sop_steps.append(f"Step {idx}: {jr[1]}")
        else:
            if best_sol.get("root_cause"):
                sop_steps.append(f"Step 1 (Root Cause Check): 診斷確認是否為「{best_sol['root_cause']}」")
            if best_sol.get("conditions") and best_sol["conditions"] != "無特定限制":
                sop_steps.append(f"Step 2 (Prerequisite): 確認適用條件「{best_sol['conditions']}」")
            if best_sol.get("solution"):
                step_num = len(sop_steps) + 1
                sop_steps.append(f"Step {step_num} (Execution): 套用驗證解法「{best_sol['solution']}」")

        diagnostic_policy = {
            "source_issue_id": b_id,
            "recommended_sop": sop_steps,
            "pruned_branches": [
                {
                    "path_id": binv[0],
                    "approach": binv[1],
                    "branch_type": binv[7] or "attempt",
                    "risk_level": binv[8] or "medium",
                    "reason": binv[3],
                    "side_effect": binv[4] or "",
                    "veto": (binv[8] or "medium").lower() in {"fatal", "high"}
                }
                for binv in b_invs
            ],
            "verification_checks": [
                {"type": bev[0], "reference": bev[1], "note": bev[2]} for bev in b_evidence
            ]
        }

    conn.close()

    warnings = []

    if best_sol:
        if best_sol.get("superseded_by"):
            warnings.append(f"工單 #{best_sol['issue_id']} 已被工單 #{best_sol['superseded_by']} 取代，建議優先查閱 #{best_sol['superseded_by']}。")
        if best_sol.get("conditions") and best_sol["conditions"] != "無特定限制":
            warnings.append(f"適用條件限制: {best_sol['conditions']}")

    # v3.3.0: cross-project honesty gate. When query tokens identify a project
    # and the top result comes from a DIFFERENT project, do not issue a
    # confident `adopt` on a foreign ticket — mark it `candidate` and warn.
    # (Same-project tokens already outrank via project_sum; this only bites
    # when the query's own project has nothing the query matches.)
    if (probe_projects and best_sol
            and best_sol.get("project", "").strip().lower().replace(" ", "")
            not in probe_projects):
        best_sol["decision"] = "candidate"
        warnings.append(
            f"注意: 最佳命中來自跨專案 ({best_sol['project']})，非查詢所屬專案 "
            f"(疑似: {', '.join(sorted(probe_projects))})，採前請核對適用條件。"
        )

    recommendation = f"採用工單 #{best_sol['issue_id']} 之驗證解法: {best_sol['solution']}" if best_sol else "未檢索到已驗證之高置信度解法，建議依標準除錯流程排查。"

    card = {
        "query": query,
        "decision": best_sol["decision"] if best_sol else "avoid",
        "recommendation": recommendation,
        "confidence": best_sol["confidence"] if best_sol else "unverified",
        "best_solution": best_sol,
        "diagnostic_policy": diagnostic_policy,
        "alternative_solutions": solutions[1:] if len(solutions) > 1 else [],
        "do_not_try": do_not_try,
        "warnings": warnings
    }
    output_json(card, pretty)

def reindex(db_path=None, pretty=False):
    """重建 FTS5 全文檢索索引"""
    conn = init_db(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM issues_fts")
    cursor.execute("SELECT id FROM issues")
    ids = [row[0] for row in cursor.fetchall()]
    conn.commit()

    for issue_id in ids:
        sync_fts_entry(conn, issue_id)

    conn.commit()
    conn.close()

    output_json({
        "status": "success",
        "message": f"Successfully reindexed {len(ids)} issues into FTS5."
    }, pretty)

def doctor(db_path=None, pretty=False):
    """系統自我診斷、資料健康檢查與專案統計 (雙向信任鏈檢查)"""
    conn = init_db(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT sqlite_version()")
    sqlite_ver = cursor.fetchone()[0]

    cursor.execute("PRAGMA user_version")
    user_ver = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM issues")
    total_issues = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM invalid_paths")
    total_invalid_paths = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM evidence")
    total_evidence = cursor.fetchone()[0]

    tokenizer = detect_best_tokenizer(conn)

    cursor.execute("SELECT project_name, COUNT(*) FROM issues GROUP BY project_name")
    projects_distribution = {r[0]: r[1] for r in cursor.fetchall()}

    cursor.execute("SELECT status, COUNT(*) FROM issues GROUP BY status")
    status_distribution = {r[0]: r[1] for r in cursor.fetchall()}

    cursor.execute("SELECT confidence, COUNT(*) FROM issues GROUP BY confidence")
    confidence_distribution = {r[0]: r[1] for r in cursor.fetchall()}

    actual_db_file = os.path.abspath(resolve_default_db_path(db_path))
    db_size_kb = round(os.path.getsize(actual_db_file) / 1024, 2) if os.path.exists(actual_db_file) else 0

    warnings = []
    
    # 1. 終態但 closed_at 為 NULL 檢查 (依 TERMINAL_STATUSES 動態生成)
    term_placeholders = ",".join(["?"] * len(TERMINAL_STATUSES))
    cursor.execute(f"SELECT id FROM issues WHERE status IN ({term_placeholders}) AND closed_at IS NULL", list(TERMINAL_STATUSES))
    bad_closed = cursor.fetchall()
    if bad_closed:
        warnings.append(f"{len(bad_closed)} terminal status issues have NULL closed_at timestamp.")

    # 2. 雙向信任鏈檢查 (Verified <-> confidence='verified')
    cursor.execute("SELECT id FROM issues WHERE status = 'Verified' AND confidence != 'verified'")
    bad_ver_conf = cursor.fetchall()
    if bad_ver_conf:
        warnings.append(f"{len(bad_ver_conf)} verified issues have confidence != 'verified'.")

    cursor.execute("SELECT id FROM issues WHERE confidence = 'verified' AND status != 'Verified'")
    bad_conf_ver = cursor.fetchall()
    if bad_conf_ver:
        warnings.append(f"{len(bad_conf_ver)} issues with confidence='verified' are not in 'Verified' status.")

    # 3. FTS 索引計數同步檢查
    cursor.execute("SELECT COUNT(*) FROM issues_fts")
    fts_count = cursor.fetchone()[0]
    if fts_count < total_issues:
        warnings.append(f"FTS index is out of sync: {total_issues} issues vs {fts_count} FTS entries. Run 'reindex' to fix.")

    # 4. 探索樹風險分佈與懸空父節點檢查
    cursor.execute("SELECT risk_level, COUNT(*) FROM invalid_paths GROUP BY risk_level")
    risk_distribution = {r[0] or "medium": r[1] for r in cursor.fetchall()}

    cursor.execute("""
        SELECT ip1.id, ip1.parent_path_id
        FROM invalid_paths ip1
        WHERE ip1.parent_path_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM invalid_paths ip2 WHERE ip2.id = ip1.parent_path_id)
    """)
    dangling_parents = cursor.fetchall()
    if dangling_parents:
        warnings.append(f"{len(dangling_parents)} invalid path records have dangling parent_path_id references.")

    conn.close()

    output_json({
        "status": "healthy" if not warnings else "warning",
        "sqlite_version": sqlite_ver,
        "schema_version": user_ver,
        "fts_tokenizer": tokenizer,
        "database_path": actual_db_file,
        "database_size_kb": db_size_kb,
        "total_issues": total_issues,
        "total_invalid_paths": total_invalid_paths,
        "total_evidence": total_evidence,
        "fts_index_entries": fts_count,
        "projects_distribution": projects_distribution,
        "status_distribution": status_distribution,
        "confidence_distribution": confidence_distribution,
        "risk_distribution": risk_distribution,
        "warnings": warnings
    }, pretty)

def dream_policy(project=None, output_rules=None, format_type="json", db_path=None, pretty=False):
    """
    Dream-RSI 離線策略提煉 (Offline Dreaming & Meta-Policy Synthesis)
    回顧過往成功與失敗的探索歷程樹，提煉專案排查策略 (Heuristics, SOP, Hard Veto Rules)
    """
    conn = init_db(db_path)
    cursor = conn.cursor()

    where_clause = ""
    params = []
    if project:
        _pn = "LOWER(REPLACE(TRIM(i.project_name), ' ', ''))"
        _pv = "LOWER(REPLACE(TRIM(?), ' ', ''))"
        where_clause = f"WHERE ({_pn} = {_pv} OR {_pn} LIKE ?)"
        params = [project, "%" + project.strip().lower().replace(" ", "") + "%"]

    cursor.execute(f"SELECT COUNT(*) FROM issues i {where_clause}", params)
    total_issues = cursor.fetchone()[0]

    inv_where = ""
    inv_params = []
    if project:
        _pn = "LOWER(REPLACE(TRIM(i.project_name), ' ', ''))"
        _pv = "LOWER(REPLACE(TRIM(?), ' ', ''))"
        inv_where = f"WHERE ({_pn} = {_pv} OR {_pn} LIKE ?)"
        inv_params = [project, "%" + project.strip().lower().replace(" ", "") + "%"]

    cursor.execute(f"""
        SELECT ip.id, ip.issue_id, i.project_name, i.subject, ip.approach, ip.reason,
               ip.failure_mode, ip.side_effect, ip.scope, ip.parent_path_id,
               ip.branch_type, ip.risk_level
        FROM invalid_paths ip
        JOIN issues i ON ip.issue_id = i.id
        {inv_where}
        ORDER BY
            CASE ip.risk_level
                WHEN 'fatal' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
            END ASC,
            ip.created_at DESC
    """, inv_params)
    inv_rows = cursor.fetchall()

    sol_where = "WHERE i.status IN ('Closed', 'Resolved', 'Verified')"
    sol_params = []
    if project:
        _pn = "LOWER(REPLACE(TRIM(i.project_name), ' ', ''))"
        _pv = "LOWER(REPLACE(TRIM(?), ' ', ''))"
        sol_where += f" AND ({_pn} = {_pv} OR {_pn} LIKE ?)"
        sol_params = [project, "%" + project.strip().lower().replace(" ", "") + "%"]

    cursor.execute(f"""
        SELECT i.id, i.project_name, i.subject, i.root_cause, i.solution, i.conditions,
               i.status, i.confidence,
               (SELECT commit_hash FROM git_revisions WHERE issue_id = i.id ORDER BY id DESC LIMIT 1) as commit_ref
        FROM issues i
        {sol_where}
        ORDER BY
            CASE i.confidence WHEN 'verified' THEN 0 WHEN 'high' THEN 1 ELSE 2 END ASC,
            i.updated_at DESC
    """, sol_params)
    sol_rows = cursor.fetchall()

    conn.close()

    hard_veto_rules = []
    risk_stats = {"fatal": 0, "high": 0, "medium": 0, "low": 0}
    seen_veto = set()

    for r in inv_rows:
        r_lvl = (r[11] or "medium").lower()
        risk_stats[r_lvl] = risk_stats.get(r_lvl, 0) + 1
        if r_lvl in {"fatal", "high"}:
            app_key = r[4].strip().lower()
            if app_key not in seen_veto:
                seen_veto.add(app_key)
                hard_veto_rules.append({
                    "path_id": r[0],
                    "issue_id": r[1],
                    "project": r[2],
                    "approach": r[4],
                    "reason": r[5],
                    "side_effect": r[7] or "",
                    "failure_mode": r[6] or "",
                    "risk_level": r_lvl,
                    "branch_type": r[10] or "attempt"
                })

    verified_sops = []
    for s in sol_rows:
        verified_sops.append({
            "issue_id": s[0],
            "project": s[1],
            "subject": s[2],
            "root_cause": s[3],
            "solution": s[4],
            "conditions": s[5] or "無特定限制",
            "confidence": s[7],
            "commit_hash": s[8] or ""
        })

    meta_heuristics = [
        "1. 進入排查前，優先調用 answer 撈出 [HARD VETO] 清單，一票否決致命級失敗路徑。",
        "2. 針對硬體/韌體專案，優先檢查 conditions 與韌體版本，絕不跨架構盲套 workaround。",
        "3. 除錯推演應紀錄探索樹 (Hypothesis -> Probe -> Fix)，失敗嘗試必須立即寫入 reject-path 帶上 --risk-level。"
    ]

    policy_data = {
        "status": "success",
        "synthesized_at": utc_now_iso(),
        "scope_project": project or "ALL_PROJECTS",
        "total_analyzed_issues": total_issues,
        "total_invalid_paths": len(inv_rows),
        "risk_distribution": risk_stats,
        "hard_veto_rules": hard_veto_rules,
        "verified_fast_path_sops": verified_sops[:10],
        "meta_heuristics": meta_heuristics
    }

    markdown_content = f"""# Project Memory Exploration Policy (Dream-RSI Synthesized)
- **Scope**: `{project or 'ALL_PROJECTS'}`
- **Generated**: `{policy_data['synthesized_at']}`
- **Evidence Base**: {total_issues} issues, {len(inv_rows)} exploration branches ({risk_stats.get('fatal', 0)} fatal, {risk_stats.get('high', 0)} high-risk)

---

## 🚫 1. HARD VETO Rules (Strictly Prohibited Paths)
These approaches caused fatal or severe hardware/system side-effects in past explorations. **Do NOT propose or execute:**
"""
    if hard_veto_rules:
        for v in hard_veto_rules:
            se_part = f" | 副作用: {v['side_effect']}" if v['side_effect'] else ""
            markdown_content += f"- **[{v['risk_level'].upper()}] {v['approach']}** (工單 #{v['issue_id']}): {v['reason']}{se_part}\n"
    else:
        markdown_content += "- (目前尚無 FATAL/HIGH 級別的硬性否決記錄)\n"

    markdown_content += """
---

## 🎯 2. Verified Fast-Path SOPs
High-confidence solutions validated by tests/commits:
"""
    if verified_sops:
        for s in verified_sops[:10]:
            cond_part = f" (條件: {s['conditions']})" if s['conditions'] and s['conditions'] != '無特定限制' else ""
            markdown_content += f"- **#{s['issue_id']} {s['subject']}**{cond_part}\n  - 根因: {s['root_cause']}\n  - 解法: {s['solution']}\n"
    else:
        markdown_content += "- (目前尚無已結案之 SOP 記錄)\n"

    markdown_content += """
---

## 🧭 3. Meta-Exploration Heuristics
"""
    for h in meta_heuristics:
        markdown_content += f"- {h}\n"

    if output_rules:
        out_path = os.path.abspath(os.path.expanduser(output_rules))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        policy_data["output_rules_path"] = out_path

    if format_type == "markdown" and not output_rules:
        print(markdown_content)
    else:
        output_json(policy_data, pretty)

def parse_kv_pairs(kv_list):
    result = {}
    if not kv_list:
        return result
    for item in kv_list:
        if "=" in item:
            k, v = item.split("=", 1)
            result[k.strip().lower()] = v.strip()
    return result

# --- Legacy Compatibility Wrapper (save) ---
def handle_legacy_save(args):
    cf_dict = {}
    if args.tags:
        cf_dict['tags'] = args.tags
    create_issue(
        project=args.project,
        subject=args.title,
        description=args.summary,
        tracker="Architecture" if "架構" in args.title else "Task",
        status="Closed",
        root_cause="Legacy record migration",
        solution=args.decisions if args.decisions else args.summary,
        ai_summary=f"{args.title} | {args.summary[:120]}",
        custom_fields_dict=cf_dict,
        allow_secret=getattr(args, 'allow_secret', False),
        db_path=getattr(args, 'db', None),
        pretty=getattr(args, 'pretty', False)
    )

def main():
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('--db', default=argparse.SUPPRESS, help="指定資料庫檔案路徑 (覆寫預設值)")
    common_parser.add_argument('--pretty', action='store_true', default=argparse.SUPPRESS, help="人類可讀之縮排 JSON 格式 (預設為 compact JSON)")
    common_parser.add_argument('--allow-secret', action='store_true', default=argparse.SUPPRESS, help="允許儲存可能含有機密敏感字元的文字")

    parser = argparse.ArgumentParser(
        description="Failure-Aware, Evidence-Grounded Episodic Memory for AI Agents",
        parents=[common_parser]
    )
    subparsers = parser.add_subparsers(dest="command")

    # 1. create 指令
    create_p = subparsers.add_parser('create', parents=[common_parser], help="建立新工單 (Issue / Ticket)")
    create_p.add_argument('--project', required=True, help="專案名稱")
    create_p.add_argument('--subject', required=True, help="工單主旨 (問題症狀 / 任務目標 / 架構主題)")
    create_p.add_argument('--description', default="", help="詳細情境、環境配置、重現步驟或背景")
    create_p.add_argument('--tracker', default="Bug", help="工單類型 (Bug, Feature, Refactor, Task, Architecture, Spike, Doc, Security)")
    create_p.add_argument('--status', default="New", help="狀態 (New, In Progress, Resolved, Closed, Rejected, WontFix)")
    create_p.add_argument('--priority', default="Normal", help="優先級 (Low, Normal, High, Urgent)")
    create_p.add_argument('--confidence', default="unverified", help="置信度 (unverified, low, medium, high, rejected)")
    create_p.add_argument('--scope', default="", help="適用範疇 (例如: production-cluster, x86-linux, client-side)")
    create_p.add_argument('--conditions', default="", help="前置或限制條件 (例如: requires shared redis)")
    create_p.add_argument('--root-cause', default="", help="根因分析 (若已知)")
    create_p.add_argument('--solution', default="", help="解決方案 / 實作成果 (若已完成)")
    create_p.add_argument('--ai-summary', default="", help="精煉摘要 (100字以內)")
    create_p.add_argument('--related-ids', default="", help="關聯之其他工單 ID (逗號分隔，例如: 1,2)")
    create_p.add_argument('--superseded-by', type=int, default=None, help="被哪張新工單取代之 ID")
    create_p.add_argument('--created-by', default="Agent", help="建立者身份標記")
    create_p.add_argument('--commit-hash', default="", help="關聯 Git Commit 雜湊碼")
    create_p.add_argument('--repo', default="", help="關聯代碼庫")
    create_p.add_argument('--diff-summary', default="", help="代碼變更概述")
    create_p.add_argument('--evidence-type', default="", help="證據類型 (git_commit, ci, test_command, log)")
    create_p.add_argument('--evidence-ref', default="", help="證據參照 (Commit hash, CI link, test command)")
    create_p.add_argument('--evidence-note', default="", help="證據說明")
    create_p.add_argument('--note', default="", help="初始排查或設計筆記")
    create_p.add_argument('--module', default="", help="模組 / 服務名稱")
    create_p.add_argument('--env', default="", help="環境 (production, staging, docker, k8s)")
    create_p.add_argument('--error-code', default="", help="錯誤代碼 / HTTP Code / Exception")
    create_p.add_argument('--platform', default="", help="硬體平台 / CPU 架構")
    create_p.add_argument('--board', default="", help="主機板 / 載板型號")
    create_p.add_argument('--bios-ver', default="", help="BIOS / 韌體版本")
    create_p.add_argument('--tags', default="", help="標籤 (逗號分隔)")
    create_p.add_argument('--cf', '--custom-field', action='append', dest='custom_field', help="動態鍵值 (格式: key=val)")

    # 2. note / journal 指令
    note_p = subparsers.add_parser('note', aliases=['journal'], parents=[common_parser], help="追加排查歷程、測試筆記或調試軌跡")
    note_p.add_argument('--id', required=True, type=int, help="工單 ID")
    note_p.add_argument('--notes', required=True, help="排查軌跡、試錯結論或技術備註")
    note_p.add_argument('--author', default="Agent", help="記錄者 (預設: Agent)")

    # 3. reject-path / invalid-path 指令
    inv_p = subparsers.add_parser('reject-path', aliases=['invalid-path'], parents=[common_parser], help="記錄細粒度負向知識 (失敗嘗試、排除路徑與副作用)")
    inv_p.add_argument('--id', required=True, type=int, help="工單 ID")
    inv_p.add_argument('--approach', required=True, help="嘗試的方法或架構 (例如: In-memory lock)")
    inv_p.add_argument('--reason', required=True, help="失敗原因 (例如: 無法跨實例同步)")
    inv_p.add_argument('--failure-mode', default="", help="失效模式 (例如: 競態條件引發 401)")
    inv_p.add_argument('--side-effect', default="", help="引發之副作用 (例如: CPU 100％ 滿載)")
    inv_p.add_argument('--scope', default="", help="生效範疇 (例如: multi-instance load balancer)")
    inv_p.add_argument('--parent-id', type=int, default=None, help="父嘗試/假說節點 ID (構成假說推演樹)")
    inv_p.add_argument('--branch-type', default="attempt", choices=["hypothesis", "probe", "workaround", "fix_attempt", "attempt"], help="探索分支類型")
    inv_p.add_argument('--risk-level', default="medium", choices=["fatal", "high", "medium", "low"], help="失敗風險層級 (fatal: 致命硬體損壞/斷電, high: 系統崩潰/資料損毀, medium: 功能失效, low: 輕微錯誤)")

    # 4. close / resolve 指令
    close_p = subparsers.add_parser('close', aliases=['resolve'], parents=[common_parser], help="結案並寫入根因、解法、AI Summary 與 Git 錨定")
    close_p.add_argument('--id', required=True, type=int, help="工單 ID")
    close_p.add_argument('--root-cause', required=True, help="確定的問題根因或架構決策原因 (Root Cause)")
    close_p.add_argument('--solution', required=True, help="驗證有效的解決方案、Patch 或完成實作")
    close_p.add_argument('--ai-summary', default="", help="結構化萃取摘要 (未填時自動生成)")
    close_p.add_argument('--status', default="Closed", help="結案狀態 (預設: Closed)")
    close_p.add_argument('--confidence', default="", help="置信度 (未填時依是否有證據自動判斷為 high/medium)")
    close_p.add_argument('--conditions', default="", help="適用限制條件")
    close_p.add_argument('--commit-hash', default="", help="修復或完成該任務的 Git Commit 雜湊碼")
    close_p.add_argument('--repo', default="", help="代碼庫")
    close_p.add_argument('--diff-summary', default="", help="關鍵變更或 Patch 摘要")
    close_p.add_argument('--evidence-type', default="", help="證據類型")
    close_p.add_argument('--evidence-ref', default="", help="證據參照")
    close_p.add_argument('--evidence-note', default="", help="證據說明")
    close_p.add_argument('--notes', default="", help="結案補充說明")

    # 5. verify 指令
    verify_p = subparsers.add_parser('verify', parents=[common_parser], help="驗證並提升工單為 Verified 狀態 (要求 Commit 或測試證據)")
    verify_p.add_argument('--id', required=True, type=int, help="工單 ID")
    verify_p.add_argument('--commit-hash', default="", help="驗證通過之 Git Commit (若在 Git 庫內將自動驗真)")
    verify_p.add_argument('--evidence-type', default="test", help="證據類型 (test, ci, benchmark, manual)")
    verify_p.add_argument('--evidence-ref', default="", help="證據參照 (CI Run URL, pytest 指令輸出, Log)")
    verify_p.add_argument('--evidence-note', default="", help="驗證筆記")
    verify_p.add_argument('--verified-by', default="Agent", help="驗證者")

    # 6. reject / wontfix 指令
    reject_p = subparsers.add_parser('reject', aliases=['wontfix'], parents=[common_parser], help="標記為無效、被否決或不可行路徑 (沉澱為負向知識)")
    reject_p.add_argument('--id', required=True, type=int, help="工單 ID")
    reject_p.add_argument('--reason', required=True, help="為何此路徑無效、引發副作用或被否決之詳細原因")
    reject_p.add_argument('--status', default="Rejected", help="狀態 (預設: Rejected)")
    reject_p.add_argument('--side-effect', default="", help="已知副作用")
    reject_p.add_argument('--scope', default="", help="生效範疇")

    # 7. update 指令
    update_p = subparsers.add_parser('update', parents=[common_parser], help="更新工單屬性或狀態")
    update_p.add_argument('--id', required=True, type=int, help="工單 ID")
    update_p.add_argument('--status')
    update_p.add_argument('--tracker')
    update_p.add_argument('--priority')
    update_p.add_argument('--confidence')
    update_p.add_argument('--subject')
    update_p.add_argument('--description')
    update_p.add_argument('--scope')
    update_p.add_argument('--conditions')
    update_p.add_argument('--root-cause')
    update_p.add_argument('--solution')
    update_p.add_argument('--ai-summary')
    update_p.add_argument('--related-ids')
    update_p.add_argument('--superseded-by', type=int)
    update_p.add_argument('--cf', '--custom-field', action='append', dest='custom_field', help="動態鍵值 (格式: key=val)")
    update_p.add_argument('--note', help="更新時連帶記錄之備註")

    # 8. search 指令
    search_p = subparsers.add_parser('search', parents=[common_parser], help="多維度混合檢索工單 (FTS5 + 動態元數據過濾)")
    search_p.add_argument('--project', default=None, help="限定專案名稱 (選填，不分大小寫)")
    search_p.add_argument('--query', default=None, help="全文檢索關鍵字 (支援中英文與特殊符號)")
    search_p.add_argument('--status', default=None, help="限定狀態")
    search_p.add_argument('--tracker', default=None, help="限定類型")
    search_p.add_argument('--confidence', default=None, help="限定置信度")
    search_p.add_argument('--module', default=None, help="模組 / 服務篩選")
    search_p.add_argument('--env', default=None, help="環境篩選")
    search_p.add_argument('--error-code', default=None, help="錯誤代碼篩選")
    search_p.add_argument('--platform', default=None, help="硬體平台篩選")
    search_p.add_argument('--tags', default=None, help="標籤篩選")
    search_p.add_argument('--cf', '--custom-field', action='append', dest='custom_field', help="自定義動態欄位過濾 (格式: key=val)")
    
    # 互斥篩選群組
    mutex_filter = search_p.add_mutually_exclusive_group()
    mutex_filter.add_argument('--closed-only', action='store_true', help="僅檢索已結案 (Closed/Resolved/Verified)")
    mutex_filter.add_argument('--verified-only', action='store_true', help="僅檢索最高信任度驗證 (Verified)")
    mutex_filter.add_argument('--rejected-only', action='store_true', help="僅檢索工單級無效/排除路徑 (Rejected/WontFix)")
    mutex_filter.add_argument('--negative-only', action='store_true', help="僅檢索負向知識 (包含工單級 Rejected 或內含 invalid_paths)")
    
    search_p.add_argument('--limit', type=int, default=5, help="最大回傳筆數 (預設: 5)")

    # 9. search-invalid 指令
    inv_search_p = subparsers.add_parser('search-invalid', parents=[common_parser], help="直接檢索細粒度負向知識條目 (Invalid Paths)")
    inv_search_p.add_argument('--query', default=None, help="檢索關鍵字")
    inv_search_p.add_argument('--project', default=None, help="限定專案")
    inv_search_p.add_argument('--limit', type=int, default=10, help="最大回傳筆數")

    # 10. similar 指令
    sim_p = subparsers.add_parser('similar', parents=[common_parser], help="建立工單前快速查重相似問題")
    sim_p.add_argument('--subject', required=True, help="擬建立之工單主旨")
    sim_p.add_argument('--project', default=None, help="限定專案")
    sim_p.add_argument('--limit', type=int, default=5, help="最大回傳筆數")

    # 11. list 指令
    list_p = subparsers.add_parser('list', parents=[common_parser], help="列出最新工單清單")
    list_p.add_argument('--project', default=None, help="限定專案名稱 (選填)")
    list_p.add_argument('--status', default=None, help="限定狀態")
    list_p.add_argument('--limit', type=int, default=5, help="最大回傳筆數")

    # 12. get 指令
    get_p = subparsers.add_parser('get', parents=[common_parser], help="提取單筆工單完整詳情 (支援 --agent 輸出精煉決策卡)")
    get_p.add_argument('--id', required=True, type=int, help="工單 ID")
    get_p.add_argument('--agent', '--brief', action='store_true', dest='agent_mode', help="輸出精煉決策卡 (為 7B/14B 模型最佳化，剔除冗長歷史 Notes 以節省 Token)")

    # 13. redact-issue 指令
    redact_p = subparsers.add_parser('redact-issue', parents=[common_parser], help="脫敏並隱藏特定工單敏感內容 (徹底抹除所有子表資料)")
    redact_p.add_argument('--id', required=True, type=int, help="工單 ID")
    redact_p.add_argument('--reason', default="Security Redaction", help="脫敏原因")

    # 14. delete-issue 指令
    del_p = subparsers.add_parser('delete-issue', parents=[common_parser], help="物理刪除特定工單及其關聯資料")
    del_p.add_argument('--id', required=True, type=int, help="工單 ID")
    del_p.add_argument('--confirm', action='store_true', required=True, help="確認物理刪除")

    # 15. export 指令
    export_p = subparsers.add_parser('export', parents=[common_parser], help="匯出記憶庫資料為 JSONL 備份檔")
    export_p.add_argument('--file', required=True, help="匯出之目標檔案路徑 (.jsonl)")
    export_p.add_argument('--project', default=None, help="限定匯出專案 (選填)")

    # 16. import 指令
    import_p = subparsers.add_parser('import', parents=[common_parser], help="從 JSONL 備份檔匯入記憶庫")
    import_p.add_argument('--file', required=True, help="匯入之來源檔案路徑 (.jsonl)")
    import_p.add_argument('--dedupe', action='store_true', help="依 project 與 subject 自動略過重複項目")

    # 17. reindex 指令
    subparsers.add_parser('reindex', parents=[common_parser], help="重建 FTS5 全文索引")

    # 18. answer / card 指令 (Agent 專屬推理證據卡)
    ans_p = subparsers.add_parser('answer', aliases=['card'], parents=[common_parser], help="Agent 專屬推理證據卡 (整合最佳解法、適用條件、代碼證據與排查禁忌)")
    ans_p.add_argument('--query', required=True, help="問題描述 / 症狀 / 錯誤關鍵字")
    ans_p.add_argument('--project', default=None, help="限定專案 (選填)")
    ans_p.add_argument('--platform', default=None, help="限定平台 (選填)")
    ans_p.add_argument('--env', default=None, help="限定環境 (選填)")
    ans_p.add_argument('--limit', type=int, default=3, help="最大候選解法數")

    # 19. doctor / stats 指令
    subparsers.add_parser('doctor', aliases=['stats'], parents=[common_parser], help="系統健康檢查、資料庫狀態與專案統計")

    # 20. dream 指令 (Dream-RSI 離線策略提煉)
    dream_p = subparsers.add_parser('dream', aliases=['synthesize-policy', 'distill'], parents=[common_parser], help="Dream-RSI 離線策略提煉 (回顧探索樹並提煉專案 SOP 與否決規則)")
    dream_p.add_argument('--project', default=None, help="限定提煉專案名稱 (選填)")
    dream_p.add_argument('--output-rules', default=None, help="輸出 Agent 規則檔案路徑 (.md)")
    dream_p.add_argument('--format', default="json", choices=["json", "markdown"], help="輸出格式 (json 或 markdown)")

    # 21. save 指令 (舊版相容)
    save_p = subparsers.add_parser('save', parents=[common_parser], help="[相容舊版] 儲存記憶")
    save_p.add_argument('--project', required=True)
    save_p.add_argument('--title', required=True)
    save_p.add_argument('--summary', required=True)
    save_p.add_argument('--decisions', default="")
    save_p.add_argument('--tags', default="")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    db_path = getattr(args, 'db', None)
    pretty = getattr(args, 'pretty', False)
    allow_secret = getattr(args, 'allow_secret', False)

    try:
        if args.command == 'create':
            cf_dict = parse_kv_pairs(args.custom_field)
            if args.module: cf_dict['module'] = args.module
            if args.env: cf_dict['env'] = args.env
            if args.error_code: cf_dict['error_code'] = args.error_code
            if args.platform: cf_dict['platform'] = args.platform
            if args.board: cf_dict['board'] = args.board
            if args.bios_ver: cf_dict['bios_ver'] = args.bios_ver
            if args.tags: cf_dict['tags'] = args.tags

            create_issue(
                project=args.project,
                subject=args.subject,
                description=args.description,
                tracker=args.tracker,
                status=args.status,
                priority=args.priority,
                confidence=args.confidence,
                scope=args.scope,
                conditions=args.conditions,
                root_cause=args.root_cause,
                solution=args.solution,
                ai_summary=args.ai_summary,
                related_ids=args.related_ids,
                superseded_by=args.superseded_by,
                created_by=args.created_by,
                commit_hash=args.commit_hash,
                repository=args.repo,
                diff_summary=args.diff_summary,
                evidence_type=args.evidence_type,
                evidence_ref=args.evidence_ref,
                evidence_note=args.evidence_note,
                custom_fields_dict=cf_dict,
                initial_note=args.note,
                allow_secret=allow_secret,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command in ['note', 'journal']:
            add_journal(args.id, args.notes, args.author, allow_secret=allow_secret, db_path=db_path, pretty=pretty)
        elif args.command in ['reject-path', 'invalid-path']:
            add_invalid_path(
                issue_id=args.id,
                approach=args.approach,
                reason=args.reason,
                failure_mode=args.failure_mode,
                side_effect=args.side_effect,
                scope=args.scope,
                parent_path_id=getattr(args, 'parent_id', None),
                branch_type=getattr(args, 'branch_type', 'attempt'),
                risk_level=getattr(args, 'risk_level', 'medium'),
                allow_secret=allow_secret,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command in ['close', 'resolve']:
            close_issue(
                issue_id=args.id,
                root_cause=args.root_cause,
                solution=args.solution,
                ai_summary=args.ai_summary,
                status=args.status,
                confidence=args.confidence,
                conditions=args.conditions,
                commit_hash=args.commit_hash,
                repository=args.repo,
                diff_summary=args.diff_summary,
                evidence_type=args.evidence_type,
                evidence_ref=args.evidence_ref,
                evidence_note=args.evidence_note,
                notes=args.notes,
                allow_secret=allow_secret,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'verify':
            verify_issue(
                issue_id=args.id,
                commit_hash=args.commit_hash,
                evidence_type=args.evidence_type,
                evidence_ref=args.evidence_ref,
                evidence_note=args.evidence_note,
                verified_by=args.verified_by,
                allow_secret=allow_secret,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command in ['reject', 'wontfix']:
            reject_issue(
                issue_id=args.id,
                reason=args.reason,
                status=args.status,
                side_effect=args.side_effect,
                scope=args.scope,
                allow_secret=allow_secret,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'update':
            cf_dict = parse_kv_pairs(args.custom_field) if args.custom_field else None
            update_issue(
                issue_id=args.id,
                status=args.status,
                tracker=args.tracker,
                priority=args.priority,
                confidence=args.confidence,
                subject=args.subject,
                description=args.description,
                scope=args.scope,
                conditions=args.conditions,
                root_cause=args.root_cause,
                solution=args.solution,
                ai_summary=args.ai_summary,
                related_ids=args.related_ids,
                superseded_by=args.superseded_by,
                custom_fields_dict=cf_dict,
                note=args.note,
                allow_secret=allow_secret,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'search':
            cf_filters = parse_kv_pairs(args.custom_field)
            if args.module: cf_filters['module'] = args.module
            if args.env: cf_filters['env'] = args.env
            if args.error_code: cf_filters['error_code'] = args.error_code
            if args.platform: cf_filters['platform'] = args.platform
            if args.tags: cf_filters['tags'] = args.tags

            search_issues(
                project=args.project,
                query=args.query,
                status=args.status,
                tracker=args.tracker,
                confidence=args.confidence,
                custom_filters=cf_filters,
                closed_only=args.closed_only,
                verified_only=args.verified_only,
                rejected_only=args.rejected_only,
                negative_only=args.negative_only,
                limit=args.limit,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'search-invalid':
            search_invalid_paths(
                query=args.query,
                project=args.project,
                limit=args.limit,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'similar':
            find_similar_issues(
                subject=args.subject,
                project=args.project,
                limit=args.limit,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'list':
            search_issues(
                project=args.project,
                status=args.status,
                limit=args.limit,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'get':
            get_issue(args.id, agent_mode=getattr(args, 'agent_mode', False), db_path=db_path, pretty=pretty)
        elif args.command == 'redact-issue':
            redact_issue(args.id, args.reason, db_path=db_path, pretty=pretty)
        elif args.command == 'delete-issue':
            delete_issue(args.id, args.confirm, db_path=db_path, pretty=pretty)
        elif args.command == 'export':
            export_data(args.file, args.project, db_path=db_path, pretty=pretty)
        elif args.command == 'import':
            import_data(args.file, dedupe=args.dedupe, allow_secret=allow_secret, db_path=db_path, pretty=pretty)
        elif args.command in ['answer', 'card']:
            answer_query(
                query=args.query,
                project=args.project,
                platform=args.platform,
                env=args.env,
                limit=args.limit,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'reindex':
            reindex(db_path=db_path, pretty=pretty)
        elif args.command in ['doctor', 'stats']:
            doctor(db_path=db_path, pretty=pretty)
        elif args.command in ['dream', 'synthesize-policy', 'distill']:
            dream_policy(
                project=args.project,
                output_rules=args.output_rules,
                format_type=args.format,
                db_path=db_path,
                pretty=pretty
            )
        elif args.command == 'save':
            handle_legacy_save(args)
    except Exception as e:
        error_code = getattr(e, 'error_code', 'VALIDATION_ERROR' if isinstance(e, ValueError) else 'EXECUTION_ERROR')
        output_json({"status": "error", "error_code": error_code, "message": f"{str(e)}"}, pretty)
        sys.exit(1)

if __name__ == '__main__':
    main()
