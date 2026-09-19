"""HỢP ĐỒNG 2 — lưu trữ SQLite. Dùng sqlite3 stdlib, không ORM (4 bảng thì ORM chỉ thêm việc).

Điểm thiết kế: bảng `analyses` khoá theo (fingerprint, target) chứ KHÔNG theo scan_id.
Quét lại target cũ -> finding không đổi được lấy từ cache, không tốn tiền API.
Đây chính là thứ làm vòng lặp vá->quét lại chạy nhanh và rẻ. Không dùng chung giữa
các target, vì cùng một lỗ hổng nhưng bản vá cho nginx và cho Flask khác nhau.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from core.config import DB_PATH
from core.models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    profile      TEXT NOT NULL DEFAULT 'baseline',
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL DEFAULT 'running',   -- running | done | error
    error        TEXT,
    summary      TEXT,          -- tóm tắt do AI viết cho lần quét này
    priority_json TEXT,         -- thứ tự nên xử lý, danh sách fingerprint
    warnings_json TEXT          -- cảnh báo của scanner (scanner chết, parse lỗi...)
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    source       TEXT NOT NULL,
    name         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    urls_json    TEXT NOT NULL,
    count        INTEGER NOT NULL,
    evidence     TEXT,
    description  TEXT,
    solution_raw TEXT,
    cwe          TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp   ON findings(fingerprint);

-- Cache kết quả AI, dùng chung cho mọi lần quét CÙNG MỘT TARGET.
-- Khoá gồm cả `model`: đổi sang bản Claude mới thì phân tích lại, thay vì lặng lẽ
-- dùng lại kết quả của model cũ rồi gán nhãn model mới - số liệu trong eval/ phải
-- nói đúng model nào sinh ra nó.
-- Khoá gồm cả `target`: bản vá phụ thuộc ngăn xếp của target. Cùng lỗi "thiếu CSP"
-- nhưng nginx vá bằng add_header, Flask vá trong after_request. Thiếu cột này thì
-- vulnapp từng được phục vụ bản vá nginx lấy từ cache của target khác.
CREATE TABLE IF NOT EXISTS analyses (
    fingerprint  TEXT NOT NULL,
    model        TEXT NOT NULL,
    target       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    json         TEXT NOT NULL,
    PRIMARY KEY (fingerprint, model, target)
);

-- Ground truth gán nhãn thủ công (TV5)
CREATE TABLE IF NOT EXISTS labels (
    fingerprint      TEXT PRIMARY KEY,
    is_true_positive INTEGER,   -- 1 = lỗ hổng thật, 0 = false positive
    patch_ok         INTEGER,   -- 1 = bản vá AI đúng, 0 = sai
    note             TEXT,
    labeled_by       TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    # timeout: hai lần quét chạy song song có thể tranh nhau ghi
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """CREATE TABLE IF NOT EXISTS không thêm cột vào bảng đã tồn tại.
    Vòng này để file doan.db tạo từ phiên bản cũ không bị vỡ."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
    for col in ("summary", "priority_json", "warnings_json"):
        if col not in cols:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")

    # analyses: khoá cũ không có target. SQLite không đổi được primary key, phải
    # dựng lại bảng. Giữ dữ liệu cũ vì đó là tiền API đã trả, nhưng gán target=''
    # (không rõ) chứ KHÔNG đoán: quy tắc đoán tự nhiên nhất ("lần quét gần nhất có
    # fingerprint đó") đo trên DB thật gán sai 18/33 dòng. get_cached không bao giờ
    # phục vụ dòng target=''; muốn dùng lại thì gán target bằng tay khi biết chắc.
    info = list(conn.execute("PRAGMA table_info(analyses)"))
    if info and "target" not in {r["name"] for r in info}:
        conn.execute("ALTER TABLE analyses RENAME TO analyses_old")
        conn.executescript(SCHEMA)  # mọi bảng khác đã có -> chỉ tạo lại analyses
        conn.executescript("""
            INSERT OR IGNORE INTO analyses (fingerprint, model, target, created_at, json)
                SELECT fingerprint, model, '', created_at, json FROM analyses_old;
            DROP TABLE analyses_old;
        """)
    conn.commit()


# ---------------------------------------------------------------- scans

def start_scan(conn: sqlite3.Connection, target: str, profile: str = "baseline") -> int:
    cur = conn.execute(
        "INSERT INTO scans (target, profile, started_at) VALUES (?, ?, ?)",
        (target, profile, _now()),
    )
    conn.commit()
    return cur.lastrowid


def finish_scan(conn: sqlite3.Connection, scan_id: int, error: str | None = None) -> None:
    conn.execute(
        "UPDATE scans SET finished_at = ?, status = ?, error = ? WHERE id = ?",
        (_now(), "error" if error else "done", error, scan_id),
    )
    conn.commit()


def get_scan(conn: sqlite3.Connection, scan_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def list_scans(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Kèm luôn số lỗ hổng để trang danh sách không phải query từng dòng."""
    return conn.execute("""
        SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS n_findings
        FROM scans s ORDER BY s.id DESC
    """).fetchall()


def save_summary(conn: sqlite3.Connection, scan_id: int, summary: str,
                 priority: list[str], warnings: list[str]) -> None:
    conn.execute(
        "UPDATE scans SET summary = ?, priority_json = ?, warnings_json = ? WHERE id = ?",
        (summary, json.dumps(priority, ensure_ascii=False),
         json.dumps(warnings, ensure_ascii=False), scan_id),
    )
    conn.commit()


def get_summary(conn: sqlite3.Connection, scan_id: int) -> tuple[str, list[str], list[str]]:
    """Trả về (tóm tắt, thứ tự ưu tiên, cảnh báo) đã lưu của một lần quét."""
    r = conn.execute(
        "SELECT summary, priority_json, warnings_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    if not r:
        return "", [], []
    return (r["summary"] or ""), json.loads(r["priority_json"] or "[]"), json.loads(r["warnings_json"] or "[]")


# ------------------------------------------------------------- findings

def save_findings(conn: sqlite3.Connection, scan_id: int, findings: list[Finding]) -> None:
    conn.executemany(
        """INSERT INTO findings
           (scan_id, fingerprint, source, name, severity, urls_json, count,
            evidence, description, solution_raw, cwe)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (scan_id, f.fingerprint, f.source, f.name, f.severity,
             json.dumps(f.urls, ensure_ascii=False), f.count,
             f.evidence, f.description, f.solution_raw, f.cwe)
            for f in findings
        ],
    )
    conn.commit()


def get_findings(conn: sqlite3.Connection, scan_id: int) -> list[Finding]:
    rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    return [
        Finding(
            fingerprint=r["fingerprint"], source=r["source"], name=r["name"],
            severity=r["severity"], urls=json.loads(r["urls_json"]), count=r["count"],
            evidence=r["evidence"] or "", description=r["description"] or "",
            solution_raw=r["solution_raw"] or "", cwe=r["cwe"] or "",
        )
        for r in rows
    ]


def compare_scans(conn: sqlite3.Connection, scan_a: int, scan_b: int) -> dict[str, list[Finding]]:
    """Diff giữa hai lần quét. Nhờ fingerprint, đây chỉ là phép toán tập hợp.

    a = lần quét trước khi vá, b = lần quét sau khi vá.
    """
    a = {f.fingerprint: f for f in get_findings(conn, scan_a)}
    b = {f.fingerprint: f for f in get_findings(conn, scan_b)}
    return {
        "fixed":      [a[k] for k in a.keys() - b.keys()],   # có ở a, mất ở b -> đã vá
        "new":        [b[k] for k in b.keys() - a.keys()],   # chỉ có ở b -> mới xuất hiện
        "persisting": [b[k] for k in a.keys() & b.keys()],   # còn tồn tại
    }


# -------------------------------------------------------- cache phân tích

def get_cached(conn: sqlite3.Connection, fingerprints: list[str], target: str,
               model: str | None = None) -> dict[str, dict]:
    """Kết quả phân tích đã lưu cho `target`, theo fingerprint.

    Khoá gồm cả model nên đổi MODEL (ví dụ sang bản Claude mới) sẽ phân tích lại
    thay vì lặng lẽ dùng lại kết quả của model cũ rồi gán nhãn model mới.

    target='' là dòng cũ không rõ sinh cho target nào -> không bao giờ trả về.
    Chặn ở đây vì mọi đường đọc cache đều đi qua hàm này.
    """
    if not fingerprints or not target:
        return {}
    qs = ",".join("?" * len(fingerprints))
    sql = f"SELECT fingerprint, json FROM analyses WHERE target = ? AND fingerprint IN ({qs})"
    params = [target, *fingerprints]
    if model:
        sql += " AND model = ?"
        params.append(model)
    else:
        sql += " ORDER BY created_at"   # bản sau ghi đè bản trước trong dict
    return {r["fingerprint"]: json.loads(r["json"]) for r in conn.execute(sql, params)}


def put_cached(conn: sqlite3.Connection, model: str, target: str, analyses: list[dict]) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO analyses (fingerprint, model, target, created_at, json) "
        "VALUES (?,?,?,?,?)",
        [(a["fingerprint"], model, target, _now(), json.dumps(a, ensure_ascii=False))
         for a in analyses],
    )
    conn.commit()
