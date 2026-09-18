"""Chạy một lần quét ở nền và giữ tiến trình cho UI đọc.

Tiến trình để trong một dict in-memory. KHÔNG dùng Celery/Redis: công cụ chạy local
một tiến trình, thêm broker vào chỉ tổ thêm thứ phải cài và phải chạy khi demo.

Hệ quả đã chấp nhận: khởi động lại server thì log tiến trình mất. Kết quả quét thì
không mất vì đã nằm trong SQLite.
"""

from __future__ import annotations

import threading

from analyzer.engine import analyze
from core import db
from scanners.runner import run_scan

# scan_id -> {"lines": [...], "status": "running" | "done" | "error"}
JOBS: dict[int, dict] = {}
_LOCK = threading.Lock()

MAX_LINES = 200  # chặn rò rỉ bộ nhớ nếu scanner nói quá nhiều


def new_job(scan_id: int) -> None:
    with _LOCK:
        JOBS[scan_id] = {"lines": [], "status": "running"}


def get_job(scan_id: int) -> dict | None:
    with _LOCK:
        job = JOBS.get(scan_id)
        return {"lines": list(job["lines"]), "status": job["status"]} if job else None


def _log(scan_id: int, msg: str) -> None:
    with _LOCK:
        job = JOBS.get(scan_id)
        if job is not None and len(job["lines"]) < MAX_LINES:
            job["lines"].append(msg)


def _finish(scan_id: int, status: str) -> None:
    with _LOCK:
        if scan_id in JOBS:
            JOBS[scan_id]["status"] = status


def run(scan_id: int, target: str, profile: str, use_ai: bool,
        provider: str | None = None) -> None:
    """Chạy trong thread riêng của FastAPI. Mọi lỗi đều được ghi lại, không ném ra ngoài."""
    # sqlite3 không cho dùng chung connection giữa các thread -> mở riêng ở đây
    conn = db.connect()
    say = lambda m: _log(scan_id, m)  # noqa: E731

    try:
        findings, warnings = run_scan(target, profile=profile, progress=say)
        db.save_findings(conn, scan_id, findings)

        if use_ai:
            result = analyze(findings, conn=conn, provider=provider, progress=say)
        else:
            say("Bỏ qua bước phân tích AI.")
            result = {"analyses": {}, "summary": "", "priority": [], "warnings": []}

        # Báo cáo được render lại từ DB khi cần xem, không lưu blob HTML.
        # Chỉ cần lưu hai thứ không nằm ở từng finding: tóm tắt và thứ tự ưu tiên.
        db.save_summary(conn, scan_id, result["summary"], result["priority"],
                        warnings + result["warnings"])
        db.finish_scan(conn, scan_id)
        say("Xong.")
        _finish(scan_id, "done")

    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        say(f"[LỖI] {msg}")
        db.finish_scan(conn, scan_id, error=msg)
        _finish(scan_id, "error")
    finally:
        conn.close()
