"""Dựng dữ liệu hiển thị và render báo cáo HTML tự chứa (mở được offline).

`context()` được cả hai nơi dùng: file báo cáo xuất ra, và trang chi tiết trên
dashboard. Dựng một lần để hai chỗ không bao giờ lệch số liệu.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import SEVERITY_ORDER, Finding

TEMPLATES = Path(__file__).parent / "web" / "templates"


def context(
    findings: list[Finding],
    analyses: dict[str, dict],
    target: str,
    model: str,
    summary: str = "",
    priority: list[str] | None = None,
    warnings: list[str] | None = None,
    profile: str = "baseline",
) -> dict:
    counts = Counter(f.severity for f in findings)
    by_fp = {f.fingerprint: f for f in findings}

    return {
        "target": target,
        "profile": profile,
        "model": model,
        "generated_at": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "findings": sorted(findings, key=Finding.sort_key),
        "analyses": analyses,
        "summary": summary or "(không có tóm tắt)",
        "counts": [(s, counts[s]) for s in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))],
        # priority từ AI là danh sách fingerprint -> đổi sang tên để người đọc hiểu
        "priority": [by_fp[fp].name for fp in (priority or []) if fp in by_fp],
        "warnings": warnings or [],
    }


def render_context(ctx: dict) -> str:
    """Render báo cáo từ context đã dựng sẵn (dashboard dùng đường này)."""
    # autoescape BẮT BUỘC: evidence và URL là dữ liệu do target kiểm soát.
    # Nhúng thô vào HTML là tự tạo XSS ngay trong báo cáo của mình.
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(["html"]),
    )
    return env.get_template("report.html").render(**ctx)


def render(*args, **kwargs) -> str:
    """Render báo cáo đầy đủ thành một chuỗi HTML tự chứa (CLI dùng đường này)."""
    return render_context(context(*args, **kwargs))
