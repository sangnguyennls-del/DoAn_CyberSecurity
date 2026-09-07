"""Render báo cáo HTML tự chứa (mở được offline, không cần server)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import SEVERITY_ORDER, Finding

TEMPLATES = Path(__file__).parent / "web" / "templates"


def render(
    findings: list[Finding],
    analyses: dict[str, dict],
    target: str,
    model: str,
    summary: str = "",
    priority: list[str] | None = None,
    warnings: list[str] | None = None,
    profile: str = "baseline",
) -> str:
    # autoescape BẮT BUỘC: evidence và URL là dữ liệu do target kiểm soát.
    # Nhúng thô vào HTML là tự tạo XSS ngay trong báo cáo của mình.
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(["html"]),
    )
    counts = Counter(f.severity for f in findings)
    by_fp = {f.fingerprint: f for f in findings}

    # priority từ AI là danh sách fingerprint -> đổi sang tên để người đọc hiểu
    priority_names = [by_fp[fp].name for fp in (priority or []) if fp in by_fp]

    return env.get_template("report.html").render(
        target=target,
        profile=profile,
        model=model,
        generated_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
        findings=sorted(findings, key=Finding.sort_key),
        analyses=analyses,
        summary=summary or "(không có tóm tắt)",
        counts=[(s, counts[s]) for s in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))],
        priority=priority_names,
        warnings=warnings or [],
    )
