"""Gọi AI phân tích findings.

Ba quyết định thiết kế:
  1. MỘT lần gọi cho TOÀN BỘ findings, không lặp từng cái. Rẻ hơn nhiều, và AI thấy
     toàn cảnh nên xếp được thứ tự ưu tiên có nghĩa.
  2. Cache theo (fingerprint, model): chỉ gửi lên API những finding chưa từng được
     model đó phân tích. Quét lại target cũ gần như miễn phí, và chạy provider thứ
     hai trên cùng lần quét vẫn gọi API thật thay vì lấy lại kết quả của provider kia.
  3. Không bao giờ raise. Lỗi mạng, hết quota, JSON hỏng, bộ lọc từ chối - tất cả
     thành warning. Báo cáo vẫn ra, chỉ thiếu cột phân tích. Không đáng để mất cả
     lần quét đã tốn 10 phút.
"""

from __future__ import annotations

import json
from collections import Counter

from analyzer import providers
from analyzer.schema import ReportOut
from core.config import AI_PROVIDER, model_for
from core.models import Finding

MAX_FIELD = 600  # cắt bớt mô tả dài để tiết kiệm token


def _payload(f: Finding) -> dict:
    """Chỉ gửi những gì AI cần. Không gửi cả object Finding cho đỡ tốn token."""
    return {
        "fingerprint": f.fingerprint,
        "source": f.source,
        "name": f.name,
        "severity_scanner": f.severity,
        "urls": f.urls,
        "count": f.count,
        "evidence": f.evidence[:MAX_FIELD],
        "description": f.description[:MAX_FIELD],
        "solution_scanner": f.solution_raw[:MAX_FIELD],
        "cwe": f.cwe,
    }


def _local_summary(findings: list[Finding]) -> str:
    """Tóm tắt không cần API - dùng khi mọi finding đều đã có trong cache."""
    c = Counter(f.severity for f in findings)
    parts = [f"{c[s]} {s}" for s in ("High", "Medium", "Low", "Info") if c[s]]
    return (f"Tìm thấy {len(findings)} lỗ hổng riêng biệt ({', '.join(parts)}). "
            f"Kết quả phân tích lấy từ cache của các lần quét trước.")


def _result(analyses, summary, priority=None, warnings=None) -> dict:
    return {
        "analyses": analyses,
        "summary": summary,
        "priority": priority or [],
        "warnings": warnings or [],
    }


def analyze(
    findings: list[Finding],
    conn=None,
    provider: str | None = None,
    progress=None,
) -> dict:
    """Trả về dict {analyses, summary, priority, warnings}."""
    say = progress or (lambda m: None)
    if not findings:
        return _result({}, "Không tìm thấy lỗ hổng nào.")

    provider = (provider or AI_PROVIDER).strip().lower()
    try:
        model = model_for(provider)
    except ValueError as e:
        say(f"  [!] {e}")
        return _result({}, _local_summary(findings), warnings=[str(e)])

    from core import db as db_mod

    cached: dict[str, dict] = {}
    if conn is not None:
        cached = db_mod.get_cached(conn, [f.fingerprint for f in findings], model)
    todo = [f for f in findings if f.fingerprint not in cached]

    if not todo:
        say(f"Toàn bộ {len(findings)} lỗ hổng đã có phân tích của {model}, không gọi API.")
        return _result(cached, _local_summary(findings))

    say(f"Gọi {model} phân tích {len(todo)} lỗ hổng mới ({len(cached)} lấy từ cache)...")
    content = json.dumps([_payload(f) for f in todo], ensure_ascii=False, indent=1)

    try:
        out, usage = providers.CALLERS[provider](content, model)
    except providers.Refused as e:
        warn = f"{e} Báo cáo vẫn giữ đầy đủ bằng chứng thô của scanner."
        say(f"  [!] {warn}")
        return _result(cached, _local_summary(findings), warnings=[warn])
    except Exception as e:
        warn = (f"Gọi {model} thất bại ({type(e).__name__}: {e}). "
                f"Báo cáo chỉ có kết quả thô của scanner.")
        say(f"  [!] {warn}")
        return _result(cached, _local_summary(findings), warnings=[warn])

    out: ReportOut
    known = {f.fingerprint for f in todo}
    # Bỏ qua fingerprint AI bịa thêm - chỉ nhận cái khớp với đầu vào
    fresh = [a.model_dump() for a in out.analyses if a.fingerprint in known]

    warnings = []
    if len(fresh) < len(todo):
        # Không nuốt lặng: số liệu đánh giá tính trên phần AI thật sự trả lời được
        warnings.append(f"{model} chỉ phân tích {len(fresh)}/{len(todo)} lỗ hổng mới.")

    if conn is not None and fresh:
        db_mod.put_cached(conn, model, fresh)

    say(f"  [ok] Nhận {len(fresh)} phân tích từ {model}. Token: {usage}")

    return _result(
        {**cached, **{a["fingerprint"]: a for a in fresh}},
        out.summary_vi,
        priority=out.priority_order,
        warnings=warnings,
    )
