"""Gọi Claude phân tích findings.

Ba quyết định thiết kế:
  1. MỘT lần gọi cho TOÀN BỘ findings, không lặp từng cái. Rẻ hơn nhiều, và AI thấy
     toàn cảnh nên xếp được thứ tự ưu tiên có nghĩa.
  2. Cache theo (fingerprint, model): chỉ gửi lên API những finding chưa từng được
     phân tích. Quét lại target cũ gần như miễn phí -> vòng lặp vá->quét lại chạy
     được nhiều lần mà không tốn thêm tiền.
  3. Không bao giờ raise. Lỗi mạng, hết quota, bộ lọc từ chối - tất cả thành warning.
     Báo cáo vẫn ra, chỉ thiếu cột phân tích. Không đáng để mất cả lần quét đã tốn
     10 phút.

Dùng `messages.parse(output_format=ReportOut)`: API bảo đảm đầu ra đúng schema, nên
không cần validate hay thử lại ở đây. Đó là lý do chọn Claude cho đồ án này - đầu ra
của mô hình chính là dữ liệu đầu vào cho phần đánh giá định lượng ở `eval/`, nên nó
phải đầy đủ, không được rơi rớt lặng lẽ.
"""

from __future__ import annotations

import json
from collections import Counter

from analyzer.prompts import SYSTEM_PROMPT
from analyzer.schema import ReportOut
from core.config import MODEL
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
    model: str = MODEL,
    progress=None,
) -> dict:
    """Trả về dict {analyses, summary, priority, warnings}."""
    say = progress or (lambda m: None)
    if not findings:
        return _result({}, "Không tìm thấy lỗ hổng nào.")

    from core import db as db_mod

    cached: dict[str, dict] = {}
    if conn is not None:
        cached = db_mod.get_cached(conn, [f.fingerprint for f in findings], model)
    todo = [f for f in findings if f.fingerprint not in cached]

    if not todo:
        say(f"Toàn bộ {len(findings)} lỗ hổng đã có trong cache, không gọi API.")
        return _result(cached, _local_summary(findings))

    say(f"Gọi Claude phân tích {len(todo)} lỗ hổng mới ({len(cached)} lấy từ cache)...")

    try:
        import anthropic

        client = anthropic.Anthropic()
        resp = client.messages.parse(
            model=model,
            max_tokens=32000,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": json.dumps([_payload(f) for f in todo], ensure_ascii=False, indent=1),
            }],
            output_format=ReportOut,
        )
    except Exception as e:
        warn = (f"Gọi Claude thất bại ({type(e).__name__}: {e}). "
                f"Báo cáo chỉ có kết quả thô của scanner.")
        say(f"  [!] {warn}")
        return _result(cached, _local_summary(findings), warnings=[warn])

    # Bộ lọc an toàn có thể từ chối nội dung bảo mật -> không để sập cả lần quét.
    # Có stop_reason riêng nên phân biệt được "bị từ chối" với "lỗi kỹ thuật",
    # và đó là số liệu đáng ghi vào báo cáo chứ không phải bug.
    if resp.stop_reason == "refusal":
        warn = ("Claude từ chối phân tích nội dung này (stop_reason=refusal). "
                "Báo cáo vẫn giữ đầy đủ bằng chứng thô của scanner.")
        say(f"  [!] {warn}")
        return _result(cached, _local_summary(findings), warnings=[warn])

    out: ReportOut = resp.parsed_output
    known = {f.fingerprint for f in todo}
    # Bỏ qua fingerprint AI bịa thêm - chỉ nhận cái khớp với đầu vào
    fresh = [a.model_dump() for a in out.analyses if a.fingerprint in known]

    warnings = []
    if len(fresh) < len(todo):
        warnings.append(f"AI chỉ phân tích {len(fresh)}/{len(todo)} lỗ hổng mới.")

    if conn is not None and fresh:
        db_mod.put_cached(conn, model, fresh)

    say(f"  [ok] Nhận {len(fresh)} phân tích. "
        f"Token: {resp.usage.input_tokens} vào / {resp.usage.output_tokens} ra")

    return _result(
        {**cached, **{a["fingerprint"]: a for a in fresh}},
        out.summary_vi,
        priority=out.priority_order,
        warnings=warnings,
    )
