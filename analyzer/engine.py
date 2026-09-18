"""Gọi Claude phân tích findings.

Bốn quyết định thiết kế:

  1. CHIA LÔ. Đo thật: mỗi lỗ hổng tốn ~2.277 token output (5 lỗ hổng -> 11.387
     token). Gộp 22 lỗ hổng vào một lời gọi thì chạm trần max_tokens, JSON đứt
     giữa chừng và mất TRẮNG cả 22 sau 8 phút chờ. Chia lô nhỏ làm mỗi lời gọi
     nằm gọn dưới trần, và quan trọng hơn: một lô hỏng thì các lô khác vẫn giữ
     được kết quả.

  2. Cache theo (fingerprint, model), GHI NGAY sau mỗi lô. Quét lại target cũ gần
     như miễn phí, và lô đã trả tiền rồi thì không bao giờ phải trả lại.

  3. Không bao giờ raise. Lỗi mạng, hết quota, bộ lọc từ chối - tất cả thành
     warning. Báo cáo vẫn ra, chỉ thiếu cột phân tích.

  4. Truyền URL mục tiêu VÀ ngăn xếp dò được vào prompt. Không có chúng, mô hình
     đoán tầng công nghệ và sinh bản vá sai tầng - xem `detect_stack()`.

Dùng `messages.stream(output_format=ReportOut)`: API bảo đảm đầu ra đúng schema,
nên không cần validate hay thử lại. Đó là lý do chọn Claude cho đồ án này - đầu ra
của mô hình chính là dữ liệu đầu vào cho phần đánh giá định lượng ở `eval/`.
Streaming là bắt buộc chứ không phải tuỳ chọn - xem ghi chú trong `_call_batch()`.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from analyzer.prompts import SYSTEM_PROMPT
from analyzer.schema import ReportOut
from core.config import MODEL
from core.models import SEVERITY_ORDER, Finding

MAX_FIELD = 600     # cắt bớt mô tả dài để tiết kiệm token
MAX_TOKENS = 32000

# Đo được ~2.277 token output/lỗ hổng -> lô 6 cái ≈ 13.700 token, còn dư gần nửa
# trần cho những finding dài bất thường.
# ponytail: chạy tuần tự, 22 lỗ hổng mất ~12 phút. Nếu thấy chậm thì chạy các lô
# song song bằng ThreadPoolExecutor như scanners/runner.py đang làm.
BATCH_SIZE = 6

# AI xếp lại mức độ theo thang riêng, có thêm Critical
AI_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
FP_RISK_ORDER = {"Thấp": 0, "Trung bình": 1, "Cao": 2}

# Banner công nghệ hay xuất hiện trong header Server / X-Powered-By
_STACK_PATTERNS = [
    re.compile(r"nginx/[\d.]+", re.I),
    re.compile(r"Apache/[\d.]+", re.I),
    re.compile(r"Werkzeug/[\d.]+", re.I),
    re.compile(r"Python/[\d.]+", re.I),
    re.compile(r"PHP/[\d.]+", re.I),
    re.compile(r"Microsoft-IIS/[\d.]+", re.I),
    re.compile(r"\bExpress\b", re.I),
]


def detect_stack(findings: list[Finding]) -> str:
    """Dò ngăn xếp công nghệ từ TOÀN BỘ kết quả quét.

    Vì sao cần: mô hình suy stack từ evidence của RIÊNG từng lỗ hổng. Đo thật trên
    target nginx - chỉ đúng MỘT finding có 'nginx/1.31.5' trong evidence của nó
    (Server Leaks Version) là nhận được bản vá nginx; bốn finding về header khác
    không có manh mối nào trong evidence riêng nên mô hình đoán là Express và trả
    về code helmet - dán vào đâu cũng không được.

    Banner chỉ xuất hiện ở một finding nhưng áp dụng cho CẢ mục tiêu, nên phải gom
    ra đây rồi đưa vào mọi lô.
    """
    found: list[str] = []
    for f in findings:
        blob = f"{f.evidence} {f.description} {f.name}"
        for pat in _STACK_PATTERNS:
            m = pat.search(blob)
            if m and m.group(0) not in found:
                found.append(m.group(0))
    return ", ".join(found)


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
    """Tóm tắt không cần API - dùng khi không có phân tích nào."""
    c = Counter(f.severity for f in findings)
    parts = [f"{c[s]} {s}" for s in ("High", "Medium", "Low", "Info") if c[s]]
    return f"Tìm thấy {len(findings)} lỗ hổng riêng biệt ({', '.join(parts)})."


def _summary_from_ai(findings: list[Finding], analyses: dict[str, dict]) -> str:
    """Tóm tắt dựng từ ĐÁNH GIÁ LẠI của AI, không phải xếp hạng của scanner.

    Tính tại chỗ thay vì dùng `summary_vi` của một lô: khi chia lô, mỗi lô chỉ
    thấy phần của nó nên tóm tắt của nó không bao quát toàn bộ. Số đếm ở đây luôn
    đúng với toàn bộ findings, và giải thích được trong báo cáo.
    """
    if not analyses:
        return _local_summary(findings)
    c = Counter(a.get("severity_ai", "?") for a in analyses.values())
    parts = [f"{c[s]} {s}" for s in ("Critical", "High", "Medium", "Low", "Info") if c[s]]
    worst = [f.name for f in findings
             if AI_SEVERITY_ORDER.get(
                 (analyses.get(f.fingerprint) or {}).get("severity_ai", ""), 9) <= 1][:3]
    tail = f" Đáng lo nhất: {'; '.join(worst)}." if worst else ""
    return (f"AI đánh giá lại {len(analyses)}/{len(findings)} lỗ hổng: "
            f"{', '.join(parts)}.{tail}")


def _priority(findings: list[Finding], analyses: dict[str, dict]) -> list[str]:
    """Thứ tự nên xử lý, tính từ đánh giá của AI.

    Tính tại chỗ thay vì ghép `priority_order` của từng lô: mỗi lô chỉ xếp hạng
    được phần của nó. Sắp theo mức độ AI đánh giá, rồi tới khả năng false positive
    (cái nào chắc là lỗi thật thì làm trước) - quy tắc này giải thích được trong
    báo cáo, khác với một thứ tự mờ do mô hình tự chọn.
    """
    scored = [f for f in findings if f.fingerprint in analyses]
    scored.sort(key=lambda f: (
        AI_SEVERITY_ORDER.get(analyses[f.fingerprint].get("severity_ai", ""), 9),
        FP_RISK_ORDER.get(analyses[f.fingerprint].get("false_positive_risk", ""), 9),
        SEVERITY_ORDER.get(f.severity, 9),
    ))
    return [f.fingerprint for f in scored]


def _result(analyses, summary, priority=None, warnings=None) -> dict:
    return {
        "analyses": analyses,
        "summary": summary,
        "priority": priority or [],
        "warnings": warnings or [],
    }


def _build_header(target: str, stack: str) -> str:
    """Phần mở đầu prompt: mục tiêu là gì và chạy trên nền gì."""
    lines: list[str] = []
    if target:
        lines.append(f"URL mục tiêu: {target}")
    if stack:
        lines.append(f"Ngăn xếp dò được từ TOÀN BỘ lần quét: {stack}")
        lines.append(
            "Ngăn xếp này áp dụng cho cả mục tiêu, kể cả khi bằng chứng của một "
            "lỗ hổng cụ thể bên dưới không nhắc tới nó. Lỗ hổng nào vá được ở "
            "tầng này thì ưu tiên vá ở đây, đừng mặc định là code ứng dụng."
        )
    return "\n".join(lines) + "\n\n" if lines else ""


def _call_batch(client, batch: list[Finding], target: str, stack: str,
                model: str) -> tuple[ReportOut, int, int]:
    """Gọi một lô, trả về (kết quả, token vào, token ra). Raise nếu hỏng."""
    content = _build_header(target, stack) + json.dumps(
        [_payload(f) for f in batch], ensure_ascii=False, indent=1
    )

    # PHẢI dùng stream(): với max_tokens lớn, SDK từ chối thẳng lời gọi non-streaming
    # ("Streaming is required for operations that may take longer than 10 minutes").
    # stream() vẫn nhận output_format nên vẫn được API bảo đảm đúng schema.
    with client.messages.stream(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": content}],
        output_format=ReportOut,
    ) as stream:
        resp = stream.get_final_message()

    if resp.stop_reason == "refusal":
        raise RuntimeError("Claude từ chối phân tích lô này (stop_reason=refusal).")
    out = resp.parsed_output
    if out is None:
        raise RuntimeError(f"Phản hồi không có phần đã parse (stop_reason={resp.stop_reason}).")
    return out, resp.usage.input_tokens, resp.usage.output_tokens


def _explain(e: Exception) -> str:
    """Đổi lỗi kỹ thuật thành câu nói được phải làm gì."""
    msg = str(e)
    if "EOF while parsing" in msg or "json_invalid" in msg:
        return (f"output bị cắt giữa chừng vì chạm trần {MAX_TOKENS:,} token - "
                f"giảm BATCH_SIZE trong analyzer/engine.py (đang là {BATCH_SIZE})")
    return f"{type(e).__name__}: {msg[:200]}"


def analyze(
    findings: list[Finding],
    conn=None,
    target: str = "",
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
        return _result(cached, _summary_from_ai(findings, cached),
                       priority=_priority(findings, cached))

    # Dò trên TOÀN BỘ findings, không chỉ lô hiện tại - banner thường chỉ nằm ở
    # một finding duy nhất nhưng áp dụng cho cả mục tiêu.
    stack = detect_stack(findings)
    batches = [todo[i:i + BATCH_SIZE] for i in range(0, len(todo), BATCH_SIZE)]
    say(f"Gọi Claude phân tích {len(todo)} lỗ hổng mới trong {len(batches)} lô "
        f"({len(cached)} lấy từ cache)"
        + (f" | ngăn xếp: {stack}" if stack else " | không dò được ngăn xếp"))

    try:
        import anthropic
        client = anthropic.Anthropic()
    except Exception as e:
        warn = f"Không khởi tạo được client Claude ({_explain(e)})."
        say(f"  [!] {warn}")
        return _result(cached, _summary_from_ai(findings, cached),
                       priority=_priority(findings, cached), warnings=[warn])

    fresh: dict[str, dict] = {}
    warnings: list[str] = []
    tok_in = tok_out = 0
    known = {f.fingerprint for f in todo}

    for i, batch in enumerate(batches, 1):
        try:
            out, ti, to = _call_batch(client, batch, target, stack, model)
        except Exception as e:
            # Một lô hỏng KHÔNG được kéo theo các lô khác - đó là điểm chính của
            # việc chia lô. Lô trước đã trả tiền rồi thì phải giữ lại.
            warn = f"Lô {i}/{len(batches)} thất bại ({_explain(e)})."
            say(f"  [!] {warn}")
            warnings.append(warn)
            continue

        tok_in += ti
        tok_out += to
        # Chỉ nhận fingerprint khớp đầu vào - bỏ qua cái AI bịa thêm
        got = [a.model_dump() for a in out.analyses if a.fingerprint in known]
        if conn is not None and got:
            db_mod.put_cached(conn, model, got)   # ghi ngay, không đợi hết vòng
        fresh.update({a["fingerprint"]: a for a in got})
        say(f"  [ok] Lô {i}/{len(batches)}: {len(got)}/{len(batch)} phân tích "
            f"({ti:,} vào / {to:,} ra)")

    if len(fresh) < len(todo):
        warnings.append(f"Nhận {len(fresh)}/{len(todo)} phân tích cho lỗ hổng mới.")

    analyses = {**cached, **fresh}
    say(f"  Tổng: {len(analyses)}/{len(findings)} lỗ hổng có phân tích. "
        f"Token: {tok_in:,} vào / {tok_out:,} ra")

    return _result(analyses, _summary_from_ai(findings, analyses),
                   priority=_priority(findings, analyses), warnings=warnings)
