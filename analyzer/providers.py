"""Gọi model. Hai provider, cùng một schema đầu ra `ReportOut`.

Khác biệt cốt lõi giữa hai bên, và lý do file này tồn tại:

  Claude   : `messages.parse(output_format=ReportOut)` - API BẢO ĐẢM đầu ra đúng
             schema. Không cần validate, không cần retry.
  DeepSeek : chỉ có JSON mode lỏng (`response_format={"type": "json_object"}`),
             không có strict JSON schema. Phải tự nhét schema vào prompt, tự
             validate bằng Pydantic, tự retry. Tài liệu DeepSeek còn cảnh báo
             "the API may occasionally return empty content".

Với đồ án này khác biệt đó không phải chuyện nhỏ: đầu ra của AI CHÍNH LÀ dữ liệu
để đo precision/recall. Nếu vài phân tích lặng lẽ rơi vì JSON hỏng thì số liệu
đánh giá bị lệch mà không ai biết. Nên phía DeepSeek phải báo rõ nó nhận được
bao nhiêu, chứ không được nuốt lỗi.
"""

from __future__ import annotations

import json
import os

from analyzer.prompts import SYSTEM_PROMPT, deepseek_json_instructions
from analyzer.schema import ReportOut
from core.config import DEEPSEEK_BASE_URL

MAX_TOKENS = 32000


class Refused(Exception):
    """Bộ lọc an toàn của nhà cung cấp từ chối phân tích nội dung này."""


class BadJSON(Exception):
    """Model trả về thứ không phải JSON hợp lệ theo schema, kể cả sau khi thử lại."""


def call_claude(user_content: str, model: str) -> tuple[ReportOut, str]:
    """Trả về (kết quả, mô tả token đã dùng)."""
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.parse(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
        output_format=ReportOut,
    )
    if resp.stop_reason == "refusal":
        raise Refused("Claude từ chối phân tích nội dung này (stop_reason=refusal).")
    return resp.parsed_output, f"{resp.usage.input_tokens} vào / {resp.usage.output_tokens} ra"


def call_deepseek(user_content: str, model: str) -> tuple[ReportOut, str]:
    from openai import OpenAI

    key = os.getenv("DEEPSEEK_API_KEY", "")
    if not key:
        raise RuntimeError("Thiếu DEEPSEEK_API_KEY trong .env.")

    client = OpenAI(api_key=key, base_url=DEEPSEEK_BASE_URL)
    messages = [
        # Schema đi kèm system prompt vì DeepSeek không nhận schema qua tham số API
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + deepseek_json_instructions()},
        {"role": "user", "content": user_content},
    ]

    used_in = used_out = 0
    last_error = ""
    # Hai lượt: lượt sau được xem lỗi của lượt trước để tự sửa. Không lặp nhiều hơn -
    # nếu hai lần đều hỏng thì vấn đề nằm ở prompt chứ không phải may rủi.
    for attempt in (1, 2):
        resp = client.chat.completions.create(
            model=model,
            max_tokens=MAX_TOKENS,
            response_format={"type": "json_object"},
            messages=messages,
        )
        if resp.usage:
            used_in += resp.usage.prompt_tokens
            used_out += resp.usage.completion_tokens

        raw = (resp.choices[0].message.content or "").strip()
        try:
            if not raw:
                raise ValueError("nội dung rỗng")
            return ReportOut.model_validate_json(raw), f"{used_in} vào / {used_out} ra"
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            if attempt == 2:
                break
            messages += [
                {"role": "assistant", "content": raw[:2000]},
                {"role": "user", "content":
                    f"Kết quả trên không hợp lệ ({last_error}). Trả lại DUY NHẤT một "
                    f"object json đúng schema đã cho, không kèm giải thích hay markdown."},
            ]

    raise BadJSON(f"DeepSeek không trả về json đúng schema sau 2 lần thử ({last_error}).")


CALLERS = {"claude": call_claude, "deepseek": call_deepseek}
