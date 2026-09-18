"""Test lớp gọi AI. Chạy offline hoàn toàn — không gọi API thật.

Trọng tâm là phía DeepSeek, vì nó KHÔNG có strict JSON schema: đầu ra chỉ được
bảo đảm bằng prompt + validate ở phía mình. Đó là chỗ dễ hỏng âm thầm nhất, mà
đầu ra của AI lại chính là dữ liệu để đo precision/recall của đồ án.
"""

from __future__ import annotations

import json

import pytest

from analyzer import providers
from analyzer.prompts import deepseek_json_instructions
from analyzer.schema import ReportOut

VALID = json.dumps({
    "summary_vi": "Mục tiêu thiếu nhiều security header.",
    "priority_order": ["fp1"],
    "analyses": [{
        "fingerprint": "fp1", "severity_ai": "High", "false_positive_risk": "Thấp",
        "explain_vi": "Giải thích", "impact_vi": "Tác động",
        "owasp_top10": "A05:2021", "cwe": "693",
        "fix_steps": ["Bước 1"], "fix_snippet": "add_header X-Frame-Options DENY;",
        "verify_vi": "curl -I",
    }],
}, ensure_ascii=False)


class _FakeOpenAI:
    """Client giả trả lần lượt các chuỗi cho trước."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = []
        self.chat = type("chat", (), {"completions": self})()

    def create(self, **kw):
        self.calls.append(kw)
        content = self._replies.pop(0) if self._replies else ""
        msg = type("m", (), {"content": content})()
        usage = type("u", (), {"prompt_tokens": 100, "completion_tokens": 50})()
        return type("r", (), {"choices": [type("c", (), {"message": msg})()], "usage": usage})()


@pytest.fixture
def fake_openai(monkeypatch):
    """Thay openai.OpenAI bằng client giả. providers import nó bên trong hàm."""
    import openai

    holder = {}

    def make(replies):
        client = _FakeOpenAI(replies)
        monkeypatch.setattr(openai, "OpenAI", lambda **kw: client)
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
        holder["client"] = client
        return client

    return make


def test_deepseek_parses_valid_json(fake_openai):
    client = fake_openai([VALID])
    out, usage = providers.call_deepseek("[]", "deepseek-v4-pro")
    assert isinstance(out, ReportOut)
    assert out.analyses[0].fingerprint == "fp1"
    assert len(client.calls) == 1
    assert "100 vào" in usage and "50 ra" in usage


def test_deepseek_retries_once_on_bad_json(fake_openai):
    """Không có strict schema nên JSON hỏng là chuyện có thật -> phải thử lại."""
    client = fake_openai(["đây không phải json", VALID])
    out, usage = providers.call_deepseek("[]", "deepseek-v4-pro")
    assert out.analyses[0].fingerprint == "fp1"
    assert len(client.calls) == 2, "phải gọi lại lần hai"
    assert "200 vào" in usage, "token của cả hai lượt phải được cộng dồn"


def test_deepseek_feeds_the_error_back_on_retry(fake_openai):
    client = fake_openai(["{ hỏng", VALID])
    providers.call_deepseek("[]", "deepseek-v4-pro")
    second = client.calls[1]["messages"]
    assert any("không hợp lệ" in m["content"] for m in second if m["role"] == "user")


def test_deepseek_gives_up_after_two_attempts(fake_openai):
    client = fake_openai(["hỏng", "vẫn hỏng"])
    with pytest.raises(providers.BadJSON):
        providers.call_deepseek("[]", "deepseek-v4-pro")
    assert len(client.calls) == 2, "không được lặp vô hạn"


def test_deepseek_treats_empty_content_as_failure(fake_openai):
    """Tài liệu DeepSeek cảnh báo API đôi khi trả content rỗng ở JSON mode.
    Rỗng mà coi là hợp lệ thì phân tích biến mất lặng lẽ."""
    client = fake_openai(["", VALID])
    out, _ = providers.call_deepseek("[]", "deepseek-v4-pro")
    assert out.analyses[0].fingerprint == "fp1"
    assert len(client.calls) == 2


def test_deepseek_requires_api_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        providers.call_deepseek("[]", "deepseek-v4-pro")


def test_deepseek_request_uses_json_mode(fake_openai):
    client = fake_openai([VALID])
    providers.call_deepseek("[]", "deepseek-v4-pro")
    kw = client.calls[0]
    assert kw["response_format"] == {"type": "json_object"}
    # DeepSeek chỉ bật JSON mode khi prompt có chữ "json"
    system = next(m["content"] for m in kw["messages"] if m["role"] == "system")
    assert "json" in system.lower()


def test_json_instructions_are_generated_from_the_pydantic_schema():
    """Schema trong prompt phải sinh từ ReportOut, không chép tay — chép tay là
    sớm muộn cũng lệch với schema thật mà không ai phát hiện."""
    text = deepseek_json_instructions()
    assert "json" in text.lower()
    for field in ("fingerprint", "severity_ai", "false_positive_risk",
                  "fix_snippet", "priority_order", "summary_vi"):
        assert field in text, f"thiếu {field} trong schema gửi cho model"
