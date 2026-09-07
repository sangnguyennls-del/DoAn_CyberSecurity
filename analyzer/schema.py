"""Schema đầu ra của AI. Dùng structured output của SDK -> KHÔNG tự parse JSON từ text."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Analysis(BaseModel):
    fingerprint: str
    severity_ai: str = Field(description="Critical | High | Medium | Low | Info")
    false_positive_risk: str = Field(description="Cao | Trung bình | Thấp")
    explain_vi: str = Field(description="Giải thích lỗ hổng bằng tiếng Việt, cho người mới học")
    impact_vi: str = Field(description="Kẻ tấn công làm được gì nếu khai thác thành công")
    owasp_top10: str = Field(description="Ví dụ: A05:2021 - Security Misconfiguration")
    cwe: str
    fix_steps: list[str] = Field(description="Các bước vá, cụ thể, theo thứ tự")
    fix_snippet: str = Field(description="Đoạn config/code áp dụng được ngay. Chuỗi rỗng nếu không có.")
    verify_vi: str = Field(description="Cách kiểm chứng đã vá xong")


class ReportOut(BaseModel):
    summary_vi: str = Field(description="Tóm tắt tình hình bảo mật của mục tiêu, 3-5 câu")
    priority_order: list[str] = Field(description="Danh sách fingerprint theo thứ tự nên xử lý trước")
    analyses: list[Analysis]
