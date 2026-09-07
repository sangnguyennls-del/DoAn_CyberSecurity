"""HỢP ĐỒNG 1 — schema chung cho mọi finding.

ĐÃ ĐÓNG BĂNG. Sửa file này là phải sửa cả 5 module -> bàn với cả nhóm trước.
Mọi module chỉ nói chuyện với nhau qua `Finding`.
"""

from __future__ import annotations

import hashlib
import html
import re
from typing import Literal
from pydantic import BaseModel, Field

Source = Literal["nikto", "zap"]

# Thứ tự nghiêm trọng -> dùng để sắp xếp báo cáo
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
ZAP_RISKCODE = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}

_TAG_RE = re.compile(r"<[^>]+>")


def clean_html(s: str) -> str:
    """ZAP trả về desc/solution dạng HTML. Bỏ tag, giải mã entity, gọn khoảng trắng."""
    return " ".join(html.unescape(_TAG_RE.sub(" ", s or "")).split())


def fingerprint(source: str, key: str) -> str:
    """Khoá định danh một LOẠI lỗ hổng, ổn định giữa các lần quét.

    Làm bốn việc cùng lúc:
      1. gom trùng trong một lần quét
      2. so sánh giữa hai lần quét (diff = phép toán tập hợp)
      3. khoá cache kết quả AI
      4. khoá join với bảng ground truth

    `key` là mã test/plugin của scanner (ổn định hơn tên hiển thị).

    CỐ Ý KHÔNG đưa URL vào khoá. Đo trên Juice Shop: test "backup/cert file found"
    của Nikto khớp 140 URL khác nhau. Nếu tính cả path thì thành 140 lỗ hổng riêng
    biệt, trong khi thực chất là MỘT vấn đề với một bản vá duy nhất - vừa làm báo
    cáo không đọc nổi, vừa vượt max_tokens khi gửi lên API.

    Số URL bị ảnh hưởng không mất đi: xem `Finding.count` và `Finding.urls`.
    Việc này cũng làm diff giữa hai lần quét bền hơn - đổi đường dẫn không tạo ra
    lỗ hổng "mới" giả.
    """
    return hashlib.sha256(f"{source}|{key}".encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    """Một lỗ hổng đã chuẩn hoá, không còn phụ thuộc scanner nào sinh ra nó."""

    fingerprint: str
    source: Source
    name: str
    severity: str = "Info"          # High | Medium | Low | Info
    urls: list[str] = Field(default_factory=list)   # tối đa 5 URL mẫu
    count: int = 1                  # số lần xuất hiện thật (trước khi gom)
    evidence: str = ""
    description: str = ""
    solution_raw: str = ""          # gợi ý gốc của scanner, để đối chiếu với AI
    cwe: str = ""

    def sort_key(self) -> tuple[int, str]:
        return (SEVERITY_ORDER.get(self.severity, 9), self.name)
