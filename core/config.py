"""Cấu hình chung + RANH GIỚI AN TOÀN của hệ thống.

`check_target` phải được gọi ở CẢ CLI LẪN API. Đây là ranh giới tin cậy:
chỉ được quét hệ thống mình sở hữu hoặc có văn bản cho phép.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse, urlunparse

from dotenv import load_dotenv

# Nạp .env ngay khi import config -> cả CLI lẫn API đều đọc được ANTHROPIC_API_KEY.
# config bị mọi module import nên đây là chỗ duy nhất cần gọi.
load_dotenv()

DB_PATH = os.getenv("DOAN_DB", "doan.db")
MODEL = "claude-opus-5"

# Container Docker không thấy localhost của máy host
DOCKER_HOST_ALIAS = "host.docker.internal"
_LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", DOCKER_HOST_ALIAS}


class TargetNotAllowed(Exception):
    """Target nằm ngoài phạm vi được phép quét."""


def check_target(url: str, allow_external: bool = False) -> str:
    """Trả về url nếu được phép quét, ngược lại raise TargetNotAllowed.

    Mặc định chỉ cho localhost và mạng nội bộ (RFC1918) — tức lab của chính nhóm.
    Quét một host ngoài internet mà không được phép là hành vi bất hợp pháp,
    nên `allow_external` phải được bật một cách có ý thức.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetNotAllowed(
            f"URL phải bắt đầu bằng http:// hoặc https:// (nhận được: {url!r})"
        )

    host = parsed.hostname
    if not host:
        raise TargetNotAllowed(f"Không đọc được hostname từ URL: {url!r}")

    if allow_external:
        return url
    if host in _LOCAL_NAMES:
        return url
    try:
        if ipaddress.ip_address(host).is_private:
            return url
    except ValueError:
        pass  # là tên miền, không phải IP -> không thuộc mạng nội bộ

    raise TargetNotAllowed(
        f"Từ chối quét {host!r}: nằm ngoài localhost/mạng nội bộ.\n"
        f"Chỉ quét hệ thống bạn sở hữu hoặc có văn bản cho phép.\n"
        f"Nếu chắc chắn, chạy lại với cờ --allow-external."
    )


def to_container_url(url: str) -> str:
    """Đổi localhost -> host.docker.internal khi truyền URL vào container.

    URL gốc được giữ nguyên để hiển thị trong báo cáo.
    """
    parsed = urlparse(url)
    if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        port = f":{parsed.port}" if parsed.port else ""
        return urlunparse(parsed._replace(netloc=f"{DOCKER_HOST_ALIAS}{port}"))
    return url
