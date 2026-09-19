"""Nikto qua Docker. Module này chỉ biết 2 việc: dựng argv, và parse JSON -> Finding.
Việc chạy subprocess do runner.py lo (để parse() test được offline).
"""

from __future__ import annotations

import re

from core.models import Finding, clean_html, fingerprint

IMAGE = "ghcr.io/sullo/nikto:latest"  # image chính thức nằm trên ghcr, KHÔNG phải Docker Hub
OUTFILE = "nikto.json"


def docker_args(container_url: str, host_outdir: str, maxtime: int = 300) -> list[str]:
    return [
        "docker", "run", "--rm",
        "-v", f"{host_outdir}:/out",
        IMAGE,
        "-h", container_url,
        "-Format", "json",
        "-output", f"/out/{OUTFILE}",
        "-maxtime", str(maxtime),
        "-nointeractive",
    ]


_QUOTED = re.compile(r"'([^']{1,60})'")


def _key(test_id: str, msg: str) -> str:
    """Khoá gom trùng cho một phát hiện Nikto.

    `test_id` không đủ: Nikto dùng chung một id cho cả họ phát hiện. Ví dụ mọi
    header lạ đều là "Uncommon header(s) '<tên>' found" với cùng một id, nên
    'x-recruiting' và 'cross-origin-embedder-policy-report-only' gộp làm một.
    Đo được ở lần quét #9 vs #17: header cũ đã vá xong mà bảng so sánh vẫn báo
    "còn tồn tại", tức là trang so sánh nói sai.

    Thêm phần nằm trong dấu nháy đơn vào khoá. Tên header, entry trong robots.txt
    đều được Nikto đặt trong nháy; còn URL thì KHÔNG, nên chỗ này không làm bung
    trở lại lỗi cũ (một phát hiện khớp 140 URL thành 140 dòng).
    """
    return "|".join([test_id, *_QUOTED.findall(msg)])


def parse(data) -> list[Finding]:
    """Nikto tuỳ phiên bản trả về dict hoặc list[dict]. Chấp nhận cả hai."""
    hosts = data if isinstance(data, list) else [data]
    out: list[Finding] = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        for v in host.get("vulnerabilities") or []:
            msg = clean_html(v.get("msg", ""))
            url = v.get("url") or "/"
            # Nikto không xếp hạng nghiêm trọng -> để Info, AI sẽ đánh giá lại
            out.append(Finding(
                fingerprint=fingerprint("nikto", _key(str(v.get("id", msg[:40])), msg)),
                source="nikto",
                name=msg[:90] or "Nikto finding",
                severity="Info",
                urls=[url],
                count=1,
                evidence=f'{v.get("method", "GET")} {url}',
                description=msg,
                solution_raw="",
                cwe="",
            ))
    return out
