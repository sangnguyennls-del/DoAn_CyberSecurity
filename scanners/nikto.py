"""Nikto qua Docker. Module này chỉ biết 2 việc: dựng argv, và parse JSON -> Finding.
Việc chạy subprocess do runner.py lo (để parse() test được offline).
"""

from __future__ import annotations

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
                fingerprint=fingerprint("nikto", str(v.get("id", msg[:40]))),
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
