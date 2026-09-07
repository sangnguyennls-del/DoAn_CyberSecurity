"""OWASP ZAP qua Docker. Ba profile: baseline (passive) / full (có active scan) / auth.

Lưu ý quan trọng: zap-baseline.py trả exit code 1 khi có WARN và 2 khi có FAIL.
Tức là "tìm thấy lỗ hổng" = exit code khác 0. Tuyệt đối không dùng check=True.
"""

from __future__ import annotations

from core.models import ZAP_RISKCODE, Finding, clean_html, fingerprint

IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
OUTFILE = "zap.json"

SCRIPTS = {
    "baseline": "zap-baseline.py",   # nhanh, chỉ passive
    "full": "zap-full-scan.py",      # có active scan, lâu hơn nhiều
}


def docker_args(container_url: str, host_outdir: str, profile: str = "baseline") -> list[str]:
    script = SCRIPTS.get(profile, SCRIPTS["baseline"])
    return [
        "docker", "run", "--rm",
        "-v", f"{host_outdir}:/zap/wrk/:rw",
        IMAGE,
        script,
        "-t", container_url,
        "-J", OUTFILE,
        "-I",   # không trả exit code thất bại chỉ vì có WARN
    ]


def parse(data) -> list[Finding]:
    out: list[Finding] = []
    for site in data.get("site") or []:
        for a in site.get("alerts") or []:
            instances = a.get("instances") or []
            urls = [i.get("uri", "") for i in instances if i.get("uri")]
            evidence = next((i.get("evidence") for i in instances if i.get("evidence")), "")
            first_url = urls[0] if urls else site.get("@name", "/")
            # pluginid ổn định hơn tên hiển thị -> dùng làm khoá fingerprint
            key = str(a.get("pluginid") or a.get("alertRef") or a.get("name", ""))
            out.append(Finding(
                fingerprint=fingerprint("zap", key, first_url),
                source="zap",
                name=a.get("name") or a.get("alert") or "ZAP alert",
                severity=ZAP_RISKCODE.get(str(a.get("riskcode", "0")), "Info"),
                urls=urls[:3],
                count=int(a.get("count") or len(instances) or 1),
                evidence=clean_html(evidence),
                description=clean_html(a.get("desc", "")),
                solution_raw=clean_html(a.get("solution", "")),
                cwe=str(a.get("cweid", "")),
            ))
    return out
