"""OWASP ZAP qua Docker. Ba profile: baseline (passive) / full (có active scan) / auth.

Lưu ý quan trọng: zap-baseline.py trả exit code 1 khi có WARN và 2 khi có FAIL.
Tức là "tìm thấy lỗ hổng" = exit code khác 0. Tuyệt đối không dùng check=True.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.models import ZAP_RISKCODE, Finding, clean_html, fingerprint

IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
OUTFILE = "zap.json"
PLAN_TEMPLATE = Path(__file__).parent / "zap_auth.yaml"
PLAN_FILE = "af-plan.yaml"

SCRIPTS = {
    "baseline": "zap-baseline.py",   # nhanh, chỉ passive
    "full": "zap-full-scan.py",      # có active scan, lâu hơn nhiều
}

# Mặc định cấu hình cho Juice Shop; target khác thì đè bằng biến môi trường
DEFAULT_LOGIN_PATH = "/rest/user/login"
DEFAULT_LOGIN_BODY = '{"email":"{%username%}","password":"{%password%}"}'


class MissingCredentials(Exception):
    """Profile auth cần tài khoản nhưng .env chưa khai báo."""


def _write_auth_plan(container_url: str, host_outdir: str) -> None:
    """Sinh file kế hoạch Automation Framework từ template.

    Tài khoản đọc từ biến môi trường, KHÔNG hardcode vào repo - kể cả tài khoản lab,
    vì thói quen commit mật khẩu là thứ dễ mang sang project thật.
    """
    user = os.getenv("ZAP_AUTH_USER", "")
    password = os.getenv("ZAP_AUTH_PASS", "")
    if not user or not password:
        raise MissingCredentials(
            "Profile auth cần ZAP_AUTH_USER và ZAP_AUTH_PASS trong .env. "
            "Tạo một tài khoản trên chính target lab của bạn rồi điền vào."
        )

    login_url = os.getenv("ZAP_LOGIN_URL", container_url.rstrip("/") + DEFAULT_LOGIN_PATH)
    body = os.getenv("ZAP_LOGIN_BODY", DEFAULT_LOGIN_BODY)
    if "'" in body:
        raise MissingCredentials("ZAP_LOGIN_BODY không được chứa dấu nháy đơn (vỡ YAML).")

    plan = PLAN_TEMPLATE.read_text(encoding="utf-8")
    for key, val in (("{{TARGET}}", container_url.rstrip("/")),
                     ("{{LOGIN_URL}}", login_url),
                     ("{{LOGIN_BODY}}", body),
                     ("{{USERNAME}}", user),
                     ("{{PASSWORD}}", password)):
        plan = plan.replace(key, val)
    (Path(host_outdir) / PLAN_FILE).write_text(plan, encoding="utf-8")


def docker_args(container_url: str, host_outdir: str, profile: str = "baseline") -> list[str]:
    """Dựng lệnh docker. Với profile auth, ghi luôn file kế hoạch vào host_outdir."""
    base = ["docker", "run", "--rm", "-v", f"{host_outdir}:/zap/wrk/:rw", IMAGE]

    if profile == "auth":
        _write_auth_plan(container_url, host_outdir)
        return base + ["zap.sh", "-cmd", "-autorun", f"/zap/wrk/{PLAN_FILE}"]

    return base + [
        SCRIPTS.get(profile, SCRIPTS["baseline"]),
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
            # alertRef ("10055-2") TRƯỚC pluginid ("10055"): một plugin phát ra nhiều
            # biến thể khác hẳn nhau. Đo thật trên nginx: "CSP: Failure to Define
            # Directive with No Fallback" và "CSP: script-src unsafe-inline" đều là
            # pluginid 10055. Gom chung thì trang so sánh báo "không đổi" trong khi
            # vấn đề đã khác -> bằng chứng "đã vá" của đồ án thành sai.
            key = str(a.get("alertRef") or a.get("pluginid") or a.get("name", ""))
            out.append(Finding(
                fingerprint=fingerprint("zap", key),
                source="zap",
                name=a.get("name") or a.get("alert") or "ZAP alert",
                severity=ZAP_RISKCODE.get(str(a.get("riskcode", "0")), "Info"),
                urls=urls[:5],
                count=int(a.get("count") or len(instances) or 1),
                evidence=clean_html(evidence),
                description=clean_html(a.get("desc", "")),
                solution_raw=clean_html(a.get("solution", "")),
                cwe=str(a.get("cweid", "")),
            ))
    return out
