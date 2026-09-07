"""OWASP ZAP qua Docker. Ba profile: baseline (passive) / full (có active scan) / auth.

Lưu ý quan trọng: zap-baseline.py trả exit code 1 khi có WARN và 2 khi có FAIL.
Tức là "tìm thấy lỗ hổng" = exit code khác 0. Tuyệt đối không dùng check=True.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from core.models import ZAP_RISKCODE, Finding, clean_html, fingerprint

IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
OUTFILE = "zap.json"
DOCKER_ALIAS = "host.docker.internal"
PLAN_TEMPLATE = Path(__file__).parent / "zap_auth.yaml"
PLAN_FILE = "af-plan.yaml"

SCRIPTS = {
    "baseline": "zap-baseline.py",   # nhanh, chỉ passive
    "full": "zap-full-scan.py",      # có active scan, lâu hơn nhiều
}

# Mặc định cấu hình cho Juice Shop; target khác thì đè bằng biến môi trường
DEFAULT_LOGIN_PATH = "/rest/user/login"
# Phải là endpoint trả 401 khi chưa đăng nhập, nếu không thì bước kiểm tra vô nghĩa
DEFAULT_CHECK_PATH = "/api/Cards"
DEFAULT_LOGIN_BODY = '{"email":"{%username%}","password":"{%password%}"}'


class AuthSetupFailed(Exception):
    """Không thiết lập được quét-có-đăng-nhập: thiếu tài khoản, hoặc đăng nhập hỏng."""


# Giữ tên cũ để code/test cũ không gãy
MissingCredentials = AuthSetupFailed


def _verify_login(container_url: str, login_url: str, body: str,
                  user: str, password: str, check_path: str) -> None:
    """Đăng nhập thử TRƯỚC khi khởi động ZAP. Hỏng thì raise.

    Vì sao không để ZAP tự kiểm: đã thử job `requestor` với `responseCode: 200` và
    `failOnError: true`. Đo thật với mật khẩu sai -> ZAP coi lệch response code là
    WARNING chứ không phải error, nên vẫn crawl hết và vẫn sinh zap.json. Kết quả
    là một lần quét ẩn danh trông y hệt lần quét có đăng nhập.

    Đó là kiểu hỏng tệ nhất cho đồ án: không báo lỗi, chỉ âm thầm sai. Nên phần
    kiểm tra phải nằm ở đây, nơi mình quyết định được điều gì xảy ra tiếp theo.
    """
    # Container thấy host.docker.internal, còn tiến trình này chạy trên host
    host = container_url.replace(DOCKER_ALIAS, "localhost")
    login = login_url.replace(DOCKER_ALIAS, "localhost")
    payload = body.replace("{%username%}", user).replace("{%password%}", password)

    def _get(url, headers=None):
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()

    try:
        req = urllib.request.Request(login, data=payload.encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            token = json.loads(r.read())["authentication"]["token"]
    except urllib.error.HTTPError as e:
        raise AuthSetupFailed(
            f"Đăng nhập thất bại (HTTP {e.code}) tại {login}. "
            f"Kiểm tra lại ZAP_AUTH_USER/ZAP_AUTH_PASS trong .env."
        ) from e
    except (urllib.error.URLError, KeyError, ValueError, TimeoutError) as e:
        raise AuthSetupFailed(
            f"Không lấy được token từ {login} ({type(e).__name__}: {e}). "
            f"Nếu target không phải Juice Shop, đặt ZAP_LOGIN_URL/ZAP_LOGIN_BODY."
        ) from e

    check = host.rstrip("/") + check_path
    try:
        status, _ = _get(check, {"Authorization": f"Bearer {token}"})
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, TimeoutError) as e:
        raise AuthSetupFailed(f"Không gọi được {check} để kiểm tra đăng nhập ({e}).") from e

    if status != 200:
        raise AuthSetupFailed(
            f"Có token nhưng {check} vẫn trả HTTP {status} -> ZAP sẽ quét ẩn danh. "
            f"Đặt ZAP_AUTH_CHECK_PATH thành một endpoint trả 401 khi chưa đăng nhập."
        )


def _write_auth_plan(container_url: str, host_outdir: str) -> None:
    """Sinh file kế hoạch Automation Framework từ template.

    Tài khoản đọc từ biến môi trường, KHÔNG hardcode vào repo - kể cả tài khoản lab,
    vì thói quen commit mật khẩu là thứ dễ mang sang project thật.
    """
    user = os.getenv("ZAP_AUTH_USER", "")
    password = os.getenv("ZAP_AUTH_PASS", "")
    if not user or not password:
        raise AuthSetupFailed(
            "Profile auth cần ZAP_AUTH_USER và ZAP_AUTH_PASS trong .env. "
            "Tạo một tài khoản trên chính target lab của bạn rồi điền vào."
        )

    login_url = os.getenv("ZAP_LOGIN_URL", container_url.rstrip("/") + DEFAULT_LOGIN_PATH)
    body = os.getenv("ZAP_LOGIN_BODY", DEFAULT_LOGIN_BODY)
    if "'" in body:
        raise AuthSetupFailed("ZAP_LOGIN_BODY không được chứa dấu nháy đơn (vỡ YAML).")

    check_path = os.getenv("ZAP_AUTH_CHECK_PATH", DEFAULT_CHECK_PATH)
    _verify_login(container_url, login_url, body, user, password, check_path)

    plan = PLAN_TEMPLATE.read_text(encoding="utf-8")
    for key, val in (("{{TARGET}}", container_url.rstrip("/")),
                     ("{{CHECK_PATH}}", check_path),
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
