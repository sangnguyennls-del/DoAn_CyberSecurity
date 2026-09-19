"""Gom bằng chứng kiểm chứng cho các dòng CHƯA gán nhãn của một lần quét.

    python -m eval.evidence <scan_id>     ->  eval/bang_chung/scan_<id>.md

Chạy các lệnh kiểm trong eval/HUONG_DAN_GAN_NHAN.md (curl.exe, đúng như người gán
tự gõ) rồi ghi lại DỮ KIỆN: lệnh, mã HTTP, header có hay không, nội dung trả về.
KHÔNG ghi kết luận và KHÔNG đụng vào cột nhãn. Quyết định "có phải điểm yếu
không" vẫn là của người gán; script chỉ bỏ phần gõ lệnh.

Lab phải đang ở ĐÚNG trạng thái lúc quét (trước vá cho #9/#20, sau vá cho
#17/#21). Đầu file ghi lại banner Server lúc kiểm để đối chiếu được.
"""

from __future__ import annotations

import csv
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from core import db
from eval.export import OUT as GROUND_TRUTH

OUT_DIR = Path(__file__).parent / "bang_chung"
MISSING = "http://{host}/khong-ton-tai-xyz"
EVIL_ORIGIN = "http://ke-tan-cong.example"

# Tên finding -> header cần xem. Nikto "Suggested security header missing: X" tự suy.
HEADERS = {
    "Content Security Policy (CSP) Header Not Set": ["Content-Security-Policy"],
    "Missing Anti-clickjacking Header": ["X-Frame-Options", "Content-Security-Policy"],
    "Cross-Origin-Embedder-Policy Header Missing or Invalid": ["Cross-Origin-Embedder-Policy"],
    "Cross-Origin-Opener-Policy Header Missing or Invalid": ["Cross-Origin-Opener-Policy"],
    "Cross-Origin-Resource-Policy Header Missing or Invalid": ["Cross-Origin-Resource-Policy"],
    "Permissions Policy Header Not Set": ["Permissions-Policy"],
    "X-Content-Type-Options Header Missing": ["X-Content-Type-Options"],
    "Deprecated Feature Policy Header Set": ["Feature-Policy", "Permissions-Policy"],
    "The X-Content-Type-Options header is not set": ["X-Content-Type-Options"],
    "/:X-Frame-Options header is deprecated": ["X-Frame-Options", "Content-Security-Policy"],
    'Server Leaks Version Information via "Server"': ["Server", "X-Powered-By"],
}


def headers_for(name: str) -> list[str]:
    """Header cần xem cho một finding; [] nếu không thuộc nhóm header."""
    if name.startswith("CSP:"):  # ZAP: "CSP: Wildcard Directive", "CSP: style-src unsafe-inline"...
        return ["Content-Security-Policy"]
    m = re.search(r"header missing: ([\w-]+)", name, re.I)
    if m:
        return [m.group(1)]
    m = re.match(r"Uncommon header\(s\) '([^']+)'", name)
    if m:
        return [m.group(1)]
    return next((v for k, v in HEADERS.items() if name.startswith(k)), [])


# ------------------------------------------------------------------ curl

def curl(*args: str) -> str:
    r = subprocess.run(["curl.exe", "-s", "--max-time", "15", *args],
                       capture_output=True, timeout=30)
    return r.stdout.decode("utf-8", errors="replace")


def head(url: str, *extra: str) -> tuple[str, dict[str, str]]:
    """(dòng trạng thái, {tên header viết thường: giá trị})."""
    lines = curl("-D", "-", "-o", "NUL", *extra, url).splitlines()
    status = lines[0] if lines else "(không có phản hồi)"
    hs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hs.setdefault(k.strip().lower(), v.strip())
    return status, hs


def meta(url: str) -> str:
    return curl("-o", "NUL", "-w", "%{http_code} %{content_type} %{size_download}", url)


def text(html: str, n: int = 300) -> str:
    """Chữ người đọc thấy được: bỏ khối <style>/<script> trước, rồi mới bỏ thẻ."""
    html = re.sub(r"<(style|script)\b.*?</\1>", " ", html, flags=re.S | re.I)
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())[:n]


def around(body: str, needle: str, width: int = 80) -> str:
    i = body.find(needle)
    return "(không tìm thấy)" if i < 0 else body[max(0, i - width): i + len(needle) + width]


# ------------------------------------------------------------ từng loại

def check_headers(r: dict, names: list[str]) -> list[str]:
    url = r["url"]
    status, hs = head(url)
    out = [f"$ curl.exe -s -D - -o NUL {url}", status]
    for h in names:
        v = hs.get(h.lower())
        out.append(f"  {h}: {v if v is not None else 'KHÔNG CÓ'}")
    html = curl(url)
    hosts = sorted({h for h in re.findall(r'(?:src|href)=["\'](https?://[^"\'/]+)', html)
                    if urlsplit(h).netloc != urlsplit(url).netloc})
    out += ["Ngữ cảnh:",
            f"  giao thức: {urlsplit(url).scheme}",
            f"  số thẻ <script> trong HTML trả về: {len(re.findall(r'<script', html, re.I))}",
            f"  số khối <style> nội tuyến: {len(re.findall(r'<style', html, re.I))}, "
            f"số thuộc tính style=: {len(re.findall(r'\sstyle\s*=', html, re.I))}",
            f"  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): "
            f"{len(re.findall(r'<form', html, re.I))}",
            f"  tài nguyên từ origin khác trong HTML: {', '.join(hosts) or 'không có'}",
            "Toàn bộ header:"] + [f"  {k}: {v}" for k, v in hs.items()]
    return out


def check_cors(r: dict) -> list[str]:
    root = r["target"]
    out = []
    for url in (r["url"], root + "/rest/products/search?q="):
        status, hs = head(url, "-H", f"Origin: {EVIL_ORIGIN}")
        out += [f'$ curl.exe -s -D - -o NUL -H "Origin: {EVIL_ORIGIN}" {url}', status]
        out += [f"  {k}: {v}" for k, v in hs.items() if k.startswith("access-control")]
        out += ["  (không có header Access-Control-* nào)"] if not any(
            k.startswith("access-control") for k in hs) else []
    out += ["Nội dung /rest/products/search?q= (200 ký tự đầu):",
            "  " + curl(root + "/rest/products/search?q=")[:200]]
    return out


def check_cache(r: dict) -> list[str]:
    url = r["url"]
    status, hs = head(url)
    keep = ("cache-control", "pragma", "expires", "etag", "last-modified", "content-type")
    return ([f"$ curl.exe -s -D - -o NUL {url}", status]
            + [f"  {k}: {hs.get(k, 'KHÔNG CÓ')}" for k in keep]
            + ["Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):", "  " + text(curl(url), 150)])


def check_file(r: dict) -> list[str]:
    url = r["url"]
    missing = MISSING.format(host=urlsplit(url).netloc)
    fmt = '"%{http_code} %{content_type} %{size_download}"'
    return [f"$ curl.exe -s -o NUL -w {fmt} {url}", "  " + meta(url),
            f"$ curl.exe -s -o NUL -w {fmt} {missing}", "  " + meta(missing),
            "Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):", "  " + text(curl(url))]


def check_robots(r: dict) -> list[str]:
    root = r["target"]
    return ([f"$ curl.exe -s {root}/robots.txt"]
            + ["  " + line for line in curl(root + "/robots.txt").splitlines()]
            + [f"$ curl.exe -s {root}/ftp/", "  " + meta(root + "/ftp/"),
               "Nội dung /ftp/ (400 ký tự đầu, đã bỏ thẻ HTML):", "  " + text(curl(root + "/ftp/"), 400)])


def check_sqli(r: dict) -> list[str]:
    root = r["target"]
    out = []
    for q in ("%27", "%27%20OR%20%271%27=%271", "an"):
        url = f"{root}/search?q={q}"
        body = curl("-w", "\n[HTTP %{http_code}]", url)
        box = re.search(r'class="box">(.*?)</div>', body, re.S)
        out += [f'$ curl.exe -s "{url}"',
                "  " + (text(box.group(1), 300) if box else text(body, 200)),
                "  " + body.strip().splitlines()[-1]]
    return out


def check_xss_reflected(r: dict) -> list[str]:
    url = r["url"]
    payload = unquote(parse_qs(urlsplit(url).query, keep_blank_values=True).get("name", [""])[0])
    body = curl(url)
    return [f'$ curl.exe -s "{url}"',
            f"  payload scanner gửi: {payload}",
            f"  payload có xuất hiện NGUYÊN VĂN trong HTML trả về: {'Có' if payload and payload in body else 'Không'}",
            "  đoạn HTML quanh chữ alert: " + around(body, "alert", 60)]


def check_xss_dom(r: dict) -> list[str]:
    root = r["target"]
    html = curl(root + "/")
    return [f"URL scanner báo: {r['url']}",
            f"  vị trí payload trong URL: {'sau dấu #' if '#' in r['url'] else 'trong path/query'}",
            f"$ curl.exe -s {root}/",
            f"  số thẻ <script> trong trang: {len(re.findall(r'<script', html, re.I))}",
            f"  số thuộc tính on...= (onclick, onload...): {len(re.findall(r'\son[a-z]+\s*=', html, re.I))}",
            "  HTML trang (400 ký tự đầu):", "  " + " ".join(html.split())[:400]]


def check_options(r: dict) -> list[str]:
    url = r["url"]
    lines = curl("-i", "-X", "OPTIONS", url).splitlines()
    return ([f"$ curl.exe -s -i -X OPTIONS {url}", "  " + (lines[0] if lines else "(không có phản hồi)")]
            + ["  " + x for x in lines if x.lower().startswith("allow")])


def check_js(r: dict) -> list[str]:
    url = r["url"]
    js = curl(url)
    fns = sorted(set(re.findall(r"bypassSecurityTrust\w+", js)))
    out = [f"$ curl.exe -s {url}", f"  kích thước: {len(js)} ký tự"]
    for fn in fns:
        out.append(f"  {fn}: {js.count(fn + '(')} lần gọi")
    idx = [m.start() for m in re.finditer(r"bypassSecurityTrustHtml\(", js)][:3]
    out += ["Ba chỗ gọi bypassSecurityTrustHtml đầu tiên (±80 ký tự):"]
    out += [f"  …{js[max(0, i - 80): i + 110]}…" for i in idx]
    return out


def check_timestamp(r: dict) -> list[str]:
    url, ts = r["url"], r["evidence"].strip()
    body = curl(url)
    when = (datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
            if ts.isdigit() else "(không đổi được)")
    return [f"Con số scanner báo: {ts}  ->  {when} (UTC)",
            f"$ curl.exe -s {url}", "  đoạn quanh con số: " + around(body, ts, 70)]


def check_generic(r: dict) -> list[str]:
    url = r["url"]
    body = curl(url)
    return [f"$ curl.exe -s {url}", "  " + meta(url),
            f"  số thẻ <script>: {len(re.findall(r'<script', body, re.I))}",
            "  đoạn quanh bằng chứng scanner ghi: " + around(body, r["evidence"][:30], 80)]


def check(r: dict) -> list[str]:
    n = r["name"]
    if n == "SQL Injection":
        return check_sqli(r)
    if n.startswith("Cross Site Scripting (Reflected)"):
        return check_xss_reflected(r)
    if n.startswith("Cross Site Scripting (DOM"):
        return check_xss_dom(r)
    if "access-control-allow-origin" in n.lower() or n.startswith("Cross-Domain Misconfiguration"):
        return check_cors(r)
    if "Storable" in n:
        return check_cache(r)
    if n.startswith("OPTIONS:"):
        return check_options(r)
    if n.startswith("Dangerous JS"):
        return check_js(r)
    if n.startswith("Timestamp Disclosure"):
        return check_timestamp(r)
    if "robots.txt" in n or n.startswith("contains 1 entry"):
        return check_robots(r)
    if names := headers_for(n):
        return check_headers(r, names)
    if r["source"] == "nikto":
        return check_file(r)
    return check_generic(r)


# ------------------------------------------------------------------ main

def main(scan_id: int) -> int:
    conn = db.connect()
    scan = db.get_scan(conn, scan_id)
    if scan is None:
        sys.exit(f"Không có lần quét #{scan_id}.")
    target = scan["target"]
    fps = {f.fingerprint for f in db.get_findings(conn, scan_id)}

    with GROUND_TRUTH.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    todo = [(i, r) for i, r in enumerate(rows, start=2)
            if r["target"] == target and r["fingerprint"] in fps
            and not r["is_true_positive"].strip()]
    if not todo:
        sys.exit(f"Lần quét #{scan_id} không còn dòng nào chưa gán nhãn trong {GROUND_TRUTH.name}.")

    status, hs = head(target + "/")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [f"# Bằng chứng kiểm chứng: lần quét #{scan_id} ({target})", "",
           f"Thu lúc {now} bằng `python -m eval.evidence {scan_id}`.", "",
           "**File này chỉ ghi dữ kiện, không có kết luận.** Quyết định 1/0 là của người gán,",
           "theo hai câu hỏi trong `HUONG_DAN_GAN_NHAN.md`. Mỗi mục ghi lệnh đã chạy để tự chạy lại được.", "",
           "Trạng thái lab lúc kiểm (đối chiếu với lúc quét):", "",
           f"    {status}", f"    Server: {hs.get('server', 'KHÔNG CÓ')}", "",
           f"Tìm dòng tương ứng trong `{GROUND_TRUTH.name}` bằng fingerprint (Ctrl+F).", ""]
    for i, r in todo:
        print(f"  kiểm dòng {i}: {r['name'][:60]}", flush=True)
        out += ["---", "", f"## Dòng {i}: {r['name']}", "",
                f"`{r['fingerprint']}` · {r['source']} · scanner xếp {r['severity_scanner']}",
                # `` `` chịu được dấu ` nằm trong URL (payload XSS có)
                f"· url `` {r['url']} `` · scanner ghi: `` {r['evidence'] or '(trống)'} ``", "",
                "```text", *check(r), "```", ""]

    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / f"scan_{scan_id}.md"
    path.write_text("\n".join(out), encoding="utf-8")
    print(f"Đã ghi {path} ({len(todo)} dòng).")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Cách dùng: python -m eval.evidence <scan_id>")
    raise SystemExit(main(int(sys.argv[1])))
