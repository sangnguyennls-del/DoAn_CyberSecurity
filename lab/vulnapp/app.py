"""Ứng dụng Flask lab - target để vá ở tầng CODE.

    python lab/vulnapp/app.py     ->  http://127.0.0.1:5000

Juice Shop không sửa được (code của người khác), nên nó chỉ chứng minh được AI vá
được CẤU HÌNH. File này là target thứ hai: lỗ hổng nằm ngay trong code.

CẢNH BÁO: Chỉ chạy trên máy cá nhân. Đã bind vào 127.0.0.1 nên máy khác trong mạng
không truy cập được - đừng đổi thành 0.0.0.0.

TRẠNG THÁI: bản ĐÃ VÁ theo `fix_snippet` Claude sinh ra cho lần quét #18.
Bản chưa vá (4 lỗ hổng cố ý) giữ ở app.py.chuava.bak. Tên finding sinh ra mỗi
thay đổi ghi ngay trong comment [..] bên cạnh. Chỗ nào nhóm phải chỉnh cho khớp
app thật thì ghi "CHỈNH:" - xem lab/KETQUA_VONG_LAP.md.
"""

import secrets
import sqlite3

# CHỈNH: snippet CSP của AI import thêm `escape` từ flask -> ImportError trên
# Flask 3.1.3 (đã bị gỡ từ 3.0). Snippet không dùng tới nó nên chỉ việc bỏ đi.
from flask import Flask, abort, g, render_template, request
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
# [Cross Site Scripting (Reflected)] - hardening cookie đi kèm
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

DB = ":memory:"
_conn = sqlite3.connect(DB, check_same_thread=False)
_conn.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT);
INSERT INTO users (username, email, role) VALUES
  ('an',  'an@lab.local',  'user'),
  ('binh','binh@lab.local','user'),
  ('admin','admin@lab.local','admin');
""")


# [OPTIONS: Allowed HTTP Methods] - tắt OPTIONS tự động ở route "/"
@app.route("/", methods=["GET"], provide_automatic_options=False)
def index():
    return render_template("page.html", message="Nhập gì đó vào một trong hai ô ở trên.")


@app.route("/search")
def search():
    # [SQL Injection] - truy vấn tham số hoá, giới hạn độ dài input
    # CHỈNH: AI không thấy mã nguồn nên đoán bảng `items(id, name, description)` và
    # template search.html; đổi sang bảng/cột thật của app này, giữ nguyên cách vá.
    q = (request.args.get("q") or "").strip()
    if len(q) > 100:
        abort(400)
    try:
        rows = _conn.execute(
            "SELECT username, email, role FROM users WHERE username LIKE ?",
            (f"%{q}%",),
        ).fetchall()
    except sqlite3.Error:
        # [SQL Injection] - log lỗi ra server, không trả chi tiết cho người dùng
        app.logger.exception("DB error on /search")
        abort(500)
    # [SQL Injection] - render_template (autoescape) thay vì nối chuỗi HTML
    return render_template("page.html", rows=rows)


@app.route("/greet")
def greet():
    # [Cross Site Scripting (Reflected)] - giới hạn độ dài, để Jinja2 tự escape
    # CHỈNH: AI đề xuất templates/greet.html; app này dùng chung page.html.
    name = (request.args.get("name") or "khách")[:80]
    return render_template("page.html", message=f"Xin chào, {name}!")


# [Content Security Policy (CSP) Header Not Set] - nonce cho script nội tuyến
@app.before_request
def gen_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.after_request
def set_security_headers(resp):
    # [Content Security Policy (CSP) Header Not Set]
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{g.csp_nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # [Missing Anti-clickjacking Header]
    resp.headers["X-Frame-Options"] = "DENY"
    # [Permissions Policy Header Not Set]
    resp.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
    )
    # [Cross-Origin-Opener-Policy Header Missing or Invalid]
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # [Cross-Origin-Embedder-Policy Header Missing or Invalid]
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    # [Cross-Origin-Resource-Policy Header Missing or Invalid]
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    # [Storable and Cacheable Content] - trang động: cấm lưu trữ
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


# [Server Leaks Version Information via "Server" HTTP Response Header Field]
# Cách 1 của AI: lab vẫn dùng dev server, chỉ bỏ chuỗi phiên bản.
class QuietHandler(WSGIRequestHandler):
    def version_string(self):
        return ""


if __name__ == "__main__":
    # 127.0.0.1: chỉ máy này truy cập được. debug=False: không lộ Werkzeug debugger.
    app.run(host="127.0.0.1", port=5000, debug=False, request_handler=QuietHandler)
