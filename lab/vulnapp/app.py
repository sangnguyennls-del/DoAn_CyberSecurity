"""Ứng dụng Flask CỐ Ý CÓ LỖ HỔNG - target lab để vá ở tầng CODE.

    python lab/vulnapp/app.py     ->  http://127.0.0.1:5000

Juice Shop không sửa được (code của người khác), nên nó chỉ chứng minh được AI vá
được CẤU HÌNH. File này là target thứ hai: bốn lỗ hổng nằm ngay trong code, vá được
bằng vài dòng, để chứng minh AI vá được cả CODE.

CẢNH BÁO: Chỉ chạy trên máy cá nhân. Đã bind vào 127.0.0.1 nên máy khác trong mạng
không truy cập được - đừng đổi thành 0.0.0.0.

Quy trình dùng file này:
  1. python lab/vulnapp/app.py
  2. python scan.py http://localhost:5000
  3. Đọc bản vá AI đề xuất trong báo cáo
  4. Sửa theo, đánh dấu lại bằng "ĐÃ VÁ"
  5. Quét lại rồi so sánh hai lần quét
"""

import sqlite3

from flask import Flask, Response, request

app = Flask(__name__)
DB = ":memory:"
_conn = sqlite3.connect(DB, check_same_thread=False)
_conn.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT);
INSERT INTO users (username, email, role) VALUES
  ('an',  'an@lab.local',  'user'),
  ('binh','binh@lab.local','user'),
  ('admin','admin@lab.local','admin');
""")

PAGE = """<!doctype html><html lang="vi"><head><meta charset="utf-8">
<title>Lab App - co lo hong</title>
<style>body{{font:15px system-ui;margin:40px;max-width:680px}}
input{{padding:6px}} .box{{background:#f1f5f9;padding:12px;border-radius:6px}}</style>
</head><body>
<h1>Ứng dụng lab (cố ý có lỗ hổng)</h1>
<p>Target để thử bản vá do AI đề xuất. Chỉ chạy trên máy cá nhân.</p>
<form action="/search"><label>Tìm user: <input name="q" value=""></label>
<button>Tìm</button></form>
<form action="/greet"><label>Tên bạn: <input name="name" value=""></label>
<button>Chào</button></form>
<div class="box">{body}</div>
</body></html>"""


@app.route("/")
def index():
    return PAGE.format(body="Nhập gì đó vào một trong hai ô ở trên.")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # LỖ HỔNG 1 - SQL Injection (CWE-89):
    # Ghép chuỗi thẳng vào câu truy vấn. Thử: /search?q=' OR '1'='1
    # Vá: dùng truy vấn tham số hoá -> "WHERE username LIKE ?" với (f"%{q}%",)
    sql = f"SELECT username, email, role FROM users WHERE username LIKE '%{q}%'"
    try:
        rows = _conn.execute(sql).fetchall()
    except sqlite3.Error as e:
        # LỖ HỔNG 2 - Lộ thông tin qua thông báo lỗi (CWE-209):
        # Trả câu SQL và lỗi gốc về cho người dùng -> giúp kẻ tấn công dò cấu trúc DB.
        # Vá: log lỗi ra server, trả về cho người dùng một câu chung chung.
        return PAGE.format(body=f"Lỗi SQL: {e}<br>Câu truy vấn: {sql}"), 500

    body = "<br>".join(f"{r[0]} - {r[1]} ({r[2]})" for r in rows) or "Không tìm thấy."
    return PAGE.format(body=body)


@app.route("/greet")
def greet():
    name = request.args.get("name", "khách")
    # LỖ HỔNG 3 - Reflected XSS (CWE-79):
    # Nhúng thẳng dữ liệu người dùng vào HTML. Thử: /greet?name=<script>alert(1)</script>
    # Vá: escape trước khi nhúng -> html.escape(name), hoặc dùng template Jinja2
    #      (Jinja2 tự escape), tuyệt đối không nối chuỗi HTML bằng tay.
    return PAGE.format(body=f"Xin chào, {name}!")


@app.after_request
def add_headers(resp: Response) -> Response:
    # LỖ HỔNG 4 - Thiếu security header (CWE-693):
    # Không có Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
    # Referrer-Policy. Đây chính là nhóm lỗi mà ZAP báo nhiều nhất.
    # Vá: thêm các header vào đây, ví dụ
    #     resp.headers["Content-Security-Policy"] = "default-src 'self'"
    #     resp.headers["X-Content-Type-Options"] = "nosniff"
    #     resp.headers["X-Frame-Options"] = "DENY"
    #     resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


if __name__ == "__main__":
    # 127.0.0.1: chỉ máy này truy cập được. debug=False: không lộ Werkzeug debugger.
    app.run(host="127.0.0.1", port=5000, debug=False)
