# Bằng chứng kiểm chứng: lần quét #20 (http://localhost:5000)

Thu lúc 2026-09-19 09:58 bằng `python -m eval.evidence 20`.

**File này chỉ ghi dữ kiện, không có kết luận.** Quyết định 1/0 là của người gán,
theo hai câu hỏi trong `HUONG_DAN_GAN_NHAN.md`. Mỗi mục ghi lệnh đã chạy để tự chạy lại được.

Trạng thái lab lúc kiểm (đối chiếu với lúc quét):

    HTTP/1.1 200 OK
    Server: Werkzeug/3.1.8 Python/3.14.3

Tìm dòng tương ứng trong `ground_truth.csv` bằng fingerprint (Ctrl+F).

---

## Dòng 2: Cross Site Scripting (DOM Based)

`f115fea0b888d86b` · zap · scanner xếp High
· url `` http://localhost:5000#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e `` · scanner ghi: `` (trống) ``

```text
URL scanner báo: http://localhost:5000#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e
  vị trí payload trong URL: sau dấu #
$ curl.exe -s http://localhost:5000/
  số thẻ <script> trong trang: 0
  số thuộc tính on...= (onclick, onload...): 0
  HTML trang (400 ký tự đầu):
  <!doctype html><html lang="vi"><head><meta charset="utf-8"> <title>Lab App - co lo hong</title> <style>body{font:15px system-ui;margin:40px;max-width:680px} input{padding:6px} .box{background:#f1f5f9;padding:12px;border-radius:6px}</style> </head><body> <h1>Ứng dụng lab (cố ý có lỗ hổng)</h1> <p>Target để thử bản vá do AI đề xuất. Chỉ chạy trên máy cá nhân.</p> <form action="/search"><label>Tìm us
```

---

## Dòng 3: Cross Site Scripting (Reflected)

`eedfc930990ff5db` · zap · scanner xếp High
· url `` http://localhost:5000/greet?name=%3C%2Fdiv%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cdiv%3E `` · scanner ghi: `` alert(1); ``

```text
$ curl.exe -s "http://localhost:5000/greet?name=%3C%2Fdiv%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cdiv%3E"
  payload scanner gửi: </div><scrIpt>alert(1);</scRipt><div>
  payload có xuất hiện NGUYÊN VĂN trong HTML trả về: Có
  đoạn HTML quanh chữ alert: ào</button></form>
<div class="box">Xin chào, </div><scrIpt>alert(1);</scRipt><div>!</div>
</body></html>
```

---

## Dòng 4: SQL Injection

`48af800c6ef141e9` · zap · scanner xếp High
· url `` http://localhost:5000/search?q=%27 `` · scanner ghi: `` HTTP/1.1 500 INTERNAL SERVER ERROR ``

```text
$ curl.exe -s "http://localhost:5000/search?q=%27"
  Lỗi SQL: unrecognized token: "'" Câu truy vấn: SELECT username, email, role FROM users WHERE username LIKE '%'%'
  [HTTP 500]
$ curl.exe -s "http://localhost:5000/search?q=%27%20OR%20%271%27=%271"
  an - an@lab.local (user) binh - binh@lab.local (user) admin - admin@lab.local (admin)
  [HTTP 200]
$ curl.exe -s "http://localhost:5000/search?q=an"
  an - an@lab.local (user)
  [HTTP 200]
```

---

## Dòng 5: Content Security Policy (CSP) Header Not Set

`a54ebc2138274d36` · zap · scanner xếp Medium
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:34 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 6: Missing Anti-clickjacking Header

`b9ea364b5ae65b74` · zap · scanner xếp Medium
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  X-Frame-Options: KHÔNG CÓ
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:35 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 7: Cross-Origin-Embedder-Policy Header Missing or Invalid

`889c3ba9a63fe998` · zap · scanner xếp Low
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  Cross-Origin-Embedder-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:35 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 8: Cross-Origin-Opener-Policy Header Missing or Invalid

`c3b6263e6ca8324c` · zap · scanner xếp Low
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  Cross-Origin-Opener-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:36 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 9: Cross-Origin-Resource-Policy Header Missing or Invalid

`33d01535b2682e2c` · zap · scanner xếp Low
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  Cross-Origin-Resource-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:36 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 10: Permissions Policy Header Not Set

`2510e61da8ca4b12` · zap · scanner xếp Low
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  Permissions-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:36 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 11: Server Leaks Version Information via "Server" HTTP Response Header Field

`24b56a2622b70091` · zap · scanner xếp Low
· url `` http://localhost:5000 `` · scanner ghi: `` Werkzeug/3.1.8 Python/3.14.3 ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  Server: Werkzeug/3.1.8 Python/3.14.3
  X-Powered-By: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:37 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 12: X-Content-Type-Options Header Missing

`d3c767640d5a5a30` · zap · scanner xếp Low
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  X-Content-Type-Options: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:37 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 13: OPTIONS: Allowed HTTP Methods: HEAD, GET, OPTIONS .

`a7324a6bf6bd367c` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` OPTIONS / ``

```text
$ curl.exe -s -i -X OPTIONS http://localhost:5000/
  HTTP/1.1 200 OK
  Allow: GET, HEAD, OPTIONS
```

---

## Dòng 14: Storable and Cacheable Content

`f269ec0a9180a152` · zap · scanner xếp Info
· url `` http://localhost:5000 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  cache-control: KHÔNG CÓ
  pragma: KHÔNG CÓ
  expires: KHÔNG CÓ
  etag: KHÔNG CÓ
  last-modified: KHÔNG CÓ
  content-type: text/html; charset=utf-8
Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):
  Lab App - co lo hong Ứng dụng lab (cố ý có lỗ hổng) Target để thử bản vá do AI đề xuất. Chỉ chạy trên máy cá nhân. Tìm user: Tìm Tên bạn: Chào Nhập gì
```

---

## Dòng 15: Suggested security header missing: content-security-policy.

`eab9b629d8846b93` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000/
HTTP/1.1 200 OK
  content-security-policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:39 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 16: Suggested security header missing: permissions-policy.

`62dbd3c2387d9dbe` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000/
HTTP/1.1 200 OK
  permissions-policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:39 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 17: Suggested security header missing: referrer-policy.

`97ad98b15735eb7e` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000/
HTTP/1.1 200 OK
  referrer-policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:39 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 18: Suggested security header missing: strict-transport-security.

`1440e5e139576a18` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000/
HTTP/1.1 200 OK
  strict-transport-security: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:40 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 19: Suggested security header missing: x-content-type-options.

`000fd7aaee188a50` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000/
HTTP/1.1 200 OK
  x-content-type-options: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:40 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```

---

## Dòng 20: The X-Content-Type-Options header is not set. This could allow the user agent to render th

`ab41431c0d7c6600` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000/
HTTP/1.1 200 OK
  X-Content-Type-Options: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: Werkzeug/3.1.8 Python/3.14.3
  date: Sat, 19 Sep 2026 02:58:41 GMT
  content-type: text/html; charset=utf-8
  content-length: 697
  connection: close
```
