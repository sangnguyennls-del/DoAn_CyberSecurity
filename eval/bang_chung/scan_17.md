# Bằng chứng kiểm chứng: lần quét #17 (http://localhost:8080)

Thu lúc 2026-09-19 12:50 bằng `python -m eval.evidence 17`.

**File này chỉ ghi dữ kiện, không có kết luận.** Quyết định 1/0 là của người gán,
theo hai câu hỏi trong `HUONG_DAN_GAN_NHAN.md`. Mỗi mục ghi lệnh đã chạy để tự chạy lại được.

Trạng thái lab lúc kiểm (đối chiếu với lúc quét):

    HTTP/1.1 200 OK
    Server: nginx

Tìm dòng tương ứng trong `ground_truth.csv` bằng fingerprint (Ctrl+F).

---

## Dòng 6: CSP: Wildcard Directive

`bd364b5981d4a74c` · zap · scanner xếp Medium
· url `` http://localhost:8080 `` · scanner ghi: `` default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số khối <style> nội tuyến: 2, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx
  date: Sat, 19 Sep 2026 05:50:18 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
  content-security-policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
  cross-origin-opener-policy: same-origin
  referrer-policy: strict-origin-when-cross-origin
  cross-origin-embedder-policy-report-only: require-corp
  permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()
```

---

## Dòng 7: CSP: style-src unsafe-inline

`5132a7b22008654d` · zap · scanner xếp Medium
· url `` http://localhost:8080 `` · scanner ghi: `` default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số khối <style> nội tuyến: 2, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx
  date: Sat, 19 Sep 2026 05:50:18 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
  content-security-policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
  cross-origin-opener-policy: same-origin
  referrer-policy: strict-origin-when-cross-origin
  cross-origin-embedder-policy-report-only: require-corp
  permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()
```

---

## Dòng 9: Cross-Origin-Resource-Policy Header Missing or Invalid

`33d01535b2682e2c` · zap · scanner xếp Low
· url `` http://localhost:8080/assets/public/favicon_js.ico `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080/assets/public/favicon_js.ico
HTTP/1.1 200 OK
  Cross-Origin-Resource-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: nginx
  date: Sat, 19 Sep 2026 05:50:19 GMT
  content-type: image/x-icon
  content-length: 15086
  connection: keep-alive
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Tue, 11 Aug 2026 05:21:02 GMT
  etag: W/"3aee-19fef445a30"
  vary: Accept-Encoding
  content-security-policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
  cross-origin-opener-policy: same-origin
  referrer-policy: strict-origin-when-cross-origin
  cross-origin-embedder-policy-report-only: require-corp
  permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()
```
