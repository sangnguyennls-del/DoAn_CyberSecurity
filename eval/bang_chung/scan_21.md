# Bằng chứng kiểm chứng: lần quét #21 (http://localhost:5000)

Thu lúc 2026-09-19 12:49 bằng `python -m eval.evidence 21`.

**File này chỉ ghi dữ kiện, không có kết luận.** Quyết định 1/0 là của người gán,
theo hai câu hỏi trong `HUONG_DAN_GAN_NHAN.md`. Mỗi mục ghi lệnh đã chạy để tự chạy lại được.

Trạng thái lab lúc kiểm (đối chiếu với lúc quét):

    HTTP/1.1 200 OK
    Server: 

Tìm dòng tương ứng trong `ground_truth.csv` bằng fingerprint (Ctrl+F).

---

## Dòng 2: /:X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy H

`4f53a6e974bae9cd` · nikto · scanner xếp Info
· url `` http://localhost:5000/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000/
HTTP/1.1 200 OK
  X-Frame-Options: DENY
  Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-mIe42WTcgYmZOxoMAgUorw'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 2
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  server: 
  date: Sat, 19 Sep 2026 05:49:47 GMT
  content-type: text/html; charset=utf-8
  content-length: 698
  content-security-policy: default-src 'self'; script-src 'self' 'nonce-mIe42WTcgYmZOxoMAgUorw'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'
  x-content-type-options: nosniff
  referrer-policy: strict-origin-when-cross-origin
  x-frame-options: DENY
  permissions-policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
  cross-origin-opener-policy: same-origin
  cross-origin-embedder-policy: require-corp
  cross-origin-resource-policy: same-origin
  cache-control: no-store, no-cache, must-revalidate, private
  pragma: no-cache
  expires: 0
  connection: close
```

---

## Dòng 3: Non-Storable Content

`09e0c4c02475faf5` · zap · scanner xếp Info
· url `` http://localhost:5000 `` · scanner ghi: `` no-store ``

```text
$ curl.exe -s -D - -o NUL http://localhost:5000
HTTP/1.1 200 OK
  cache-control: no-store, no-cache, must-revalidate, private
  pragma: no-cache
  expires: 0
  etag: KHÔNG CÓ
  last-modified: KHÔNG CÓ
  content-type: text/html; charset=utf-8
Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):
  Lab App - da va Ứng dụng lab (đã vá theo đề xuất AI) Target để thử bản vá do AI đề xuất. Chỉ chạy trên máy cá nhân. Tìm user: Tìm Tên bạn: Chào Nhập g
```
