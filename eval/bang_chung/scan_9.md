# Bằng chứng kiểm chứng: lần quét #9 (http://localhost:8080)

Thu lúc 2026-09-19 09:58 bằng `python -m eval.evidence 9`.

**File này chỉ ghi dữ kiện, không có kết luận.** Quyết định 1/0 là của người gán,
theo hai câu hỏi trong `HUONG_DAN_GAN_NHAN.md`. Mỗi mục ghi lệnh đã chạy để tự chạy lại được.

Trạng thái lab lúc kiểm (đối chiếu với lúc quét):

    HTTP/1.1 200 OK
    Server: nginx/1.31.5

Tìm dòng tương ứng trong `ground_truth.csv` bằng fingerprint (Ctrl+F).

---

## Dòng 21: Content Security Policy (CSP) Header Not Set

`a54ebc2138274d36` · zap · scanner xếp Medium
· url `` http://localhost:8080 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:58:41 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 22: Cross-Domain Misconfiguration

`9c4d9003d2bd54fa` · zap · scanner xếp Medium
· url `` http://localhost:8080 `` · scanner ghi: `` Access-Control-Allow-Origin: * ``

```text
$ curl.exe -s -D - -o NUL -H "Origin: http://ke-tan-cong.example" http://localhost:8080
HTTP/1.1 200 OK
  access-control-allow-origin: *
$ curl.exe -s -D - -o NUL -H "Origin: http://ke-tan-cong.example" http://localhost:8080/rest/products/search?q=
HTTP/1.1 200 OK
  access-control-allow-origin: *
Nội dung /rest/products/search?q= (200 ký tự đầu):
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-09-19 02:28:42.920 +
```

---

## Dòng 23: Cross-Origin-Embedder-Policy Header Missing or Invalid

`889c3ba9a63fe998` · zap · scanner xếp Low
· url `` http://localhost:8080 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  Cross-Origin-Embedder-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:58:41 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 24: Cross-Origin-Opener-Policy Header Missing or Invalid

`c3b6263e6ca8324c` · zap · scanner xếp Low
· url `` http://localhost:8080 `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  Cross-Origin-Opener-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:58:41 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 25: Dangerous JS Functions

`03fb900d860642b2` · zap · scanner xếp Low
· url `` http://localhost:8080/main.js `` · scanner ghi: `` bypassSecurityTrustHtml( ``

```text
$ curl.exe -s http://localhost:8080/main.js
  kích thước: 1206999 ký tự
  bypassSecurityTrustHtml: 8 lần gọi
  bypassSecurityTrustUrl: 2 lần gọi
Ba chỗ gọi bypassSecurityTrustHtml đầu tiên (±80 ký tự):
  …derService.find(this.orderId).subscribe(e=>{this.results.orderNo=this.sanitizer.bypassSecurityTrustHtml(`<code>${e.data[0].orderId}</code>`),this.results.email=e.data[0].email,this.results.t…
  …roductDescription(e){for(let i=0;i<e.length;i++)e[i].description=this.sanitizer.bypassSecurityTrustHtml(e[i].description)}ngOnDestroy(){this.routerSubscription&&this.routerSubscription.unsub…
  …ge`,e)}),this.dataSource.filter=e.toLowerCase(),this.searchValue=this.sanitizer.bypassSecurityTrustHtml(e),this.gridDataSourceSubscription&&this.gridDataSourceSubscription.unsubscribe(),this…
```

---

## Dòng 26: Deprecated Feature Policy Header Set

`abdf50e893132521` · zap · scanner xếp Low
· url `` http://localhost:8080 `` · scanner ghi: `` Feature-Policy ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  Feature-Policy: payment 'self'
  Permissions-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:58:42 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 27: Server Leaks Version Information via "Server" HTTP Response Header Field

`24b56a2622b70091` · zap · scanner xếp Low
· url `` http://localhost:8080 `` · scanner ghi: `` nginx/1.31.5 ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  Server: nginx/1.31.5
  X-Powered-By: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:58:42 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 28: Timestamp Disclosure - Unix

`20e49727388c7a0b` · zap · scanner xếp Low
· url `` http://localhost:8080/styles.css `` · scanner ghi: `` 1528301887 ``

```text
Con số scanner báo: 1528301887  ->  2018-06-06T16:18:07+00:00 (UTC)
$ curl.exe -s http://localhost:8080/styles.css
  đoạn quanh con số: 075471698, 38.2924528302, 38.2924528302);--theme-warn-darker: rgb(159.1528301887, 22.2471698113, 22.2471698113);--theme-warn-dark: rgb(141.2547169811,
```

---

## Dòng 29: /:X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy H

`4f53a6e974bae9cd` · nikto · scanner xếp Info
· url `` http://localhost:8080/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080/
HTTP/1.1 200 OK
  X-Frame-Options: SAMEORIGIN
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:58:42 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 30: /robots.txt: Entry '/ftp/' is returned a non-forbidden or redirect HTTP code (200).

`2482290b247f05be` · nikto · scanner xếp Info
· url `` http://localhost:8080/ftp/ `` · scanner ghi: `` GET /ftp/ ``

```text
$ curl.exe -s http://localhost:8080/robots.txt
  User-agent: *
  Disallow: /ftp
$ curl.exe -s http://localhost:8080/ftp/
  200 text/html; charset=utf-8 11264
Nội dung /ftp/ (400 ký tự đầu, đã bỏ thẻ HTML):
  listing directory /ftp/ ~ / ftp / quarantine 8/11/2026 5:21:02 AM acquisitions.md 909 8/11/2026 5:21:02 AM announcement_encrypted.md 369237 8/11/2026 5:21:02 AM coupons_2013.md.bak 131 8/11/2026 5:21:02 AM eastere.gg 324 8/11/2026 5:21:02 AM encrypt.pyc 573 8/11/2026 5:21:02 AM incident-support.kdbx 3246 8/11/2026 5:21:02 AM legal.md 3047 9/19/2026 2:28:40 AM package-lock.json.bak 750353 8/11/2026
```

---

## Dòng 31: Contains authorization information.

`fad1e3ac9930c1fd` · nikto · scanner xếp Info
· url `` http://localhost:8080/.htpasswd `` · scanner ghi: `` GET /.htpasswd ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/.htpasswd
  200 text/html; charset=UTF-8 9393
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/khong-ton-tai-xyz
  200 text/html; charset=UTF-8 9393
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  OWASP Juice Shop
```

---

## Dòng 32: Modern Web Application

`90b531a64e9472ea` · zap · scanner xếp Info
· url `` http://localhost:8080 `` · scanner ghi: `` window.addEventListener("load", function(){ window.cookieconsent.initialise({ "palette": { "popup": { "background": "var(--theme-primary)", "text": "v ``

```text
$ curl.exe -s http://localhost:8080
  200 text/html; charset=UTF-8 9393
  số thẻ <script>: 4
  đoạn quanh bằng chứng scanner ghi: ="icon" type="image/x-icon" href="assets/public/favicon_js.ico">
  <script>
    window.addEventListener("load", function(){
      window.cookieconsent.initialise({
        "palette": {
     
```

---

## Dòng 33: Non-Storable Content

`09e0c4c02475faf5` · zap · scanner xếp Info
· url `` http://localhost:8080/ftp/encrypt.pyc `` · scanner ghi: `` 403 ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080/ftp/encrypt.pyc
HTTP/1.1 403 Forbidden
  cache-control: KHÔNG CÓ
  pragma: KHÔNG CÓ
  expires: KHÔNG CÓ
  etag: KHÔNG CÓ
  last-modified: KHÔNG CÓ
  content-type: text/html; charset=utf-8
Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):
  Error: Only .md and .pdf files are allowed! OWASP Juice Shop (Express ^4.22.1) 403 Error: Only .md and .pdf files are allowed! &nbsp; &nbsp;at verify 
```

---

## Dòng 34: Potentially interesting backup/cert file found. .

`1bf6ee6f5a671119` · nikto · scanner xếp Info
· url `` http://localhost:8080/hostdocker.tar `` · scanner ghi: `` HEAD /hostdocker.tar ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/hostdocker.tar
  200 text/html; charset=UTF-8 9393
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/khong-ton-tai-xyz
  200 text/html; charset=UTF-8 9393
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  OWASP Juice Shop
```

---

## Dòng 35: Retrieved access-control-allow-origin header: *.

`c0e6b9779987519b` · nikto · scanner xếp Info
· url `` http://localhost:8080/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL -H "Origin: http://ke-tan-cong.example" http://localhost:8080/
HTTP/1.1 200 OK
  access-control-allow-origin: *
$ curl.exe -s -D - -o NUL -H "Origin: http://ke-tan-cong.example" http://localhost:8080/rest/products/search?q=
HTTP/1.1 200 OK
  access-control-allow-origin: *
Nội dung /rest/products/search?q= (200 ký tự đầu):
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-09-19 02:28:42.920 +
```

---

## Dòng 36: Storable and Cacheable Content

`f269ec0a9180a152` · zap · scanner xếp Info
· url `` http://localhost:8080/robots.txt `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080/robots.txt
HTTP/1.1 200 OK
  cache-control: KHÔNG CÓ
  pragma: KHÔNG CÓ
  expires: KHÔNG CÓ
  etag: W/"1c-8HgF6mNyhsSFK0pascC9uB0wjX0"
  last-modified: KHÔNG CÓ
  content-type: text/plain; charset=utf-8
Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):
  User-agent: * Disallow: /ftp
```

---

## Dòng 37: Storable but Non-Cacheable Content

`eeeba1036fffb5ea` · zap · scanner xếp Info
· url `` http://localhost:8080 `` · scanner ghi: `` max-age=0 ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080
HTTP/1.1 200 OK
  cache-control: public, max-age=0
  pragma: KHÔNG CÓ
  expires: KHÔNG CÓ
  etag: W/"24b1-1a0b77ea450"
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  content-type: text/html; charset=UTF-8
Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):
  OWASP Juice Shop
```

---

## Dòng 38: Suggested security header missing: permissions-policy.

`69acf6cbff83068f` · nikto · scanner xếp Info
· url `` http://localhost:8080/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080/
HTTP/1.1 200 OK
  permissions-policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:58:54 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 39: This might be interesting.

`6292f0e186ae5409` · nikto · scanner xếp Info
· url `` http://localhost:8080/ftp/ `` · scanner ghi: `` GET /ftp/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/ftp/
  200 text/html; charset=utf-8 11264
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/khong-ton-tai-xyz
  200 text/html; charset=UTF-8 9393
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  listing directory /ftp/ ~ / ftp / quarantine 8/11/2026 5:21:02 AM acquisitions.md 909 8/11/2026 5:21:02 AM announcement_encrypted.md 369237 8/11/2026 5:21:02 AM coupons_2013.md.bak 131 8/11/2026 5:21:02 AM eastere.gg 324 8/11/2026 5:21:02 AM encrypt.pyc 573 8/11/2026 5:21:02 AM incident-support.kdbx
```

---

## Dòng 40: This might be interesting.

`b35dbe53f6e1a282` · nikto · scanner xếp Info
· url `` http://localhost:8080/public/ `` · scanner ghi: `` GET /public/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/public/
  200 text/html; charset=UTF-8 9393
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8080/khong-ton-tai-xyz
  200 text/html; charset=UTF-8 9393
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  OWASP Juice Shop
```

---

## Dòng 41: Uncommon header(s) 'x-recruiting' found, with contents: /#/jobs.

`e4078e690eee9b5d` · nikto · scanner xếp Info
· url `` http://localhost:8080/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8080/
HTTP/1.1 200 OK
  x-recruiting: /#/jobs
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: https://fonts.googleapis.com, https://fonts.gstatic.com
Toàn bộ header:
  server: nginx/1.31.5
  date: Sat, 19 Sep 2026 02:59:06 GMT
  content-type: text/html; charset=UTF-8
  content-length: 9393
  connection: keep-alive
  access-control-allow-origin: *
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  feature-policy: payment 'self'
  x-recruiting: /#/jobs
  accept-ranges: bytes
  cache-control: public, max-age=0
  last-modified: Sat, 19 Sep 2026 02:28:45 GMT
  etag: W/"24b1-1a0b77ea450"
  vary: Accept-Encoding
```

---

## Dòng 42: contains 1 entry which should be manually viewed.

`16cfa0418b62410a` · nikto · scanner xếp Info
· url `` http://localhost:8080/robots.txt `` · scanner ghi: `` GET /robots.txt ``

```text
$ curl.exe -s http://localhost:8080/robots.txt
  User-agent: *
  Disallow: /ftp
$ curl.exe -s http://localhost:8080/ftp/
  200 text/html; charset=utf-8 11264
Nội dung /ftp/ (400 ký tự đầu, đã bỏ thẻ HTML):
  listing directory /ftp/ ~ / ftp / quarantine 8/11/2026 5:21:02 AM acquisitions.md 909 8/11/2026 5:21:02 AM announcement_encrypted.md 369237 8/11/2026 5:21:02 AM coupons_2013.md.bak 131 8/11/2026 5:21:02 AM eastere.gg 324 8/11/2026 5:21:02 AM encrypt.pyc 573 8/11/2026 5:21:02 AM incident-support.kdbx 3246 8/11/2026 5:21:02 AM legal.md 3047 9/19/2026 2:28:40 AM package-lock.json.bak 750353 8/11/2026
```
