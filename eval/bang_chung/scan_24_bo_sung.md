# Bằng chứng bổ sung: lần quét #24 (http://localhost:8090)

Thu ngày 2026-09-19, sau khi người gán đánh dấu 9 dòng "không thể kiểm chứng". **Chỉ ghi
dữ kiện, không có kết luận.** Quyết định 1/0 là của người gán.

## Trạng thái lab lúc kiểm

- Mọi trang của Mutillidae chuyển hướng sang `database-offline.php`, báo
  "Access denied for user 'admin'@'localhost'". Tài khoản MySQL mà
  `classes/MySQLHandler.php` dùng không còn trong `mysql.user`.
- MySQL có 94 database, phần lớn mang tên payload của ZAP (`"><script>alert(1);</script>`,
  `../../etc/passwd`, `() { :;}; /bin/sleep 15`...), tức active scan đã chạy lệnh SQL thật qua
  phpMyAdmin.
- phpMyAdmin 3.5.2.2 mở được mà không hỏi mật khẩu (curl không cookie vẫn nhận trang quản trị).

```text
$ curl.exe -s -o NUL -w "%{http_code} %{redirect_url}" "http://localhost:8090/index.php?page=home.php"
  302 http://localhost:8090/database-offline.php
$ docker exec mutillidae mysql -uroot -N -e "SELECT COUNT(*) FROM information_schema.SCHEMATA"
  94
```

## Cross Site Scripting (Persistent) - `fdb252661d23ae94`

Người gán mở URL trong trình duyệt: các tên database chứa payload hiện ra dưới dạng chữ,
không có hộp thoại nào bật lên. Đếm trong mã nguồn trả về:

```text
$ curl.exe -s "http://localhost:8090/phpmyadmin/server_databases.php?dbstats=1&pos=0&sort_by=SCHEMA_DATA_FREE&sort_order=desc&token=f3e66299f6885b76b07c9e8396c40f0d"
  kích thước 132747 ký tự
  payload                          dạng thô   dạng đã mã hoá HTML
  <scrIpt>alert(1);</scRipt>          0             30
  <script>alert(1);</script>          0             12
  <img src=x onerror=prompt()>        0             36
  onMouseOver="alert(1);              0              6
$ curl.exe -s "http://localhost:8090/phpmyadmin/navigation.php?token=f3e66299f6885b76b07c9e8396c40f0d"
  kích thước 24807 ký tự; dạng thô 0, dạng đã mã hoá 13
```

## Cross Site Scripting (Reflected) - `eedfc930990ff5db`

ZAP báo tham số `dbstats=;alert(1)` được phản chiếu. Người gán xem mã nguồn (Ctrl+U) thấy 72
kết quả cho `alert(1)`.

> **ĐÍNH CHÍNH (thu lần 2).** Lần thử đầu bên dưới dùng token phiên của ZAP (`f3e66…`) trong
> một phiên khác. Token không khớp thì phpMyAdmin bỏ tham số trên URL, nên kết quả
> "đánh dấu 0 lần, ô ẩn value=0" là do tham số bị bỏ, **không** chứng minh `dbstats` không
> được phản chiếu. Nhãn `0 FP-sai` của dòng này được gán khi chỉ có kết quả lần đầu.
> Kết quả đúng là lần 2, với phiên và token hợp lệ.

Lần 2, phiên hợp lệ (lấy cookie + token từ `/phpmyadmin/index.php`, rồi gọi với token đó):

```text
[dbstats=zzdanhdau123]  chuỗi đánh dấu xuất hiện: 1 lần; ô ẩn dbstats: value="1"
  vị trí: <input type="hidden" name="return_url" value="server_databases.php?dbstats=zzdanhdau123&amp;token=...
[dbstats=zz%22%3C%3Edd] (thử ký tự " < >)
  vị trí: <input type="hidden" name="return_url" value="server_databases.php?dbstats=zz%22%3C%3Edd&amp;token=...
  -> " < > vẫn ở dạng mã hoá URL (%22 %3C %3E) trong giá trị thuộc tính, không thành ký tự thô
[dbstats=zzdanhdau123, token của ZAP]  ô ẩn dbstats: value="0"   (tham số bị bỏ)
```

Dòng Persistent thu lại với phiên hợp lệ (URL của ZAP, dbstats=1, có cột thống kê): 0 dạng
thô, 84 dạng đã mã hoá - không đổi so với lần đầu.

Lần 1 (token của ZAP, **không hợp lệ**, giữ lại để đối chiếu):

```text
$ curl.exe -s "http://localhost:8090/phpmyadmin/server_databases.php?checkall=1&sort_by=SCHEMA_NAME&sort_order=asc&token=f3e66299f6885b76b07c9e8396c40f0d&dbstats=zzdanhdau123"
  chuỗi zzdanhdau123 xuất hiện: 0 lần
  ô ẩn dbstats: name="dbstats" value="0"
  alert(1) vẫn xuất hiện: 72 lần (URL này không hề chứa alert(1))
$ (cùng URL, dbstats=%3Balert%281%29 như ZAP gửi)
  ô ẩn dbstats: name="dbstats" value="0"
  alert(1): 72 lần, nằm trên 12 dòng, cả 12 đều là dòng liệt kê database (selected_dbs[] / openDb)
```

Trong danh sách database có một database tên đúng là `;alert(1)` (chuỗi ZAP ghi làm bằng
chứng), cùng các database khác chứa `alert(1)` do ZAP tạo ở bước quét chủ động.

## Cookie Poisoning - `3068752dff660398`

ZAP báo giá trị tham số `set_theme` xuất hiện trong cookie. Thu với phiên và token hợp lệ
(lấy từ `/phpmyadmin/index.php`), xem header `Set-Cookie` của phản hồi:

```text
[index.php?set_theme=original&token=...]  Set-Cookie: pma_theme=original; ...; path=/phpmyadmin/; httponly
[index.php?set_theme=zzmark1&token=...]   Set-Cookie: pma_theme=original; ...; path=/phpmyadmin/; httponly
```

- `original` là tên một theme có thật; giá trị ZAP gửi chính là `original`.
- Chuỗi đánh dấu `zzmark1` không xuất hiện trong cookie; cookie giữ theme hợp lệ `original`.

Người gán kiểm lại trên trình duyệt (phiên riêng, token của trình duyệt), DevTools → Network →
Response Headers:

```text
[index.php?set_theme=zzmark1]   trang báo "Theme zzmark1 not found!"; phản hồi KHÔNG có Set-Cookie
[index.php?set_theme=zz%3Bmark2] trang báo "Theme zz;mark2 not found!"; phản hồi KHÔNG có Set-Cookie
```

## User Controllable Charset - `31de4352d2238277`

ZAP không ghi tham số nào điều khiển charset. Người gán thử tham số khả nghi `charset_of_file`
trên trình duyệt (phiên riêng, token của trình duyệt), xem mã nguồn:

```text
[view-source: import.php?charset_of_file=zzmark1&token=...]
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  nội dung: "import.php: Missing parameter: import_type ... import.php: Missing parameter: format"
  chuỗi zzmark1 trong mã nguồn: 0 lần
```

Giới hạn của lần thử: trang dừng sớm vì thiếu tham số bắt buộc (`import_type`, `format`), nên
lần thử này không cho biết charset có bị điều khiển trong một lần import đầy đủ hay không.

## Dangerous JS Functions - `03fb900d860642b2`

ZAP đếm 7 chỗ trên 3 file (`functions.js`, `gis_data_editor.js`, `jquery-ui-1.8.16.custom.js`).
Người gán chụp hai chỗ `eval(` trong `functions.js`; đoạn code phía trước mỗi chỗ:

```text
$ curl.exe -s "http://localhost:8090/phpmyadmin/js/functions.js?ts=1526333067"
  số chỗ gọi eval( trong functions.js: 2

  (1) function goToUrl(a,b){eval("document.location.href = '"+b+"pos="+a.options[a.selectedIndex].value+"'")}
      -> chuỗi đem eval ghép từ tham số b và giá trị <option> đang chọn của ô <select> a

  (2) h=$(".callback",this).text(); ...
      $.post(k,{ajax_request:true},function(m){if(m.success==true){ ... eval(h)} else {PMA_ajaxShowMessage(m.error,false); ...
      -> h là nội dung chữ của phần tử class "callback" nằm trong nút bật/tắt trên trang;
         chỉ được eval khi yêu cầu AJAX tới máy chủ trả success
```

Chưa kiểm hai file còn lại.

## User Controllable HTML Element Attribute (Potential XSS) - `c7648d9a06688ec0`

Người gán xem mã nguồn trên trình duyệt (phiên riêng, token của trình duyệt):

```text
[view-source: main.php?collation_connection=zzmark1&lang=en&token=...]  zzmark1: 2 lần
  dòng 8:  <code>#1273 - Unknown collation: 'zzmark1'</code>            (chữ trong HTML)
  dòng 15: window.parent.setAll('en', 'zzmark1', '1', '', '', '<token>');  (chuỗi JavaScript nháy đơn)
[view-source: main.php?collation_connection=zz"mark2&lang=en&token=...]  (dấu " gửi qua URL)
  dòng 8:  Unknown collation: 'zz&quot;mark2'      -> " thành &quot; (mã hoá HTML)
  dòng 15: setAll('en', 'zz\"mark2', ...)          -> " thành \" trong chuỗi JavaScript
```

- Với giá trị không hợp lệ, trang trả lỗi "Unknown collation"; trong trang lỗi này giá trị nằm
  ở chữ HTML và chuỗi JavaScript, không thấy trong thuộc tính HTML nào.
- ZAP đếm 10 chỗ với giá trị hợp lệ `utf8_general_ci`; trang lỗi ở trên không cho thấy các
  chỗ đó. Chưa thử ký tự nháy đơn trong chuỗi JavaScript.

## SQL Injection - MySQL (Time Based) - `a740905d7f6c81c9`

```text
[cửa sổ InPrivate, không cookie] http://localhost:8090/phpmyadmin/
  -> vào thẳng trang quản trị, KHÔNG hỏi mật khẩu; "User: root@localhost"
  -> trang tự cảnh báo: "Your configuration file contains settings (root with no password) ...
     open to intrusion"
```

Cùng với 94 database do ZAP tạo (mục đầu file): SQL gửi qua phpMyAdmin đã được thực thi.
`import.php?sql_query=` là tính năng chạy câu SQL của phpMyAdmin.

## SQL Injection - `48af800c6ef141e9`

ZAP ghi bằng chứng "You have an error in your SQL syntax", đếm 6 chỗ trên 3 URL (`main.php` với
`target=`, `main.php` với `token=`, `import.php`). Người gán so hai trang trên trình duyệt
(phiên riêng, token của trình duyệt), tìm "SQL syntax":

```text
Lần 1 (BỊ NHIỄU, không dùng): cả trang A và B đều báo "#1273 - Unknown collation: 'zz"mark2'"
  -> giá trị collation từ lần thử dòng 66 còn lưu trong phiên; lỗi này có trước khi xử lý target.

Lần 2, sau khi đặt lại collation_connection=utf8_general_ci:
  [A] main.php?target=chk_rel.php&token=...                  trang chính bình thường; "SQL syntax" 0/0
  [B] main.php?target=chk_rel.php+AND+1%3D1+--+&token=...    trang chính bình thường; "SQL syntax" 0/0
  -> hai trang giống nhau; không tái hiện được chuỗi lỗi ZAP ghi
```

Chỉ kiểm URL đầu tiên trong 3 URL ZAP báo.

## Sau khi chốt nhãn: dựng lại container (19/09)

Container cũ bị xoá, tạo lại từ image `citizenstig/nowasp` (`-p 127.0.0.1:8090:80`), khởi tạo DB
bằng `set-up-database.php`:

```text
container khởi động:           2026-09-19T15:02:49Z
classes/MySQLHandler.php sửa:  2026-09-19 15:02:55 +0000   (6 giây sau khi khởi động)
set-up-database.php:           "Connected to MySQL server at 127.0.0.1 as admin"
index.php?page=home.php:       200 (không còn chuyển sang database-offline.php)
số database trong MySQL:       4
```

- Script khởi động của image tự ghi lại `MySQLHandler.php` và dùng tài khoản MySQL `admin`. Ở
  container cũ, file này có mốc sửa 07:38:54, tức 49 giây trước khi lần quét #23 bắt đầu; mốc đó
  là lúc container cũ khởi động, không phải một lần sửa tay.
- Tài khoản `admin` là tài khoản gốc của image. Nó biến mất ở container cũ sau khi khởi động;
  nguyên nhân vẫn chưa xác định.
