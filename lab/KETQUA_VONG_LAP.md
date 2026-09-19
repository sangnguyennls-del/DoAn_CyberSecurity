# Vòng lặp vá → quét lại

Hai target, hai tầng vá. Ở cả hai, bản vá lấy từ trường `fix_snippet` do Claude sinh
ra; mỗi dòng trong file đã vá ghi tên finding sinh ra nó để đối chiếu với báo cáo.

| Target | Tầng vá | Trước vá | Sau vá | Đã vá | Mới xuất hiện | Còn tồn tại |
|---|---|---|---|---|---|---|
| nginx trước Juice Shop, `:8080` | cấu hình | #9: 22 | #17: 16 | 9 | 3 | 13 |
| vulnapp Flask, `:5000` | code | #20: 19 | #21: 4 | 17 | 2 | 2 |

```
python scan.py --compare 9 17
python scan.py --compare 20 21
```

---

## Phần 1. nginx, tầng cấu hình

Mục tiêu: `http://localhost:8080`, nginx reverse proxy đặt trước OWASP Juice Shop.
Vá ở tầng cấu hình vì Juice Shop là code của người khác, không sửa được.

| | Lần quét #9 (trước vá) | Lần quét #17 (sau vá) |
|---|---|---|
| Nikto, số lần xuất hiện thô | 152 | 117 |
| ZAP, số lần xuất hiện thô | 48 | 41 |
| Tổng thô | 200 | 158 |
| Sau gom trùng | **22** | **16** |
| Banner Server | `nginx/1.31.5` | `nginx` |

(Log lúc chạy in ra "ZAP: 10 phát hiện thô" vì đếm số cảnh báo trong file JSON,
còn bảng này đếm số lần xuất hiện thực tế sau khi trải các instance của mỗi cảnh
báo. Hai cách đếm khác nhau, số nào cũng dùng được miễn là nói rõ.)

Bản vá nằm ở `nginx/nginx.conf`, giữa hai mốc `>>> BẮT ĐẦU BẢN VÁ <<<` và
`>>> KẾT THÚC BẢN VÁ <<<`. Bản chưa vá giữ ở `nginx/nginx.conf.chuava.bak`.

### Bản vá này lấy từ đâu

Toàn bộ khối lệnh lấy từ `fix_snippet` của lần quét #9. Không có dòng nào nhóm tự
viết thêm. Chỗ duy nhất nhóm can thiệp là gom các đoạn rời của nhiều finding vào
một khối và bỏ phần trùng nhau.

Lần chạy đầu tiên mô hình vá sai tầng: nó trả về `helmet` của Express cho một mục
tiêu chạy nginx, vì prompt để nó tự đoán ngăn xếp. Sửa bằng cách quét banner
`Server` trên toàn bộ lần quét rồi đưa kết quả vào đầu mỗi lô yêu cầu. Sau khi
sửa, 4/4 finding sinh lại đều trả về `add_header`/`proxy_hide_header` của nginx.

### Kết quả

**Đã vá: 9**

| Mức | Nguồn | Lỗ hổng |
|---|---|---|
| Medium | zap | Content Security Policy (CSP) Header Not Set |
| Medium | zap | Cross-Domain Misconfiguration |
| Low | zap | Cross-Origin-Opener-Policy Header Missing or Invalid |
| Low | zap | Server Leaks Version Information via "Server" Header |
| Info | nikto | `/robots.txt`: Entry `/ftp/` trả về mã 200 |
| Info | nikto | Contains authorization information |
| Info | zap | Non-Storable Content |
| Info | nikto | Retrieved access-control-allow-origin header: `*` |
| Info | nikto | This might be interesting |

**Mới xuất hiện: 3, cả ba đều do chính bản vá gây ra**

| Lỗ hổng | Nguyên nhân |
|---|---|
| CSP: Wildcard Directive | CSP của AI có `img-src ... https:`, ZAP coi `https:` là wildcard |
| CSP: style-src unsafe-inline | CSP của AI tự đưa `'unsafe-inline'` vào `style-src` |
| Cross-Origin-Resource-Policy Header Missing | bật COEP kéo theo yêu cầu CORP, mà dòng CORP trong snippet lại đang bị comment |

**Còn tồn tại: 13.** Một dòng trong số đó che mất tiến triển thật: finding Nikto
"Suggested security header missing" đi từ x4 xuống x1 (chỉ còn HSTS), tức 3/4
header đã vá, nhưng lần quét này ghi trước khi có quy tắc tách theo tên header
(xem Phần 3) nên bảng so sánh xếp cả họ vào "còn tồn tại". Phía ZAP không bị ảnh
hưởng: CSP và các header khác vẫn nằm đúng ở cột "đã vá".

### Bản vá của AI sai ở đâu

Bốn lỗi đo được bằng `curl -D -` sau khi áp bản vá, không phải nhận định cảm tính.

1. **Header trùng, giá trị mâu thuẫn.** Response trả về `X-Frame-Options: SAMEORIGIN`
   của Juice Shop lẫn `DENY` của nginx. AI thêm `add_header` mà quên
   `proxy_hide_header X-Frame-Options`. Đây là lý do finding
   "X-Frame-Options header is deprecated" của Nikto vẫn còn ở lần quét #17.

2. **Đoạn mã tự mâu thuẫn với phần giải thích của chính nó.** Phần chữ khuyên bật
   `Content-Security-Policy-Report-Only` trước, chuyển sang bản chặn thật sau khi
   Console sạch. Nhưng trong snippet, dòng để không comment lại là bản chặn thật.
   Người dùng dán y nguyên sẽ bỏ qua bước thăm dò mà AI vừa dặn. Hệ quả đo được:
   CSP chặn luôn `<script>` inline khởi tạo banner cookie-consent của Juice Shop.

3. **Cách xử lý đúng bị bỏ trong comment.** Với `Deprecated Feature Policy Header
   Set`, AI viết `proxy_hide_header Feature-Policy;` dưới dạng dòng ghi chú. Áp
   bản vá xong, `Feature-Policy: payment 'self'` vẫn lộ và finding vẫn còn.

4. **COEP vẫn thiếu, đúng như dự đoán.** Nhóm làm theo khuyến nghị Report-Only của
   AI, nên ZAP tiếp tục báo thiếu COEP. Đây là đánh đổi có chủ ý giữa an toàn khi
   triển khai và việc làm sạch bảng kết quả, không phải bản vá hỏng.

---

## Phần 2. vulnapp, tầng code

Mục tiêu: `http://localhost:5000`, app Flask khoảng 100 dòng nhóm tự viết với 4 lỗ
hổng cố ý (SQL injection, lộ lỗi SQL, XSS phản chiếu, thiếu security header). Quét
bằng profile `full` vì ZAP chỉ bắt được SQLi khi có active scan.

Bản vá nằm trong `vulnapp/app.py` và `vulnapp/templates/page.html`. Bản chưa vá
giữ ở `vulnapp/app.py.chuava.bak`.

### Kiểm chứng bằng tay trước khi quét lại

| Thử | Trước vá | Sau vá |
|---|---|---|
| `/search?q=' OR '1'='1` | trả về cả 3 user, gồm admin | "Không tìm thấy." |
| `/search?q=an` | có kết quả | vẫn có kết quả, chức năng không hỏng |
| `/search?q='` | lộ câu SQL gốc, HTTP 500 | HTTP 200, không lộ gì |
| `/greet?name=<script>...` | phản chiếu nguyên vẹn | `&lt;script&gt;...` |
| Header `Server` | `Werkzeug/3.1.8 Python/3.14.3` | rỗng |

### Kết quả

**Đã vá: 17**, gồm cả 3 lỗ hổng High:

| Mức | Nguồn | Lỗ hổng |
|---|---|---|
| High | zap | SQL Injection |
| High | zap | Cross Site Scripting (Reflected) |
| High | zap | Cross Site Scripting (DOM Based) |
| Medium | zap | Content Security Policy (CSP) Header Not Set |
| Medium | zap | Missing Anti-clickjacking Header |
| Low | zap | Cross-Origin-Embedder-Policy / Opener-Policy / Resource-Policy (3 finding) |
| Low | zap | Permissions Policy Header Not Set |
| Low | zap | Server Leaks Version Information via "Server" Header |
| Low | zap | X-Content-Type-Options Header Missing |
| Info | zap | Storable and Cacheable Content |
| Info | nikto | Suggested security header missing: CSP, permissions-policy, referrer-policy, x-content-type-options (4 finding) |
| Info | nikto | The X-Content-Type-Options header is not set |

XSS DOM biến mất cùng XSS phản chiếu dù app không có một dòng JavaScript nào. Rất
có thể ZAP quan sát chính payload phản chiếu chạy trong trình duyệt và báo thêm
một lần dưới tên khác. AI không biết app không có JS nên đề xuất sửa
`static/app.js`, một file không tồn tại, và tự đánh giá khả năng false positive là
"Trung bình". Ca này đáng đưa vào bước gán nhãn.

**Mới xuất hiện: 2, cả hai do chính bản vá gây ra, và AI đánh giá đúng cả hai**

| Lỗ hổng | Nguyên nhân | AI nói |
|---|---|---|
| X-Frame-Options header is deprecated (Nikto) | bản vá thêm `X-Frame-Options: DENY` theo đề xuất cho finding clickjacking của ZAP. Hai scanner mâu thuẫn nhau: ZAP đòi header này, Nikto chê nó lỗi thời | Low, FP trung bình |
| Non-Storable Content (ZAP) | `Cache-Control: no-store` là đúng thứ bản vá muốn | Info, FP cao: ghi chú hiệu năng, không phải lỗ hổng |

**Còn tồn tại: 2**

| Lỗ hổng | Vì sao còn |
|---|---|
| Suggested security header missing: strict-transport-security | AI không vá, và đúng: HSTS vô nghĩa trên HTTP thuần. AI tự xếp FP cao |
| OPTIONS: Allowed HTTP Methods | trước là `HEAD, OPTIONS, GET`, sau là `GET, HEAD`. Bản vá đã gỡ OPTIONS, Nikto vẫn liệt kê method còn lại (Info) |

### Bản vá của AI sai ở đâu

AI chỉ đọc output của scanner, không đọc mã nguồn. Gợi ý cách vá nằm trong comment
của `app.py.chuava.bak` không lọt tới mô hình.

1. **Dán nguyên văn thì app không chạy.** Snippet cho "CSP Header Not Set" có
   `from flask import ..., escape`. `flask.escape` đã bị gỡ từ Flask 3.0; trên Flask
   3.1.3 đang cài, dòng này báo `ImportError`. Snippet không dùng `escape` ở đâu cả,
   nên sửa bằng cách bỏ nó khỏi dòng import.

2. **Đoán tên thay vì hỏi.** Snippet SQLi truy vấn bảng `items(id, name, description)`
   và render `search.html`; snippet XSS dùng `greet.html`. Không cái nào tồn tại.
   Nhóm giữ nguyên cách vá (truy vấn tham số hoá, Jinja2 tự escape) và đổi tên cho
   khớp app thật. Các chỗ chỉnh này đánh dấu `CHỈNH:` trong `app.py`.

3. **Năm chuỗi CSP khác nhau cho cùng một app.** Sáu finding có đoạn CSP, trả về năm
   chuỗi khác nhau (khác ở `base-uri 'self'` hay `'none'`, có nonce hay không, có
   `style-src` hay không), mỗi cái trong một hàm `after_request` riêng. Dán hết vào
   thì các hàm ghi đè lẫn nhau theo thứ tự đăng ký. Nhóm dùng chuỗi của đúng finding
   "CSP Header Not Set" và gom mọi header vào một hàm, như AI tự gợi ý ở các snippet
   sau ("bổ sung vào hook đã tạo ở phần CSP").

4. **CSP chặn chính CSS của trang.** `style-src 'self'` không cho `<style>` nội tuyến
   trong `page.html`, nên trang mất định dạng. Chức năng không ảnh hưởng.

---

## Phần 3. Lỗi của chính công cụ mà vòng lặp phát hiện ra

Các lỗi dưới đây không lộ ra qua test đơn vị. Chỉ khi chạy vòng lặp thật trên hai
target thì chúng mới xuất hiện.

**Cache dùng chung giữa các target.** Khoá cache ban đầu chỉ có fingerprint. Lần
quét #18 của vulnapp lấy 7 phân tích từ cache của target nginx, và báo cáo khuyên
`server_tokens off` cho `nginx/1.31.5` với một app Flask không có nginx nào. Khoá
giờ là `(fingerprint, model, target)`. 33 dòng cache cũ được gán lại target theo
lịch sử đã đối chiếu (thời điểm sinh khớp đúng với từng lần quét). Quy tắc đoán tự
động "lần quét gần nhất có fingerprint đó" đã được thử và gán sai 18/33 dòng, nên
không dùng. Nhãn ground truth cũng khoá theo `(fingerprint, target)`.

**Nikto dùng chung một id cho cả họ phát hiện.** Hai ca đo được:

- `Uncommon header(s) 'x-recruiting'` đã vá xong nhưng gộp với một header lạ mới
  xuất hiện, bảng so sánh báo "còn tồn tại" (#9 → #17).
- `Suggested security header missing: <tên>` gộp 5 header làm một, vá 4 cái vẫn báo
  "còn tồn tại", và finding về HSTS hiện bản vá AI viết cho CSP (#18 → #19).

Khoá gom trùng của Nikto giờ gồm cả phần trong dấu nháy và tên header sau
"missing:". URL không nằm trong hai phần đó, nên không làm bung lại ca cũ (một phát
hiện khớp 140 URL thành 140 dòng). Mỗi ca có test hồi quy trong `tests/test_scan.py`.

**Bản vá xoá mất tín hiệu mà bộ phân tích cần.** `server_tokens off` và
`version_string()` rỗng bịt banner, nên ở các lần quét sau vá (#17, #21)
`detect_stack()` trả về rỗng. Vá càng kỹ thì lần quét sau càng khó nhận diện ngăn
xếp. Cache theo target che bớt việc này: ở #21 cả 4 finding lấy phân tích sinh lúc
còn banner. Nhưng 3 finding mới ở #17 đã được phân tích khi không có thông tin ngăn
xếp. Hướng xử lý nếu cần: cho phép ghi đè ngăn xếp theo target.

**Hạn chế còn lại.** Phân tích được cache theo fingerprint, nên khi chi tiết của thông
báo đổi mà fingerprint giữ nguyên, báo cáo hiện lời giải thích của lần đầu. Ví dụ ở
#21, finding OPTIONS đã thành `GET, HEAD` nhưng lời giải thích vẫn nhắc
`HEAD, OPTIONS, GET`. Kết luận của phân tích không đổi nên chấp nhận.

---

## Chạy lại từ đầu

```powershell
# nginx
docker run --rm -d -p 127.0.0.1:3000:3000 --name juiceshop bkimminich/juice-shop
copy lab\nginx\nginx.conf.chuava.bak lab\nginx\nginx.conf
docker run --rm -d --name lab-nginx -p 127.0.0.1:8080:80 `
  -v "${PWD}\lab\nginx\nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
python scan.py http://localhost:8080                   # trước vá
# dán bản vá AI vào nginx.conf giữa hai mốc, rồi: docker restart lab-nginx
python scan.py http://localhost:8080                   # sau vá

# vulnapp
copy lab\vulnapp\app.py.chuava.bak lab\vulnapp\app.py
python lab\vulnapp\app.py                              # cửa sổ riêng
python scan.py http://localhost:5000 --profile full    # trước vá
# sửa app.py theo fix_snippet trong báo cáo, khởi động lại app
python scan.py http://localhost:5000 --profile full    # sau vá

python scan.py --compare <id trước> <id sau>
```
