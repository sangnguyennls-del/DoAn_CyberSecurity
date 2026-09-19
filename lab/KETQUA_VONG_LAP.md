# Vòng lặp vá → quét lại (tầng cấu hình)

Mục tiêu: `http://localhost:8080` — nginx reverse proxy đặt trước OWASP Juice Shop.
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
`>>> KẾT THÚC BẢN VÁ <<<`. Mỗi dòng ghi tên finding đã sinh ra nó. Bản chưa vá
giữ nguyên ở `nginx/nginx.conf.chuava.bak` để chạy lại từ đầu khi cần demo.

## Bản vá này lấy từ đâu

Toàn bộ khối lệnh lấy từ trường `fix_snippet` do Claude sinh ra khi phân tích lần
quét #9. Không có dòng nào nhóm tự viết thêm. Chỗ duy nhất nhóm can thiệp là gom
các đoạn rời của nhiều finding vào một khối và bỏ phần trùng nhau.

Lần chạy đầu tiên mô hình vá sai tầng: nó trả về `helmet` của Express cho một mục
tiêu chạy nginx, vì prompt để nó tự đoán ngăn xếp. Sửa bằng cách quét banner
`Server` trên toàn bộ lần quét rồi đưa kết quả vào đầu mỗi lô yêu cầu. Sau khi
sửa, 4/4 finding sinh lại đều trả về `add_header`/`proxy_hide_header` của nginx.

## Kết quả đo được

```
python scan.py --compare 9 17
```

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

**Mới xuất hiện: 3 — cả ba đều do chính bản vá gây ra**

| Lỗ hổng | Nguyên nhân |
|---|---|
| CSP: Wildcard Directive | CSP của AI có `img-src ... https:`, ZAP coi `https:` là wildcard |
| CSP: style-src unsafe-inline | CSP của AI tự đưa `'unsafe-inline'` vào `style-src` |
| Cross-Origin-Resource-Policy Header Missing | bật COEP kéo theo yêu cầu CORP, mà dòng CORP trong snippet lại đang bị comment |

**Còn tồn tại: 13**, trong đó 4 ca đáng nói ở mục dưới.

## Bản vá của AI sai ở đâu

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

## Hai thứ vòng lặp này phát hiện ra trong chính công cụ

**Bản vá xoá mất tín hiệu mà bộ phân tích cần.** `server_tokens off` bịt banner
`nginx/1.31.5`, nên ở lần quét #17 `detect_stack()` trả về chuỗi rỗng và log in ra
"không dò được ngăn xếp". Vá càng kỹ thì lần quét sau càng khó nhận diện ngăn xếp.
Hiện chấp nhận hạn chế này; hướng xử lý là cho phép ghi đè ngăn xếp theo mục tiêu.

**Trang so sánh từng nói sai.** Nikto dùng chung một id cho mọi header lạ, nên
`'x-recruiting'` (đã vá xong) và `'cross-origin-embedder-policy-report-only'` (mới
xuất hiện) gộp chung một fingerprint, và bảng so sánh xếp nhầm vào cột "còn tồn
tại". Đã sửa bằng cách đưa phần trong dấu nháy đơn của thông báo vào khoá gom
trùng. Tên header và entry robots.txt đều nằm trong nháy, còn URL thì không, nên
không làm bung trở lại lỗi cũ: hai finding nặng nhất (140 và 112 URL) không chứa
dấu nháy nào. Hai test hồi quy giữ chỗ này ở `tests/test_scan.py`.

Vì fingerprint đổi, các finding Nikto có dấu nháy sẽ được coi là mới ở lần quét
sau và tốn một lượt gọi API. Số lượng nhỏ, chấp nhận được.

## Chạy lại từ đầu

```powershell
docker run --rm -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
copy lab\nginx\nginx.conf.chuava.bak lab\nginx\nginx.conf
docker run --rm -d --name lab-nginx -p 8080:80 `
  -v "${PWD}\lab\nginx\nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine

python scan.py http://localhost:8080          # lần quét trước vá
# đọc bản vá AI trong báo cáo, dán vào nginx.conf giữa hai mốc
docker restart lab-nginx
python scan.py http://localhost:8080          # lần quét sau vá
python scan.py --compare <id trước> <id sau>
```
