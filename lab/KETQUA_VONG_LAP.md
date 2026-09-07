# Kết quả vòng lặp vá → quét lại (nginx, tầng cấu hình)

Chạy thật ngày 07/09/2026. Đây là bằng chứng bản vá có tác dụng, và là số liệu đưa
thẳng vào mục "Kết quả" của báo cáo.

## Thiết lập

| | |
|---|---|
| Target | nginx reverse proxy (cổng 8080) đặt trước OWASP Juice Shop |
| Scanner | Nikto 2.5.0 + OWASP ZAP baseline, chạy song song qua Docker |
| Lần quét `#9` — trước khi vá | 164 phát hiện thô → **22 lỗ hổng riêng biệt** |
| Lần quét `#10` — sau khi vá | **16 lỗ hổng riêng biệt** |

Bản vá: 8 security header + `server_tokens off` + 3 `proxy_hide_header`, dán vào
`lab/nginx/nginx.conf` giữa hai dòng `>>> BẮT ĐẦU BẢN VÁ <<<`.

## Kết quả

```
python scan.py --compare 9 10
```

### Đã vá — 8 lỗ hổng biến mất

| Mức độ | Nguồn | Lỗ hổng | Vá bằng |
|---|---|---|---|
| Medium | ZAP | Content Security Policy (CSP) Header Not Set | `add_header Content-Security-Policy` |
| Medium | ZAP | Cross-Domain Misconfiguration | `proxy_hide_header Access-Control-Allow-Origin` |
| Low | ZAP | Cross-Origin-Embedder-Policy Header Missing or Invalid | `add_header Cross-Origin-Embedder-Policy` |
| Low | ZAP | Cross-Origin-Opener-Policy Header Missing or Invalid | `add_header Cross-Origin-Opener-Policy` |
| Low | ZAP | Deprecated Feature Policy Header Set | `proxy_hide_header Feature-Policy` |
| Low | ZAP | Server Leaks Version Information via "Server" Header | `server_tokens off` |
| Info | Nikto | Retrieved access-control-allow-origin header: `*` | `proxy_hide_header` |
| Info | Nikto | Uncommon header 'x-recruiting' | `proxy_hide_header X-Recruiting` |

### Mới xuất hiện — 2 lỗ hổng

| Mức độ | Nguồn | Lỗ hổng |
|---|---|---|
| Medium | ZAP | CSP: script-src unsafe-inline |
| Medium | ZAP | CSP: style-src unsafe-inline |

### Còn tồn tại — 14 lỗ hổng

Chủ yếu là lỗi nằm trong chính Juice Shop (`Dangerous JS Functions`, `/ftp/` truy cập
được, backup file) — không sửa được từ lớp proxy. Riêng `strict-transport-security`
còn thiếu là **đúng**: HSTS trên HTTP thuần vô nghĩa, phải có HTTPS trước.

## Phát hiện quan trọng nhất: bản vá đánh đổi, không phải xoá sạch

Bản vá làm biến mất 8 lỗ hổng nhưng **sinh ra 2 lỗ hổng mới ở mức Medium**.

Nguyên nhân: CSP phải chứa `'unsafe-inline'` cho `script-src` và `style-src` thì Juice
Shop mới chạy được. Tức là "đã có CSP" không đồng nghĩa với "đã an toàn" — một CSP có
`unsafe-inline` gần như không chặn được XSS, và ZAP báo đúng.

Ý nghĩa với đồ án — đây là luận điểm trung tâm nên viết vào phần kết luận:

> Một bản vá do AI đề xuất **không thể được tin ngay**, kể cả khi nó làm biến mất đúng
> lỗ hổng mà nó nhắm tới. Bước *quét lại* không phải thủ tục hình thức: nó là thứ duy
> nhất bắt được lỗ hổng mới do chính bản vá tạo ra. Một quy trình chỉ có
> "quét → AI đề xuất → áp dụng" mà thiếu bước quét lại sẽ **âm thầm làm hệ thống có
> thêm lỗ hổng mới** trong khi báo cáo rằng đã vá xong.
>
> Ở đây bản vá là một **đánh đổi có ý thức**: chấp nhận `unsafe-inline` để ứng dụng
> chạy được, đổi lấy việc bịt 8 lỗ khác. Đánh đổi đó phải được ghi lại và giải thích,
> chứ không được giấu đi bằng con số "16 < 22".

Đúng đây là lý do vòng lặp này tồn tại trong đồ án, thay vì chỉ dừng ở bước sinh bản vá.

## Một bug phát hiện được nhờ chính vòng lặp này

Ở lần chạy đầu, `compare` báo "không có gì thay đổi" giữa hai lần quét, trong khi lỗ
hổng CSP đã đổi từ *Failure to Define Directive with No Fallback* sang *script-src
unsafe-inline*.

Nguyên nhân: fingerprint dùng `pluginid` của ZAP, mà **một plugin phát ra nhiều biến
thể khác hẳn nhau** — cả hai đều là pluginid `10055`. Gom chung khoá thì hai vấn đề
khác nhau trở thành một, và **bằng chứng "đã vá" của đồ án thành sai**.

Đã sửa: khoá dùng `alertRef` (`10055-1` / `10055-2`) trước, `pluginid` làm dự phòng.
Số liệu ở trên là kết quả **chạy lại toàn bộ** sau khi sửa, nên trước/sau dùng chung
một bản khoá.

Bài học đáng viết vào báo cáo: công cụ đo cũng phải được kiểm chứng. Nếu chỉ chạy một
lần rồi tin luôn con số, nhóm đã báo cáo một kết quả sai mà không hề biết.

## Lưu ý về tính tái lập

Bản vá dùng ở trên do nhóm tự viết (lúc chạy thử chưa có API key). Khi demo thật, bản
vá phải lấy từ cột "Phân tích & bản vá" trong báo cáo do AI sinh — và cần lưu lại
nguyên văn đề xuất của AI để đối chiếu được với kết quả quét lại.

`lab/nginx/nginx.conf` trong repo đang ở trạng thái **chưa vá** — đó là điểm xuất phát
để chạy lại toàn bộ quy trình.
