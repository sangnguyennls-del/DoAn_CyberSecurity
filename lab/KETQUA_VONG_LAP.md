# Kết quả vòng lặp vá → quét lại (nginx, tầng cấu hình)

Chạy thật ngày 07/09/2026 trên máy nhóm. Đây là bằng chứng bản vá có tác dụng, và là
số liệu đưa thẳng vào mục "Kết quả" của báo cáo.

## Thiết lập

| | |
|---|---|
| Target | nginx reverse proxy (cổng 8080) đặt trước OWASP Juice Shop |
| Scanner | Nikto 2.5.0 + OWASP ZAP baseline, chạy song song qua Docker |
| Lần quét trước khi vá | `#6` — 164 phát hiện thô → **19 lỗ hổng riêng biệt** |
| Lần quét sau khi vá | `#7` — **13 lỗ hổng riêng biệt** |

Bản vá: thêm 8 security header + `server_tokens off` + 3 `proxy_hide_header` vào
`lab/nginx/nginx.conf` (xem khối giữa `>>> BẮT ĐẦU BẢN VÁ <<<`).

## Kết quả so sánh

```
python scan.py --compare 6 7
```

### Đã vá — 7 lỗ hổng biến mất

| Mức độ | Nguồn | Lỗ hổng | Vá bằng |
|---|---|---|---|
| Medium | ZAP | Content Security Policy (CSP) Header Not Set | `add_header Content-Security-Policy` |
| Medium | ZAP | Cross-Domain Misconfiguration | `proxy_hide_header Access-Control-Allow-Origin` |
| Low | ZAP | Cross-Origin-Embedder-Policy Header Missing or Invalid | `add_header Cross-Origin-Embedder-Policy` |
| Low | ZAP | Deprecated Feature Policy Header Set | `proxy_hide_header Feature-Policy` |
| Low | ZAP | Server Leaks Version Information via "Server" Header | `server_tokens off` |
| Info | Nikto | Retrieved access-control-allow-origin header: `*` | `proxy_hide_header` |
| Info | Nikto | Uncommon header 'x-recruiting' | `proxy_hide_header X-Recruiting` |

### Mới xuất hiện — 1 lỗ hổng

| Mức độ | Nguồn | Lỗ hổng |
|---|---|---|
| Medium | ZAP | **CSP: Failure to Define Directive with No Fallback** |

### Còn tồn tại — 12 lỗ hổng

Chủ yếu là lỗi nằm trong chính ứng dụng Juice Shop (`Dangerous JS Functions`,
`/ftp/` truy cập được, backup file), không sửa được từ lớp proxy. Riêng
`strict-transport-security` còn thiếu là **đúng**: HSTS trên HTTP thuần không có ý
nghĩa, phải có HTTPS trước.

## Phát hiện quan trọng nhất: bản vá đẻ ra lỗ hổng mới

Thêm CSP làm biến mất cảnh báo "CSP Header Not Set", nhưng lại **sinh ra một cảnh báo
mới ở cùng mức Medium**: `CSP: Failure to Define Directive with No Fallback`.

Nguyên nhân: `default-src` không phải là fallback cho mọi directive. Các directive như
`form-action`, `frame-src`, `object-src`, `base-uri` không kế thừa từ `default-src`,
nên CSP mới tuy có vẻ chặt nhưng vẫn hở đúng những chỗ đó.

Ý nghĩa với đồ án — đây là luận điểm trung tâm nên viết vào phần kết luận:

> Một bản vá do AI đề xuất **không thể được tin ngay**, kể cả khi nó làm biến mất đúng
> lỗ hổng mà nó nhắm tới. Bước *quét lại* không phải thủ tục hình thức: nó là thứ duy
> nhất bắt được lỗ hổng mới do chính bản vá tạo ra. Một quy trình chỉ có
> "quét → AI đề xuất → áp dụng" mà thiếu bước quét lại sẽ **âm thầm làm hệ thống có
> thêm lỗ hổng mới** trong khi báo cáo rằng đã vá xong.

Chính xác đây là lý do vòng lặp này tồn tại trong đồ án, thay vì chỉ dừng ở bước sinh
bản vá.

## Bước tiếp theo

Sửa CSP cho đủ directive rồi quét lần 3, kỳ vọng cảnh báo Medium mới này biến mất:

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'" always;
```

```powershell
docker restart lab-nginx
python scan.py http://localhost:8080
python scan.py --compare 7 8
```

Ba lần quét liên tiếp (chưa vá → vá → vá lại) là một dòng câu chuyện rất tốt để demo:
nó cho thấy quy trình là **lặp**, không phải một phát ăn ngay.

## Lưu ý về tính tái lập

Bản vá dùng ở trên do nhóm tự viết (lúc chạy thử chưa có API key). Khi demo thật, bản
vá phải lấy từ cột "Phân tích & bản vá" trong báo cáo do AI sinh — và cần ghi lại
nguyên văn đề xuất của AI để đối chiếu được với kết quả quét lại.
