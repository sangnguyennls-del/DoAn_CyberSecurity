# Lab — môi trường quét và vòng lặp vá → quét lại

Bốn target, mỗi cái một vai trò. Chỉ chạy trên máy cá nhân.

| Target | Cổng | Vai trò |
|---|---|---|
| OWASP Juice Shop | 3000 | Bề mặt quét phong phú, nhiều lỗ hổng hiện đại. **Không vá được** (code người khác). |
| nginx reverse proxy → Juice Shop | 8080 | Vá được ở **tầng cấu hình**: header, banner, cookie |
| `vulnapp/app.py` (Flask) | 5000 | Vá được ở **tầng code**: SQLi, XSS, lộ lỗi |
| OWASP Mutillidae II | 8090 | Target thứ ba cho phần đánh giá AI, không vá |

Cần cả hai loại target vá được: nếu chỉ có nginx thì chỉ chứng minh được AI vá cấu
hình, không chứng minh được AI vá code.

## 1. Juice Shop — target chính để quét

```powershell
docker run --rm -d -p 127.0.0.1:3000:3000 --name juiceshop bkimminich/juice-shop
python scan.py http://localhost:3000
```

## 2. nginx proxy — vá ở tầng cấu hình

Juice Shop không sửa được, nhưng phần lớn phát hiện của ZAP/Nikto là lỗi **cấu hình**
(thiếu header, lộ banner) — và những thứ đó vá được ở lớp proxy đặt trước nó.

```powershell
# Juice Shop phải đang chạy trước
docker run --rm -d --name lab-nginx -p 127.0.0.1:8080:80 `
  -v "${PWD}/lab/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro" `
  nginx:alpine

python scan.py http://localhost:8080          # lần quét TRƯỚC khi vá
```

Đọc bản vá AI đề xuất trong báo cáo, dán vào giữa hai dòng đánh dấu
`>>> BẮT ĐẦU BẢN VÁ <<<` / `>>> KẾT THÚC BẢN VÁ <<<` trong `nginx/nginx.conf`, rồi:

```powershell
docker restart lab-nginx
python scan.py http://localhost:8080          # lần quét SAU khi vá
python scan.py --compare <id_trước> <id_sau>
```

Những phát hiện nằm ở cột **đã vá** chính là bằng chứng bản vá AI đề xuất có tác dụng thật.

## 3. vulnapp — vá ở tầng code

```powershell
pip install flask
python lab/vulnapp/app.py                     # http://127.0.0.1:5000
python scan.py http://localhost:5000 --profile full
```

> **Phải dùng `--profile full`.** `baseline` chỉ quét passive — nó đọc response chứ không
> thử tấn công, nên chỉ tìm ra lỗ hổng 4 (thiếu header). Đo thật trên vulnapp: baseline
> ra 12 lỗ hổng nhưng **không có SQLi lẫn XSS**. Muốn ZAP tìm được lỗ hổng 1–3 thì phải
> có active scan, tức `--profile full`, vì chỉ chế độ đó mới fuzz tham số `q` và `name`.
>
> Nếu quên, phần demo "AI vá code" sẽ không có gì để vá.

Bốn lỗ hổng cố ý, đánh dấu sẵn trong `vulnapp/app.py` bằng comment `LỖ HỔNG N`:

| # | Lỗ hổng | CWE | Vá bằng |
|---|---|---|---|
| 1 | SQL Injection ở `/search` | CWE-89 | Truy vấn tham số hoá |
| 2 | Lộ câu SQL trong thông báo lỗi | CWE-209 | Log ra server, trả lỗi chung chung |
| 3 | Reflected XSS ở `/greet` | CWE-79 | `html.escape()` hoặc template Jinja2 |
| 4 | Thiếu security header | CWE-693 | Thêm header trong `after_request` |

Tự kiểm chứng trước khi vá:

```powershell
curl "http://127.0.0.1:5000/search?q=' OR '1'='1"          # SQLi: trả về mọi user
curl "http://127.0.0.1:5000/greet?name=<script>alert(1)</script>"   # XSS: script vào thẳng HTML
curl -I http://127.0.0.1:5000/                              # không có CSP/X-Frame-Options
```

Vá theo đề xuất của AI, chạy lại đúng ba lệnh trên để xác nhận đã hết, rồi quét lại
và so sánh.

## 4. Mutillidae — target thứ ba

```powershell
docker run -d --name mutillidae -p 127.0.0.1:8090:80 citizenstig/nowasp
curl.exe -s http://localhost:8090/set-up-database.php > NUL      # khởi tạo DB lần đầu
curl.exe -s -o NUL -w "%{http_code}\n" "http://localhost:8090/index.php?page=home.php"
#   phải thấy 200; nếu thấy 302 sang database-offline.php thì DB chưa sẵn sàng
python scan.py http://localhost:8090 --profile full
```

> **Active scan làm hỏng target này.** Image đi kèm phpMyAdmin tự đăng nhập MySQL bằng root
> không mật khẩu. Ở lần quét #23/#24, ZAP chạy SQL thật qua đó (94 database mang tên payload)
> và Mutillidae chuyển sang `database-offline.php`. Sau mỗi lần quét `full`, dựng lại container
> từ đầu (`docker rm -f mutillidae` rồi chạy lại hai lệnh đầu) trước khi dùng tiếp.

## Dọn dẹp

```powershell
docker stop juiceshop lab-nginx mutillidae
```

## Lưu ý an toàn

Mọi target chỉ mở trên `127.0.0.1`: `vulnapp` tự bind `127.0.0.1`, các container publish
dạng `-p 127.0.0.1:<cổng>:<cổng>`. Máy khác trong mạng không truy cập được — **đừng bỏ phần
`127.0.0.1:`**, vì đây là các ứng dụng cố ý có lỗ hổng. Scanner trong Docker vẫn tới được
chúng qua `host.docker.internal`.
