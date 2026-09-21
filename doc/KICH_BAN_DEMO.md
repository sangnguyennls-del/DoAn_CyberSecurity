# Kịch bản demo

Bản demo trực tiếp cho buổi bảo vệ. **Thời lượng: 4–5 phút.** Mục tiêu: cho thấy hệ thống chạy thật,
không phải ảnh chụp. Diễn theo đúng thứ tự dưới đây.

## Chuẩn bị trước khi lên (làm trước ở nhà, đừng làm trực tiếp)

Bốn thứ phải sẵn sàng, vì quét thật mất vài phút và tốn tiền API — **không quét trực tiếp trên sân khấu**.

```powershell
# 1. Docker Desktop đang chạy. Dựng ba target (chỉ mở trên 127.0.0.1):
docker run --rm -d -p 127.0.0.1:3000:3000 --name juiceshop bkimminich/juice-shop
docker run --rm -d --name lab-nginx -p 127.0.0.1:8080:80 `
  -v "${PWD}\lab\nginx\nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine

# 2. Kích hoạt môi trường và chạy dashboard:
.\.venv\Scripts\Activate.ps1
uvicorn api.main:app        # -> http://127.0.0.1:8000

# 3. Kiểm tra sẵn có dữ liệu cũ trong doan.db: các lần quét #9, #17, #20, #21 phải còn.
python scan.py --list

# 4. Mở sẵn 3 tab trình duyệt:
#    - http://127.0.0.1:8000            (trang chủ)
#    - http://127.0.0.1:8000/scans/9    (chi tiết một lần quét)
#    - http://127.0.0.1:8000/compare?a=9&b=17   (so sánh)
```

> Nếu mạng hội trường yếu hoặc không có: mọi thứ chạy cục bộ, không cần internet, trừ lần quét MỚI
> (cần gọi API Claude). Demo dưới đây chỉ xem dữ liệu đã có nên **không cần mạng**.

---

## Bước 1 — Trang chủ (45 giây)

Mở tab `http://127.0.0.1:8000`.

> "Đây là dashboard. Trên cùng là form quét mới: nhập URL, chọn chế độ baseline / full / auth. Bên
> dưới là biểu đồ diễn biến số lỗ hổng qua các lần quét, và lịch sử. Cột thấp dần sau khi vá là dấu
> hiệu tốt."

Chỉ vào biểu đồ, chỉ vào lịch sử. **Không bấm quét mới** (mất thời gian và tốn tiền).

## Bước 2 — Chi tiết một lần quét (1 phút 30)

Mở tab `http://127.0.0.1:8000/scans/9` (nginx, 22 lỗ hổng).

> "Đây là chi tiết lần quét nginx. Phần tóm tắt cho biết AI đánh giá lại 22 lỗ hổng thành mấy mức, và
> thứ tự nên xử lý. Kéo xuống một phát hiện cụ thể…"

Kéo tới thẻ **Content Security Policy (CSP) Header Not Set**. Chỉ rõ hai cột:

> "Bên trái là bằng chứng thô của scanner và các URL. Bên phải là phân tích của Claude: đánh giá lại
> mức độ, khả năng false positive, giải thích tiếng Việt cho người mới học, tác động, và — quan trọng
> nhất — đoạn bản vá cụ thể dán được ngay. Có nhãn 'Gợi ý do AI sinh, cần kiểm chứng.'"

## Bước 3 — So sánh trước/sau khi vá (1 phút)

Mở tab `http://127.0.0.1:8000/compare?a=9&b=17`.

> "Đây là phần mạnh nhất. Sau khi áp bản vá AI đề xuất vào nginx rồi quét lại, trang so sánh chia ba
> cột: **đã vá** 9 mục, **mới xuất hiện** 3 mục, **còn tồn tại** 13. Những phát hiện ở cột đã vá chính
> là bằng chứng bản vá của AI có tác dụng thật — không phải nhóm nói suông."

Có thể mở thêm `compare?a=20&b=21` để cho thấy vulnapp: 17 đã vá, gồm SQL injection và XSS.

## Bước 4 — Số liệu đánh giá (1 phút)

Mở một cửa sổ terminal (đã activate venv), gõ:

```powershell
python -m eval.metrics all
```

> "Cuối cùng là con số. Lệnh này gộp toàn bộ 115 cặp đã gán nhãn trên ba target và in ra ma trận nhầm
> lẫn, precision, recall, tách theo từng loại nhãn. Precision gần 87%, recall 25%. Mọi số trong báo cáo
> đều chạy lại được bằng đúng lệnh này."

(Tuỳ chọn) chạy `pytest -q` cho thấy 59 test qua trong dưới 1 giây.

---

## Phương án dự phòng

- **Docker không lên / dashboard lỗi:** dùng báo cáo PDF (`doc/Báo cáo đồ án.pdf`) — các hình 3.5, 3.6,
  3.7 và 5.2, 5.3 chính là ảnh chụp các màn hình trên.
- **Không có máy chiếu phụ cho terminal:** đọc kết quả `eval.metrics` đã in sẵn trong `eval/KETQUA_DANH_GIA.md`.
- **Bị hỏi "quét thử live được không":** giải thích rằng quét full mất vài phút và tốn tiền API, nên đã
  chuẩn bị dữ liệu sẵn; nếu thầy/cô muốn, chạy `python scan.py http://localhost:8080 --no-ai` (chỉ scanner,
  không tốn tiền) để xem kết quả thô sinh ra trong ~1 phút.

## Dọn sau demo

```powershell
docker stop juiceshop lab-nginx
```
