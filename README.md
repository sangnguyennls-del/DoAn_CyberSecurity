# AI hỗ trợ quét lỗ hổng bảo mật Web

Đồ án môn **Nhập môn đảm bảo an ninh thông tin** — nhóm 5 thành viên.

Nối hai công cụ quét lỗ hổng (**Nikto** + **OWASP ZAP**) với **Claude API** để tự động phân
tích kết quả scan và đề xuất bản vá cụ thể.

Scanner trả về hàng trăm phát hiện thô, trùng lặp, lẫn false positive, và không nói phải sửa
gì. Hệ thống này trả lời ba câu hỏi mà scanner thuần không trả lời được:

1. **Cái nào đáng lo thật?** — AI đánh giá lại mức độ và ước lượng khả năng false positive
2. **Sửa thế nào?** — AI sinh bản vá cụ thể (đoạn config/code dán được ngay)
3. **AI nói có đúng không?** — đo bằng ground truth gán nhãn thủ công, và chứng minh bằng
   vòng lặp *áp bản vá → quét lại → lỗ hổng biến mất*

## ⚠ Phạm vi hợp pháp

**Chỉ được quét hệ thống bạn sở hữu hoặc có văn bản cho phép.** Quét một hệ thống không thuộc
quyền của mình là hành vi vi phạm pháp luật, kể cả khi chỉ là quét thăm dò.

Công cụ mặc định **từ chối** mọi mục tiêu ngoài `localhost` và mạng nội bộ (RFC1918). Cờ
`--allow-external` tồn tại cho trường hợp có phép bằng văn bản — đừng dùng nó để lách.

## Cài đặt

Yêu cầu: **Docker Desktop** (đang chạy), **Python 3.12+**, một **Anthropic API key**.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env      # rồi điền ANTHROPIC_API_KEY vào .env
```

Kéo image (lần đầu khá lâu, ZAP ~1.5GB):

```powershell
docker pull ghcr.io/sullo/nikto
docker pull ghcr.io/zaproxy/zaproxy:stable
docker pull bkimminich/juice-shop
```

## Dựng lab

```powershell
docker run --rm -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
# mở http://localhost:3000 để xác nhận đã lên
```

## Sử dụng

```powershell
# Chỉ chạy scanner, xem kết quả thô — KHÔNG tốn tiền API. Dùng khi đang dev.
python scan.py http://localhost:3000 --no-ai

# Full pipeline: quét -> AI phân tích -> báo cáo HTML
python scan.py http://localhost:3000 --open

# Quét kỹ hơn (có active scan, lâu hơn nhiều)
python scan.py http://localhost:3000 --profile full

# Lịch sử các lần quét
python scan.py --list

# So sánh trước/sau khi vá — phần chứng minh bản vá AI có tác dụng thật
python scan.py --compare 1 2
```

Báo cáo là một file HTML tự chứa, mở được offline. Mỗi lỗ hổng hiển thị **bằng chứng thô của
scanner bên trái, phân tích + bản vá của AI bên phải** để người đọc tự đối chiếu.

## Kiểm thử

```powershell
pytest -q
```

Test chạy hoàn toàn offline — không cần Docker, không gọi API, không cần mạng. Chạy sau mỗi
lần sửa parser hoặc schema.

## Kiến trúc

```
scan.py / api          CLI và Web dashboard — cùng gọi một bộ hàm bên dưới
   │
   ├── scanners/       Nikto + ZAP qua Docker, chạy song song -> chuẩn hoá -> gom trùng
   ├── analyzer/       Claude structured output: đánh giá lại + sinh bản vá
   ├── report.py       Render HTML (Jinja2, autoescape bắt buộc)
   └── core/           Hai "hợp đồng" dùng chung: models.Finding và db (SQLite)
```

### Hai hợp đồng — không tự ý sửa

| File | Vai trò |
|---|---|
| `core/models.py` | Schema `Finding` — mọi module nói chuyện với nhau qua đây |
| `core/db.py` | Schema SQLite — 4 bảng: `scans`, `findings`, `analyses`, `labels` |

Sửa hai file này là ảnh hưởng cả 5 người. **Bàn với cả nhóm trước khi đổi.**

### `fingerprint` — điểm thiết kế cốt lõi

`sha256(source | mã_plugin)`, cắt còn 16 ký tự. Một trường làm bốn việc:

1. gom trùng trong một lần quét (ZAP lặp cùng alert trên hàng chục URL)
2. so sánh giữa hai lần quét — diff chỉ là phép toán tập hợp
3. khoá cache kết quả AI — quét lại target cũ gần như miễn phí
4. khoá join với bảng ground truth khi đánh giá độ chính xác

**URL cố ý không nằm trong khoá.** Đo thật trên Juice Shop: test "backup/cert file found"
của Nikto khớp **140 URL khác nhau**. Nếu tính cả đường dẫn thì thành 140 lỗ hổng riêng biệt,
trong khi thực chất là *một* vấn đề với *một* bản vá — vừa làm báo cáo không đọc nổi, vừa
vượt `max_tokens` khi gửi lên API.

Số URL bị ảnh hưởng không mất đi: xem `count` (số thật) và `urls` (5 mẫu). Cách này cũng làm
diff giữa hai lần quét bền hơn — đổi đường dẫn không tạo ra lỗ hổng "mới" giả.

## Phân công

| Người | Sở hữu | Nội dung |
|---|---|---|
| TV1 | `scanners/` | Docker orchestration, ZAP baseline/full/authenticated, chuẩn hoá, gom trùng |
| TV2 | `analyzer/` | Prompt, structured output, cache, tinh chỉnh theo số liệu của TV5 |
| TV3 | `core/`, `api/` | SQLite, FastAPI, background job, logic diff |
| TV4 | `web/` | Dashboard, biểu đồ, báo cáo HTML |
| TV5 | `lab/`, `eval/` | Dựng target, ground truth, đo độ chính xác, vòng lặp vá→quét lại |

Mỗi người làm trên branch riêng, merge qua Pull Request.

## Ghi chú kỹ thuật (đã xử lý sẵn, đừng "sửa lại")

- **Exit code khác 0 không phải lỗi.** Cả Nikto lẫn ZAP trả exit code khác 0 khi *tìm thấy*
  lỗ hổng (ZAP: 1=WARN, 2=FAIL). Điều kiện thành công là file JSON tồn tại và parse được.
- **Output ghi vào `%TEMP%`, không ghi vào thư mục dự án.** Đường dẫn dự án có dấu cách
  (`IT Learning`, `Cyber security`) làm bind mount Docker hay gãy.
- **`localhost` được đổi thành `host.docker.internal`** khi truyền vào container, vì container
  không thấy localhost của máy host. URL gốc vẫn giữ để hiển thị.
- **Jinja2 `autoescape=True` là bắt buộc.** Evidence và URL là dữ liệu do target kiểm soát;
  nhúng thô vào HTML là tự tạo XSS ngay trong báo cáo của mình. Có test canh việc này.

## Giới hạn đã biết

- ZAP `baseline` chỉ quét passive → không vào được phần sau màn login của Juice Shop. Profile
  `authenticated` (TV1, tuần 6–7) mới xử lý được.
- Nikto không xếp hạng mức độ nghiêm trọng, mọi phát hiện đều vào `Info` rồi để AI đánh giá lại.
- **Mọi bản vá do AI đề xuất đều chưa được kiểm chứng tự động.** Phải đối chiếu với bằng
  chứng thô và thử trên lab trước khi áp dụng. Báo cáo ghi rõ điều này ở từng lỗ hổng.
