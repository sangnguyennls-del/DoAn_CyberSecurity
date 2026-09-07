# AI hỗ trợ quét lỗ hổng bảo mật Web

Đồ án môn **Nhập môn đảm bảo an ninh thông tin**.

Nối hai công cụ quét lỗ hổng (**Nikto** + **OWASP ZAP**) với **Claude API** để tự động phân
tích kết quả scan và đề xuất bản vá cụ thể.

Scanner trả về hàng trăm phát hiện thô, trùng lặp, lẫn false positive, và không nói phải sửa
gì. Hệ thống này trả lời ba câu hỏi mà scanner thuần không trả lời được:

1. **Cái nào đáng lo thật?** — AI đánh giá lại mức độ và ước lượng khả năng false positive
2. **Sửa thế nào?** — AI sinh bản vá cụ thể (đoạn config/code dán được ngay)
3. **AI nói có đúng không?** — đo bằng ground truth gán nhãn thủ công (`eval/`), và chứng
   minh bằng vòng lặp *áp bản vá → quét lại → lỗ hổng biến mất* (`lab/`)

## ⚠ Phạm vi hợp pháp

**Chỉ được quét hệ thống bạn sở hữu hoặc có văn bản cho phép.** Quét một hệ thống không thuộc
quyền của mình là hành vi vi phạm pháp luật, kể cả khi chỉ là quét thăm dò.

Công cụ mặc định **từ chối** mọi mục tiêu ngoài `localhost` và mạng nội bộ (RFC1918) — chặn
ở cả CLI lẫn web form. Cờ `--allow-external` tồn tại cho trường hợp có phép bằng văn bản.

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
docker pull ghcr.io/sullo/nikto      # image chính thức trên ghcr, KHÔNG phải Docker Hub
docker pull ghcr.io/zaproxy/zaproxy:stable
docker pull bkimminich/juice-shop
docker pull nginx:alpine             # cho target vá được ở lab/
```

## Dựng lab

```powershell
docker run --rm -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
```

Chi tiết ba target và quy trình vá → quét lại: xem [lab/README.md](lab/README.md).

## Dùng bằng dashboard

```powershell
uvicorn api.main:app --reload      # -> http://127.0.0.1:8000
```

Nhập URL → bấm quét → xem tiến trình realtime → xem báo cáo → so sánh hai lần quét.

## Dùng bằng CLI

```powershell
# Chỉ chạy scanner, xem kết quả thô — KHÔNG tốn tiền API. Dùng khi đang dev.
python scan.py http://localhost:3000 --no-ai

# Full pipeline: quét -> AI phân tích -> báo cáo HTML
python scan.py http://localhost:3000 --open

# Quét kỹ hơn (có active scan, lâu hơn nhiều)
python scan.py http://localhost:3000 --profile full

python scan.py --list                 # lịch sử
python scan.py --compare 1 2          # trước/sau khi vá
```

Dashboard và CLI dùng chung một bộ hàm và chung một database — quét bằng CLI vẫn xem được
trên dashboard và ngược lại.

## Đánh giá độ chính xác của AI

```powershell
python -m eval.export 4        # xuất phiếu gán nhãn ra eval/ground_truth.csv
# ... mở bằng Excel, điền is_true_positive và patch_ok ...
python -m eval.metrics 4       # in precision/recall, chất lượng bản vá
```

Gán nhãn phải **tự kiểm chứng bằng tay** (curl, DevTools, đọc code) rồi mới điền — gán theo
lời AI là chấm bài bằng đáp án của người làm bài, số liệu sẽ vô nghĩa.

## Kiểm thử

```powershell
pytest -q
```

32 test chạy hoàn toàn offline — không cần Docker, không gọi API, không cần mạng.

## Kiến trúc

```
scan.py (CLI)  ─┐
api/ (dashboard)─┴─> cùng một bộ hàm bên dưới, cùng một database
   │
   ├── scanners/   Nikto + ZAP qua Docker, chạy song song -> chuẩn hoá -> gom trùng
   ├── analyzer/   Claude structured output: đánh giá lại + sinh bản vá + cache
   ├── report.py   Dựng context và render HTML (Jinja2, autoescape bắt buộc)
   ├── core/       Hai "hợp đồng" dùng chung: models.Finding và db (SQLite)
   ├── web/        Template dashboard + báo cáo (chung partial _findings.html)
   ├── lab/        Ba target: Juice Shop, nginx proxy, vulnapp Flask
   └── eval/       Ground truth + đo precision/recall
```

### Hai hợp đồng — không tự ý sửa

| File | Vai trò |
|---|---|
| `core/models.py` | Schema `Finding` — mọi module nói chuyện với nhau qua đây |
| `core/db.py` | Schema SQLite — 4 bảng: `scans`, `findings`, `analyses`, `labels` |

### `fingerprint` — điểm thiết kế cốt lõi

`sha256(source | mã_plugin)`, cắt còn 16 ký tự. Một trường làm bốn việc:

1. gom trùng trong một lần quét
2. so sánh giữa hai lần quét — diff chỉ là phép toán tập hợp
3. khoá cache kết quả AI — quét lại target cũ gần như miễn phí
4. khoá join với bảng ground truth khi đánh giá độ chính xác

**URL cố ý không nằm trong khoá.** Đo thật trên Juice Shop: test "backup/cert file found"
của Nikto khớp **140 URL khác nhau**. Nếu tính cả đường dẫn thì thành 140 lỗ hổng riêng biệt,
trong khi thực chất là *một* vấn đề với *một* bản vá — vừa làm báo cáo không đọc nổi, vừa
vượt `max_tokens` khi gửi lên API. Với khoá hiện tại: 163 phát hiện thô → 18 lỗ hổng.

Số URL bị ảnh hưởng không mất đi: xem `count` (số thật) và `urls` (5 mẫu). Cách này cũng làm
diff giữa hai lần quét bền hơn — quét lại target không đổi cho ra diff rỗng hoàn toàn.

## Ghi chú kỹ thuật (đã xử lý sẵn, đừng "sửa lại")

- **Exit code khác 0 không phải lỗi.** Cả Nikto lẫn ZAP trả exit code khác 0 khi *tìm thấy*
  lỗ hổng (ZAP: 1=WARN, 2=FAIL). Điều kiện thành công là file JSON tồn tại và parse được.
- **Output Docker ghi vào `%TEMP%`, không ghi vào thư mục dự án.** Đường dẫn dự án có dấu
  cách (`IT Learning`, `Cyber security`) làm bind mount hay gãy.
- **`localhost` được đổi thành `host.docker.internal`** khi truyền vào container. URL gốc
  vẫn giữ để hiển thị.
- **Jinja2 `autoescape=True` là bắt buộc** ở cả `report.py` lẫn dashboard. Evidence và URL
  là dữ liệu do target kiểm soát; nhúng thô vào HTML là tự tạo XSS ngay trong báo cáo của
  mình. Có test canh việc này.
- **htmx được vendor vào `web/static/`**, không lấy từ CDN — hôm demo mất mạng vẫn chạy.
- **Không có đăng nhập trên dashboard.** Nó chạy được lệnh `docker` nên tuyệt đối không
  expose ra ngoài mạng; nếu cần, phải thêm xác thực trước.

## Giới hạn đã biết

- ZAP `baseline` chỉ quét passive → không vào được phần sau màn login của Juice Shop.
  Profile `authenticated` chưa làm.
- Nikto không xếp hạng mức độ nghiêm trọng, mọi phát hiện đều vào `Info` rồi để AI đánh giá lại.
- Tiến trình quét giữ trong bộ nhớ → khởi động lại server thì mất log, nhưng kết quả quét
  không mất vì đã nằm trong SQLite.
- **Mọi bản vá do AI đề xuất đều chưa được kiểm chứng tự động.** Phải đối chiếu với bằng
  chứng thô và thử trên lab trước khi áp dụng. Báo cáo ghi rõ điều này ở từng lỗ hổng.
