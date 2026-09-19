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
docker run --rm -d -p 127.0.0.1:3000:3000 --name juiceshop bkimminich/juice-shop
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

## Quét có đăng nhập

`baseline` và `full` chỉ thấy phần công khai. Profile `auth` để ZAP đăng nhập trước rồi mới
quét, nhờ đó chạm được phần sau màn login (giỏ hàng, thông tin cá nhân, API của user).

```powershell
# Tạo một tài khoản trên chính target lab, rồi điền vào .env:
#   ZAP_AUTH_USER=... / ZAP_AUTH_PASS=...
python scan.py http://localhost:3000 --profile auth
```

Dùng ZAP Automation Framework (`scanners/zap_auth.yaml`) với `spiderAjax` — Juice Shop là SPA
Angular nên spider thường chỉ thấy `index.html` (đo thật: 149 URL so với 1.077 URL của
spiderAjax). Mặc định cấu hình cho Juice Shop; target khác thì đè bằng `ZAP_LOGIN_URL` /
`ZAP_LOGIN_BODY` / `ZAP_AUTH_CHECK_PATH`.

Tài khoản **không hardcode trong repo** — kể cả tài khoản lab, vì thói quen commit mật khẩu
rất dễ mang sang project thật.

**Đăng nhập được kiểm tra trước khi khởi động ZAP**, không phó mặc cho ZAP. Lý do: đã thử để
ZAP tự kiểm bằng job `requestor` với `failOnError: true`, nhưng đo thật với mật khẩu sai thì
ZAP coi lệch response code là *warning* — nó vẫn crawl hết và vẫn sinh báo cáo. Kết quả là một
lần quét **ẩn danh trông y hệt** lần quét có đăng nhập. Với một đồ án lấy bằng chứng làm trung
tâm thì đó là kiểu hỏng tệ nhất: không báo lỗi, chỉ âm thầm sai.

Nên công cụ tự đăng nhập thử, lấy token, gọi một endpoint cần quyền (`/api/Cards` — trả 401
khi chưa đăng nhập; `/rest/user/whoami` **không** dùng được vì trả 200 cả hai trường hợp).
Hỏng thì dừng ngay dưới 1 giây kèm thông báo rõ, ZAP bị bỏ qua còn Nikto vẫn chạy.

Đo thật trên Juice Shop — `auth` tìm thêm 7 lỗ hổng mà `baseline` bỏ sót, gồm
`Session ID in URL Rewrite` (Medium) và `Application Error Disclosure`. Hai mục
`Authentication Request Identified` / `Session Management Response Identified` là bằng chứng
ZAP đã thật sự nhận ra luồng đăng nhập.

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

59 test chạy hoàn toàn offline — không cần Docker, không gọi API, không cần mạng.

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

`sha256(source | mã_biến_thể)`, cắt còn 16 ký tự. Một trường làm bốn việc:

1. gom trùng trong một lần quét
2. so sánh giữa hai lần quét — diff chỉ là phép toán tập hợp
3. khoá cache kết quả AI, **ghép với target** — quét lại target cũ gần như miễn phí
4. khoá join với ground truth, **ghép với target**

Hai việc sau từng dùng fingerprint trơn và đó là lỗi đo được: cache dùng chung giữa các
target, nên vulnapp (Flask) được phục vụ bản vá nginx sinh cho target `:8080`, và báo cáo
khuyên `server_tokens off` cho một app không có nginx. Cùng một lỗ hổng nhưng bản vá phụ
thuộc ngăn xếp, nên khoá cache giờ là `(fingerprint, model, target)`. Dòng cache cũ không
rõ target được giữ lại với `target=''` và không bao giờ được dùng.

**URL cố ý không nằm trong khoá.** Đo thật trên Juice Shop: test "backup/cert file found"
của Nikto khớp **140 URL khác nhau**. Nếu tính cả đường dẫn thì thành 140 lỗ hổng riêng biệt,
trong khi thực chất là *một* vấn đề với *một* bản vá — vừa làm báo cáo không đọc nổi, vừa
vượt `max_tokens` khi gửi lên API. Với khoá hiện tại: 163 phát hiện thô → 18 lỗ hổng.

Số URL bị ảnh hưởng không mất đi: xem `count` (số thật) và `urls` (5 mẫu). Cách này cũng làm
diff giữa hai lần quét bền hơn — quét lại target không đổi cho ra diff rỗng hoàn toàn.

**Khoá dùng `alertRef` chứ không phải `pluginid`.** Một plugin ZAP phát ra nhiều biến thể
khác hẳn nhau: `CSP: Failure to Define Directive with No Fallback` và
`CSP: script-src unsafe-inline` đều là pluginid `10055` nhưng alertRef khác nhau. Nếu gom
theo pluginid, trang so sánh sẽ báo "không có gì thay đổi" trong khi vấn đề đã đổi hẳn —
tức là **bằng chứng "đã vá" của đồ án trở thành sai**. Có test hồi quy canh việc này.

**Với Nikto, khoá có thêm phần nằm trong dấu nháy đơn.** Nikto dùng chung một id cho mọi
header lạ, nên `'x-recruiting'` (đã vá) và một header mới xuất hiện từng gộp làm một, và
trang so sánh báo "còn tồn tại" cho thứ đã vá xong. Tên header, entry robots.txt nằm trong
nháy; URL thì không, nên không làm bung lại ca 140 URL ở trên.

## Vì sao dùng Claude

Dùng `messages.stream(..., output_format=ReportOut)` — **API bảo đảm đầu ra đúng schema**,
không cần validate hay thử lại ở phía mình. Phải stream vì `max_tokens` lớn: SDK từ chối
gọi không-stream ở mức này. Findings được chia lô 6 cái một lần gọi, lô nào xong ghi cache
ngay, để một lô hỏng không làm mất tiền của các lô trước.

Đây là lý do chọn, chứ không phải tiện tay: đầu ra của mô hình **chính là dữ liệu đầu vào**
cho phần đánh giá định lượng ở `eval/`. Nếu vài phân tích rơi vì JSON hỏng thì precision và
recall bị lệch — và lệch *không ngẫu nhiên*, vì finding nào fail thường là finding có evidence
dài, ký tự lạ, tức đúng những ca biên đáng quan tâm nhất. Đó là lỗi phương pháp chứ không
phải lỗi code.

Claude cũng có `stop_reason == "refusal"` riêng, nên phân biệt được "mô hình từ chối" với
"lỗi kỹ thuật". Với đồ án mà đầu vào là dữ liệu lỗ hổng, số lần bị từ chối là một số liệu
đáng ghi vào báo cáo, không phải một bug cần giấu.

Chi phí đo trên dữ liệu thật (lần quét #9, 22 lỗ hổng): 18.437 token vào / 47.293 token ra,
khoảng **33.500đ**, tức chừng 1.500đ mỗi lỗ hổng. Phần lớn là token *ra*, vì mỗi lỗ hổng
kèm giải thích và đoạn mã vá. Quét lại cùng target chỉ trả tiền cho lỗ hổng mới xuất hiện:
lần quét lại #17 sau khi vá nginx chỉ gọi API cho 3/16 lỗ hổng.

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

- ZAP `baseline` chỉ quét passive. Dùng `--profile auth` để vào được phần sau màn login,
  `--profile full` để có active scan.
- Nikto không xếp hạng mức độ nghiêm trọng, mọi phát hiện đều vào `Info` rồi để AI đánh giá lại.
- Tiến trình quét giữ trong bộ nhớ → khởi động lại server thì mất log, nhưng kết quả quét
  không mất vì đã nằm trong SQLite.
- **Mọi bản vá do AI đề xuất đều chưa được kiểm chứng tự động.** Phải đối chiếu với bằng
  chứng thô và thử trên lab trước khi áp dụng. Báo cáo ghi rõ điều này ở từng lỗ hổng.
