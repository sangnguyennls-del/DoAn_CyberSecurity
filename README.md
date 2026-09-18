# AI hỗ trợ quét lỗ hổng bảo mật Web

Đồ án môn **Nhập môn đảm bảo an ninh thông tin**.

Nối hai công cụ quét lỗ hổng (**Nikto** + **OWASP ZAP**) với một **mô hình ngôn ngữ**
(**Claude** hoặc **DeepSeek**) để tự động phân tích kết quả scan và đề xuất bản vá cụ thể.

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

Yêu cầu: **Docker Desktop** (đang chạy), **Python 3.12+**, và API key của ít nhất một
provider (**Anthropic** hoặc **DeepSeek**).

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env      # rồi điền API key vào .env
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

## Chọn mô hình: Claude hay DeepSeek

```powershell
python scan.py http://localhost:3000 --provider claude
python scan.py http://localhost:3000 --provider deepseek
```

Mặc định lấy từ `AI_PROVIDER` trong `.env` (không đặt thì là `claude`). Dashboard có ô chọn
tương ứng.

| | Claude (`claude-opus-5`) | DeepSeek (`deepseek-v4-pro`) |
|---|---|---|
| Ràng buộc đầu ra | **Strict JSON schema** — API bảo đảm đúng schema | Chỉ JSON mode lỏng (`json_object`) |
| Xử lý ở phía ta | Không cần validate | Nhét schema vào prompt, tự validate, **thử lại 1 lần** |
| Giá / 1M token | $5 vào / $25 ra | ~$0.66–1.32 vào / ~$1.98–3.96 ra |

Khác biệt quan trọng nhất **không phải giá mà là ràng buộc đầu ra**. DeepSeek không có strict
schema, nên JSON hỏng là chuyện có thật — tài liệu của họ còn cảnh báo *"the API may
occasionally return empty content"*. Với đồ án này điều đó đáng lo hơn bình thường: đầu ra
của AI **chính là dữ liệu** để đo precision/recall, nên vài phân tích rơi lặng lẽ sẽ làm lệch
số liệu đánh giá mà không ai biết.

Vì vậy nhánh DeepSeek validate bằng Pydantic, thử lại một lần có kèm thông báo lỗi cho model
tự sửa, và nếu vẫn hỏng thì **báo rõ số lượng nhận được** thay vì im lặng (`... chỉ phân tích
15/18 lỗ hổng mới`). Schema trong prompt được sinh thẳng từ `analyzer/schema.py`, không chép
tay, nên không thể lệch.

### So sánh hai mô hình — dùng luôn làm nội dung báo cáo

Cache khoá theo `(fingerprint, model)` nên chạy được cả hai trên **cùng một lần quét**, rồi
chấm điểm riêng từng bên trên **cùng một bộ nhãn thủ công**:

```powershell
python scan.py http://localhost:3000 --provider claude
python scan.py http://localhost:3000 --provider deepseek   # dùng lại findings đã có

python -m eval.export 4                        # gán nhãn MỘT lần, dùng cho cả hai
python -m eval.metrics 4 claude-opus-5
python -m eval.metrics 4 deepseek-v4-pro
```

Cùng lỗ hổng, cùng ground truth, chỉ khác mô hình — đây là so sánh có nghĩa, và là thứ biến
đồ án từ "chúng em dùng AI" thành "chúng em đo được AI nào tốt hơn cho việc này".

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

42 test chạy hoàn toàn offline — không cần Docker, không gọi API, không cần mạng.

## Kiến trúc

```
scan.py (CLI)  ─┐
api/ (dashboard)─┴─> cùng một bộ hàm bên dưới, cùng một database
   │
   ├── scanners/   Nikto + ZAP qua Docker, chạy song song -> chuẩn hoá -> gom trùng
   ├── analyzer/   Gọi Claude hoặc DeepSeek: đánh giá lại + sinh bản vá + cache
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
3. khoá cache kết quả AI — quét lại target cũ gần như miễn phí
4. khoá join với bảng ground truth khi đánh giá độ chính xác

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
