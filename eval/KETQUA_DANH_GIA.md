# Kết quả đánh giá AI so với nhãn thủ công

Hai đợt. Đợt 1: 46 cặp trên hai target vá được (nginx, vulnapp). Đợt 2: thêm 69 cặp trên
OWASP Mutillidae II, xem mục "Mở rộng" bên dưới. Số gộp cả ba target:

```
python -m eval.metrics all
```

| | Precision | Recall | Accuracy |
|---|---|---|---|
| Đợt 1 (46 cặp) | 100% (5/5) | 17% (5/30) | 46% (21/46) |
| **Gộp ba target (115 cặp)** | **86,7% (13/15)** | **25,5% (13/51)** | 65,2% (75/115) |

## Mẫu và cách gán (đợt 1)

46 cặp (finding, target), lấy từ bốn lần quét:

| Target | Trước vá | Chỉ xuất hiện sau vá | Tổng |
|---|---|---|---|
| nginx trước Juice Shop, `:8080` | #9: 22 | #17: 3 | 25 |
| vulnapp Flask, `:5000` | #20: 19 | #21: 2 | 21 |

- Một người gán (`sangnl`), theo quy trình trong `HUONG_DAN_GAN_NHAN.md`. Các finding trước vá
  được kiểm trên lab chưa vá; các finding chỉ có sau vá được kiểm trên lab đã vá.
- Bằng chứng thu bằng `eval/evidence.py`, lưu ở `eval/bang_chung/`. File chỉ chứa lệnh và kết
  quả thô. Phiếu gán nhãn không có cột kết luận của AI.
- Quy tắc: `1` = điểm yếu thật; `0` = không, chia hai loại: `FP-sai` (scanner khẳng định sai)
  và `FP-info` (quan sát đúng nhưng không phải điểm yếu trong bối cảnh này).
- Một nhãn được đổi **trước khi** chạy bất kỳ số liệu nào: "Cross-Domain Misconfiguration" từ
  `1` sang `0`. Lần kiểm tính nhất quán cho thấy nó và "Retrieved access-control-allow-origin
  header: \*" dựa trên cùng một quan sát (`Access-Control-Allow-Origin: *` trên `:8080`) nhưng
  mang nhãn ngược nhau.

Phân bố nhãn: 16 lỗ hổng thật, 30 không phải (4 `FP-sai`, 26 `FP-info`).

---

## Chỉ số chính (đợt 1)

Định nghĩa đặt từ trước khi gán (`eval/metrics.py`): Positive = "đây là false positive"; AI
dự đoán Positive khi `false_positive_risk = "Cao"`.

Gộp trên 46 cặp duy nhất:

|  | AI nói FP | AI nói thật |
|---|---|---|
| Thật sự là FP | 5 | 25 |
| Thật sự là lỗ hổng | **0** | 16 |

| Chỉ số | Giá trị |
|---|---|
| Precision | 100% (5/5) |
| Recall | 17% (5/30) |
| Accuracy | 46% (21/46) |

AI **không bác nhầm lỗ hổng thật nào**. Đây là tính chất quan trọng nhất với một công cụ bảo
mật: bỏ sót nhiễu chỉ tốn thời gian đọc, còn bác nhầm lỗ hổng thật là bỏ lọt rủi ro. Nhưng 5
mẫu Positive là quá ít để khẳng định AI "không bao giờ" bác nhầm.

Theo từng lần quét (`python -m eval.metrics <id>`), các lần quét trùng mẫu nhau nên không cộng
được:

| Lần quét | Precision | Recall |
|---|---|---|
| #9 | 3/3 | 3/17 |
| #17 | 2/2 | 2/15 |
| #20 | 1/1 | 1/8 |
| #21 | 2/2 | 2/4 |

---

## Recall thấp đến từ đâu

Tách theo loại nhãn, AI trả `false_positive_risk` như sau:

| Nhãn của người | n | AI: Cao | Trung bình | Thấp |
|---|---|---|---|---|
| `FP-sai` | 4 | 3 | 1 | 0 |
| `FP-info` | 26 | 2 | 4 | 20 |
| Lỗ hổng thật | 16 | 0 | 2 | 14 |

Khi scanner **khẳng định sai**, AI bắt được 3/4. Khi scanner **quan sát đúng nhưng không đáng
lo**, AI gần như không gọi đó là false positive (2/26). Recall thấp đến gần như hoàn toàn từ
nhóm thứ hai.

Nguyên nhân nằm ở câu hỏi, không nằm ở mô hình. Prompt yêu cầu AI ước lượng false positive
theo độ mạnh của bằng chứng ("nếu bằng chứng yếu, hãy nói rõ là yếu"), tức là hỏi "scanner có
nói sai không". Quy tắc gán nhãn thì tính cả `FP-info` là `0`, tức là hỏi "có đáng lo không".
Hai trường đang đo hai câu hỏi khác nhau.

AI trả lời câu "có đáng lo không" ở một trường khác là **mức độ nghiêm trọng**. Đây là phân
tích làm sau khi thấy số liệu, không thay cho chỉ số chính:

| Nhãn của người | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Lỗ hổng thật (16) | 1 | 4 | 5 | 6 | **0** |
| `FP-info` (26) | 0 | 0 | 2 | 12 | 12 |
| `FP-sai` (4) | 0 | 0 | 2 | 1 | 1 |

24/26 dòng `FP-info` được AI xếp Low hoặc Info, và không lỗ hổng thật nào bị xếp Info. Hai
ngoại lệ là hai dòng CORS, xem phần thảo luận.

Hướng sửa cho vòng sau, chọn một trong hai: thêm vào schema một trường riêng "có cần xử lý
không" để so với nhãn hiện tại; hoặc gán nhãn hai câu hỏi tách biệt (scanner đúng/sai, đáng
lo/không) và đo mỗi trường AI với đúng câu hỏi của nó. Không đổi quy tắc gán cho mẫu này sau
khi đã thấy kết quả.

### Độ nhạy theo ngưỡng

Chỉ để tham khảo, không thay định nghĩa chính. Nếu tính cả "Trung bình" là AI nói FP:
precision 83% (10/12), recall 33% (10/30). Hai lỗ hổng thật khi đó bị tính nhầm là
"Dangerous JS Functions" và "Cross Site Scripting (DOM Based)", cũng là hai ca người gán phải
phán đoán nhiều nhất. Mức "Trung bình" của AI rơi đúng vào những chỗ khó.

---

## Ca đáng thảo luận

Lời của AI dưới đây trích nguyên văn từ phân tích lưu trong DB (xem trên dashboard), không
phải suy diễn.

**CORS `Access-Control-Allow-Origin: *` trên Juice Shop.** Người gán `0 FP-info` cả hai dòng:
endpoint thử (`/rest/products/search`) trả danh mục sản phẩm công khai, không có
`Access-Control-Allow-Credentials`, nên trang của origin khác không đọc được phản hồi của
request có kèm credential. AI xếp Medium, rủi ro FP Thấp. AI đồng ý phần credential ("với
ACAO: * thì browser KHÔNG gửi cookie/credential kèm theo… nên kẻ tấn công không đọc được dữ
liệu riêng tư cần đăng nhập") nhưng nêu một rủi ro khác: "Nếu ứng dụng chạy trên
localhost/mạng nội bộ, đây là con đường để website bên ngoài dò và trích xuất nội dung dịch vụ
nội bộ vốn không expose ra Internet." Bất đồng thật nằm ở điểm này: app lab chạy trên
`localhost`.

**"This might be interesting" trên `/public/`.** Người gán `FP-sai`: URL trả về cùng mã,
cùng kiểu, cùng 9393 byte với một đường dẫn không tồn tại. Đó là trang `index.html` mà Juice
Shop (Express) trả cho mọi đường dẫn lạ; nginx ở đây chỉ `proxy_pass`, không có `try_files`.
AI để rủi ro FP "Trung bình" và chính nó đã nêu khả năng này: "Nikto chỉ báo 'might be
interesting' dựa trên việc response khác 404, nó KHÔNG khẳng định có directory listing. Có
thể server trả 301 redirect, trả 403, hoặc trả index.html". Đây là dòng `FP-sai` duy nhất AI
không xếp "Cao".

**XSS DOM trên vulnapp.** Người gán giữ `1`: target có XSS thật, payload phản chiếu nguyên
văn ở `/greet`. Phân loại "DOM-based" thì không khớp app: vulnapp không có dòng JavaScript
nào (0 thẻ `<script>`, 0 thuộc tính `on...=`), và payload của ZAP nằm sau dấu `#`. AI để rủi
ro FP "Trung bình" với lý do: "trường evidence RỖNG… Rất có thể đây là hệ quả lan sang từ
Reflected XSS đã xác nhận ở /search và /greet (ZAP đôi khi báo trùng)". Thí nghiệm ở lần quét
#22 ủng hộ cách hiểu này: chỉ thêm CSP chặn script nội tuyến lên bản chưa vá thì cảnh báo XSS
DOM biến mất, còn XSS phản chiếu vẫn còn.

**Mức độ trên 16 lỗ hổng thật.** AI đổi mức ở 9/16 dòng. Phần lớn là từ Info đi lên, vì Nikto
không xếp hạng gì cả và để mọi thứ ở Info. Đáng chú ý: hai dòng `/ftp/` đi từ Info lên High
(thư mục liệt kê được cả `coupons_2013.md.bak`, `encrypt.pyc`), SQL injection từ High lên
Critical, "Dangerous JS Functions" từ Low lên High.

---

## Mở rộng: Mutillidae và kết quả gộp ba target

### Mẫu

Lần quét #24 (`http://localhost:8090`, OWASP Mutillidae II, image `citizenstig/nowasp`, Apache
2.4.7 + PHP 5.5.9, profile `full`): 341 phát hiện thô -> 72 lỗ hổng (28 Nikto, 44 ZAP). Cả 72
có phân tích AI. 69 dòng gán được; 3 dòng để trống vì không đủ dữ kiện (Path Traversal,
Dangerous JS Functions, User Controllable Charset) và bị loại khỏi mẫu.

- Hai người gán chia nhau các dòng (`sangnl` 44, `tinnt` 28 lúc nộp), không gán trùng.
- Không có vòng lặp vá nên `patch_ok` để trống cả 72 dòng.
- Phân bố: 48 lỗ hổng thật, 21 không (7 `FP-sai`, 14 `FP-info`).
- Bằng chứng: `bang_chung/scan_24.md` (tự động) và `bang_chung/scan_24_bo_sung.md` (9 dòng khó,
  phần lớn do người gán tự kiểm trên trình duyệt).

### Chỉ số

| Target | n | Precision | Recall |
|---|---|---|---|
| vulnapp `:5000` | 21 | 2/2 | 2/10 |
| nginx `:8080` | 25 | 3/3 | 3/20 |
| Mutillidae `:8090` | 69 | 8/10 | 8/21 |
| **Gộp** | **115** | **13/15 (86,7%)** | **13/51 (25,5%)** |

Khả năng FP do AI đưa ra, theo loại nhãn (gộp):

| Nhãn của người | n | AI: Cao | Trung bình | Thấp |
|---|---|---|---|---|
| `FP-sai` | 11 | 7 | 3 | 1 |
| `FP-info` | 40 | 6 | 8 | 26 |
| Lỗ hổng thật | 64 | 2 | 13 | 49 |

Mức độ AI đánh giá, theo loại nhãn (gộp):

| Nhãn của người | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Lỗ hổng thật (64) | 3 | 16 | 19 | 23 | 3 |
| `FP-info` (40) | 0 | 0 | 3 | 17 | 20 |
| `FP-sai` (11) | 0 | 2 | 4 | 3 | 2 |

Mẫu hình của đợt 1 giữ nguyên trên target thứ ba: AI bắt `FP-sai` tốt (7/11) hơn hẳn `FP-info`
(6/40), và báo hiệu "không đáng lo" qua mức độ (37/40 dòng `FP-info` ở Low/Info). Ngưỡng rộng
(tính cả "Trung bình"): precision 61,5% (24/39), recall 47,1% (24/51).

### Hai lỗ hổng thật bị AI xếp FP "Cao"

Precision 100% của đợt 1 không giữ được. Hai ca, trích nguyên văn phân tích trong DB:

**SQL Injection - MySQL (Time Based), phpMyAdmin.** Người gán `1`: phpMyAdmin vào thẳng bằng
root không mật khẩu, SQL do ZAP gửi đã chạy thật (94 database). AI xếp rủi ro FP "Cao" nhưng
mức độ **High**, với lý do: "phpMyAdmin theo thiết kế nhận tham số sql_query và thực thi đúng câu
SQL đó — ZAP gửi payload vào đây thì tất nhiên SQL được chạy, nhưng đó là chức năng chứ không
phải lỗ hổng injection … Tuy vậy mình vẫn giữ mức High, không phải vì tin cảnh báo injection, mà
vì bằng chứng này phơi bày một sự thật nghiêm trọng hơn: phpMyAdmin đang mở công khai". Người và
AI thống nhất về bản chất; chỉ khác ở chỗ trường FP của AI trả lời "ZAP gọi tên có đúng không",
còn nhãn trả lời "có điểm yếu thật không". Cùng hiện tượng với ca XSS DOM ở đợt 1.

**Information Disclosure - Suspicious Comments.** Người gán `1` ("lộ comment nội bộ của lập trình
viên"). AI xếp FP "Cao", mức Low: kiểm tra theo từ khoá, "nhiều khả năng là một comment mang tính
giảng dạy trong Mutillidae". Bất đồng thật; comment nằm trong file tài liệu
`documentation/Mutillidae-Test-Scripts.txt`.

### Target bị chính active scan làm hỏng

- phpMyAdmin 3.5.2.2 trong image đăng nhập MySQL bằng root không mật khẩu. Active scan của ZAP đi
  qua đó và chạy SQL thật: MySQL có 94 database, phần lớn mang tên payload của ZAP.
- Lúc quét #24 và lúc gán nhãn, mọi trang của Mutillidae chuyển sang `database-offline.php`
  ("Access denied for user 'admin'"); tài khoản MySQL mà ứng dụng dùng không còn. Chưa xác định
  được nguyên nhân mất tài khoản.
- Lần quét #23 (trước đó, dừng giữa chừng vì chi phí) có 116 dòng "RFI from RSnake's RFI list"; #24
  không có dòng nào. Giả thuyết chưa kiểm chứng: `index.php` chỉ còn chuyển hướng nên các test RFI
  không khớp.
- Nhãn gán theo trạng thái lúc quét #24, nên phép đo vẫn nhất quán; nhưng đây là một target đã
  hỏng, không phải Mutillidae nguyên bản.
- Sau khi chốt nhãn, container được dựng lại từ image gốc (4 database, trang chủ trả 200). Trong
  container mới, `MySQLHandler.php` được ghi lại 6 giây sau khi khởi động và tài khoản `admin` là
  của chính image: file cấu hình không bị ai sửa tay; tài khoản `admin` mất sau khi container cũ
  khởi động, nguyên nhân chưa xác định. Chi tiết: `bang_chung/scan_24_bo_sung.md`.

### Chi phí

| Lần | Phân tích | Token vào / ra | Ước tính |
|---|---|---|---|
| #23 (dừng sau 9/32 lô) | 54/190 | 48.252 / 105.916 | ≈ 2,9 USD |
| #24 (46 lấy từ cache) | 26 + 6 chạy lại | 27.106 / 51.663 | ≈ 1,4 USD |

Chạy hết #23 với khoá gom trùng cũ sẽ tốn khoảng 10 USD, phần lớn cho 116 dòng RFI gần như giống
hệt nhau. Khoá Nikto giờ gom họ này về một dòng (có test hồi quy); chưa thử lại trên lần quét thật
vì RFI không xuất hiện ở #24.

---

## Chất lượng bản vá

`patch_ok` gán cho 16 lỗ hổng thật; lý do từng dòng ở cột `note_patchok`. Quy tắc: `1` nếu áp
đoạn vá của **chính dòng đó** thì finding biến mất và chức năng không hỏng (được đổi tên cho
khớp app thật); `0` nếu dán nguyên văn thì lỗi, sai tầng, hoặc không có tác dụng; để trống nếu
không áp thử được.

**13/15 bản vá dùng được (87%)**, một dòng để trống.

| Cách kiểm chứng | Dùng được | Không |
|---|---|---|
| A. Áp trong vòng lặp vá → quét lại | 7 | 2 |
| B. Áp riêng đoạn vá lên bản chưa vá, chạy thật, đo header và chức năng | 6 | 0 |
| C. Không áp thử được (Dangerous JS Functions: sửa mã Angular của Juice Shop) | (để trống) | |

| Target | Dùng được |
|---|---|
| nginx trước Juice Shop, `:8080` | 3/4 |
| vulnapp Flask, `:5000` | 10/11 |

Loại B cần vì trong vòng lặp, nhóm gom mọi header vào một khối, nên nhiều finding biến mất nhờ
đoạn vá của dòng **khác**; vòng lặp không chứng minh được gì cho đoạn vá của chính dòng đó. Để
có kết quả thay vì để trống, từng đoạn vá được dán riêng vào `app.py.chuava.bak`, chạy thật,
rồi kiểm header bằng HTTP và kiểm `/search`, `/greet` còn trả đúng. Cả 5 đoạn vá header đều
chạy, kể cả hai đoạn dán nguyên văn cả dòng `app = Flask(__name__)` ngay sau dòng tạo app có
sẵn.

Hai bản vá không dùng được, mỗi cái một kiểu lỗi:

- **Dán nguyên văn thì app không chạy.** CSP trên vulnapp: `from flask import ..., escape`
  báo `ImportError` trên Flask 3.1.3.
- **Sai tầng.** "This might be interesting" (`/ftp/`) trên `:8080`: đoạn vá chính viết cho
  Express (mã Juice Shop), phương án nginx chỉ nằm trong comment. Phân tích này sinh trước
  khi sửa lỗi nhận diện ngăn xếp.

Một bản vá được tính là dùng được nhưng cần nói rõ giới hạn: **XSS DOM** trên vulnapp. Phần
CSP của đoạn vá làm cảnh báo biến mất và không hỏng chức năng, nên đạt quy tắc. Nhưng phần
JavaScript nhắm `static/app.js` không tồn tại, XSS phản chiếu gốc vẫn còn (CSP chỉ chặn việc
thực thi trong trình duyệt), và CSP đó sinh thêm "CSP: Failure to Define Directive with No
Fallback" (Medium). Quy tắc `patch_ok` đo "finding có biến mất không", không đo "lỗ hổng gốc
có được sửa không", và ca này cho thấy hai điều đó có thể khác nhau.

Ảnh hưởng của 18 phân tích sinh trước khi sửa prompt: sau khi lọc về 16 lỗ hổng thật, chỉ 4
dòng dùng chúng (đều ở `:8080`); 3 dòng gán được, 2/3 dùng được. Không sinh lại, vì chi phí
(khoảng 27.000đ) không tương xứng với 3 dòng. Phân tích sinh sau khi sửa: 11/12.

## Nhật ký chỉnh sửa phiếu

Mọi thay đổi sau lần gán đầu, theo thứ tự. Ảnh chụp phiếu ở từng mốc nằm trong
`eval/bang_chung/`: `phieu_1_sau_luot_1.csv` (ngay sau khi gán xong lượt 1, 41 dòng) và
`phieu_2_truoc_khi_claude_sua.csv` (46 dòng, đủ `patch_ok` và `note_patchok` do người gán điền).

1. Trước khi chạy số liệu, người gán đổi "Cross-Domain Misconfiguration" từ `1` sang `0 FP-info`
   sau khi kiểm tính nhất quán (xem phần mẫu).
2. Sau khi xem số liệu `is_true_positive`, người gán xem lại ca XSS DOM và giữ `1`.
3. Ngày 19/09, theo yêu cầu người gán, Claude:
   - sửa ba ghi chú `note` bị chép nhầm dòng (hai dòng Nikto ghi "Thiếu Referrer-Policy" cho
     header khác; dòng CSP của `:5000` nhắc "port 8080");
   - viết lại `note` của XSS DOM theo lập luận người gán dùng để giữ `1`;
   - đổi `patch_ok` của 5 dòng loại B từ `0` sang `1` dựa trên thử riêng từng đoạn vá (người
     gán đánh `0` với lý do "không được dùng trực tiếp", tức chưa áp thử);
   - đổi `patch_ok` của Dangerous JS Functions từ `0` sang trống (không áp thử được);
   - đánh dấu "phân tích trước khi sửa prompt" cho 4 dòng `:8080`.
   Mỗi thay đổi `patch_ok` có ghi "(Claude đổi từ 0)" trong `note_patchok`. Không đổi
   `is_true_positive` nào.
4. Người gán xem kết quả thử riêng bản vá XSS DOM (lần quét #22) và đổi `patch_ok` từ `0`
   sang `1`: cảnh báo biến mất, chức năng không hỏng.

Đợt 2 (Mutillidae, 19/09):

5. Phiếu nộp có nhãn nằm nhầm ở cột `patch_ok` (ghi chú "FP-sai"/"FP-info" đi kèm số 0). Người
   gán xác nhận điền nhầm cột; Claude chuyển 72 dòng sang `is_true_positive`, để trống
   `patch_ok`. Bản nộp nguyên trạng: `bang_chung/phieu_3_mutillidae_nguyen_ban.csv`.
6. 9 dòng ghi "không thể kiểm chứng" được thu thêm bằng chứng (`bang_chung/scan_24_bo_sung.md`),
   phần lớn do người gán tự làm trên trình duyệt theo hướng dẫn, chỉ dùng chuỗi đánh dấu vô hại.
7. Đính chính bằng chứng dòng XSS Reflected: lần thu đầu dùng token phiên của ZAP trong phiên khác,
   phpMyAdmin bỏ tham số, nên kết luận "không phản chiếu" là sai. Nhãn `0 FP-sai` đã được gán khi
   chỉ có kết quả sai đó; người gán kiểm lại với phiên hợp lệ (tham số có phản chiếu, dấu `"` vẫn là
   `%22`) và giữ nhãn; ghi chú viết lại theo dữ kiện đúng.
8. Gán 6/9 dòng sau khi có bằng chứng: người gán đưa nhãn 0/1; loại `FP-sai`/`FP-info` quy theo
   quy tắc đã thống nhất, người gán duyệt bảng trước khi Claude ghi vào phiếu. 3 dòng để trống.
   Ảnh chụp phiếu lúc này: `bang_chung/phieu_4_mutillidae_chot.csv`.
9. Kiểm tính nhất quán có hệ thống (mọi tên cảnh báo có ở từ hai target): "Modern Web Application"
   `:8090` mang `1` trong khi `:8080` là `0 FP-info` cho cùng một cảnh báo thông tin. Người gán đổi
   `:8090` sang `0 FP-info`. Bước này chạy sau khi Claude đã chạy thử lệnh tính gộp (để kiểm nó
   tái lập đúng số đợt 1) nhưng trước khi người gán thấy số liệu nào.

## Hạn chế

- Chưa đo đồng thuận giữa các người gán: đợt 1 một người gán; đợt 2 hai người chia nhau các dòng,
  không gán trùng.
- Mutillidae bị hỏng trong lúc quét (mục "Target bị chính active scan làm hỏng"); 3 dòng của nó để
  trống; phân bố nhãn nghiêng về lỗ hổng thật (48/69) vì đây là ứng dụng cố ý có lỗ hổng.
- `patch_ok` của 6 dòng (5 loại B và XSS DOM) dựa trên thử nghiệm tự động do Claude chạy; kết
  quả là dữ kiện đo được (header có mặt, chức năng còn chạy), nhưng người thực hiện không phải
  người gán.
- Mẫu nhỏ: 115 cặp, trong đó 11 `FP-sai` và 15 dự đoán Positive.
- Ranh giới `FP-info` với `1` ở nhóm "thiếu header" phụ thuộc quy tắc người gán tự chốt.
- Cả ba target đều do nhóm dựng hoặc chọn; vulnapp và Mutillidae cố ý có lỗ hổng.
- Các lần quét dùng profile baseline (nginx) hoặc full (vulnapp, Mutillidae); chưa có lần quét full nào
  trên Juice Shop.
