# Hướng dẫn gán nhãn ground truth

Nhãn trong `ground_truth.csv` là thước đo duy nhất để trả lời "AI nói có đúng không".
Gán sai hoặc gán theo lời AI thì mọi con số precision/recall trong báo cáo đều vô nghĩa,
nên phần này đáng làm chậm và cẩn thận.

Tổng khối lượng: 46 dòng, khoảng 3-5 phút mỗi dòng, tức 3-4 giờ. Chia ra nhiều buổi.

---

## 1. Điền gì vào từng cột

### `is_true_positive`: trên target này, lúc quét, có điểm yếu bảo mật thật không?

| Giá trị | Nghĩa |
|---|---|
| `1` | Có điểm yếu thật. Sửa đi thì target an toàn hơn. |
| `0` | Không. Ghi vào `note` một trong hai mã dưới. |
| để trống | Không kiểm chứng được. Ghi lý do vào `note`. Dòng trống không được tính, và như vậy trung thực hơn là đoán. |

Hai loại `0`, phải tách ra vì báo cáo cần nói AI lọc được loại nào:

- `FP-sai`: scanner khẳng định một điều không đúng. Ví dụ: Juice Shop là SPA, trả trang
  chủ cho mọi đường dẫn lạ với mã 200, nên "tìm thấy file backup" thực ra là tìm thấy
  trang chủ.
- `FP-info`: scanner quan sát đúng, nhưng đó không phải điểm yếu trong bối cảnh này.
  Ví dụ: "thiếu HSTS" trên một trang chỉ chạy HTTP thuần, nơi HSTS không có tác dụng gì.

Tính cả `FP-info` là `0` vì nhãn trả lời câu hỏi "có đáng lo không". Lưu ý đo được sau khi
gán (xem `KETQUA_DANH_GIA.md`): trường `false_positive_risk` của AI **không** trả lời câu đó
mà trả lời "scanner có khẳng định sai không"; AI thể hiện "không đáng lo" qua mức độ nghiêm
trọng. Giả định ban đầu ở đây là sai. Quy tắc vẫn giữ cho mẫu đã gán, nhưng khi so phải tách
`FP-sai` và `FP-info`.

### `patch_ok`: bản vá AI đề xuất cho finding này có dùng được không?

| Giá trị | Nghĩa |
|---|---|
| `1` | Áp lên target thì finding biến mất (quét lại hoặc kiểm tay), và chức năng không hỏng. |
| `0` | Áp nguyên văn thì lỗi (crash, sai tầng), hoặc không làm finding biến mất, hoặc làm hỏng chức năng. Ghi lý do vào `note`. |
| để trống | Chưa áp thử, hoặc `is_true_positive = 0` (không có gì để vá). |

Được phép đổi *tên* cho khớp app thật (tên bảng, tên file template) vì AI không thấy mã
nguồn. Phải sửa *logic* mới chạy thì là `0`. Ví dụ đã đo được: snippet CSP của vulnapp
import `flask.escape`, dán nguyên văn thì app không khởi động, nên dòng đó là `0`.

Bằng chứng cho `patch_ok` của `:8080` và `:5000` phần lớn đã có sẵn trong
`lab/KETQUA_VONG_LAP.md`: finding nằm ở cột "đã vá" thì điều kiện "finding biến mất"
đã được chứng minh; các tác dụng phụ đo được cũng ghi ở đó.

### `note`, `note_patchok` và `labeled_by`

`note`: lý do cho `is_true_positive`: mã (nếu là 0), lý do ngắn, lệnh đã chạy. Dùng dấu `;`
thay dấu phẩy.
`note_patchok`: lý do cho `patch_ok` (cột người gán tự thêm; `eval.export` giữ nguyên mọi cột
người gán thêm vào).
`labeled_by`: tên người gán.

---

## 2. Quy trình hai lượt

**Bằng chứng đã gom sẵn.** `python -m eval.evidence <scan_id>` chạy các lệnh kiểm ở mục 4
cho mọi dòng chưa gán của lần quét đó và ghi kết quả thô vào `eval/bang_chung/scan_<id>.md`:
lệnh, mã HTTP, header có hay không, nội dung trả về. File chỉ có dữ kiện, không có kết luận.
Mở nó cạnh phiếu, đọc mục của dòng đang gán, trả lời hai câu hỏi ở mục 4 rồi điền. Chỗ nào
thấy bằng chứng chưa đủ thì tự chạy thêm lệnh.

**Lượt 1, chỉ điền `is_true_positive`. Chưa đọc phân tích AI.** Phiếu đã cố ý bỏ các cột
kết luận của AI. Trên dashboard, chỉ đọc cột bằng chứng thô bên trái, đừng đọc cột AI bên
phải. Đọc lời AI trước thì nhãn sẽ lệch theo AI, và precision đo ra cao giả tạo.

**Lượt 2, điền `patch_ok`.** Lúc này mới đọc bản vá AI và đối chiếu với
`KETQUA_VONG_LAP.md`.

Không quay lại sửa nhãn lượt 1 sau khi đã đọc AI. Nếu thật sự phát hiện mình sai, sửa và
ghi `sửa sau khi đọc AI` vào `note`, rồi nêu số dòng như vậy trong báo cáo.

---

## 3. Dựng lab đúng trạng thái. Bước dễ sai nhất.

Nhãn phải phản ánh target **lúc được quét**. Repo hiện đang ở trạng thái *đã vá*. Nếu
kiểm một finding của lần quét trước vá trên target đã vá, header đã có sẵn và bạn sẽ gán
nhầm thành false positive.

### Đợt 1: lần quét #9 và #20 (trước vá), 41 dòng, là phiếu hiện tại

```powershell
docker run --rm -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
docker rm -f lab-nginx
docker run --rm -d --name lab-nginx -p 8080:80 `
  -v "${PWD}\lab\nginx\nginx.conf.chuava.bak:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
python lab\vulnapp\app.py.chuava.bak        # cửa sổ riêng, để chạy suốt lúc gán
```

Kiểm chắc là đang ở bản chưa vá trước khi bắt đầu:

```powershell
curl.exe -sI http://localhost:8080/ | findstr /i "^server"
#   phải thấy: Server: nginx/1.31.5
curl.exe -s "http://localhost:5000/search?q=%27%20OR%20%271%27=%271" | findstr admin
#   phải thấy dòng admin@lab.local
```

### Đợt 2: lần quét #17 và #21 (sau vá), thêm khoảng 5 dòng

```powershell
python -m eval.export 17
python -m eval.export 21
```

Chỉ những finding *mới xuất hiện sau khi vá* được thêm vào. Finding có ở cả hai lần quét
đã có nhãn từ đợt 1, không gán lại. Đổi lab sang bản đã vá:

```powershell
docker rm -f lab-nginx
docker run --rm -d --name lab-nginx -p 8080:80 `
  -v "${PWD}\lab\nginx\nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
python lab\vulnapp\app.py                   # tắt bản chưa vá trước
curl.exe -sI http://localhost:8080/ | findstr /i "^server"
#   phải thấy: Server: nginx   (không có số phiên bản)
python -m eval.evidence 17                  # gom bằng chứng cho các dòng mới, trên bản ĐÃ VÁ
python -m eval.evidence 21
```

---

## 4. Cách kiểm từng loại finding

Trong PowerShell, gõ `curl.exe` chứ không gõ `curl`: `curl` trần là tên khác của
`Invoke-WebRequest`, cú pháp khác hẳn. Mỗi dòng của phiếu có sẵn cột `url` (đã đổi về
`localhost`, curl được ngay) và `evidence` (bằng chứng scanner ghi lại).

Với mỗi dòng, trả lời hai câu theo thứ tự:

```
(a) Điều scanner khẳng định có đúng không?   -- chạy lệnh kiểm với cột url
      sai                          -> 0, note: FP-sai; <lệnh và kết quả>
      đúng -> (b) Đó có phải điểm yếu trên target này không?
                  không            -> 0, note: FP-info; <lý do>
                  có               -> 1, note: <lệnh và kết quả>
      không kiểm được              -> để trống, note: không kiểm được; <lý do>
```

Mẹo: một lệnh `curl.exe -s -D - -o NUL <target>/` in ra toàn bộ header của target, đủ
để trả lời câu (a) cho mọi dòng "thiếu header" của target đó cùng lúc.

Phần dưới chỉ đưa **cách kiểm** và **câu hỏi cần trả lời**, không đưa đáp án. Đáp án do
người dựng hệ thống AI đưa ra thì cũng là chấm bài bằng đáp án của người làm bài.

**Thiếu security header** (CSP, X-Content-Type-Options, clickjacking, Permissions-Policy,
COOP/COEP/CORP, HSTS)

```powershell
curl.exe -s -D - -o NUL http://localhost:5000/
```

Header vắng mặt thì quan sát của scanner là đúng. Câu hỏi còn lại: với loại trang này,
header đó có chặn được một kiểu tấn công thật không? Nhóm header này nên chốt **một quy
tắc** trước khi gán rồi áp cho mọi dòng, và ghi quy tắc đó vào báo cáo. Ví dụ phải nghĩ:
HSTS trên HTTP thuần; COEP/CORP trên một trang không nhúng tài nguyên chéo nguồn.

**Lộ phiên bản** (Server Leaks Version)

```powershell
curl.exe -sI http://localhost:8080/ | findstr /i "^server x-powered-by"
```

Có số phiên bản cụ thể thì quan sát đúng. Hỏi: kẻ tấn công dùng con số đó được gì?

**Nikto "tìm thấy file"** (backup/cert file, This might be interesting, Contains
authorization information)

```powershell
curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}\n" http://localhost:8080/<url mẫu>
curl.exe -s -o NUL -w "%{http_code} %{content_type} %{size_download}\n" http://localhost:8080/khong-ton-tai-xyz
```

Hai dòng giống hệt nhau (cùng mã, cùng loại, cùng kích thước) nghĩa là đó chỉ là trang
fallback của SPA. Khác nhau thì mở hẳn URL ra xem nội dung thật.

**robots.txt có entry `/ftp/`**

```powershell
curl.exe -s http://localhost:8080/robots.txt
curl.exe -s http://localhost:8080/ftp/
```

Hỏi: thư mục đó có liệt kê file thật không, và các file đó có nên công khai không?

**CORS** (Access-Control-Allow-Origin: *, Cross-Domain Misconfiguration)

```powershell
curl.exe -s -D - -o NUL -H "Origin: http://ke-tan-cong.example" "http://localhost:8080/rest/products/search?q="
```

Hỏi: header trả về cho phép origin nào? Endpoint đó trả dữ liệu công khai hay dữ liệu
riêng của người dùng? Có `Access-Control-Allow-Credentials: true` không?

**SQL injection, XSS phản chiếu** (vulnapp): lệnh thử nằm trong bảng "Kiểm chứng bằng tay"
của `lab/KETQUA_VONG_LAP.md`. Lấy được dữ liệu admin, hoặc script trả về nguyên vẹn, là
có lỗ hổng.

**XSS DOM** (vulnapp): mở trang, `Ctrl+U` xem mã nguồn. XSS DOM cần một đoạn JavaScript
đọc dữ liệu người dùng rồi ghi vào trang. Hỏi: trang có JavaScript nào không? Nếu không,
cái ZAP thấy là gì? Ghi rõ lập luận vào `note`, ca này đáng đưa vào báo cáo.

**Dangerous JS Functions**: báo cáo ZAP ghi tên hàm và file. Tìm nó:

```powershell
curl.exe -s http://localhost:8080/main.js | findstr /c:"bypassSecurityTrust"
```

Hỏi: dữ liệu người dùng có chảy vào hàm đó không? Không lần ra được thì để trống và ghi
`không kiểm được`, đừng đoán.

**Timestamp Disclosure**: đổi con số ZAP báo ra ngày giờ

```powershell
[DateTimeOffset]::FromUnixTimeSeconds(1528301887)
```

Hỏi: đó là thời điểm gì (lúc build, lúc tạo tài khoản...) và lộ ra thì hại gì?

**Cache** (Storable and Cacheable, Non-Storable): `curl.exe -sI <url>` xem
`Cache-Control`. Hỏi: trang đó có chứa dữ liệu riêng của người dùng không?

**Finding mang tính thông tin** (Modern Web Application, OPTIONS, Uncommon header,
robots.txt "contains 1 entry"): quan sát thường đúng. Hỏi: thông tin này giúp kẻ tấn công
làm được việc gì mà trước đó chưa làm được?

---

## 5. Một người gán thì sao

Phương pháp chuẩn là hai người gán độc lập rồi đo tỉ lệ đồng thuận. Nếu chỉ có một người:

- Nhờ ai đó gán độc lập chỉ 15-20 dòng cũng đủ để đo đồng thuận trên một mẫu nhỏ.
- Hoặc tự gán lại 10 dòng chọn ngẫu nhiên sau 2-3 ngày mà không nhìn nhãn cũ, rồi đo
  xem mình có nhất quán với chính mình không.
- Dù thế nào, ghi "ground truth do một người gán" vào phần hạn chế của báo cáo.

---

## 6. Lưu file

- Cách đơn giản nhất: sửa thẳng trong VS Code.
- Dùng Excel thì lưu bằng **CSV UTF-8 (Comma delimited)**. Kiểu "CSV (Comma delimited)"
  thường sẽ làm hỏng tiếng Việt trong cột `note`.
- **Đóng file trong Excel trước khi chạy `eval.export`**: Excel khoá file, lệnh sẽ báo
  `PermissionError` (đã gặp thật).

---

## 7. Sau khi gán xong

```powershell
python -m eval.metrics 9      # nginx, trước vá
python -m eval.metrics 20     # vulnapp, trước vá
```

Dòng nào có nhãn nhưng thiếu cột `target` sẽ bị báo `[BỎ QUA]`, không bị bỏ lặng lẽ.
