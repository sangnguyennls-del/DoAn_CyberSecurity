# Kịch bản thuyết trình

Đồ án: **AI hỗ trợ quét lỗ hổng bảo mật Web**. Dùng kèm bộ slide 16 trang.
Thời lượng gợi ý: **10–12 phút nói + 4–5 phút demo**. Lời thoại là gợi ý, không cần đọc thuộc.

Phân vai gợi ý (nhóm 5): người 1 nói slide 1–3 (đặt vấn đề), người 2 slide 4–6 (kiến trúc),
người 3 slide 7–9 (vòng lặp vá), người 4 slide 10–13 (đánh giá), người 5 slide 14–16 + demo.

---

## Slide 1 — Bìa (30 giây)

"Em/nhóm xin trình bày đồ án *AI hỗ trợ quét lỗ hổng bảo mật Web*. Ý tưởng là nối hai công cụ
quét quen thuộc là Nikto và OWASP ZAP với mô hình ngôn ngữ Claude, để tự động phân tích kết quả
và đề xuất bản vá. Điểm khác biệt của nhóm nằm ở vế cuối: **không chỉ ghép công cụ, mà tự đo xem
AI nói đúng đến đâu**."

## Slide 2 — Vấn đề (1 phút)

"Vì sao cần AI ở đây? Vì đầu ra của scanner rất khó dùng. Ba con số trên màn hình:
- Một lần quét nginx sinh **200** dòng cảnh báo thô — quá nhiều để đọc.
- Trong 115 cảnh báo nhóm kiểm bằng tay, **51 không phải lỗ hổng thật** — lẫn rất nhiều nhiễu.
- Và gợi ý sửa lỗi gốc của ZAP đúng với *mọi* hệ thống nên **không giúp được hệ thống nào** cụ thể.

Người mới học đọc file JSON của ZAP gần như không rút ra được hành động nào."

## Slide 3 — Ba câu hỏi (1 phút)

"Hệ thống của nhóm trả lời ba câu mà scanner thuần không trả lời được: *Cái nào đáng lo thật? Sửa
thế nào? Và — quan trọng nhất — AI nói có đúng không?* Hai câu đầu nhiều nhóm làm được bằng cách
gọi API. Câu thứ ba, đo độ chính xác của AI, mới là phần biến đồ án từ 'ghép công cụ' thành 'có
đánh giá', và là trọng tâm báo cáo."

## Slide 4 — Kiến trúc (1 phút)

"Đây là kiến trúc tổng thể. Có hai cửa vào: dòng lệnh và dashboard, dùng chung một bộ hàm và một
database. Mọi URL phải qua hàm `check_target` — chỉ cho localhost và mạng nội bộ. Tầng scanner chạy
Nikto và ZAP song song qua Docker. Tầng analyzer nhận diện ngăn xếp công nghệ, lấy cache, chỉ gửi
phần thiếu lên Claude để tiết kiệm tiền. Kết quả lưu SQLite, rồi sinh báo cáo và trang so sánh."

## Slide 5 — Fingerprint (1 phút)

"Điểm thiết kế cốt lõi là *fingerprint* — một mã băm ngắn làm bốn việc cùng lúc: gom trùng, so sánh
hai lần quét, làm khoá cache, và làm khoá nối với nhãn. Chi tiết đáng chú ý: URL cố ý không nằm
trong khoá. Một test của Nikto khớp tới 140 URL, nhưng thực chất là *một* vấn đề với *một* bản vá —
nếu tính cả URL thì báo cáo có 140 dòng vô nghĩa."

## Slide 6 — Giao diện (45 giây)

"Trên giao diện, mỗi phát hiện đặt bằng chứng thô của scanner bên trái, phân tích và bản vá của AI
bên phải, để người đọc tự đối chiếu. Mọi phân tích đều gắn nhãn 'Gợi ý do AI sinh, cần kiểm chứng
thủ công trước khi áp dụng.'"

## Slide 7 — Quy trình đánh giá (45 giây)

"Nhóm dùng hai quy trình. Quy trình (a) chứng minh bản vá có tác dụng thật: quét, áp bản vá, quét
lại, so sánh. Quy trình (b) đo độ chính xác của AI bằng nhãn thủ công, với các bước kiểm soát thiên
lệch mà em/mình nói ở slide sau."

## Slide 8 — Vòng lặp nginx (1 phút)

"Target thứ nhất vá được ở tầng cấu hình. Trước vá 22 lỗ hổng, sau vá còn 16: **9 phát hiện chuyển
sang cột đã vá**. Ba phát hiện mới xuất hiện đều do chính bản vá gây ra — đây là bài học: sau khi vá
luôn phải quét lại. Toàn bộ bản vá lấy nguyên từ trường `fix_snippet` của AI, nhóm chỉ gom lại và
đổi tên cho khớp."

## Slide 9 — Vòng lặp vulnapp (1 phút)

"Target thứ hai là ứng dụng Flask nhóm tự viết, vá được ở tầng mã nguồn. Đây là chỗ chứng minh AI vá
được *code* chứ không chỉ cấu hình: 17 trong 19 phát hiện biến mất, gồm cả ba lỗ hổng mức High là SQL
injection, XSS phản chiếu và XSS DOM. Cần cả hai loại target: chỉ có nginx thì chỉ chứng minh được AI
vá cấu hình."

## Slide 10 — Kiểm soát thiên lệch (1 phút)

"Đây là phần quan trọng về phương pháp. Nguy cơ lớn nhất là gán nhãn theo lời AI — chẳng khác gì chấm
bài bằng đáp án của người làm bài. Vì Claude chính là mô hình đang được đánh giá, nó **không được tự
gán nhãn**. Bốn biện pháp: phiếu mù không có cột AI; bằng chứng chỉ ghi dữ kiện; chốt nhãn trước khi
xem số liệu; và mọi chỉnh sửa đều vào nhật ký."

## Slide 11 — Kết quả chính (1 phút 15)

"Gộp 115 cặp trên ba target: **precision gần 87%, recall 25,5%**. Với công cụ bảo mật, precision quan
trọng hơn recall: bỏ sót nhiễu chỉ tốn thời gian đọc, còn bác nhầm lỗ hổng thật là bỏ lọt rủi ro. Bảng
bên phải tách theo từng target. Nói thẳng: AI có bác nhầm 2 trong 64 lỗ hổng thật, nên đúng hơn là nói
AI *hiếm khi* bác nhầm, không phải *không bao giờ*."

## Slide 12 — Recall thấp đến từ đâu (1 phút)

"Vì sao recall chỉ 25%? Không phải AI kém. Khi scanner khẳng định sai, AI bắt được 7 trên 11. Nhưng khi
scanner quan sát đúng mà không đáng lo, AI chỉ gọi 6 trên 40 là false positive. Nguyên nhân nằm ở *câu
hỏi*: trường false-positive của AI trả lời 'scanner có nói sai không', còn AI thể hiện 'có đáng lo không'
ở trường mức độ — 37 trên 40 dòng đó được xếp Low hoặc Info. Hai bên đang đo hai câu khác nhau."

## Slide 13 — Chất lượng bản vá (45 giây)

"Về bản vá: 13 trên 15 dùng được, tức 87%. Hai ca hỏng cho thấy hai kiểu lỗi điển hình của AI: dán
nguyên văn thì app crash vì AI dùng một hàm đã bị gỡ khỏi Flask; và vá sai tầng vì AI đoán nhầm ngăn
xếp. Bài học: AI không thấy mã nguồn thì sẽ đoán tên, nên bản vá luôn cần người kiểm."

## Slide 14 — Lỗi công cụ & target bị hỏng (1 phút)

"Nhóm trung thực về mặt trái. Vòng lặp chạy thật làm lộ 4 lỗi của chính công cụ mà test đơn vị không bắt
được — ba đã sửa kèm test hồi quy. Và một bài học an toàn đắt giá: trên Mutillidae, active scan của ZAP
đã chạy SQL thật qua một phpMyAdmin mở không mật khẩu, tạo 94 database rác và làm ứng dụng offline. Đó là
lý do rất thực tế cho nguyên tắc chỉ quét hệ thống của mình, và chụp lại target trước mỗi lần quét."

## Slide 15 — Kết luận (1 phút)

"Tóm lại: nhóm làm được pipeline hoàn chỉnh qua cả CLI và dashboard; đo được precision 87%, recall 25%
trên 115 cặp có nhãn; vòng lặp vá xoá được lỗ hổng thật trên cả hai tầng; và chỉ ra được nguyên nhân
recall thấp. Hạn chế: mẫu còn nhỏ, target do nhóm dựng. Hướng phát triển rõ nhất là tách hai câu hỏi để
recall phản ánh đúng năng lực AI. Toàn bộ khoảng 3.200 dòng Python, 59 test, đã công khai trên GitHub."

## Slide 16 — Demo & cảm ơn

Chuyển sang demo (xem `KICH_BAN_DEMO.md`). Kết: "Nhóm xin cảm ơn thầy/cô và các bạn đã lắng nghe. Nhóm
sẵn sàng nhận câu hỏi."

---

## Câu hỏi có thể gặp (chuẩn bị trước)

- **Vì sao chọn Claude mà không phải model khác?** Vì đầu ra của model chính là dữ liệu đầu vào cho phần
  đánh giá định lượng; structured output bảo đảm đúng schema nên không cần tự bóc tách JSON hay thử lại.
- **Recall 25% thấp vậy có dùng được không?** Recall thấp chỉ nghĩa là người vẫn phải đọc một phần nhiễu;
  precision cao mới là điều quan trọng với công cụ bảo mật. Và recall thấp do lệch câu hỏi, không do model.
- **Sao lại có Claude trong danh sách contributor trên GitHub?** Vì mỗi commit ghi dòng đồng tác giả để
  minh bạch việc dùng AI trong quá trình làm — khớp với phần trình bày trong báo cáo.
- **Số liệu có tin được không?** Mọi con số chạy lại được: `python -m eval.metrics all`, `pytest -q`.
