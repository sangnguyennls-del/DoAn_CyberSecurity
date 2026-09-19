# Công cụ đã dùng để thu bằng chứng cho `patch_ok`

Chạy từ thư mục gốc dự án, với `PYTHONPATH` trỏ vào đó.

| Script | Làm gì | Kết quả |
|---|---|---|
| `ban_va.py` | Với mỗi dòng `is_true_positive = 1`: đoạn vá AI viết, dòng nào trong file đã vá lấy từ nó, finding còn hay mất ở lần quét sau vá, phân tích sinh trước hay sau khi sửa prompt | `eval/bang_chung/ban_va.md` |
| `thu_ban_va.py` | Dán RIÊNG đoạn vá của từng dòng loại B vào `lab/vulnapp/app.py.chuava.bak` (bỏ dòng trùng hệt code có sẵn), chạy thật trên cổng 5000, đo header và kiểm `/search`, `/greet` | in JSON ra màn hình |
| `thu_nguyen_van.py` | Như trên cho hai đoạn vá có dòng `app = Flask(__name__)`, nhưng dán nguyên văn không bỏ dòng nào, ngay sau dòng tạo app có sẵn | in JSON ra màn hình |

Cổng 5000 phải trống trước khi chạy hai script thử.

## Thí nghiệm XSS DOM (lần quét #22)

Phần JavaScript của đoạn vá nhắm `static/app.js` không tồn tại nên chỉ áp phần Python (CSP qua
`after_request`). Các bước đã chạy:

1. Tạo bản app: `app.py.chuava.bak` + khối từ dòng `# app.py — CSP chan inline handler` trở đi
   trong `fix_snippet` của `f115fea0b888d86b` (target `http://localhost:5000`), chèn trước
   `if __name__ == "__main__":`.
2. Chạy bản app đó, xác nhận SQLi vẫn còn (đúng bản chưa vá) và header CSP có mặt.
3. `python scan.py http://localhost:5000 --profile full --no-ai --no-nikto` (chỉ ZAP, không gọi API).
4. Kết quả #22: không còn "Cross Site Scripting (DOM Based)"; "Cross Site Scripting (Reflected)"
   vẫn còn; thêm "CSP: Failure to Define Directive with No Fallback".
