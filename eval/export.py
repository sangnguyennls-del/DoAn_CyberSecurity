"""Xuất phiếu gán nhãn ra CSV để gán tay trong Excel.

    python -m eval.export <scan_id>

Sinh eval/ground_truth.csv với hai cột để trống cho người gán:

  is_true_positive : 1 = lỗ hổng THẬT, 0 = false positive
  patch_ok         : 1 = bản vá AI đề xuất dùng được, 0 = sai/không dùng được
                     (để trống nếu chưa kiểm)

Cách gán cho đúng phương pháp:
  - Mở từng phát hiện, tự kiểm chứng bằng tay (curl, DevTools, đọc code) rồi mới gán.
    Đừng gán theo cảm tính hay theo chính lời AI - như thế là chấm bài bằng đáp án
    của người làm bài, số liệu sẽ vô nghĩa.
  - Nên hai người gán độc lập rồi đối chiếu. Tỉ lệ đồng thuận giữa hai người tự nó
    là một số liệu đáng đưa vào báo cáo, và những chỗ lệch thường là ca thú vị nhất.
  - Chạy lại lệnh này sẽ GIỮ NGUYÊN nhãn đã gán, chỉ thêm dòng mới.

Quy trình chi tiết: eval/HUONG_DAN_GAN_NHAN.md
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from urllib.parse import urljoin

from core import db
from core.config import DOCKER_HOST_ALIAS

OUT = Path(__file__).parent / "ground_truth.csv"
# `target` nằm trong khoá: cùng một lỗ hổng trên nginx và trên Flask có bản vá khác
# nhau, nên patch_ok (thậm chí is_true_positive) phải gán riêng cho từng target.
# KHÔNG có cột kết luận của AI (severity_ai, fp_risk_ai): nhìn thấy AI nói gì trước
# khi tự kiểm thì nhãn lệch theo AI, và precision/recall đo ra cao giả tạo.
# metrics.py đọc kết luận AI thẳng từ DB, không cần nó nằm trong phiếu.
# `url` và `evidence` để mỗi dòng tự chứa đủ thứ cần kiểm, khỏi phải mở dashboard,
# nơi phân tích AI nằm ngay cạnh bằng chứng.
COLUMNS = ["fingerprint", "target", "source", "severity_scanner", "name", "url", "evidence",
           "is_true_positive", "patch_ok", "note", "labeled_by"]
LABEL_COLS = ("is_true_positive", "patch_ok", "note")


def main(scan_id: int) -> int:
    conn = db.connect()
    findings = db.get_findings(conn, scan_id)
    if not findings:
        sys.exit(f"Lần quét #{scan_id} không có phát hiện nào.")
    target = db.get_scan(conn, scan_id)["target"]
    analyses = db.get_cached(conn, [f.fingerprint for f in findings], target)

    # Giữ nhãn đã gán từ lần trước - không được ghi đè công sức của người gán
    existing: dict[tuple[str, str], dict] = {}
    # Cột người gán tự thêm (vd `note_patchok`) phải được giữ nguyên: ghi lại chỉ theo
    # COLUMNS thì những cột đó bị xoá sạch mà không báo gì.
    extra: list[str] = []
    if OUT.exists():
        with OUT.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            existing = {(r["fingerprint"], r.get("target", "")): r for r in reader}
            extra = [c for c in (reader.fieldnames or []) if c not in COLUMNS]
    fields = COLUMNS + extra

    rows = []
    for f in sorted(findings, key=lambda x: x.sort_key()):
        old = existing.get((f.fingerprint, target), {})
        rows.append({
            "fingerprint": f.fingerprint,
            "target": target,
            "source": f.source,
            "severity_scanner": f.severity,
            "name": f.name,
            # URL phải curl được ngay từ máy người gán: ZAP lưu dạng host.docker.internal
            # (scanner chạy trong container), Nikto lưu đường dẫn tương đối (/abc.tar)
            "url": urljoin(target, (f.urls[0] if f.urls else "").replace(DOCKER_HOST_ALIAS, "localhost")),
            "evidence": " ".join(f.evidence.split())[:150],
            "is_true_positive": old.get("is_true_positive", ""),
            "patch_ok": old.get("patch_ok", ""),
            "note": old.get("note", ""),
            "labeled_by": old.get("labeled_by", ""),
            **{c: old.get(c, "") for c in extra},
        })

    # Giữ cả nhãn của các lần quét khác đã gán trước đó. Dòng target trống là phiếu
    # xuất từ bản cũ, chưa có cột target: metrics không bao giờ khớp được nó, nên
    # chưa gán gì thì bỏ đi (để người gán khỏi tốn công điền vào dòng chết); đã gán
    # thì giữ lại và báo, vì đó là công sức của người gán.
    seen = {(r["fingerprint"], r["target"]) for r in rows}
    orphans = 0
    for key, old in existing.items():
        if key in seen:
            continue
        if not key[1]:
            if not any((old.get(c) or "").strip() for c in (*LABEL_COLS, *extra)):
                continue
            orphans += 1
        rows.append({c: old.get(c, "") for c in fields})

    # utf-8-sig để Excel trên Windows mở ra không bị vỡ tiếng Việt
    try:
        f = OUT.open("w", encoding="utf-8-sig", newline="")
    except PermissionError:
        # Excel khoá độc quyền file CSV đang mở. open() hỏng thì file chưa bị cắt.
        sys.exit(f"Không ghi được {OUT.name}: file đang bị khoá, thường là do đang mở "
                 "trong Excel. Đóng file rồi chạy lại. Nhãn đã gán không bị ảnh hưởng.")
    with f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    n_todo = sum(1 for r in rows if r["is_true_positive"] not in ("0", "1"))
    print(f"Đã ghi {OUT} ({len(rows)} dòng, {n_todo} dòng chưa gán nhãn).")
    if orphans:
        print(f"CẢNH BÁO: {orphans} dòng đã gán nhãn nhưng thiếu cột target -> metrics bỏ qua. "
              "Điền target cho các dòng đó.")
    if len(analyses) < len(findings):
        print(f"Lưu ý: {len(findings) - len(analyses)} lỗ hổng chưa có phân tích AI -> gán nhãn "
              f"được nhưng metrics không đo được. Chạy: python scan.py --analyze {scan_id}")
    print("Điền cột is_true_positive và patch_ok, rồi chạy:")
    print(f"  python -m eval.metrics {scan_id}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Cách dùng: python -m eval.export <scan_id>")
    raise SystemExit(main(int(sys.argv[1])))
