"""Xuất phiếu gán nhãn ra CSV để gán tay trong Excel.

    python -m eval.export <scan_id> [model]

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
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from core import db

OUT = Path(__file__).parent / "ground_truth.csv"
COLUMNS = ["fingerprint", "source", "severity_scanner", "severity_ai",
           "fp_risk_ai", "name", "is_true_positive", "patch_ok", "note", "labeled_by"]


def main(scan_id: int, model: str | None = None) -> int:
    conn = db.connect()
    findings = db.get_findings(conn, scan_id)
    if not findings:
        sys.exit(f"Lần quét #{scan_id} không có phát hiện nào.")
    analyses = db.get_cached(conn, [f.fingerprint for f in findings], model)

    # Giữ nhãn đã gán từ lần trước - không được ghi đè công sức của người gán
    existing: dict[str, dict] = {}
    if OUT.exists():
        with OUT.open(encoding="utf-8-sig", newline="") as f:
            existing = {r["fingerprint"]: r for r in csv.DictReader(f)}

    rows = []
    for f in sorted(findings, key=lambda x: x.sort_key()):
        ai = analyses.get(f.fingerprint, {})
        old = existing.get(f.fingerprint, {})
        rows.append({
            "fingerprint": f.fingerprint,
            "source": f.source,
            "severity_scanner": f.severity,
            "severity_ai": ai.get("severity_ai", ""),
            "fp_risk_ai": ai.get("false_positive_risk", ""),
            "name": f.name,
            "is_true_positive": old.get("is_true_positive", ""),
            "patch_ok": old.get("patch_ok", ""),
            "note": old.get("note", ""),
            "labeled_by": old.get("labeled_by", ""),
        })

    # Giữ cả nhãn của các lần quét khác đã gán trước đó
    seen = {r["fingerprint"] for r in rows}
    rows += [
        {c: old.get(c, "") for c in COLUMNS}
        for fp, old in existing.items() if fp not in seen
    ]

    # utf-8-sig để Excel trên Windows mở ra không bị vỡ tiếng Việt
    with OUT.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    n_todo = sum(1 for r in rows if r["is_true_positive"] not in ("0", "1"))
    print(f"Đã ghi {OUT} ({len(rows)} dòng, {n_todo} dòng chưa gán nhãn).")
    if not analyses:
        print("Lưu ý: lần quét này chưa có phân tích AI -> cột severity_ai/fp_risk_ai trống.")
    print("Mở bằng Excel, điền cột is_true_positive và patch_ok, rồi chạy:")
    print(f"  python -m eval.metrics {scan_id}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("Cách dùng: python -m eval.export <scan_id> [model]")
    raise SystemExit(main(int(sys.argv[1]), sys.argv[2] if len(sys.argv) == 3 else None))
