"""Đo độ chính xác của AI so với nhãn thủ công.

    python -m eval.export  <scan_id>    # xuất phiếu gán nhãn ra CSV
    # ... gán nhãn bằng tay trong Excel ...
    python -m eval.metrics <scan_id>    # nạp nhãn và in bảng số liệu

Đây là phần biến đồ án từ "ghép công cụ" thành "có đánh giá". Không có phần này thì
không trả lời được câu hỏi quan trọng nhất: AI nói có đúng không?

Định nghĩa dùng trong bài (ghi rõ để bảo vệ được trước hội đồng):

  Bài toán   : AI dự đoán một phát hiện của scanner có phải FALSE POSITIVE không.
  Positive   : phát hiện đó LÀ false positive.
  Dự đoán    : AI trả `false_positive_risk` = "Cao"  -> dự đoán Positive
                                            = "Trung bình"/"Thấp" -> Negative
  Nhãn thật  : cột is_true_positive trong ground_truth.csv
               (1 = lỗ hổng thật -> Negative, 0 = false positive -> Positive)

  Precision  = trong số AI kêu "chắc là FP", bao nhiêu % đúng là FP
               -> thấp nghĩa là AI hay bác nhầm lỗ hổng thật. NGUY HIỂM.
  Recall     = trong số FP thật sự, AI lọc ra được bao nhiêu %
               -> thấp nghĩa là AI bỏ sót nhiễu, người vẫn phải đọc thủ công.

Với công cụ bảo mật, precision quan trọng hơn recall: bỏ sót một chút nhiễu chỉ tốn
thời gian, còn bác nhầm một lỗ hổng thật là bỏ lọt rủi ro.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from core import db

GROUND_TRUTH = Path(__file__).parent / "ground_truth.csv"
FP_PREDICT_POSITIVE = {"cao"}  # AI coi là false positive khi rủi ro FP = "Cao"


def load_labels() -> dict[tuple[str, str], dict]:
    """Nạp nhãn thủ công. Bỏ qua dòng chưa gán (cột để trống)."""
    if not GROUND_TRUTH.exists():
        sys.exit(f"Chưa có {GROUND_TRUTH}. Chạy `python -m eval.export <scan_id>` trước.")

    out: dict[tuple[str, str], dict] = {}
    with GROUND_TRUTH.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            tp = (row.get("is_true_positive") or "").strip()
            if tp not in ("0", "1"):
                continue  # chưa gán nhãn
            if not row.get("target"):
                # nhãn không khớp được với lần quét nào -> nói ra, đừng lặng lẽ bỏ
                print(f"[BỎ QUA] {row['fingerprint']}: thiếu cột target, nhãn này không được tính.",
                      file=sys.stderr)
                continue
            out[(row["fingerprint"], row.get("target", ""))] = {
                "is_true_positive": int(tp),
                "patch_ok": (row.get("patch_ok") or "").strip(),
                "name": row.get("name", ""),
            }
    return out


def _rate(num: int, den: int) -> str:
    return f"{num / den * 100:5.1f}%  ({num}/{den})" if den else "   n/a  (0/0)"


def predicts_false_positive(ai: dict) -> bool:
    """AI có đang nói phát hiện này là false positive không."""
    return (ai.get("false_positive_risk", "") or "").strip().lower() in FP_PREDICT_POSITIVE


def confusion(pairs: list[tuple[dict, dict]]) -> tuple[int, int, int, int]:
    """Trả về (tp, fp, fn, tn). Positive = "đây là false positive".

    Hàm thuần, không I/O -> test được. Công thức này sai thì toàn bộ phần đánh giá
    của đồ án vô nghĩa, nên nó có test riêng.
    """
    tp = fp = fn = tn = 0
    for label, ai in pairs:
        actual = label["is_true_positive"] == 0      # đúng là false positive
        predicted = predicts_false_positive(ai)
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def main(scan_id: int) -> int:
    conn = db.connect()
    findings = db.get_findings(conn, scan_id)
    target = db.get_scan(conn, scan_id)["target"]
    analyses = db.get_cached(conn, [f.fingerprint for f in findings], target)
    labels = load_labels()

    if not analyses:
        sys.exit(f"Lần quét #{scan_id} chưa có phân tích AI. Chạy lại không kèm --no-ai.")

    # Chỉ tính trên phần vừa có nhãn thật vừa có dự đoán của AI
    pairs = [
        (labels[(f.fingerprint, target)], analyses[f.fingerprint], f)
        for f in findings
        if (f.fingerprint, target) in labels and f.fingerprint in analyses
    ]
    if not pairs:
        sys.exit("Không có phát hiện nào vừa được gán nhãn vừa có phân tích AI.")

    tp, fp, fn, tn = confusion([(l, a) for l, a, _ in pairs])

    raw_total = sum(f.count for f in findings)
    patch_labeled = [l for l, _, _ in pairs if l["patch_ok"] in ("0", "1")]
    patch_ok = sum(1 for l in patch_labeled if l["patch_ok"] == "1")
    reranked = sum(
        1 for _, ai, f in pairs
        if (ai.get("severity_ai", "") or "").lower() != f.severity.lower()
    )

    print(f"""
=== ĐÁNH GIÁ AI - LẦN QUÉT #{scan_id} ===

Mẫu: {len(pairs)} phát hiện có cả nhãn thủ công lẫn phân tích AI
      (trên tổng {len(findings)} lỗ hổng riêng biệt, {raw_total} phát hiện thô)

--- Phát hiện false positive ---
Ma trận nhầm lẫn (Positive = "đây là false positive"):
                        AI nói FP    AI nói thật
  Thật sự là FP    {tp:>10}   {fn:>13}
  Thật sự là lỗi   {fp:>10}   {tn:>13}

  Precision   {_rate(tp, tp + fp)}   AI kêu FP thì đúng bao nhiêu %
  Recall      {_rate(tp, tp + fn)}   lọc được bao nhiêu % nhiễu thật sự
  Accuracy    {_rate(tp + tn, len(pairs))}

  Với công cụ bảo mật, precision quan trọng hơn: {fp} lần AI bác nhầm lỗ hổng thật.

--- Chất lượng bản vá ---
  Bản vá dùng được   {_rate(patch_ok, len(patch_labeled))}

--- Giá trị AI thêm vào ---
  Đánh giá lại mức độ khác scanner: {reranked}/{len(pairs)} phát hiện
  Gom trùng: {raw_total} phát hiện thô -> {len(findings)} lỗ hổng
             (giảm {(1 - len(findings) / raw_total) * 100:.0f}% khối lượng phải đọc)
""")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Cách dùng: python -m eval.metrics <scan_id>")
    raise SystemExit(main(int(sys.argv[1])))
