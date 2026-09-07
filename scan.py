"""CLI: quét -> phân tích -> báo cáo HTML.

    python scan.py http://localhost:3000
    python scan.py http://localhost:3000 --no-ai      # chỉ scanner, không tốn tiền API
    python scan.py --list                             # lịch sử các lần quét
    python scan.py --compare 1 2                      # diff giữa hai lần quét

Đây là xương sống của hệ thống: dashboard (api/) dùng lại đúng các hàm này,
chỉ khác ở chỗ hiển thị.
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

import report
from analyzer.engine import analyze
from core import db
from core.config import MODEL, TargetNotAllowed, check_target
from scanners.runner import run_scan


def cmd_scan(args) -> int:
    try:
        target = check_target(args.url, allow_external=args.allow_external)
    except TargetNotAllowed as e:
        print(f"\n[TỪ CHỐI] {e}\n", file=sys.stderr)
        return 2

    conn = db.connect()
    scan_id = db.start_scan(conn, target, args.profile)
    print(f"Lần quét #{scan_id} -> {target}\n")

    try:
        findings, warnings = run_scan(
            target,
            profile=args.profile,
            use_nikto=not args.no_nikto,
            use_zap=not args.no_zap,
            progress=print,
        )
        db.save_findings(conn, scan_id, findings)

        if args.no_ai:
            result = {"analyses": {}, "summary": "", "priority": [], "warnings": []}
            print("Bỏ qua bước phân tích AI (--no-ai).")
        else:
            result = analyze(findings, conn=conn, progress=print)

        html = report.render(
            findings=findings,
            analyses=result["analyses"],
            target=target,
            model=MODEL,
            summary=result["summary"],
            priority=result["priority"],
            warnings=warnings + result["warnings"],
            profile=args.profile,
        )
        out = Path(args.out)
        out.write_text(html, encoding="utf-8")
        # Lưu để dashboard hiển thị lại được lần quét chạy từ CLI
        db.save_summary(conn, scan_id, result["summary"], result["priority"],
                        warnings + result["warnings"])
        db.finish_scan(conn, scan_id)

        print(f"\nBáo cáo: {out.resolve()}")
        print(f"Xem lại sau bằng: python scan.py --compare <id> {scan_id}")
        if args.open:
            webbrowser.open(out.resolve().as_uri())
        return 0

    except Exception as e:
        db.finish_scan(conn, scan_id, error=f"{type(e).__name__}: {e}")
        raise


def cmd_list(_args) -> int:
    conn = db.connect()
    rows = db.list_scans(conn)
    if not rows:
        print("Chưa có lần quét nào.")
        return 0
    print(f"{'ID':>4}  {'Trạng thái':<10} {'Số lỗ hổng':>10}  {'Bắt đầu':<20} Mục tiêu")
    for r in rows:
        n = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (r["id"],)
        ).fetchone()[0]
        print(f"{r['id']:>4}  {r['status']:<10} {n:>10}  {r['started_at']:<20} {r['target']}")
    return 0


def cmd_compare(args) -> int:
    """Trước/sau khi vá. Đây là phần chứng minh bản vá AI đề xuất có tác dụng thật."""
    conn = db.connect()
    diff = db.compare_scans(conn, args.compare[0], args.compare[1])
    labels = [
        ("ĐÃ VÁ (có ở #%d, mất ở #%d)" % tuple(args.compare), "fixed"),
        ("MỚI XUẤT HIỆN", "new"),
        ("CÒN TỒN TẠI", "persisting"),
    ]
    for title, key in labels:
        items = diff[key]
        print(f"\n=== {title}: {len(items)} ===")
        for f in sorted(items, key=lambda x: x.sort_key()):
            print(f"  [{f.severity:<6}] {f.source:<5} {f.name}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Quét lỗ hổng web bằng Nikto + OWASP ZAP, phân tích và đề xuất bản vá bằng AI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Chỉ quét hệ thống bạn sở hữu hoặc có văn bản cho phép.",
    )
    p.add_argument("url", nargs="?", help="URL mục tiêu, ví dụ http://localhost:3000")
    p.add_argument("--profile", choices=["baseline", "full", "auth"], default="baseline",
                   help="baseline = nhanh, chỉ passive. full = có active scan, lâu hơn nhiều. "
                        "auth = đăng nhập trước khi quét (cần ZAP_AUTH_USER/ZAP_AUTH_PASS trong .env).")
    p.add_argument("--no-ai", action="store_true", help="Chỉ chạy scanner, không gọi API")
    p.add_argument("--no-nikto", action="store_true")
    p.add_argument("--no-zap", action="store_true")
    p.add_argument("--allow-external", action="store_true",
                   help="Cho phép quét ngoài localhost/mạng nội bộ. Chỉ dùng khi có phép.")
    p.add_argument("-o", "--out", default="report.html", help="File báo cáo đầu ra")
    p.add_argument("--open", action="store_true", help="Mở báo cáo sau khi xong")
    p.add_argument("--list", action="store_true", help="Liệt kê các lần quét đã lưu")
    p.add_argument("--compare", nargs=2, type=int, metavar=("A", "B"),
                   help="So sánh hai lần quét (A = trước khi vá, B = sau khi vá)")
    args = p.parse_args()

    if args.list:
        return cmd_list(args)
    if args.compare:
        return cmd_compare(args)
    if not args.url:
        p.error("thiếu URL mục tiêu (hoặc dùng --list / --compare)")
    if args.no_nikto and args.no_zap:
        p.error("--no-nikto và --no-zap cùng lúc thì không còn scanner nào để chạy")
    return cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
