"""Gom trùng theo fingerprint.

ZAP lặp cùng một alert trên hàng chục URL. Không gom thì báo cáo không đọc nổi
và gửi lên API tốn gấp nhiều lần token.
"""

from __future__ import annotations

from core.models import SEVERITY_ORDER, Finding


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        cur = merged.get(f.fingerprint)
        if cur is None:
            merged[f.fingerprint] = f.model_copy(deep=True)
            continue
        cur.count += f.count
        # giữ tối đa 5 URL mẫu, không trùng
        for u in f.urls:
            if u not in cur.urls and len(cur.urls) < 5:
                cur.urls.append(u)
        # giữ mức nghiêm trọng cao nhất
        if SEVERITY_ORDER.get(f.severity, 9) < SEVERITY_ORDER.get(cur.severity, 9):
            cur.severity = f.severity
        if not cur.evidence:
            cur.evidence = f.evidence
    return sorted(merged.values(), key=Finding.sort_key)
