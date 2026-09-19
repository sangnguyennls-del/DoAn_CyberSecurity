"""Test chạy offline: không cần Docker, không gọi API, không cần mạng.

Mục đích: mỗi khi ai đó sửa parser hay schema, chạy `pytest -q` là biết ngay có gãy không.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

import report
from analyzer.engine import _local_summary
from core import db
from core.config import TargetNotAllowed, check_target, to_container_url
from core.models import Finding, fingerprint
from scanners import nikto, zap
from scanners.dedupe import dedupe

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ parser

def test_zap_parse():
    f = {x.name: x for x in zap.parse(load("zap.json"))}
    assert len(f) == 3
    assert f["Cross Site Scripting (Reflected)"].severity == "High"
    assert f["Content Security Policy (CSP) Header Not Set"].severity == "Medium"
    assert f["X-Content-Type-Options Header Missing"].severity == "Low"
    assert f["Cross Site Scripting (Reflected)"].cwe == "79"


def test_zap_parse_strips_html_and_caps_urls():
    csp = next(x for x in zap.parse(load("zap.json")) if x.cwe == "693" and "CSP" in x.name)
    assert "<p>" not in csp.description
    assert csp.description.startswith("Content Security Policy")
    assert len(csp.urls) == 4, "giữ tối đa 5 URL mẫu; fixture có 4"
    assert csp.count == 4, "count phải là số lần xuất hiện thật, không phải số URL đã giữ"


def test_nikto_parse():
    findings = nikto.parse(load("nikto.json"))
    assert len(findings) == 4
    # Nikto không xếp hạng nghiêm trọng -> để Info, AI sẽ đánh giá lại
    assert all(f.severity == "Info" for f in findings)
    assert all(f.source == "nikto" for f in findings)


def test_nikto_parse_accepts_list_form():
    """Tuỳ phiên bản, Nikto trả về dict hoặc list[dict]. Phải nhận cả hai."""
    data = load("nikto.json")
    assert len(nikto.parse([data])) == len(nikto.parse(data))


# ------------------------------------------------------------- fingerprint

def test_fingerprint_separates_different_plugins():
    assert fingerprint("zap", "40012") != fingerprint("zap", "10038")


def test_fingerprint_separates_scanners():
    """Nikto và ZAP có thể trùng mã test - phải tách theo nguồn."""
    assert fingerprint("nikto", "999103") != fingerprint("zap", "999103")


def test_fingerprint_stable_across_runs():
    """Nếu fingerprint không ổn định thì diff giữa hai lần quét vô nghĩa."""
    assert fingerprint("nikto", "999103") == fingerprint("nikto", "999103")


def test_one_nikto_test_across_many_urls_collapses_to_one_finding():
    """Hồi quy cho ca đo được thật trên Juice Shop: test "backup/cert file found"
    của Nikto khớp 140 URL. Đó là MỘT vấn đề với một bản vá, không phải 140."""
    data = {"vulnerabilities": [
        {"id": "999986", "method": "GET", "url": f"/backup{i}.bak",
         "msg": "Potentially interesting backup/cert file found."}
        for i in range(140)
    ]}
    merged = dedupe(nikto.parse(data))
    assert len(merged) == 1, "140 URL cùng một test phải gom về 1 lỗ hổng"
    assert merged[0].count == 140, "số URL bị ảnh hưởng không được mất"
    assert len(merged[0].urls) == 5, "chỉ giữ 5 URL mẫu cho báo cáo đọc được"


def test_two_different_uncommon_headers_stay_separate():
    """Hồi quy cho ca đo được giữa lần quét #9 và #17.

    Nikto dùng chung một id cho MỌI header lạ. Sau khi vá, 'x-recruiting' đã
    bị gỡ và một header khác xuất hiện, nhưng hai cái gộp chung fingerprint nên
    bảng so sánh báo "còn tồn tại" cho một thứ đã vá xong. Trang so sánh là bằng
    chứng chính của đồ án, nó không được phép nói sai.
    """
    data = {"vulnerabilities": [
        {"id": "999966", "method": "GET", "url": "/",
         "msg": "Uncommon header(s) 'x-recruiting' found, with contents: /#/jobs."},
        {"id": "999966", "method": "GET", "url": "/",
         "msg": "Uncommon header(s) 'cross-origin-embedder-policy-report-only' found."},
    ]}
    merged = dedupe(nikto.parse(data))
    assert len(merged) == 2, "hai header khác nhau là hai vấn đề khác nhau"


def test_each_missing_security_header_is_its_own_finding():
    """Hồi quy cho lần quét #18 -> #19: 5 header thiếu từng gộp làm một finding,
    nên vá 4/5 vẫn bị báo "còn tồn tại" và HSTS hiện bản vá AI viết cho CSP."""
    headers = ["content-security-policy", "permissions-policy", "referrer-policy",
               "strict-transport-security", "x-content-type-options"]
    data = {"vulnerabilities": [
        {"id": "013587", "method": "GET", "url": "/",
         "msg": f"Suggested security header missing: {h}."} for h in headers
    ]}
    assert len(dedupe(nikto.parse(data))) == 5


def test_same_uncommon_header_still_collapses():
    """Mặt còn lại: cùng một header trên nhiều URL vẫn phải gom về một."""
    data = {"vulnerabilities": [
        {"id": "999966", "method": "GET", "url": f"/trang{i}",
         "msg": "Uncommon header(s) 'x-recruiting' found, with contents: /#/jobs."}
        for i in range(12)
    ]}
    merged = dedupe(nikto.parse(data))
    assert len(merged) == 1 and merged[0].count == 12


# ----------------------------------------------------------------- dedupe

def mk(key: str, url: str = "/", sev: str = "Info", count: int = 1) -> Finding:
    return Finding(
        fingerprint=fingerprint("zap", key), source="zap", name=key,
        severity=sev, urls=[url], count=count,
    )


def test_dedupe_merges_and_sums_count():
    out = dedupe([mk("A", "/", count=2), mk("A", "/", count=3), mk("B", "/")])
    assert len(out) == 2
    a = next(f for f in out if f.name == "A")
    assert a.count == 5


def test_dedupe_keeps_highest_severity():
    out = dedupe([mk("A", "/", sev="Low"), mk("A", "/", sev="High")])
    assert out[0].severity == "High"


def test_dedupe_caps_urls_at_five():
    same = [
        Finding(fingerprint="same", source="zap", name="A", urls=[f"/p?i={i}"], count=1)
        for i in range(20)
    ]
    out = dedupe(same)[0]
    assert len(out.urls) == 5
    assert out.count == 20, "cắt bớt URL mẫu nhưng count phải giữ đủ"


def test_dedupe_sorts_by_severity():
    out = dedupe([mk("i", "/a", sev="Info"), mk("h", "/b", sev="High"), mk("m", "/c", sev="Medium")])
    assert [f.severity for f in out] == ["High", "Medium", "Info"]


# ------------------------------------------------------- ranh giới an toàn

@pytest.mark.parametrize("url", [
    "http://localhost:3000",
    "http://127.0.0.1:8080/path",
    "http://192.168.1.10",
    "http://10.0.0.5:3000",
    "https://172.16.4.1",
])
def test_allowlist_accepts_local_targets(url):
    assert check_target(url) == url


@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://google.com/search",
    "http://8.8.8.8",
])
def test_allowlist_blocks_external_targets(url):
    with pytest.raises(TargetNotAllowed):
        check_target(url)


def test_allow_external_flag_overrides():
    assert check_target("http://example.com", allow_external=True)


def test_allowlist_rejects_non_http_scheme():
    with pytest.raises(TargetNotAllowed):
        check_target("file:///etc/passwd")


def test_to_container_url():
    assert to_container_url("http://localhost:3000/x") == "http://host.docker.internal:3000/x"
    assert to_container_url("http://192.168.1.5:80/x") == "http://192.168.1.5:80/x"


# -------------------------------------------------------------- lưu trữ

def test_compare_scans():
    conn = db.connect(":memory:")
    s1 = db.start_scan(conn, "http://localhost:3000")
    db.save_findings(conn, s1, [mk("A"), mk("B")])
    s2 = db.start_scan(conn, "http://localhost:3000")
    db.save_findings(conn, s2, [mk("B"), mk("C")])

    d = db.compare_scans(conn, s1, s2)
    assert [f.name for f in d["fixed"]] == ["A"]
    assert [f.name for f in d["new"]] == ["C"]
    assert [f.name for f in d["persisting"]] == ["B"]


def test_analysis_cache_roundtrip():
    conn = db.connect(":memory:")
    t = "http://localhost:3000"
    db.put_cached(conn, "claude-opus-5", t, [{"fingerprint": "abc", "severity_ai": "High"}])
    assert db.get_cached(conn, ["abc", "xyz"], t) == {"abc": {"fingerprint": "abc", "severity_ai": "High"}}


def test_analysis_cache_is_per_target():
    """Hồi quy cho ca đo được ở lần quét #18: vulnapp (Flask) nhận bản vá nginx.

    Cùng một lỗ hổng "CSP Header Not Set" nhưng bản vá cho nginx và cho Flask khác
    hẳn nhau. Cache khoá theo fingerprint thôi thì target sau được phục vụ bản vá
    của target trước, và báo cáo khuyên `server_tokens off` cho một app không có nginx.
    """
    conn = db.connect(":memory:")
    db.put_cached(conn, "claude-opus-5", "http://localhost:8080",
                  [{"fingerprint": "csp", "fix_snippet": "add_header ..."}])
    assert db.get_cached(conn, ["csp"], "http://localhost:5000") == {}
    assert db.get_cached(conn, ["csp"], "http://localhost:8080")["csp"]["fix_snippet"] == "add_header ..."


def test_migration_keeps_old_analyses_with_unknown_target(tmp_path):
    """DB tạo từ bản cũ (khoá không có target) phải nâng cấp được mà không mất dữ
    liệu đã trả tiền API, và không được tự đoán target cho dòng cũ."""
    import sqlite3
    path = str(tmp_path / "cu.db")
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE analyses (fingerprint TEXT NOT NULL, model TEXT NOT NULL,
            created_at TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (fingerprint, model));
        INSERT INTO analyses VALUES ('abc', 'claude-opus-5', '2026-09-18', '{"fingerprint":"abc"}');
    """)
    old.close()

    conn = db.connect(path)
    rows = conn.execute("SELECT fingerprint, target, json FROM analyses").fetchall()
    assert [tuple(r) for r in rows] == [("abc", "", '{"fingerprint":"abc"}')]
    assert db.get_cached(conn, ["abc"], "http://localhost:3000") == {}
    db.connect(path)  # chạy migration lần hai không được hỏng gì


def test_analysis_cache_never_serves_unknown_target():
    """Dòng cache cũ không rõ sinh cho target nào (target='') không được dùng lại."""
    conn = db.connect(":memory:")
    db.put_cached(conn, "claude-opus-5", "", [{"fingerprint": "abc"}])
    assert db.get_cached(conn, ["abc"], "") == {}


def test_findings_roundtrip_preserves_fields():
    conn = db.connect(":memory:")
    s = db.start_scan(conn, "http://localhost:3000")
    original = Finding(fingerprint="fp1", source="zap", name="XSS", severity="High",
                       urls=["/a", "/b"], count=7, evidence="ev", description="desc",
                       solution_raw="sol", cwe="79")
    db.save_findings(conn, s, [original])
    assert db.get_findings(conn, s)[0] == original


# ---------------------------------------------- an toàn khi render báo cáo

def test_report_escapes_attacker_controlled_evidence():
    """Evidence và URL do target kiểm soát. Nhúng thô vào HTML là tự tạo XSS
    ngay trong báo cáo của mình -> Jinja2 autoescape phải chặn."""
    payload = '<script>alert("xss")</script>'
    f = Finding(fingerprint="fp1", source="zap", name="Test", severity="High",
                urls=[f"http://localhost:3000/?q={payload}"], evidence=payload,
                description=payload)
    html = report.render([f], {}, "http://localhost:3000", "claude-opus-5")

    assert "<script>alert" not in html, "payload thoát ra được -> báo cáo dính XSS"
    assert "&lt;script&gt;" in html, "payload phải bị escape chứ không phải bị xoá"


def test_report_renders_without_ai_analysis():
    """--no-ai vẫn phải ra báo cáo đầy đủ phần scanner."""
    html = report.render([mk("A", sev="High")], {}, "http://localhost:3000", "claude-opus-5")
    assert "Chưa có phân tích AI" in html


def test_report_shows_warnings():
    html = report.render([], {}, "http://localhost:3000", "claude-opus-5",
                         warnings=["Nikto: không tìm thấy lệnh docker"])
    assert "không tìm thấy lệnh docker" in html


def test_local_summary_counts_by_severity():
    s = _local_summary([mk("a", "/1", sev="High"), mk("b", "/2", sev="High"), mk("c", "/3", sev="Low")])
    assert "2 High" in s and "1 Low" in s


# -------------------------------------------------- công thức đánh giá AI

def test_confusion_matrix_counts_each_quadrant():
    """Positive = "đây là false positive". Nhãn: is_true_positive 0 = FP thật."""
    from eval.metrics import confusion
    pairs = [
        ({"is_true_positive": 0}, {"false_positive_risk": "Cao"}),          # TP
        ({"is_true_positive": 1}, {"false_positive_risk": "Cao"}),          # FP - bác nhầm lỗ hổng thật
        ({"is_true_positive": 0}, {"false_positive_risk": "Thấp"}),         # FN - bỏ sót nhiễu
        ({"is_true_positive": 1}, {"false_positive_risk": "Trung bình"}),   # TN
    ]
    assert confusion(pairs) == (1, 1, 1, 1)


def test_false_positive_prediction_only_on_high_risk():
    from eval.metrics import predicts_false_positive
    assert predicts_false_positive({"false_positive_risk": "Cao"})
    assert predicts_false_positive({"false_positive_risk": " cao "})
    assert not predicts_false_positive({"false_positive_risk": "Trung bình"})
    assert not predicts_false_positive({"false_positive_risk": "Thấp"})
    assert not predicts_false_positive({}), "thiếu trường thì không được coi là FP"


# ------------------------------------------------- quét có đăng nhập (auth)

def test_auth_profile_requires_credentials(monkeypatch, tmp_path):
    """Thiếu tài khoản phải báo lỗi rõ ràng, không sinh plan rỗng."""
    monkeypatch.delenv("ZAP_AUTH_USER", raising=False)
    monkeypatch.delenv("ZAP_AUTH_PASS", raising=False)
    with pytest.raises(zap.AuthSetupFailed):
        zap.docker_args("http://localhost:3000", str(tmp_path), "auth")


def test_auth_plan_substitutes_every_placeholder(monkeypatch, tmp_path):
    monkeypatch.setenv("ZAP_AUTH_USER", "hocvien@lab.local")
    monkeypatch.setenv("ZAP_AUTH_PASS", "matkhau-lab")
    monkeypatch.setattr(zap, "_verify_login", lambda *a, **k: None)  # test offline
    args = zap.docker_args("http://host.docker.internal:3000/", str(tmp_path), "auth")

    assert "-autorun" in args
    plan = (tmp_path / zap.PLAN_FILE).read_text(encoding="utf-8")
    config = [l for l in plan.splitlines() if not l.lstrip().startswith("#")]
    assert not any("{{" in l for l in config), "còn placeholder chưa thay -> ZAP sẽ chạy sai"
    assert "hocvien@lab.local" in plan and "matkhau-lab" in plan
    assert "http://host.docker.internal:3000/rest/user/login" in plan


def test_login_check_failure_stops_the_scan(monkeypatch, tmp_path):
    """Đăng nhập hỏng PHẢI dừng lại. Nếu chạy tiếp, ZAP quét ẩn danh và cho ra
    một báo cáo trông y hệt lần quét có đăng nhập - sai mà không ai biết."""
    monkeypatch.setenv("ZAP_AUTH_USER", "sai@lab.local")
    monkeypatch.setenv("ZAP_AUTH_PASS", "sai")

    def boom(*a, **k):
        raise zap.AuthSetupFailed("Đăng nhập thất bại (HTTP 401)")
    monkeypatch.setattr(zap, "_verify_login", boom)

    with pytest.raises(zap.AuthSetupFailed):
        zap.docker_args("http://localhost:3000", str(tmp_path), "auth")


def test_missing_credentials_does_not_kill_nikto(monkeypatch, tmp_path):
    """Bug đã sửa: docker_args ném exception thì cả lần quét chết, kể cả Nikto."""
    monkeypatch.delenv("ZAP_AUTH_USER", raising=False)
    monkeypatch.delenv("ZAP_AUTH_PASS", raising=False)
    from scanners import runner

    # Không thực sự chạy docker: chỉ cần chắc lỗi biến thành warning, không raise
    monkeypatch.setattr(runner, "_run_one", lambda *a, **k: ([], None))
    findings, warns = runner.run_scan("http://localhost:3000", profile="auth")
    assert any("ZAP_AUTH_USER" in w for w in warns)
    assert findings == []


def test_zap_variants_of_same_plugin_stay_separate():
    """Hồi quy cho bug đo được thật: ZAP plugin 10055 phát ra nhiều biến thể CSP
    khác hẳn nhau. Nếu gom chung fingerprint thì diff giữa hai lần quét báo
    "không đổi" trong khi vấn đề đã thay đổi - làm hỏng bằng chứng vá lỗi."""
    def alert(ref, name):
        return {"pluginid": "10055", "alertRef": ref, "name": name, "riskcode": "2",
                "instances": [{"uri": "http://localhost:8080/"}], "count": "1"}

    findings = zap.parse({"site": [{"@name": "http://localhost:8080", "alerts": [
        alert("10055-1", "CSP: Failure to Define Directive with No Fallback"),
        alert("10055-2", "CSP: script-src unsafe-inline"),
    ]}]})
    assert len({f.fingerprint for f in findings}) == 2, "hai biến thể phải khác fingerprint"
    assert len(dedupe(findings)) == 2, "dedupe không được gộp hai biến thể khác nhau"


# ------------------------------------------------ pipeline đánh giá (eval/)

def _seeded_db(monkeypatch, tmp_path):
    """DB tạm với 3 lỗ hổng + phân tích AI giả, đủ để chạy hết đường eval."""
    conn = db.connect(":memory:")
    scan_id = db.start_scan(conn, "http://localhost:3000")
    findings = [mk("A", sev="High"), mk("B", sev="Medium"), mk("C", sev="Low")]
    db.save_findings(conn, scan_id, findings)
    db.put_cached(conn, "claude-opus-5", "http://localhost:3000", [
        {"fingerprint": findings[0].fingerprint, "severity_ai": "Critical",
         "false_positive_risk": "Thấp"},
        {"fingerprint": findings[1].fingerprint, "severity_ai": "Medium",
         "false_positive_risk": "Cao"},
        {"fingerprint": findings[2].fingerprint, "severity_ai": "Info",
         "false_positive_risk": "Cao"},
    ])
    monkeypatch.setattr(db, "connect", lambda *a, **k: conn)
    return conn, scan_id, findings


def test_metrics_runs_end_to_end(monkeypatch, tmp_path, capsys):
    from eval import metrics
    _, scan_id, findings = _seeded_db(monkeypatch, tmp_path)

    csv_path = tmp_path / "gt.csv"
    rows = [
        # A: lỗ hổng thật, AI nói thật      -> TN
        (findings[0].fingerprint, "1", "1"),
        # B: lỗ hổng thật, AI nói FP        -> FP (bác nhầm lỗ hổng thật)
        (findings[1].fingerprint, "1", "0"),
        # C: đúng là FP, AI nói FP          -> TP
        (findings[2].fingerprint, "0", ""),
    ]
    csv_path.write_text(
        "fingerprint,target,is_true_positive,patch_ok,name\n"
        + "".join(f"{fp},http://localhost:3000,{tp},{ok},x\n" for fp, tp, ok in rows)
        # cùng fingerprint nhưng target khác -> không được tính vào lần quét này
        + f"{rows[0][0]},http://localhost:8080,0,0,x\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(metrics, "GROUND_TRUTH", csv_path)

    assert metrics.main(scan_id) == 0
    out = capsys.readouterr().out
    assert "Precision" in out and "Recall" in out
    assert "1 lần AI bác nhầm lỗ hổng thật" in out
    assert "3 phát hiện" in out, "phải tính trên đúng 3 mẫu có cả nhãn lẫn phân tích"


def test_metrics_ignores_unlabelled_rows(monkeypatch, tmp_path):
    from eval import metrics
    csv_path = tmp_path / "gt.csv"
    csv_path.write_text(
        "fingerprint,target,is_true_positive,patch_ok,name\n"
        "aaa,http://t,1,,x\n"
        "bbb,http://t,,,x\n"        # chưa gán -> phải bị bỏ qua
        "ccc,http://t,khong-hop-le,,x\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(metrics, "GROUND_TRUTH", csv_path)
    assert set(metrics.load_labels()) == {("aaa", "http://t")}


def test_export_preserves_existing_labels(monkeypatch, tmp_path):
    """Chạy lại export không được xoá công sức gán nhãn của người dùng."""
    from eval import export
    _, scan_id, findings = _seeded_db(monkeypatch, tmp_path)
    out = tmp_path / "gt.csv"
    monkeypatch.setattr(export, "OUT", out)

    export.main(scan_id)
    text = out.read_text(encoding="utf-8-sig")
    assert "fp_risk_ai" not in text and "severity_ai" not in text, \
        "phiếu gán nhãn không được lộ kết luận của AI"
    t = "http://localhost:3000"
    text = text.replace(f"{findings[0].fingerprint},{t},zap,High,A,{t}/,,,,,",
                        f"{findings[0].fingerprint},{t},zap,High,A,{t}/,,1,1,ghi chú,an")
    out.write_text(text, encoding="utf-8-sig")

    export.main(scan_id)  # chạy lại
    import csv as _csv
    with out.open(encoding="utf-8-sig", newline="") as f:
        rows = {r["fingerprint"]: r for r in _csv.DictReader(f)}
    kept = rows[findings[0].fingerprint]
    assert kept["is_true_positive"] == "1" and kept["patch_ok"] == "1"
    assert kept["note"] == "ghi chú" and kept["labeled_by"] == "an"


def test_export_keeps_columns_the_labeller_added(monkeypatch, tmp_path):
    """Người gán tự thêm cột `note_patchok`. Export chỉ ghi COLUMNS thì cột đó bị xoá
    sạch ở lần chạy sau mà không báo gì."""
    from eval import export
    _, scan_id, findings = _seeded_db(monkeypatch, tmp_path)
    out = tmp_path / "gt.csv"
    monkeypatch.setattr(export, "OUT", out)
    export.main(scan_id)
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    rows[0]["note_patchok"] = "lý do bản vá"
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows({**r, "note_patchok": r.get("note_patchok", "")} for r in rows)

    export.main(scan_id)
    kept = {r["fingerprint"]: r for r in csv.DictReader(out.open(encoding="utf-8-sig"))}
    assert kept[rows[0]["fingerprint"]]["note_patchok"] == "lý do bản vá"


def test_export_drops_dead_rows_but_keeps_labelled_ones(monkeypatch, tmp_path):
    """Dòng target trống (phiếu bản cũ) không bao giờ khớp được khi đo. Chưa gán thì
    bỏ, để người gán khỏi điền vào dòng chết; đã gán thì giữ, vì đó là công sức."""
    from eval import export
    _, scan_id, _ = _seeded_db(monkeypatch, tmp_path)
    out = tmp_path / "gt.csv"
    out.write_text(
        "fingerprint,target,source,severity_scanner,name,is_true_positive,patch_ok,note,labeled_by\n"
        "cu_chua_gan,,zap,Low,X,,,,\n"
        "cu_da_gan,,zap,Low,Y,1,,,an\n",
        encoding="utf-8-sig",
    )
    monkeypatch.setattr(export, "OUT", out)
    export.main(scan_id)
    text = out.read_text(encoding="utf-8-sig")
    assert "cu_chua_gan" not in text
    assert "cu_da_gan" in text


def test_evidence_picks_the_right_header_to_check():
    """Kiểm nhầm header thì bằng chứng ghi "KHÔNG CÓ" cho một thứ đang có -> gán nhầm."""
    from eval.evidence import headers_for
    assert headers_for("Suggested security header missing: referrer-policy.") == ["referrer-policy"]
    assert headers_for("Uncommon header(s) 'x-recruiting' found, with contents: /#/jobs.") == ["x-recruiting"]
    assert headers_for("Missing Anti-clickjacking Header") == ["X-Frame-Options", "Content-Security-Policy"]
    assert headers_for("CSP: Wildcard Directive") == ["Content-Security-Policy"]
    assert headers_for("SQL Injection") == []


def test_report_write_failure_does_not_fail_the_scan(tmp_path):
    """Bug đã sửa: ghi file báo cáo hỏng thì cả lần quét bị đánh dấu error, dù
    findings đã lưu đủ trong DB. Mất 10 phút quét chỉ vì sai đường dẫn -o."""
    from scan import save_report_file

    # Đường dẫn không ghi được (thư mục lại là một file đang tồn tại)
    blocker = tmp_path / "chan"
    blocker.write_text("x", encoding="utf-8")
    out, warn = save_report_file("<html></html>", str(blocker / "bao-cao.html"))
    assert out is None and warn is not None
    assert "Kết quả vẫn đã lưu" in warn


def test_report_write_creates_missing_parent_dirs(tmp_path):
    from scan import save_report_file

    out, warn = save_report_file("<html>xin chào</html>", str(tmp_path / "a" / "b" / "r.html"))
    assert warn is None
    assert out.read_text(encoding="utf-8") == "<html>xin chào</html>"


# ------------------------------------------------- dò ngăn xếp công nghệ

def test_detect_stack_finds_server_banner():
    """Hồi quy: regex từng chứa ký tự backspace nên không khớp gì, detect_stack
    luôn trả rỗng. Mô hình mất manh mối về stack và sinh bản vá sai tầng - hỏng
    âm thầm, không test nào bắt được."""
    from analyzer.engine import detect_stack
    fs = [
        Finding(fingerprint="a", source="zap", name="Server Leaks Version",
                evidence="nginx/1.31.5"),
        Finding(fingerprint="b", source="zap", name="CSP Header Not Set"),
    ]
    assert detect_stack(fs) == "nginx/1.31.5"


def test_detect_stack_empty_when_no_banner():
    from analyzer.engine import detect_stack
    assert detect_stack([Finding(fingerprint="a", source="zap", name="X")]) == ""


def test_batch_header_carries_target_and_stack():
    """Ngăn xếp phải vào prompt của MỌI lô, không chỉ lô chứa finding có banner."""
    from analyzer.engine import _build_header
    h = _build_header("http://localhost:8080", "nginx/1.31.5")
    assert "http://localhost:8080" in h
    assert "nginx/1.31.5" in h
    assert _build_header("", "") == ""
