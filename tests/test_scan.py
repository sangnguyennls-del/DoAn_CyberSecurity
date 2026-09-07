"""Test chạy offline: không cần Docker, không gọi API, không cần mạng.

Mục đích: mỗi khi ai đó sửa parser hay schema, chạy `pytest -q` là biết ngay có gãy không.
"""

from __future__ import annotations

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
    db.put_cached(conn, "claude-opus-5", [{"fingerprint": "abc", "severity_ai": "High"}])
    assert db.get_cached(conn, ["abc", "xyz"]) == {"abc": {"fingerprint": "abc", "severity_ai": "High"}}


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
    with pytest.raises(zap.MissingCredentials):
        zap.docker_args("http://localhost:3000", str(tmp_path), "auth")


def test_auth_plan_substitutes_every_placeholder(monkeypatch, tmp_path):
    monkeypatch.setenv("ZAP_AUTH_USER", "hocvien@lab.local")
    monkeypatch.setenv("ZAP_AUTH_PASS", "matkhau-lab")
    args = zap.docker_args("http://host.docker.internal:3000/", str(tmp_path), "auth")

    assert "-autorun" in args
    plan = (tmp_path / zap.PLAN_FILE).read_text(encoding="utf-8")
    config = [l for l in plan.splitlines() if not l.lstrip().startswith("#")]
    assert not any("{{" in l for l in config), "còn placeholder chưa thay -> ZAP sẽ chạy sai"
    assert "hocvien@lab.local" in plan and "matkhau-lab" in plan
    assert "http://host.docker.internal:3000/rest/user/login" in plan


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
