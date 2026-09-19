"""Áp RIÊNG đoạn vá của từng dòng loại B lên bản chưa vá, chạy thật, đo header + chức năng."""
import json
import py_compile
import subprocess
import tempfile
import sys
import time
import urllib.request
from pathlib import Path

from core import db

ROOT = Path.cwd()
OUT = Path(tempfile.gettempdir()) / "thu_ban_va"  # bản app tạm, không ghi vào repo
OUT.mkdir(exist_ok=True)
TARGET = "http://localhost:5000"
BASE = (ROOT / "lab/vulnapp/app.py.chuava.bak").read_text(encoding="utf-8").splitlines()
DUP = {"from flask import Flask", "app = Flask(__name__)"}   # đã có sẵn trong app
TESTS = {
    "d3c767640d5a5a30": "X-Content-Type-Options",   # ZAP X-Content-Type-Options Header Missing
    "eab9b629d8846b93": "Content-Security-Policy",  # Nikto missing: content-security-policy
    "97ad98b15735eb7e": "Referrer-Policy",          # Nikto missing: referrer-policy
    "000fd7aaee188a50": "X-Content-Type-Options",   # Nikto missing: x-content-type-options
    "ab41431c0d7c6600": "X-Content-Type-Options",   # Nikto X-Content-Type-Options not set
}


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception as e:  # noqa: BLE001
        return None, {}, str(e)


def build(fp: str) -> tuple[Path, list[str]]:
    a = json.loads(db.connect().execute(
        "SELECT json FROM analyses WHERE fingerprint=? AND target=?", (fp, TARGET)).fetchone()[0])
    snippet = a["fix_snippet"].splitlines()
    dropped = [s for s in snippet if s.strip() in DUP]
    keep = [s for s in snippet if s.strip() not in DUP]
    i = next(k for k, line in enumerate(BASE) if line.startswith('if __name__ == "__main__":'))
    src = BASE[:i] + ["", f"# ===== đoạn vá của {fp}, dán nguyên văn ====="] + keep + [""] + BASE[i:]
    path = OUT / f"app_{fp}.py"
    path.write_text("\n".join(src) + "\n", encoding="utf-8")
    return path, dropped


def run(path: Path):
    proc = subprocess.Popen([sys.executable, str(path)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    for _ in range(30):
        if proc.poll() is not None:
            return proc, "app thoát ngay khi chạy: " + proc.stderr.read().decode("utf-8", "replace")[-300:]
        if get(TARGET + "/")[0]:
            return proc, None
        time.sleep(0.5)
    return proc, "app không lên sau 15 giây"


def stop(proc):
    proc.kill()
    proc.wait()
    for _ in range(30):
        if get(TARGET + "/")[0] is None:
            return
        time.sleep(0.3)


results = {}
for fp, header in TESTS.items():
    path, dropped = build(fp)
    r = {"header": header, "dropped": dropped}
    try:
        py_compile.compile(str(path), doraise=True)
        r["compile"] = "ok"
    except py_compile.PyCompileError as e:
        r["compile"] = f"LỖI: {e.msg[-200:]}"
        results[fp] = r
        continue
    proc, err = run(path)
    if err:
        r["run"] = err
    else:
        st, hs, _ = get(TARGET + "/")
        r["run"] = "ok"
        r["header_value"] = next((v for k, v in hs.items() if k.lower() == header.lower()), None)
        s1 = get(TARGET + "/search?q=an")
        s2 = get(TARGET + "/greet?name=test")
        r["chuc_nang"] = {
            "/": st,
            "/search?q=an có 'an@lab.local'": s1[0] == 200 and "an@lab.local" in s1[2],
            "/greet?name=test có 'Xin chào, test'": s2[0] == 200 and "Xin chào, test" in s2[2],
        }
    stop(proc)
    results[fp] = r

print(json.dumps(results, ensure_ascii=False, indent=2))
