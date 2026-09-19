import importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("h", Path(__file__).parent / "thu_ban_va.py")
# Dùng lại hàm của harness nhưng không chạy vòng lặp chính của nó
src = (Path(__file__).parent / "thu_ban_va.py").read_text(encoding="utf-8").split("\nresults = {}")[0]
ns = {"__file__": str(Path(__file__).parent / "thu_ban_va.py")}
exec(compile(src, "harness", "exec"), ns)
res = {}
for fp, header in (("eab9b629d8846b93", "Content-Security-Policy"), ("ab41431c0d7c6600", "X-Content-Type-Options")):
    a = json.loads(ns["db"].connect().execute("SELECT json FROM analyses WHERE fingerprint=? AND target=?", (fp, ns["TARGET"])).fetchone()[0])
    base = ns["BASE"]
    i = next(k for k, l in enumerate(base) if l.strip() == "app = Flask(__name__)")
    path = ns["OUT"] / f"nguyenvan_{fp}.py"
    path.write_text("\n".join(base[:i+1] + ["", "# ===== dán NGUYÊN VĂN, không bỏ dòng nào ====="] + a["fix_snippet"].splitlines() + [""] + base[i+1:]) + "\n", encoding="utf-8")
    proc, err = ns["run"](path)
    r = {"run": err or "ok"}
    if not err:
        st, hs, _ = ns["get"](ns["TARGET"] + "/")
        s1 = ns["get"](ns["TARGET"] + "/search?q=an"); s2 = ns["get"](ns["TARGET"] + "/greet?name=test")
        r.update(header_value=next((v for k, v in hs.items() if k.lower() == header.lower()), None),
                 search_ok=s1[0] == 200 and "an@lab.local" in s1[2], greet_ok=s2[0] == 200 and "Xin chào, test" in s2[2])
    ns["stop"](proc); res[fp] = r
print(json.dumps(res, ensure_ascii=False, indent=2))
