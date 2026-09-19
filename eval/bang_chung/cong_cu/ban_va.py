"""Gom dữ kiện để gán patch_ok cho các dòng is_true_positive = 1. Chỉ dữ kiện, không kết luận."""
import csv
import json
import re
from pathlib import Path

from core import db

ROOT = Path.cwd()
PROMPT_FIX_UTC = "2026-09-18T14:29:40"      # commit 1125eda, 21:29:40 +07:00
LOOP = {  # target -> (lần quét trước vá, sau vá, file đã vá)
    "http://localhost:8080": (9, 17, "lab/nginx/nginx.conf"),
    "http://localhost:5000": (20, 21, "lab/vulnapp/app.py"),
}

c = db.connect()
rows = [r for r in csv.DictReader(open(ROOT / "eval/ground_truth.csv", encoding="utf-8-sig"))
        if r["is_true_positive"].strip() == "1"]


def tagged_blocks(lines: list[str], name: str) -> list[str]:
    out = []
    for i, line in enumerate(lines):
        for tag in re.findall(r"# \[([^\]]+)\]", line):
            key = tag.replace("...", "").strip().rstrip(".")[:25]
            if name.startswith(key):
                block = [f"{i + 1:>4}: {line.rstrip()}"]
                for j in range(i + 1, min(i + 9, len(lines))):
                    if not lines[j].strip() or "# [" in lines[j]:
                        break
                    block.append(f"{j + 1:>4}: {lines[j].rstrip()}")
                out.append("\n".join(block))
    return out


def chinh_blocks(lines: list[str]) -> list[str]:
    out, i = [], 0
    while i < len(lines):
        if "# CHỈNH:" in lines[i]:
            block = [f"{i + 1:>4}: {lines[i].rstrip()}"]
            i += 1
            while i < len(lines) and lines[i].strip().startswith("#") and "CHỈNH:" not in lines[i] \
                    and "# [" not in lines[i]:
                block.append(f"{i + 1:>4}: {lines[i].rstrip()}")
                i += 1
            out.append("\n".join(block))
        else:
            i += 1
    return out


md = ["# Dữ kiện để gán `patch_ok`", "",
      "Cho các dòng `is_true_positive = 1`. **Chỉ dữ kiện, không kết luận.** Quy tắc ở mục 1 của",
      "`HUONG_DAN_GAN_NHAN.md`: `1` nếu áp bản vá của CHÍNH dòng này thì finding biến mất và chức năng",
      "không hỏng (được đổi tên cho khớp app thật); `0` nếu dán nguyên văn thì lỗi, sai tầng, không làm",
      "finding biến mất, hoặc làm hỏng chức năng; để trống nếu chưa áp thử được. Ghi lý do vào `note`.", "",
      f"Mốc sửa lỗi nhận diện ngăn xếp (commit `1125eda`): {PROMPT_FIX_UTC} UTC. Phân tích sinh trước",
      "mốc này được viết khi AI chưa biết target chạy nginx.", ""]

for target, (before, after, patched) in LOOP.items():
    lines = (ROOT / patched).read_text(encoding="utf-8").splitlines()
    after_fps = {f.fingerprint: f for f in db.get_findings(c, after)}
    mine = [r for r in rows if r["target"] == target]
    md += ["---", "", f"# {target}: {len(mine)} dòng", "",
           f"Vòng lặp: quét #{before} (trước vá) -> áp bản vá vào `{patched}` -> quét #{after} (sau vá).",
           "Tác dụng phụ đo được của cả bản vá: xem `lab/KETQUA_VONG_LAP.md`.", ""]
    ch = chinh_blocks(lines)
    if ch:
        md += [f"Những chỗ nhóm phải chỉnh khi áp (ghi `CHỈNH:` trong `{patched}`):", "", "```text",
               *[b + "\n" for b in ch], "```", ""]
    for r in mine:
        a_row = c.execute("SELECT created_at, json FROM analyses WHERE fingerprint=? AND target=?",
                          (r["fingerprint"], target)).fetchone()
        a = json.loads(a_row["json"])
        when = a_row["created_at"][:19]
        blocks = tagged_blocks(lines, r["name"])
        f_after = after_fps.get(r["fingerprint"])
        md += [f"## {r['name']}", "",
               f"`{r['fingerprint']}` · nhãn của bạn: `1` · note: {r['note'][:160]}", "",
               f"- Phân tích AI sinh lúc {when} UTC: "
               f"**{'TRƯỚC' if when < PROMPT_FIX_UTC else 'SAU'}** mốc sửa prompt.",
               f"- Ở lần quét sau vá #{after}: "
               + (f"**CÒN** (`{f_after.name[:70]}`)" if f_after else "**KHÔNG CÒN**"),
               f"- Dòng trong `{patched}` gắn tên finding này: "
               + (f"{len(blocks)} khối (bên dưới)" if blocks else "**không có** (bản vá của dòng này không được dùng trực tiếp)"),
               ""]
        if blocks:
            md += ["```text", *[b + "\n" for b in blocks], "```", ""]
        steps = a.get("fix_steps") or []
        if steps:
            md += ["Các bước AI đề xuất:", ""] + [f"{i}. {s}" for i, s in enumerate(steps, 1)] + [""]
        md += ["Đoạn vá AI viết cho dòng này (nguyên văn):", "", "```text",
               a.get("fix_snippet") or "(AI để trống)", "```", ""]

out = ROOT / "eval/bang_chung/ban_va.md"
out.write_text("\n".join(md), encoding="utf-8")
print(f"Đã ghi {out} ({len(rows)} dòng)")
