"""Chạy Nikto và ZAP song song qua Docker, gộp kết quả về list[Finding].

Ba bẫy trên Windows đã xử lý sẵn ở đây:
  1. Output ghi vào tempfile.mkdtemp() (dưới %TEMP%) — đường dẫn dự án có dấu cách
     ("IT Learning", "Cyber security") làm bind mount Docker hay gãy.
  2. Container không thấy localhost của host -> đổi sang host.docker.internal.
  3. CẢ HAI scanner trả exit code khác 0 khi TÌM THẤY lỗ hổng (ZAP: 1=WARN, 2=FAIL).
     Điều kiện thành công là file JSON tồn tại và parse được, KHÔNG phải returncode.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core.config import to_container_url
from core.models import Finding
from scanners import nikto, zap
from scanners.dedupe import dedupe

TIMEOUT = 1800  # 30 phút — zap-full-scan trên Juice Shop có thể rất lâu


def _run_one(name: str, args: list[str], outdir: Path, outfile: str, parse_fn):
    """Chạy một scanner. Trả về (findings, warning|None) — không bao giờ raise."""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
    except FileNotFoundError:
        return [], f"{name}: không tìm thấy lệnh docker. Docker Desktop đã chạy chưa?"
    except subprocess.TimeoutExpired:
        return [], f"{name}: quá {TIMEOUT}s, đã huỷ."

    path = outdir / outfile
    if not path.exists():
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        return [], f"{name}: không sinh ra {outfile} (exit {proc.returncode}). " + " | ".join(tail)

    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        return [], f"{name}: {outfile} không phải JSON hợp lệ ({e})."

    try:
        return parse_fn(data), None
    except Exception as e:  # scanner đổi format output giữa các phiên bản
        return [], f"{name}: parse thất bại ({type(e).__name__}: {e})."


def run_scan(
    url: str,
    profile: str = "baseline",
    use_nikto: bool = True,
    use_zap: bool = True,
    progress=None,
) -> tuple[list[Finding], list[str]]:
    """Quét `url`, trả về (findings đã gom trùng, danh sách cảnh báo).

    Một scanner chết thì vẫn tiếp tục với scanner còn lại — lỗi đi vào `warnings`
    và được hiển thị trong báo cáo, không làm sập cả lần quét.
    """
    say = progress or (lambda m: None)
    target = to_container_url(url)
    outdir = Path(tempfile.mkdtemp(prefix="doan_scan_"))

    jobs = []
    warnings: list[str] = []
    if use_nikto:
        jobs.append(("Nikto", nikto.docker_args(target, str(outdir)), nikto.OUTFILE, nikto.parse))
    if use_zap:
        try:
            args = zap.docker_args(target, str(outdir), profile)
            jobs.append(("ZAP", args, zap.OUTFILE, zap.parse))
        except zap.AuthSetupFailed as e:
            # Thiếu tài khoản cho profile auth không được phép giết cả lần quét:
            # Nikto vẫn chạy được, và người dùng cần thấy lý do trong báo cáo.
            warnings.append(f"ZAP: {e}")
            say(f"  [!] ZAP bị bỏ qua: {e}")

    if not jobs:
        say("Không còn scanner nào chạy được.")
        return [], warnings

    say(f"Chạy {len(jobs)} scanner song song trên {target} (profile={profile})...")
    try:
        with ThreadPoolExecutor(max_workers=len(jobs) or 1) as pool:
            results = list(pool.map(
                lambda j: _run_one(j[0], j[1], outdir, j[2], j[3]), jobs
            ))
    finally:
        shutil.rmtree(outdir, ignore_errors=True)

    findings: list[Finding] = []
    for (name, *_), (found, warn) in zip(jobs, results):
        if warn:
            warnings.append(warn)
            say(f"  [!] {warn}")
        else:
            say(f"  [ok] {name}: {len(found)} phát hiện thô")
        findings.extend(found)

    merged = dedupe(findings)
    say(f"Gom trùng: {len(findings)} thô -> {len(merged)} lỗ hổng riêng biệt")
    return merged, warnings
