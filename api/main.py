"""Dashboard FastAPI.

    uvicorn api.main:app --reload    ->  http://127.0.0.1:8000

Không có đăng nhập/phân quyền: công cụ chạy local trên máy nhóm, không expose ra ngoài.
Nếu có ngày đưa lên mạng thì phải thêm xác thực TRƯỚC - nó chạy được lệnh docker.
"""

from __future__ import annotations

import html
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import report
from api import jobs
from core import db
from core.config import MODEL, TargetNotAllowed, check_target

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="AI hỗ trợ quét lỗ hổng bảo mật Web")
app.mount("/static", StaticFiles(directory=ROOT / "web" / "static"), name="static")

# Jinja2Templates của Starlette bật autoescape sẵn - evidence/URL do target kiểm soát
# nên đây là điều bắt buộc, đừng tắt đi.
templates = Jinja2Templates(directory=ROOT / "web" / "templates")


def _scan_context(conn, scan_id: int) -> dict:
    """Dựng lại dữ liệu hiển thị của một lần quét từ DB.

    Báo cáo không lưu dạng blob HTML mà render lại từ đây, nên trang chi tiết và
    file tải về luôn khớp nhau.
    """
    findings = db.get_findings(conn, scan_id)
    summary, priority, warnings = db.get_summary(conn, scan_id)
    analyses = db.get_cached(conn, [f.fingerprint for f in findings])
    row = db.get_scan(conn, scan_id)
    return report.context(
        findings=findings,
        analyses=analyses,
        target=row["target"],
        model=MODEL,
        summary=summary,
        priority=priority,
        warnings=warnings,
        profile=row["profile"],
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request, error: str = ""):
    conn = db.connect()
    try:
        return templates.TemplateResponse(request, "index.html", {
            "page": "index", "scans": db.list_scans(conn), "error": error,
        })
    finally:
        conn.close()


@app.post("/scans")
def start_scan(
    background: BackgroundTasks,
    target: str = Form(...),
    profile: str = Form("baseline"),
    use_ai: str = Form(""),
):
    # Ranh giới an toàn phải chặn ở CẢ CLI LẪN API, không chỉ một chỗ
    try:
        target = check_target(target)
    except TargetNotAllowed as e:
        msg = str(e).replace("\n", " ")
        return RedirectResponse(f"/?error={msg}", status_code=303)

    conn = db.connect()
    try:
        scan_id = db.start_scan(conn, target, profile)
    finally:
        conn.close()

    jobs.new_job(scan_id)
    # Hàm đồng bộ -> FastAPI chạy nó trong threadpool, không chặn event loop
    background.add_task(jobs.run, scan_id, target, profile, bool(use_ai))
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int):
    conn = db.connect()
    try:
        row = db.get_scan(conn, scan_id)
        if row is None:
            return RedirectResponse("/?error=Không tìm thấy lần quét", status_code=303)

        ctx = {"page": "detail", "scan": row}
        if row["status"] == "done":
            ctx.update(_scan_context(conn, scan_id))
        return templates.TemplateResponse(request, "detail.html", ctx)
    finally:
        conn.close()


@app.get("/scans/{scan_id}/progress", response_class=HTMLResponse)
def scan_progress(scan_id: int):
    """HTMX poll 2 giây/lần. Khi xong trả HX-Refresh để trình duyệt tải lại trang."""
    job = jobs.get_job(scan_id)
    if job is None:
        # Server vừa khởi động lại -> log in-memory đã mất, đọc trạng thái từ DB
        conn = db.connect()
        try:
            row = db.get_scan(conn, scan_id)
        finally:
            conn.close()
        done = row is not None and row["status"] != "running"
        return Response("<div class='log'>Không còn log tiến trình (server đã khởi động lại).</div>",
                        media_type="text/html",
                        headers={"HX-Refresh": "true"} if done else {})

    body = "<div class='log'>" + "\n".join(
        # Nội dung log chứa output của scanner -> phải escape trước khi nhúng vào HTML
        html.escape(line) for line in job["lines"]
    ) + "</div>"
    headers = {"HX-Refresh": "true"} if job["status"] != "running" else {}
    return Response(body, media_type="text/html", headers=headers)


@app.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def scan_report(scan_id: int):
    """Báo cáo tự chứa, tải về mở offline được."""
    conn = db.connect()
    try:
        if db.get_scan(conn, scan_id) is None:
            return Response("Không tìm thấy lần quét", status_code=404)
        ctx = _scan_context(conn, scan_id)
    finally:
        conn.close()
    return HTMLResponse(report.render_context(ctx))


@app.get("/compare", response_class=HTMLResponse)
def compare(request: Request, a: int | None = None, b: int | None = None):
    conn = db.connect()
    try:
        scans = db.list_scans(conn)
        ctx = {"page": "compare", "scans": scans, "a": a, "b": b, "diff": None, "error": ""}

        if a is not None and b is not None:
            if a == b:
                ctx["error"] = "Chọn hai lần quét khác nhau."
            else:
                ctx["diff"] = db.compare_scans(conn, a, b)
        return templates.TemplateResponse(request, "compare.html", ctx)
    finally:
        conn.close()
