from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import init_db, db_cursor
from app.scoring import explain_risk
from app.reports import generate_report


ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(
    title="CTI-Pulse",
    description="Public vulnerability intelligence aggregation and prioritization",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    q: str = Query("", description="CVE ID or keyword"),
    priority: str = Query("", description="Critical, High, Medium, or Low"),
    kev: bool = Query(False),
) -> HTMLResponse:
    clauses = []
    params = []
    if q:
        clauses.append("(cve_id LIKE ? OR description LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if priority:
        clauses.append("priority = ?")
        params.append(priority)
    if kev:
        clauses.append("in_kev = 1")
    where = " AND ".join(clauses) if clauses else "1=1"
    with db_cursor() as conn:
        cves = conn.execute(
            f"SELECT * FROM cves WHERE {where} ORDER BY risk_score DESC, cve_id",
            params,
        ).fetchall()
        summary = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(in_kev) AS kev,
                   SUM(poc_count > 0) AS pocs,
                   SUM(priority='Critical') AS critical
            FROM cves
            """
        ).fetchone()
    return templates.TemplateResponse(request, "index.html", {
        "cves": cves, "summary": summary, "q": q,
        "priority": priority, "kev": kev,
    })


@app.get("/cve/{cve_id}", response_class=HTMLResponse)
def cve_detail(request: Request, cve_id: str) -> HTMLResponse:
    cve_id = cve_id.upper()
    with db_cursor() as conn:
        cve = conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
        pocs = conn.execute(
            "SELECT * FROM poc_references WHERE cve_id=? ORDER BY stars DESC", (cve_id,)
        ).fetchall()
        mappings = conn.execute(
            "SELECT * FROM attack_mappings WHERE cve_id=? ORDER BY technique_id", (cve_id,)
        ).fetchall()
        history = conn.execute(
            "SELECT * FROM epss_history WHERE cve_id=? ORDER BY observed_at DESC", (cve_id,)
        ).fetchall()
    if cve is None:
        return templates.TemplateResponse(request, "404.html", {"cve_id": cve_id}, status_code=404)
    explanation = explain_risk(cve["cvss"], cve["epss"], bool(cve["in_kev"]), cve["poc_count"])
    return templates.TemplateResponse(request, "detail.html", {
        "cve": cve, "pocs": pocs, "mappings": mappings,
        "history": history, "explanation": explanation,
    })


@app.get("/api/v1/cves")
def api_cves(
    q: str = "",
    priority: str = "",
    kev: bool = False,
    limit: int = Query(100, ge=1, le=500),
):
    clauses = []
    params = []
    if q:
        clauses.append("(cve_id LIKE ? OR description LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if priority:
        clauses.append("priority=?")
        params.append(priority)
    if kev:
        clauses.append("in_kev=1")
    where = " AND ".join(clauses) if clauses else "1=1"
    params.append(limit)
    with db_cursor() as conn:
        rows = conn.execute(
            f"SELECT * FROM cves WHERE {where} ORDER BY risk_score DESC LIMIT ?", params
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/v1/cves/{cve_id}")
def api_cve(cve_id: str):
    cve_id = cve_id.upper()
    with db_cursor() as conn:
        cve = conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
        pocs = conn.execute("SELECT * FROM poc_references WHERE cve_id=?", (cve_id,)).fetchall()
        mappings = conn.execute("SELECT * FROM attack_mappings WHERE cve_id=?", (cve_id,)).fetchall()
    if cve is None:
        return {"detail": "CVE not found"}
    result = dict(cve)
    result["explanation"] = explain_risk(cve["cvss"], cve["epss"], bool(cve["in_kev"]), cve["poc_count"])
    result["pocs"] = [dict(row) for row in pocs]
    result["attack_mappings"] = [dict(row) for row in mappings]
    return result


@app.post("/api/v1/reports/weekly")
def api_weekly_report():
    path = generate_report()
    return {"report": path.name, "download_url": f"/reports/{path.name}"}


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    from app.config import REPORTS_DIR
    reports = sorted(REPORTS_DIR.glob("*.pdf"), reverse=True)
    return templates.TemplateResponse(request, "reports.html", {
        "reports": [{"name": path.name} for path in reports],
    })


@app.get("/reports/{name}")
def download_report(name: str):
    path = ROOT / "reports" / name
    if not path.is_file():
        return {"detail": "Report not found"}
    return FileResponse(path, media_type="application/pdf", filename=name)
