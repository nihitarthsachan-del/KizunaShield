"""
KizunaShield — Attack Surface & Ransomware Risk Scanner (MVP backend).

Routes:
  GET  /                         -> marketing landing page
  GET  /dashboard                -> exposure dashboard (talks to the API below)
  GET  /api/orgs                 -> list all orgs with scores
  GET  /api/orgs/{org_id}        -> full scored detail for one org
  GET  /api/orgs/{org_id}/report -> download compliance PDF report
"""
import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from scoring import score_all_orgs
from report_generator import generate_report

app = FastAPI(title="KizunaShield — Attack Surface & Ransomware Risk Scanner")

BASE_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Serve landing.html's/dashboard.html's own asset references (none currently,
# but this keeps room for future css/js/img files without touching routes).
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


def _read_static(filename: str) -> str:
    with open(os.path.join(STATIC_DIR, filename), encoding="utf-8") as f:
        return f.read()


def get_scored_orgs():
    # Recomputed on each call — cheap for MVP scale, keeps demo data "live"
    return {org["org_id"]: org for org in score_all_orgs()}


@app.get("/", response_class=HTMLResponse)
def landing():
    return _read_static("landing.html")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return _read_static("dashboard.html")


@app.get("/api/orgs")
def list_orgs():
    orgs = get_scored_orgs()
    return [
        {
            "org_id": o["org_id"],
            "name": o["name"],
            "sector": o["sector"],
            "location": o["location"],
            "org_risk_score": o["org_risk_score"],
            "org_risk_level": o["org_risk_level"],
            "asset_count": len(o["assets"]),
        }
        for o in orgs.values()
    ]


@app.get("/api/orgs/{org_id}")
def get_org(org_id: str):
    orgs = get_scored_orgs()
    org = orgs.get(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@app.get("/api/orgs/{org_id}/report")
def get_report(org_id: str):
    orgs = get_scored_orgs()
    org = orgs.get(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    path = generate_report(org)
    return FileResponse(path, media_type="application/pdf", filename=f"{org['name']}_incident_report.pdf")
