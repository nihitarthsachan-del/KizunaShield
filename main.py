"""
KizunaShield — Attack Surface & Ransomware Risk Scanner (MVP backend).

Routes:
  GET /                          -> marketing landing page
  GET /dashboard                 -> exposure dashboard (talks to the API below)
  GET /api/orgs                  -> list all orgs with scores
  GET /api/orgs/{org_id}         -> full scored detail for one org
  GET /api/orgs/{org_id}/report  -> download compliance PDF report
"""
import os
import json
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scoring import score_all_orgs
from report_generator import generate_report
from connect_notifications import send_request_report

app = FastAPI(title="KizunaShield — Attack Surface & Ransomware Risk Scanner")

BASE_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(BASE_DIR, "static")
CONNECT_REQUESTS_PATH = os.getenv(
    "CONNECT_REQUESTS_PATH", "/tmp/kizunashield_connect_requests.json"
)

# Serve landing.html's/dashboard.html's own asset references (none currently,
# but this keeps room for future css/js/img files without touching routes).
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


def _read_static(filename: str) -> str:
    with open(os.path.join(STATIC_DIR, filename), encoding="utf-8") as f:
        return f.read()


class ConnectRequest(BaseModel):
    method: Literal["ip_range", "agent", "saas"]
    org_name: str
    contact_email: str
    details: Optional[dict] = None


def _load_connect_requests() -> list:
    if not os.path.exists(CONNECT_REQUESTS_PATH):
        return []
    with open(CONNECT_REQUESTS_PATH, encoding="utf-8") as f:
        return json.load(f)


def _save_connect_requests(requests_log: list) -> None:
    parent = os.path.dirname(CONNECT_REQUESTS_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(CONNECT_REQUESTS_PATH, "w", encoding="utf-8") as f:
        json.dump(requests_log, f, indent=2)


def get_scored_orgs():
    # Recomputed on each call — cheap for MVP scale, keeps demo data "live"
    return {org["org_id"]: org for org in score_all_orgs()}


@app.get("/", response_class=HTMLResponse)
def landing():
    return _read_static("landing.html")


@app.get("/connect", response_class=HTMLResponse)
def connect_page():
    return _read_static("connect.html")


@app.post("/api/connect")
def submit_connect_request(payload: ConnectRequest):
    requests_log = _load_connect_requests()
    entry = payload.model_dump()
    entry["request_id"] = f"req_{len(requests_log) + 1:04d}"
    entry["submitted_at"] = datetime.now(timezone.utc).isoformat()
    requests_log.append(entry)
    _save_connect_requests(requests_log)
    try:
        send_request_report(entry)
    except RuntimeError as exc:
        # Keep the request recorded, but expose a clear configuration failure
        # instead of falsely claiming that an email was sent.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"status": "received", "request_id": entry["request_id"]}


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

    # generate_report now returns an in-memory BytesIO buffer instead of
    # writing a PDF to disk (see report_generator.py) — required for
    # serverless deploys (e.g. Vercel) where the app directory is read-only
    # and only /tmp is writable.
    pdf_buffer = generate_report(org)
    filename = f"{org['name']}_incident_report.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
