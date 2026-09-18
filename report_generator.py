"""
Compliance-ready incident report generator.
Takes a scored org (from scoring.py) and produces a PDF report.
"""
import io
from datetime import datetime

import os
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

REMEDIATION_LIBRARY = {
    "remote_admin": "Disable direct internet exposure of remote admin services (RDP/VPN); require MFA and place behind a VPN gateway.",
    "file_sharing": "Disable SMBv1 and restrict file-sharing ports to internal network segments only.",
    "file_transfer": "Replace unencrypted FTP with SFTP/FTPS and patch to the latest server version.",
    "web_server": "Patch web server software to the latest stable release and apply a WAF in front of public sites.",
    "iot_admin_panel": "Change default credentials, restrict admin panel access by IP allowlist, and update firmware.",
    "ot_ics": "Segment OT/ICS networks from the internet entirely; use a jump host with strict access controls.",
    "database": "Remove direct internet exposure of database ports; require VPN + authentication for remote access.",
    "mail_server": "Keep mail server software patched and monitor for abuse; low immediate ransomware risk.",
}


def build_recommendations(org):
    seen = set()
    recs = []
    # Sort assets by risk score descending so top priorities come first
    for a in sorted(org["assets"], key=lambda x: -x["risk_score"]):
        exposure = a.get("exposure_type")
        if exposure not in seen:
            seen.add(exposure)
            rec = REMEDIATION_LIBRARY.get(exposure, "Review and restrict this exposed service.")
            recs.append(f"[{a['hostname']}] {rec}")
    return recs


def generate_report(org) -> io.BytesIO:
    """
    Render the org's compliance report and return it as an in-memory PDF
    (BytesIO), rather than writing to disk.

    Serverless platforms (Vercel, Lambda, etc.) mount the deployment bundle
    read-only and only expose a writable /tmp — writing report PDFs next to
    the source (the old `reports/` dir under the app directory) raises
    OSError: [Errno 30] Read-only file system in that environment, which
    FastAPI surfaces as a 500. Generating in memory sidesteps the filesystem
    entirely and works the same locally and in serverless.
    """
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report.html")

    critical_count = sum(1 for a in org["assets"] if a["risk_level"] == "Critical")
    high_count = sum(1 for a in org["assets"] if a["risk_level"] == "High")

    html_content = template.render(
        org=org,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        critical_count=critical_count,
        high_count=high_count,
        recommendations=build_recommendations(org),
    )

    buffer = io.BytesIO()
    result = pisa.CreatePDF(src=html_content, dest=buffer)
    if result.err:
        raise RuntimeError(f"PDF generation failed for {org['org_id']}")

    buffer.seek(0)
    return buffer


if __name__ == "__main__":
    from scoring import score_all_orgs

    for org in score_all_orgs():
        pdf_buffer = generate_report(org)
        out_path = f"/tmp/{org['org_id']}_report.pdf"
        with open(out_path, "wb") as f:
            f.write(pdf_buffer.read())
        print(f"Generated: {out_path}")
