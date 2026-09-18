"""HTML report and SMTP email delivery for scan requests."""

from __future__ import annotations

import html
import json
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

NOTIFY_EMAIL = os.getenv("SCAN_NOTIFY_EMAIL", "madipadige.nikhil4u@gmail.com")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "KizunaShield")


def _esc(value: object) -> str:
    return html.escape(str(value if value not in (None, "") else "—"))


def build_request_report(entry: dict) -> str:
    details = entry.get("details") or {}
    detail_rows = "".join(
        f"<tr><th>{_esc(key.replace('_', ' ').title())}</th><td>{_esc(value)}</td></tr>"
        for key, value in details.items()
    ) or "<tr><td colspan=\"2\">No additional details supplied.</td></tr>"
    generated = _esc(entry.get("submitted_at"))
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><title>KizunaShield scan request</title>
<style>body{{font-family:Arial,sans-serif;color:#1c1b19;background:#f1ece1;margin:0;padding:28px}}.card{{max-width:760px;margin:auto;background:#fff;padding:32px;border:1px solid #ddd4c5}}h1{{color:#10192c;margin-top:0}}h2{{color:#bf3b2c;border-bottom:1px solid #e5ddd0;padding-bottom:8px}}table{{border-collapse:collapse;width:100%;margin:14px 0 26px}}th,td{{text-align:left;border:1px solid #ddd4c5;padding:10px;vertical-align:top}}th{{width:32%;background:#f7f3eb}}.ref{{font-size:20px;font-weight:bold;color:#bf3b2c}}.small{{color:#625e57;font-size:13px}}</style></head>
<body><main class=\"card\"><h1>New KizunaShield scan request</h1>
<p class=\"ref\">Reference: {_esc(entry.get('request_id'))}</p>
<h2>Requester</h2><table><tr><th>Organization</th><td>{_esc(entry.get('org_name'))}</td></tr><tr><th>Contact email</th><td>{_esc(entry.get('contact_email'))}</td></tr><tr><th>Requested connection method</th><td>{_esc(entry.get('method'))}</td></tr><tr><th>Submitted at</th><td>{generated}</td></tr></table>
<h2>What they want / supplied details</h2><table>{detail_rows}</table>
<h2>Follow-up checklist</h2><ol><li>Confirm the requester and organization details.</li><li>Review the requested connection method and scope before authorizing access.</li><li>Agree on scan timing, authorization, and expected deliverables.</li><li>Follow up using the requester email above and reference the request ID.</li></ol>
<p class=\"small\">This report was generated automatically by KizunaShield. It is a request summary, not a completed security scan.</p></main></body></html>"""


def send_request_report(entry: dict) -> None:
    """Send the request report through an authenticated SMTP mailbox."""
    missing = [name for name, value in {
        "SMTP_USER": SMTP_USER,
        "SMTP_PASSWORD": SMTP_PASSWORD,
        "SMTP_FROM": SMTP_FROM,
    }.items() if not value]
    if missing:
        raise RuntimeError(f"Email automation is not configured: missing {', '.join(missing)}")

    report_html = build_request_report(entry)
    message = EmailMessage()
    message["Subject"] = f"KizunaShield scan request {entry['request_id']} — {entry.get('org_name', 'Unknown organization')}"
    message["From"] = formataddr((SMTP_FROM_NAME, SMTP_FROM))
    message["To"] = NOTIFY_EMAIL
    message.set_content("A new KizunaShield scan request is attached as an HTML email. Please view it in an HTML-capable email client.")
    message.add_alternative(report_html, subtype="html")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise RuntimeError(f"Email automation failed: {exc}") from exc
