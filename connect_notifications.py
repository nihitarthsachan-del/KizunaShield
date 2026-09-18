"""HTML report and email delivery for network scan requests."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

NOTIFY_EMAIL = os.getenv("SCAN_NOTIFY_EMAIL", "madipadige.nikhil4u@gmail.com")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
EMAIL_FROM = os.getenv("SCAN_EMAIL_FROM", "KizunaShield <onboarding@resend.dev>")


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
    """Send the report through Resend when configured; fail loudly for observability."""
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY is not configured")
    report_html = build_request_report(entry)
    payload = json.dumps({
        "from": EMAIL_FROM,
        "to": [NOTIFY_EMAIL],
        "subject": f"KizunaShield scan request {entry['request_id']} — {entry.get('org_name', 'Unknown organization')}",
        "html": report_html,
    }).encode("utf-8")
    request = Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            if response.status >= 300:
                raise RuntimeError(f"Email provider returned HTTP {response.status}")
    except (HTTPError, URLError) as exc:
        raise RuntimeError(f"Email delivery failed: {exc}") from exc
