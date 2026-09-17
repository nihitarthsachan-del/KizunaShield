# KizunaShield — Attack Surface & Ransomware Risk Scanner

A low-cost, automated tool that discovers exposed assets, scores ransomware
risk using known-exploited-vulnerability data, and auto-generates a
compliance-ready incident report — built for resource-constrained SMEs
facing Japan's Cyber Response Capability Enhancement Act (effective
Oct 1, 2026).

## How it works

1. **`data/sample_orgs.json`** — demo dataset of 5 fictional Japanese SMEs
   with realistic exposed assets (RDP, FTP, SMB, IoT admin panels, OT/SCADA,
   databases). Swap this for real scan output later.
2. **`scoring.py`** — rule-based risk engine. Each asset gets a base score
   from its exposure type (remote admin, file sharing, OT/ICS, etc.), boosted
   by any match against `data/kev_sample.json` (modeled on CISA's Known
   Exploited Vulnerabilities catalog), with an extra boost if that CVE has
   documented ransomware use. Org-level score blends max + average asset risk.
3. **`report_generator.py`** — renders `templates/report.html` with Jinja2
   and converts it to a PDF via xhtml2pdf (pure Python, no native
   dependencies): executive summary, asset inventory, matched CVEs,
   prioritized remediation steps, and a compliance readiness note.
4. **`main.py`** — FastAPI backend serving the landing page, the dashboard,
   and three API endpoints: `/api/orgs`, `/api/orgs/{id}`,
   `/api/orgs/{id}/report`.
5. **`static/landing.html`** — marketing landing page with a Japanese-inspired
   design system (indigo/washi/vermillion palette, Shippori Mincho + Zen Kaku
   Gothic New type). Links through to the live dashboard.
6. **`static/dashboard.html`** — the working exposure dashboard, styled to
   match the landing page: click an org, see its scored assets, generate its
   compliance PDF report — all driven by the live API, not mock data.

## Run it

```bash
pip install -r requirements.txt   # add --break-system-packages on some Linux setups
uvicorn main:app --reload
```

Open http://localhost:8000 for the landing page, or go straight to
http://localhost:8000/dashboard for the exposure dashboard. All 5 demo orgs
load sorted by risk score; click one, review its exposed assets, then
generate its PDF report.

## Project structure

```
KizunaShield/
├── main.py                 # FastAPI app: routes + API
├── scoring.py               # risk scoring engine
├── report_generator.py      # PDF report generation
├── data/
│   ├── sample_orgs.json     # demo SME dataset
│   └── kev_sample.json      # known-exploited-vulnerabilities reference data
├── templates/
│   └── report.html          # Jinja2 template for the PDF report
├── static/
│   ├── landing.html         # marketing landing page
│   └── dashboard.html       # exposure dashboard (frontend)
└── requirements.txt
```

## Extending beyond the demo (post-hackathon / stretch)

- **Real scanning**: replace `data/sample_orgs.json` with live output from
  `python-nmap` (against a target you own) or the Shodan/Censys APIs
  (passive recon, no active scanning needed — safer and faster to demo).
- **Real KEV data**: swap `data/kev_sample.json` for a live pull of CISA's
  KEV JSON feed and NVD CVE lookups.
- **Persistence**: add a database so orgs can be scanned on a recurring
  schedule and reports show trend-over-time.
- **Auth + multi-tenant**: needed before any real SME's data touches this.

## Demo script (for judges)

1. Open the landing page — leads with the compliance urgency and the real
   numbers behind the problem.
2. Click "See a sample scan" to open the dashboard — orgs are pre-sorted by
   risk, worst first.
3. Click the top (Critical/High) org — walk through its exposed asset table
   and the matched known-exploited vulnerabilities.
4. Click "Generate compliance report" — hand judges the PDF. This is the
   moment that ties exposure discovery directly to Japan's Oct 2026
   reporting deadline — lead your narrative up to it, not past it.

