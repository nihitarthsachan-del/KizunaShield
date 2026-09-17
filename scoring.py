"""
Ransomware risk scoring engine.

Rule-based (no ML needed for MVP): each exposed asset gets a base score from
its exposure type, boosted by any known-exploited-vulnerability (KEV) hits,
with an extra boost if that CVE has documented ransomware use.
"""
import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

EXPOSURE_BASE_SCORE = {
    "remote_admin": 30,
    "ot_ics": 30,
    "file_sharing": 25,
    "database": 20,
    "iot_admin_panel": 20,
    "file_transfer": 15,
    "web_server": 10,
    "mail_server": 5,
}

CVE_SEVERITY_BONUS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
}

RANSOMWARE_USE_BONUS = 15


def load_json(filename):
    with open(os.path.join(DATA_DIR, filename), "r") as f:
        return json.load(f)


def score_asset(asset, kev_db):
    base = EXPOSURE_BASE_SCORE.get(asset.get("exposure_type"), 10)
    cve_bonus = 0
    matched_cves = []

    for cve_id in asset.get("cves", []):
        entry = kev_db.get(cve_id)
        if entry:
            bonus = CVE_SEVERITY_BONUS.get(entry["severity"], 10)
            if entry.get("known_ransomware_use"):
                bonus += RANSOMWARE_USE_BONUS
            cve_bonus += bonus
            matched_cves.append({
                "cve_id": cve_id,
                "name": entry["name"],
                "severity": entry["severity"],
                "known_ransomware_use": entry.get("known_ransomware_use", False),
            })

    score = min(100, base + cve_bonus)
    return {
        **asset,
        "risk_score": score,
        "risk_level": score_to_level(score),
        "matched_vulnerabilities": matched_cves,
    }


def score_to_level(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def score_org(org, kev_db):
    scored_assets = [score_asset(a, kev_db) for a in org["assets"]]
    if scored_assets:
        max_score = max(a["risk_score"] for a in scored_assets)
        avg_score = sum(a["risk_score"] for a in scored_assets) / len(scored_assets)
        org_score = round(min(100, max_score * 0.65 + avg_score * 0.35))
    else:
        org_score = 0

    return {
        "org_id": org["org_id"],
        "name": org["name"],
        "sector": org["sector"],
        "location": org["location"],
        "org_risk_score": org_score,
        "org_risk_level": score_to_level(org_score),
        "assets": scored_assets,
    }


def score_all_orgs():
    orgs = load_json("sample_orgs.json")
    kev_db = load_json("kev_sample.json")
    return [score_org(org, kev_db) for org in orgs]


if __name__ == "__main__":
    results = score_all_orgs()
    for org in results:
        print(f"{org['name']} ({org['org_id']}) — Risk: {org['org_risk_score']} [{org['org_risk_level']}]")
        for a in org["assets"]:
            print(f"   {a['service']} :{a['port']} -> {a['risk_score']} [{a['risk_level']}]")
