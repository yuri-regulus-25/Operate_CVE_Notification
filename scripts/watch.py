import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

PUBLIC_DIR = Path("public")
ALERTS_PATH = PUBLIC_DIR / "alerts.json"

KEYWORDS = [
    "AlmaLinux",
    "Red Hat Enterprise Linux",
    "RHEL",
    "npm",
    "composer",
    "Vue.js",
    "Vue",
    "Vuetify",
    "Laravel",
]

SEVERITIES = {"CRITICAL", "HIGH"}

def fetch_nvd():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)

    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))

def get_severity(cve):
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key)
        if values:
            return values[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")

    return "UNKNOWN"

def get_score(cve):
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key)
        if values:
            return values[0].get("cvssData", {}).get("baseScore")

    return None

def get_description(cve):
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""

def match_keyword(text):
    lower_text = text.lower()

    for keyword in KEYWORDS:
        if keyword.lower() in lower_text:
            return keyword

    return None

def main():
    PUBLIC_DIR.mkdir(exist_ok=True)

    data = fetch_nvd()
    alerts = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        description = get_description(cve)
        severity = get_severity(cve)
        score = get_score(cve)

        matched = match_keyword(description)

        if not matched:
            continue

        if severity not in SEVERITIES:
            continue

        alerts.append({
            "cve_id": cve_id,
            "matched": matched,
            "severity": severity,
            "score": score,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(alerts),
        "alerts": alerts
    }

    with ALERTS_PATH.open("w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()