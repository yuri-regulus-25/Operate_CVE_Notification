import json
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

PUBLIC_DIR = Path("docs")
ALERTS_PATH = PUBLIC_DIR / "alerts.json"

KEYWORDS = [
    "AlmaLinux",
    "Red Hat Enterprise Linux",
    "RHEL",

    "npm",
    "Node.js",

    "composer",
    "Laravel",
    "Symfony",
    "symfony",
    "AuraSQL",
    "Aura SQL",

    "Vue.js",
    "Vue",
    "Vuetify",

    "PostgreSQL",

    "Apache HTTP Server",
    "Apache Tomcat",
]

CATEGORY_MAP = {
    "AlmaLinux": "OS",
    "Red Hat Enterprise Linux": "OS",
    "RHEL": "OS",

    "npm": "JS",
    "Node.js": "JS",
    "Vue.js": "JS",
    "Vue": "JS",
    "Vuetify": "JS",

    "composer": "PHP",
    "Laravel": "PHP",
    "Symfony": "PHP",
    "symfony": "PHP",
    "AuraSQL": "PHP",
    "Aura SQL": "PHP",

    "PostgreSQL": "DB",

    "Apache HTTP Server": "WEB",
    "Apache Tomcat": "WEB",
}

NVD_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "NONE",
    "UNKNOWN",
}

JVN_SEVERITIES = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "NONE",
]


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


def fetch_jvn(severity):
    params = {
        "method": "getVulnOverviewList",
        "feed": "oka",
        "cvssV3Severity": severity,
    }

    url = "https://jvndb.jvn.jp/myjvn?" + urllib.parse.urlencode(params)

    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


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


def truncate_text(text, limit=500):
    if not text:
        return ""

    if len(text) <= limit:
        return text

    return text[:limit] + "..."


def match_keyword(text):
    lower_text = text.lower()

    for keyword in KEYWORDS:
        if keyword.lower() in lower_text:
            return keyword

    return None


def make_alert_id(source, cve_id, matched):
    return f"{source}:{cve_id}:{matched}".lower()


def decide_priority(severity, matched):
    if severity == "CRITICAL":
        return "URGENT"

    if severity == "HIGH":
        return "WATCH"

    if severity == "MEDIUM":
        return "NOTICE"

    if severity == "LOW":
        return "LOW"

    return "INFO"


def normalize_nvd(data):
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

        if severity not in NVD_SEVERITIES:
            continue

        source = "NVD"

        alerts.append({
            "alert_id": make_alert_id(source, cve_id, matched),
            "source": source,
            "category": CATEGORY_MAP.get(matched, "UNKNOWN"),
            "priority": decide_priority(severity, matched),
            "cve_id": cve_id,
            "matched": matched,
            "severity": severity,
            "score": score,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": truncate_text(description),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return alerts


def normalize_jvn(xml_text, severity):
    alerts = []

    if not xml_text:
        print(f"JVN {severity}: empty xml")
        return alerts

    root = ET.fromstring(xml_text)

    namespaces = {
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "item": "http://jvndb.jvn.jp/myjvn/Item#",
        "sec": "http://jvn.jp/rss/mod_sec/",
    }

    items = root.findall(".//item:item", namespaces)
    print(f"JVN {severity}: raw items = {len(items)}")

    matched_count = 0

    for item in items:
        title = item.findtext("item:title", default="", namespaces=namespaces)
        link = item.findtext("item:link", default="", namespaces=namespaces)
        identifier = item.findtext("sec:identifier", default="", namespaces=namespaces)
        description = item.findtext("item:description", default="", namespaces=namespaces)

        text = f"{title} {description}"
        matched = match_keyword(text)

        if not matched:
            continue

        matched_count += 1

        source = "JVN"
        cve_id = identifier if identifier else title

        alerts.append({
            "alert_id": make_alert_id(source, cve_id, matched),
            "source": source,
            "category": CATEGORY_MAP.get(matched, "UNKNOWN"),
            "priority": decide_priority(severity, matched),
            "cve_id": cve_id,
            "matched": matched,
            "severity": severity,
            "score": "",
            "published": "",
            "last_modified": "",
            "description": truncate_text(title or description),
            "url": link,
        })

    print(f"JVN {severity}: matched items = {matched_count}")

    return alerts

def dedupe_alerts(alerts):
    seen = set()
    results = []

    for alert in alerts:
        key = alert.get("alert_id")

        if key in seen:
            continue

        seen.add(key)
        results.append(alert)

    return results


def count_by_source(alerts):
    result = {}

    for alert in alerts:
        source = alert.get("source", "UNKNOWN")
        result[source] = result.get(source, 0) + 1

    return result


def main():
    PUBLIC_DIR.mkdir(exist_ok=True)

    alerts = []

    try:
        nvd_data = fetch_nvd()
        alerts.extend(normalize_nvd(nvd_data))
    except Exception as e:
        print(f"NVD fetch failed: {e}")

    for severity in JVN_SEVERITIES:
        try:
            jvn_xml = fetch_jvn(severity)
            alerts.extend(normalize_jvn(jvn_xml, severity))
        except Exception as e:
            print(f"JVN fetch failed: {severity}: {e}")

    alerts = dedupe_alerts(alerts)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(alerts),
        "sources": count_by_source(alerts),
        "alerts": alerts,
    }

    with ALERTS_PATH.open("w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()