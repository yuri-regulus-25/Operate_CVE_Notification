import os
import time
import urllib.parse

from external_service.http import fetch_json
from external_service.model import FETCH_ERROR, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event, severity_level


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _description(cve):
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def _severity(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            return {"level": severity_level(data.get("baseScore"), data.get("baseSeverity")), "cvss": data.get("baseScore")}
    return {"level": "UNKNOWN", "cvss": None}


def normalize_item(item, service_key, keyword):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    description = _description(cve)
    event = make_event(
        "NVD",
        service_key,
        cve_id,
        description,
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        cve.get("published", ""),
        cve.get("lastModified", ""),
        raw={"keyword": keyword},
    )
    if event:
        event["severity"] = _severity(cve)
    return event


def fetch_for_service(service, start_iso, end_iso, results_per_page=100, delay=3):
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY")

    events = []
    for keyword in service.get("sources", {}).get("nvd_keywords", []):
        for date_params in (
            {"pubStartDate": start_iso, "pubEndDate": end_iso},
            {"lastModStartDate": start_iso, "lastModEndDate": end_iso},
        ):
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page,
                "startIndex": 0,
                **date_params,
            }
            try:
                data = fetch_json(NVD_API_URL + "?" + urllib.parse.urlencode(params), headers=headers)
            except Exception as error:
                return [], {"status": FETCH_ERROR, "message": str(error)}
            for item in data.get("vulnerabilities", []):
                event = normalize_item(item, service["key"], keyword)
                if event:
                    events.append(event)
            time.sleep(delay)

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}
