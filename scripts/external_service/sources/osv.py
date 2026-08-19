import json
import time
import urllib.error
import urllib.request

from external_service.http import fetch_json
from external_service.model import FETCH_ERROR, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


def normalize_vuln(vuln, service):
    aliases = vuln.get("aliases", [])
    cve = next((alias for alias in aliases if alias.startswith("CVE-")), vuln.get("id", ""))
    event = make_event(
        "OSV",
        service["key"],
        vuln.get("summary") or cve,
        vuln.get("details", ""),
        vuln.get("database_specific", {}).get("url", ""),
        vuln.get("published", ""),
        vuln.get("modified", ""),
        raw={"package": service.get("sdk", {})},
    )
    if event and cve.startswith("CVE-"):
        event["id"] = cve
    return event


def _post_json(url, payload, timeout=60, retries=3, retry_base_delay=10):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "external-service-risk-watch/1.0"},
    )
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt >= retries:
                raise
            time.sleep(retry_base_delay * attempt)
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt >= retries:
                raise
            time.sleep(retry_base_delay * attempt)


def fetch_for_services(services):
    sdk_services = [service for service in services if service.get("sdk")]
    if not sdk_services:
        return [], {"status": SUCCESS_NO_RESULTS, "count": 0}

    payload = {
        "queries": [
            {
                "package": {
                    "ecosystem": service["sdk"]["ecosystem"],
                    "name": service["sdk"]["package"],
                },
                "version": service["sdk"]["version"],
            }
            for service in sdk_services
        ]
    }

    try:
        batch = _post_json(OSV_BATCH_URL, payload)
        events = []
        for service, result in zip(sdk_services, batch.get("results", [])):
            for vuln_ref in result.get("vulns", []):
                vuln = fetch_json(OSV_VULN_URL + vuln_ref["id"])
                event = normalize_vuln(vuln, service)
                if event:
                    events.append(event)
    except Exception as error:
        return [], {"status": FETCH_ERROR, "message": str(error)}

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}
