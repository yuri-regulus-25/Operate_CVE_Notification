import json
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

from external_service.http_client import fetch_text
from external_service.model import FETCH_ERROR, SCHEMA_CHANGED, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event


MSRC_CVRF_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/"


class TextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        value = data.strip()
        if value:
            self.parts.append(value)


def parse_graph_changelog_html(html_text, service_key, url):
    parser = TextParser()
    parser.feed(html_text)
    text = "\n".join(parser.parts)

    if "Microsoft Graph" not in text and "Change type" not in text:
        return [], {"status": SCHEMA_CHANGED, "message": "Microsoft Graph changelog markers were not found."}

    events = []
    lines = parser.parts
    for index, line in enumerate(lines):
        if line not in {"Change", "Deletion", "Deprecation"}:
            continue
        window = " ".join(lines[max(0, index - 4):index + 8])
        if not re.search(r"calendar|event|calendarView|online meeting|teams|oauth|permission|deprecat|delet|breaking", window, re.I):
            continue
        event = make_event(
            "Microsoft Graph Changelog",
            service_key,
            f"Microsoft Graph {line}",
            window,
            url,
            raw={"source": "graph_changelog_html"},
        )
        if event:
            events.append(event)

    return events, {
        "status": SUCCESS if events else SUCCESS_NO_RESULTS,
        "raw_count": len(lines),
        "count": len(events),
    }


def parse_msrc_updates(json_text, service_key, url):
    data = json.loads(json_text)
    values = data.get("value", [])
    if not isinstance(values, list):
        return [], {"status": SCHEMA_CHANGED, "message": "MSRC updates response did not contain a value list."}

    events = []
    for item in values:
        title = item.get("DocumentTitle") or item.get("Title") or item.get("ID", "")
        description = " ".join(str(item.get(key, "")) for key in ("Alias", "DocumentTitle", "Severity"))
        if not re.search(r"graph|teams|outlook|calendar|oauth", f"{title} {description}", re.I):
            continue
        event = make_event("MSRC", service_key, title, description, url, item.get("InitialReleaseDate", ""), item.get("CurrentReleaseDate", ""), raw=item)
        if event:
            events.append(event)

    return events, {
        "status": SUCCESS if events else SUCCESS_NO_RESULTS,
        "raw_count": len(values),
        "count": len(events),
    }


def _parse_date(value):
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except ValueError:
        return None


def recent_update_ids(json_text, lookback_days=45):
    data = json.loads(json_text)
    values = data.get("value", [])
    if not isinstance(values, list):
        return [], {"status": SCHEMA_CHANGED, "message": "MSRC updates response did not contain a value list."}

    threshold = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    ids = []
    for item in values:
        current = _parse_date(item.get("CurrentReleaseDate") or item.get("InitialReleaseDate"))
        if current and current < threshold:
            continue
        doc_id = item.get("ID")
        if doc_id:
            ids.append(doc_id)

    return ids, {"status": SUCCESS if ids else SUCCESS_NO_RESULTS, "raw_count": len(values), "count": len(ids)}


def parse_cvrf_document(json_text, service_key, url):
    data = json.loads(json_text)
    vulnerabilities = data.get("Vulnerability", [])
    products = {}
    for product in data.get("ProductTree", {}).get("FullProductName", []):
        product_id = product.get("ProductID")
        if product_id:
            products[product_id] = product.get("Value", "")

    if not isinstance(vulnerabilities, list):
        return [], {"status": SCHEMA_CHANGED, "message": "CVRF document did not contain a vulnerability list."}

    events = []
    for vuln in vulnerabilities:
        cve = vuln.get("CVE", "")
        notes = " ".join(note.get("Value", "") for note in vuln.get("Notes", []))
        statuses = []
        for value in vuln.get("ProductStatuses", []):
            statuses.extend(value.get("ProductID", []))
        affected = [products.get(product_id, product_id) for product_id in statuses]
        text = " ".join([cve, notes, " ".join(affected)])
        if not re.search(r"graph|teams|outlook|calendar|oauth", text, re.I):
            continue
        title = cve or vuln.get("Title", {}).get("Value", "MSRC vulnerability")
        event = make_event(
            "MSRC",
            service_key,
            title,
            text,
            url,
            data.get("DocumentTracking", {}).get("InitialReleaseDate", ""),
            data.get("DocumentTracking", {}).get("CurrentReleaseDate", ""),
            raw={"affected": affected},
        )
        if event:
            events.append(event)

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "raw_count": len(vulnerabilities), "count": len(events)}


def cvrf_detail_url(doc_id):
    return f"{MSRC_CVRF_BASE_URL}{doc_id}"


def fetch_for_service(service, graph_urls, msrc_url, lookback_days=45):
    events = []
    health = {}

    for url in graph_urls:
        key = f"microsoft_graph:{service['key']}:{url}"
        try:
            html_text = fetch_text(url)
            parsed, status = parse_graph_changelog_html(html_text, service["key"], url)
            events.extend(parsed)
            health[key] = status
        except Exception as error:
            health[key] = {"status": FETCH_ERROR, "message": str(error)}

    if msrc_url:
        try:
            updates_text = fetch_text(msrc_url)
            ids, status = recent_update_ids(updates_text, lookback_days=lookback_days)
            health[f"msrc_updates:{service['key']}"] = status
            for doc_id in ids:
                detail_url = cvrf_detail_url(doc_id)
                try:
                    detail_text = fetch_text(detail_url)
                    parsed, detail_status = parse_cvrf_document(detail_text, service["key"], detail_url)
                    events.extend(parsed)
                    health[f"msrc_cvrf:{service['key']}:{doc_id}"] = detail_status
                except Exception as error:
                    health[f"msrc_cvrf:{service['key']}:{doc_id}"] = {"status": FETCH_ERROR, "message": str(error)}
        except Exception as error:
            health[f"msrc_updates:{service['key']}"] = {"status": FETCH_ERROR, "message": str(error)}

    return events, health
