import xml.etree.ElementTree as ET
import urllib.parse
from datetime import datetime, timedelta, timezone

from external_service.http_client import fetch_text

from external_service.model import FETCH_ERROR, PARSE_ERROR, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event


JVN_API_URL = "https://jvndb.jvn.jp/myjvn"
NAMESPACES = {
    "rss": "http://purl.org/rss/1.0/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
}


def parse_jvn(xml_text, service_key, requested_keyword):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        return [], {"status": PARSE_ERROR, "message": str(error)}

    events = []
    for item in root.findall(".//rss:item", NAMESPACES):
        title = item.findtext("rss:title", default="", namespaces=NAMESPACES)
        if "該当する脆弱性対策情報はありません" in title:
            continue
        description = item.findtext("rss:description", default="", namespaces=NAMESPACES)
        link = item.findtext("rss:link", default="", namespaces=NAMESPACES)
        published = item.findtext("dcterms:issued", default="", namespaces=NAMESPACES)
        event = make_event("JVN", service_key, title, description, link, published, raw={"keyword": requested_keyword})
        if event:
            events.append(event)

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}


def _date_params(prefix, start, end):
    return {
        f"{prefix}StartY": f"{start.year:04d}",
        f"{prefix}StartM": f"{start.month:02d}",
        f"{prefix}StartD": f"{start.day:02d}",
        f"{prefix}EndY": f"{end.year:04d}",
        f"{prefix}EndM": f"{end.month:02d}",
        f"{prefix}EndD": f"{end.day:02d}",
    }


def fetch_for_service(service, lookback_days=14):
    events = []
    end = datetime.now(timezone(timedelta(hours=9))).date()
    start = end - timedelta(days=lookback_days)

    for keyword in service.get("sources", {}).get("nvd_keywords", []):
        for date_type, date_values in (
            ("published", _date_params("dateFirstPublished", start, end)),
            ("modified", _date_params("datePublished", start, end)),
        ):
            params = {
                "method": "getVulnOverviewList",
                "feed": "hnd",
                "keyword": keyword,
                "useSynonym": "1",
                "rangeDatePublic": "n",
                "rangeDatePublished": "n",
                "rangeDateFirstPublished": "n",
                "maxCountItem": 50,
                **date_values,
            }
            try:
                xml_text = fetch_text(JVN_API_URL + "?" + urllib.parse.urlencode(params), timeout=60, retries=3)
                parsed, status = parse_jvn(xml_text, service["key"], keyword)
                events.extend(parsed)
                if status["status"] not in {SUCCESS, SUCCESS_NO_RESULTS}:
                    return events, status
            except Exception as error:
                return events, {"status": FETCH_ERROR, "message": f"{keyword}/{date_type}: {error}"}

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}
