import json
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

PUBLIC_DIR = Path("docs")
ALERTS_PATH = PUBLIC_DIR / "alerts.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 2000
NVD_LOOKBACK_DAYS = 30
JVN_API_URL = "https://jvndb.jvn.jp/myjvn"
JVN_RESULTS_PER_PAGE = 50
JVN_LOOKBACK_DAYS = 30
JVN_TIMEZONE = timezone(timedelta(hours=9))

NVD_KEYWORDS = [
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
    "pgAdmin",
    "pgAdmin 4",
    "pgadmin4",
    "Apache HTTP Server",
    "Apache Tomcat",
]

NVD_CATEGORY_MAP = {
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
    "pgAdmin": "DB",
    "pgAdmin 4": "DB",
    "pgadmin4": "DB",
    "Apache HTTP Server": "WEB",
    "Apache Tomcat": "WEB",
}

JVN_KEYWORDS = [
    "Apache",
    "PostgreSQL",
    "Node.js",
    "Laravel",
    "Symfony",
    "Vue",
    "Vue.js",
    "Vuetify",
    "composer",
    "npm",
    "AlmaLinux",
    "Red Hat Enterprise Linux",
    "RHEL",
]

JVN_CATEGORY_MAP = {
    "Apache": "WEB",
    "PostgreSQL": "DB",
    "Node.js": "JS",
    "Vue": "JS",
    "Vue.js": "JS",
    "Vuetify": "JS",
    "npm": "JS",
    "composer": "PHP",
    "Laravel": "PHP",
    "Symfony": "PHP",
    "AlmaLinux": "OS",
    "Red Hat Enterprise Linux": "OS",
    "RHEL": "OS",
}


def format_nvd_datetime(value):
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def update_jvn_date_params(params, prefix, start, end):
    params.update({
        f"{prefix}StartY": f"{start.year:04d}",
        f"{prefix}StartM": f"{start.month:02d}",
        f"{prefix}StartD": f"{start.day:02d}",
        f"{prefix}EndY": f"{end.year:04d}",
        f"{prefix}EndM": f"{end.month:02d}",
        f"{prefix}EndD": f"{end.day:02d}",
    })


def get_jvn_status(xml_text):
    root = ET.fromstring(xml_text)

    for element in root.iter():
        if element.tag.endswith("Status"):
            return element.attrib

    return {}


def parse_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def fetch_nvd_page(params):
    url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
    print(f"NVD URL: {url}")

    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_nvd_by_date(date_type):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=NVD_LOOKBACK_DAYS)

    base_params = {
        "resultsPerPage": NVD_RESULTS_PER_PAGE,
        "startIndex": 0,
    }

    if date_type == "modified":
        base_params.update({
            "lastModStartDate": format_nvd_datetime(start),
            "lastModEndDate": format_nvd_datetime(end),
        })
    elif date_type == "published":
        base_params.update({
            "pubStartDate": format_nvd_datetime(start),
            "pubEndDate": format_nvd_datetime(end),
        })
    else:
        raise ValueError(f"Unknown NVD date_type: {date_type}")

    all_vulnerabilities = []
    start_index = 0
    total_results = None

    while True:
        params = dict(base_params)
        params["startIndex"] = start_index

        data = fetch_nvd_page(params)

        vulnerabilities = data.get("vulnerabilities", [])
        results_per_page = data.get("resultsPerPage", len(vulnerabilities))
        total_results = data.get("totalResults", 0)

        print(
            f"NVD [{date_type}]: "
            f"startIndex={start_index}, "
            f"resultsPerPage={results_per_page}, "
            f"pageItems={len(vulnerabilities)}, "
            f"totalResults={total_results}"
        )

        all_vulnerabilities.extend(vulnerabilities)

        if not vulnerabilities:
            break

        start_index += results_per_page

        if start_index >= total_results:
            break

        time.sleep(0.6)

    return {
        "source_date_type": date_type,
        "totalResults": total_results,
        "vulnerabilities": all_vulnerabilities,
    }


def fetch_nvd():
    published = fetch_nvd_by_date("published")
    modified = fetch_nvd_by_date("modified")

    return {
        "vulnerabilities": (
            published.get("vulnerabilities", [])
            + modified.get("vulnerabilities", [])
        )
    }


def fetch_jvn_page(params):
    url = JVN_API_URL + "?" + urllib.parse.urlencode(params)

    print(f"JVN URL: {url}")

    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def fetch_jvn_by_keyword_date(keyword, date_type):
    end = datetime.now(JVN_TIMEZONE).date()
    start = end - timedelta(days=JVN_LOOKBACK_DAYS)

    base_params = {
        "method": "getVulnOverviewList",
        "feed": "hnd",
        "keyword": keyword,
        "useSynonym": "1",
        "rangeDatePublic": "n",
        "rangeDatePublished": "n",
        "rangeDateFirstPublished": "n",
        "startItem": 1,
        "maxCountItem": JVN_RESULTS_PER_PAGE,
    }

    if date_type == "modified":
        update_jvn_date_params(
            base_params,
            "datePublished",
            start,
            end,
        )
    elif date_type == "published":
        update_jvn_date_params(
            base_params,
            "dateFirstPublished",
            start,
            end,
        )
    else:
        raise ValueError(f"Unknown JVN date_type: {date_type}")

    xml_pages = []
    start_item = 1

    while True:
        params = dict(base_params)
        params["startItem"] = start_item

        xml_text = fetch_jvn_page(params)
        xml_pages.append(xml_text)

        status = get_jvn_status(xml_text)
        total_results = parse_int(status.get("totalRes"))
        page_items = parse_int(status.get("totalResRet"))
        first_result = parse_int(
            status.get("firstRes"),
            start_item,
        )

        print(
            f"JVN [{keyword}/{date_type}]: "
            f"startItem={first_result}, "
            f"pageItems={page_items}, "
            f"totalResults={total_results}"
        )

        if page_items <= 0:
            break

        start_item = first_result + page_items

        if start_item > total_results:
            break

        time.sleep(0.6)

    return xml_pages


def fetch_jvn_by_keyword(keyword):
    return (
        fetch_jvn_by_keyword_date(keyword, "published")
        + fetch_jvn_by_keyword_date(keyword, "modified")
    )


def get_severity(cve):
    metrics = cve.get("metrics", {})

    for key in [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]:
        values = metrics.get(key)

        if values:
            return values[0].get(
                "cvssData",
                {},
            ).get(
                "baseSeverity",
                "UNKNOWN",
            )

    return "UNKNOWN"


def get_score(cve):
    metrics = cve.get("metrics", {})

    for key in [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]:
        values = metrics.get(key)

        if values:
            return values[0].get(
                "cvssData",
                {},
            ).get(
                "baseScore"
            )

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


def match_nvd_keyword(text):
    lower_text = text.lower()

    for keyword in NVD_KEYWORDS:
        if keyword.lower() in lower_text:
            return keyword

    return None


def make_alert_id(source, cve_id, matched):
    return f"{source}:{cve_id}:{matched}".lower()


def decide_priority(severity):
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

        matched = match_nvd_keyword(description)

        if not matched:
            continue

        source = "NVD"

        alerts.append({
            "alert_id": make_alert_id(
                source,
                cve_id,
                matched,
            ),
            "source": source,
            "category": NVD_CATEGORY_MAP.get(
                matched,
                "UNKNOWN",
            ),
            "priority": decide_priority(severity),
            "cve_id": cve_id,
            "matched": matched,
            "severity": severity,
            "score": score,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "title": cve_id,
            "description": truncate_text(description),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return alerts


def normalize_jvn(xml_text, requested_keyword):
    alerts = []

    if not xml_text:
        print("JVN: empty xml")
        return alerts

    root = ET.fromstring(xml_text)

    namespaces = {
        "rss": "http://purl.org/rss/1.0/",
        "dc": "http://purl.org/dc/elements/1.1/",
        "dcterms": "http://purl.org/dc/terms/",
        "sec": "http://jvn.jp/rss/mod_sec/3.0/",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    }

    items = root.findall(".//rss:item", namespaces)

    print(
        f"JVN [{requested_keyword}]: raw items = {len(items)}"
    )

    for item in items:
        title = item.findtext(
            "rss:title",
            default="",
            namespaces=namespaces,
        )

        if "MyJVN　該当する脆弱性対策情報はありません。" in title:
            continue

        link = item.findtext(
            "rss:link",
            default="",
            namespaces=namespaces,
        )

        identifier = item.findtext(
            "sec:identifier",
            default="",
            namespaces=namespaces,
        )

        description = item.findtext(
            "rss:description",
            default="",
            namespaces=namespaces,
        )

        cvss = item.find("sec:cvss", namespaces)

        score = (
            cvss.attrib.get("score", "")
            if cvss is not None
            else ""
        )

        severity = (
            cvss.attrib.get(
                "severity",
                "UNKNOWN",
            ).upper()
            if cvss is not None
            else "UNKNOWN"
        )

        cve_ids = [
            ref.attrib.get("id", "")
            for ref in item.findall(
                "sec:references",
                namespaces,
            )
            if ref.attrib.get("source") == "CVE"
        ]

        source = "JVN"
        matched = requested_keyword

        cve_id = (
            cve_ids[0]
            if cve_ids
            else (
                identifier
                if identifier
                else title
            )
        )

        alerts.append({
            "alert_id": make_alert_id(
                source,
                cve_id,
                matched,
            ),
            "source": source,
            "category": JVN_CATEGORY_MAP.get(
                matched,
                "UNKNOWN",
            ),
            "priority": decide_priority(severity),
            "cve_id": cve_id,
            "matched": matched,
            "severity": severity,
            "score": score,
            "published": item.findtext(
                "dcterms:issued",
                default="",
                namespaces=namespaces,
            ),
            "last_modified": item.findtext(
                "dcterms:modified",
                default="",
                namespaces=namespaces,
            ),
            "title": truncate_text(
                title
            ),
            "description": truncate_text(
                description or title
            ),
            "url": link,
        })

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
        result[source] = (
            result.get(source, 0) + 1
        )

    return result


def main():
    PUBLIC_DIR.mkdir(exist_ok=True)

    alerts = []

    try:
        nvd_data = fetch_nvd()
        alerts.extend(normalize_nvd(nvd_data))
    except Exception as e:
        print(f"NVD fetch failed: {e}")

    for keyword in JVN_KEYWORDS:
        try:
            jvn_xml_pages = fetch_jvn_by_keyword(keyword)

            for jvn_xml in jvn_xml_pages:
                alerts.extend(
                    normalize_jvn(
                        jvn_xml,
                        keyword,
                    )
                )
        except Exception as e:
            print(
                f"JVN fetch failed: {keyword}: {e}"
            )

    alerts = dedupe_alerts(alerts)

    output = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "count": len(alerts),
        "sources": count_by_source(alerts),
        "alerts": alerts,
    }

    with ALERTS_PATH.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            output,
            f,
            ensure_ascii=False,
            indent=2,
        )


if __name__ == "__main__":
    main()
