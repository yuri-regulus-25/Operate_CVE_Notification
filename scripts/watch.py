import json
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

PUBLIC_DIR = Path("docs")
ALERTS_PATH = PUBLIC_DIR / "alerts.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_RESULTS_PER_PAGE = 2000
NVD_LOOKBACK_DAYS = 15
NVD_REQUEST_DELAY = 0.7 if NVD_API_KEY else 6.1
NVD_MAX_RETRIES = 3

JVN_API_URL = "https://jvndb.jvn.jp/myjvn"
JVN_RESULTS_PER_PAGE = 50
JVN_LOOKBACK_DAYS = 15
JVN_TIMEZONE = timezone(timedelta(hours=9))

# ============================================================
# Keyword Settings
# ============================================================
# - NVD / JVN で同じキーワード群を使用する
# - category は既存 alerts.json 互換を優先して OS / WEB / DB / PHP / JS / UNKNOWN を維持
# - Windows / Windows Server 関連は OS として扱う
# - IIS / RDP / SMB など Windows 周辺コンポーネントも検索対象に含める

KEYWORD_GROUPS = {
    "Linux": [
        "AlmaLinux",
        "Red Hat Enterprise Linux",
        "RHEL",
    ],

    "Windows": [
        "Microsoft Windows",
        "Windows Server",
        "Windows 10",
        "Windows 11",
        "Windows Server 2012",
        "Windows Server 2016",
        "Windows Server 2019",
        "Windows Server 2022",
        "Windows Server 2025",

        "Windows Kernel",
        "Win32k",
        "Windows Installer",
        "Windows TCP/IP",
        "Windows Common Log File System",
        "CLFS",
        "BitLocker",
        "Hyper-V",
    ],
    "WEB": [
        "Apache",
        "Apache HTTP Server",
        "Apache Tomcat",
        "IIS",
        "Remote Desktop Services",
        "RDP",
        "SMB",
        "NTLM",
        "Kerberos",
        "Active Directory",
        "LDAP",
        "DNS Server",
        "DHCP Server",
        "Windows Print Spooler",
        "Windows Routing and Remote Access Service",
        "RRAS",
        "Microsoft Defender",
        "Windows Defender",
    ],

    "DB": [
        "PostgreSQL",
        "pgAdmin",
        "pgAdmin 4",
        "pgadmin4",
    ],

    "PHP": [
        "composer",
        "Composer",
        "Laravel",
        "Symfony",
        "symfony",
        "AuraSQL",
        "Aura SQL",
    ],

    "JS": [
        "npm",
        "Node.js",
        "Vue.js",
        "Vue",
        "Vuetify",
    ],
}


def flatten_keywords(keyword_groups):
    keywords = []

    for group_keywords in keyword_groups.values():
        for keyword in group_keywords:
            if keyword not in keywords:
                keywords.append(keyword)

    return keywords


def build_category_map(keyword_groups):
    category_map = {}

    for category, group_keywords in keyword_groups.items():
        for keyword in group_keywords:
            category_map[keyword] = category

    return category_map


NVD_KEYWORDS = flatten_keywords(KEYWORD_GROUPS)
JVN_KEYWORDS = NVD_KEYWORDS.copy()

NVD_CATEGORY_MAP = build_category_map(KEYWORD_GROUPS)
JVN_CATEGORY_MAP = NVD_CATEGORY_MAP.copy()

STRONG_REJECT_PATTERNS = [
    "Windows版",
    "for Windows",
    "Windows version",
    "on Windows",
    "Windows環境",
    "Linux, UNIX and Windows",
    "Windows/macOS/Linux",
    "Vue, React, Angular",
    "Vue/React/Angular",
    "supports Vue",
    "RDP/VNC/SSH",
    "SMB service on device",
]

MICROSOFT_CONTEXT = [
    "Microsoft",
    "Windows",
    "Active Directory",
    "Microsoft Entra",
    "Azure AD",
]

WINDOWS_CONTEXT = [
    "Microsoft",
    "Windows",
    "Win32k",
    "CLFS",
    "BitLocker",
    "Hyper-V",
    "Defender",
    "Active Directory",
]

PHP_COMPOSER_CONTEXT = [
    "PHP",
    "package manager",
    "dependency manager",
]

NPM_CONTEXT = [
    "npm package",
    "npm CLI",
    "npm registry",
    "package.json",
    "Node.js",
    "Node package",
]

PRODUCT_RULES = [
    {
        "key": "almalinux",
        "display": "AlmaLinux",
        "category": "OS",
        "formal": ["AlmaLinux"],
        "cpe": ["almalinux"],
    },
    {
        "key": "rhel",
        "display": "Red Hat Enterprise Linux",
        "category": "OS",
        "formal": ["Red Hat Enterprise Linux"],
        "aliases": ["RHEL"],
        "cpe": ["redhat:enterprise_linux", "red_hat:enterprise_linux", "rhel"],
    },
    {
        "key": "microsoft_windows",
        "display": "Microsoft Windows",
        "category": "OS",
        "formal": [
            "Microsoft Windows",
            "Windows Server",
            "Windows 10",
            "Windows 11",
            "Windows Server 2012",
            "Windows Server 2016",
            "Windows Server 2019",
            "Windows Server 2022",
            "Windows Server 2025",
        ],
        "cpe": ["microsoft:windows", "microsoft:windows_server"],
    },
    {
        "key": "windows_kernel",
        "display": "Windows Kernel",
        "category": "OS",
        "formal": ["Windows Kernel"],
        "cpe": [],
    },
    {
        "key": "win32k",
        "display": "Win32k",
        "category": "OS",
        "aliases": ["Win32k"],
        "contexts": WINDOWS_CONTEXT,
        "cpe": [],
    },
    {
        "key": "windows_installer",
        "display": "Windows Installer",
        "category": "OS",
        "formal": ["Windows Installer"],
        "cpe": ["microsoft:windows_installer"],
    },
    {
        "key": "windows_tcp_ip",
        "display": "Windows TCP/IP",
        "category": "OS",
        "formal": ["Windows TCP/IP"],
        "cpe": [],
    },
    {
        "key": "windows_clfs",
        "display": "Windows Common Log File System",
        "category": "OS",
        "formal": ["Windows Common Log File System"],
        "aliases": ["CLFS"],
        "contexts": ["Windows Common Log File System"],
        "cpe": [],
    },
    {
        "key": "bitlocker",
        "display": "BitLocker",
        "category": "OS",
        "formal": ["BitLocker"],
        "cpe": ["microsoft:bitlocker"],
    },
    {
        "key": "hyper_v",
        "display": "Hyper-V",
        "category": "OS",
        "formal": ["Hyper-V"],
        "exclude": ["Linux kernel on Hyper-V"],
        "cpe": ["microsoft:hyper-v"],
    },
    {
        "key": "apache_http_server",
        "display": "Apache HTTP Server",
        "category": "WEB",
        "formal": ["Apache HTTP Server", "Apache httpd"],
        "cpe": ["apache:http_server"],
    },
    {
        "key": "apache_tomcat",
        "display": "Apache Tomcat",
        "category": "WEB",
        "formal": ["Apache Tomcat", "Tomcat"],
        "cpe": ["apache:tomcat"],
    },
    {
        "key": "iis",
        "display": "IIS",
        "category": "WEB",
        "formal": ["Internet Information Services", "Microsoft IIS"],
        "aliases": ["IIS"],
        "contexts": ["Microsoft", "Windows", "Internet Information Services"],
        "cpe": ["microsoft:internet_information_services", "microsoft:iis"],
    },
    {
        "key": "remote_desktop_services",
        "display": "Remote Desktop Services",
        "category": "WEB",
        "formal": ["Remote Desktop Services"],
        "aliases": ["RDP"],
        "contexts": ["Remote Desktop Services"],
        "cpe": ["microsoft:remote_desktop_services"],
    },
    {
        "key": "smb",
        "display": "SMB",
        "category": "WEB",
        "formal": ["Windows SMB", "SMB Server", "Samba"],
        "aliases": ["SMB"],
        "contexts": ["Windows SMB", "SMB Server", "Samba", "Microsoft"],
        "cpe": ["microsoft:smb", "samba:samba"],
    },
    {
        "key": "ntlm",
        "display": "NTLM",
        "category": "WEB",
        "aliases": ["NTLM"],
        "contexts": ["Microsoft", "Windows", "Active Directory", "authentication"],
        "cpe": [],
    },
    {
        "key": "kerberos",
        "display": "Kerberos",
        "category": "WEB",
        "formal": ["Kerberos"],
        "contexts": MICROSOFT_CONTEXT + ["MIT Kerberos", "Heimdal"],
        "cpe": ["mit:kerberos", "heimdal:heimdal"],
    },
    {
        "key": "active_directory",
        "display": "Active Directory",
        "category": "WEB",
        "formal": ["Active Directory"],
        "cpe": ["microsoft:active_directory"],
    },
    {
        "key": "ldap",
        "display": "LDAP",
        "category": "WEB",
        "aliases": ["LDAP"],
        "contexts": ["Active Directory", "OpenLDAP", "Microsoft", "Windows"],
        "cpe": ["openldap:openldap", "microsoft:active_directory"],
    },
    {
        "key": "windows_dns_server",
        "display": "Windows DNS Server",
        "category": "WEB",
        "formal": ["Windows DNS Server", "Microsoft DNS"],
        "aliases": ["DNS Server"],
        "contexts": ["Windows DNS Server", "Microsoft DNS"],
        "cpe": ["microsoft:dns_server"],
    },
    {
        "key": "windows_dhcp_server",
        "display": "Windows DHCP Server",
        "category": "WEB",
        "formal": ["Windows DHCP Server", "Microsoft DHCP"],
        "aliases": ["DHCP Server"],
        "contexts": ["Windows DHCP Server", "Microsoft DHCP"],
        "cpe": ["microsoft:dhcp_server"],
    },
    {
        "key": "windows_print_spooler",
        "display": "Windows Print Spooler",
        "category": "WEB",
        "formal": ["Windows Print Spooler", "Print Spooler"],
        "contexts": ["Windows", "Microsoft"],
        "cpe": [],
    },
    {
        "key": "rras",
        "display": "Windows Routing and Remote Access Service",
        "category": "WEB",
        "formal": ["Windows Routing and Remote Access Service", "Routing and Remote Access Service"],
        "aliases": ["RRAS"],
        "contexts": ["Routing and Remote Access Service"],
        "cpe": [],
    },
    {
        "key": "microsoft_defender",
        "display": "Microsoft Defender",
        "category": "WEB",
        "formal": ["Microsoft Defender", "Windows Defender"],
        "cpe": ["microsoft:defender", "microsoft:windows_defender"],
    },
    {
        "key": "postgresql",
        "display": "PostgreSQL",
        "category": "DB",
        "formal": ["PostgreSQL"],
        "cpe": ["postgresql:postgresql"],
    },
    {
        "key": "pgadmin",
        "display": "pgAdmin",
        "category": "DB",
        "formal": ["pgAdmin", "pgAdmin 4", "pgadmin4"],
        "cpe": ["pgadmin:pgadmin", "pgadmin:pgadmin4"],
    },
    {
        "key": "composer",
        "display": "Composer",
        "category": "PHP",
        "formal": ["PHP Composer", "Composer package manager"],
        "aliases": ["Composer", "composer"],
        "contexts": PHP_COMPOSER_CONTEXT,
        "cpe": ["getcomposer:composer", "composer:composer"],
    },
    {
        "key": "laravel",
        "display": "Laravel",
        "category": "PHP",
        "formal": ["Laravel"],
        "cpe": ["laravel:laravel"],
    },
    {
        "key": "symfony",
        "display": "Symfony",
        "category": "PHP",
        "formal": ["Symfony", "symfony"],
        "cpe": ["symfony:symfony"],
    },
    {
        "key": "aurasql",
        "display": "AuraSQL",
        "category": "PHP",
        "formal": ["AuraSQL", "Aura SQL"],
        "cpe": ["auraphp:aurasql", "aura:sql"],
    },
    {
        "key": "npm",
        "display": "npm",
        "category": "JS",
        "formal": ["npm CLI", "npm package", "npm registry"],
        "aliases": ["npm"],
        "contexts": NPM_CONTEXT,
        "cpe": ["npmjs:npm", "npm:npm"],
    },
    {
        "key": "nodejs",
        "display": "Node.js",
        "category": "JS",
        "formal": ["Node.js", "Nodejs"],
        "cpe": ["nodejs:node.js", "nodejs:node"],
    },
    {
        "key": "vuejs",
        "display": "Vue.js",
        "category": "JS",
        "formal": ["Vue.js", "vuejs"],
        "aliases": ["Vue"],
        "contexts": ["Vue.js", "vuejs", "npm package vue"],
        "cpe": ["vuejs:vue", "vue:vue"],
    },
    {
        "key": "vuetify",
        "display": "Vuetify",
        "category": "JS",
        "formal": ["Vuetify"],
        "cpe": ["vuetifyjs:vuetify", "vuetify:vuetify"],
    },
]


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

    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    request = urllib.request.Request(
        url,
        headers=headers,
    )

    for attempt in range(1, NVD_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            message = e.headers.get("message", "")

            print(
                f"NVD request failed: "
                f"status={e.code}, "
                f"attempt={attempt}/{NVD_MAX_RETRIES}, "
                f"message={message or e.reason}"
            )

            if attempt >= NVD_MAX_RETRIES:
                raise

            time.sleep(NVD_REQUEST_DELAY * attempt)
        except urllib.error.URLError as e:
            print(
                f"NVD request failed: "
                f"attempt={attempt}/{NVD_MAX_RETRIES}, "
                f"reason={e.reason}"
            )

            if attempt >= NVD_MAX_RETRIES:
                raise

            time.sleep(NVD_REQUEST_DELAY * attempt)


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

        time.sleep(NVD_REQUEST_DELAY)

    return {
        "source_date_type": date_type,
        "totalResults": total_results,
        "vulnerabilities": all_vulnerabilities,
    }


def fetch_nvd():
    vulnerabilities = []

    date_types = [
        "published",
        "modified",
    ]

    for index, date_type in enumerate(date_types):
        try:
            data = fetch_nvd_by_date(date_type)
            vulnerabilities.extend(
                data.get("vulnerabilities", [])
            )
        except Exception as e:
            print(f"NVD {date_type} fetch failed: {e}")

        if index < len(date_types) - 1:
            time.sleep(NVD_REQUEST_DELAY)

    return {
        "vulnerabilities": vulnerabilities
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


def normalize_text(value):
    return re.sub(r"\s+", " ", value or "").strip()


def contains_phrase(text, phrase):
    return phrase.lower() in text.lower()


def contains_word(text, word):
    pattern = r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def contains_any(text, patterns):
    return any(contains_phrase(text, pattern) for pattern in patterns)


def matching_reject_patterns(text):
    return [
        pattern
        for pattern in STRONG_REJECT_PATTERNS
        if contains_phrase(text, pattern)
    ]


def iter_cpe_match_nodes(node):
    for cpe_match in node.get("cpeMatch", []):
        yield cpe_match

    for child in node.get("nodes", []):
        yield from iter_cpe_match_nodes(child)


def collect_nvd_cpe_names(cve):
    names = []

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for cpe_match in iter_cpe_match_nodes(node):
                criteria = cpe_match.get("criteria", "")

                if criteria:
                    names.append(criteria)

    return names


def cpe_matches(rule, cpe_text):
    return any(
        pattern.lower() in cpe_text
        for pattern in rule.get("cpe", [])
    )


def find_formal_match(rule, title, description):
    for term in rule.get("formal", []):
        if contains_phrase(title, term):
            return term, "title", 90

    for term in rule.get("formal", []):
        if contains_phrase(description, term):
            return term, "description_formal", 70

    return None, None, 0


def find_alias_match(rule, title, description):
    for term in rule.get("aliases", []):
        if contains_word(title, term):
            return term, "title_alias", 75

    for term in rule.get("aliases", []):
        if contains_word(description, term):
            return term, "description_alias", 45

    return None, None, 0


def classify_rule(rule, title, description, cpe_names):
    title = normalize_text(title)
    description = normalize_text(description)
    full_text = normalize_text(f"{title} {description}")
    cpe_text = " ".join(cpe_names or []).lower()

    for pattern in rule.get("exclude", []):
        if contains_phrase(full_text, pattern):
            return None

    if cpe_matches(rule, cpe_text):
        return {
            "product_key": rule["key"],
            "matched": rule["display"],
            "category": rule["category"],
            "confidence": "cpe",
            "score": 100,
        }

    matched_term, match_type, score = find_formal_match(
        rule,
        title,
        description,
    )

    if not matched_term:
        matched_term, match_type, score = find_alias_match(
            rule,
            title,
            description,
        )

    if not matched_term:
        return None

    contexts = rule.get("contexts", [])

    if contexts and not contains_any(full_text, contexts):
        return None

    reject_patterns = matching_reject_patterns(full_text)

    if reject_patterns:
        return None

    return {
        "product_key": rule["key"],
        "matched": rule["display"],
        "category": rule["category"],
        "confidence": match_type,
        "score": score,
    }


def classify_product(title="", description="", cpe_names=None):
    candidates = []

    for rule in PRODUCT_RULES:
        classification = classify_rule(
            rule,
            title,
            description,
            cpe_names or [],
        )

        if classification:
            candidates.append(classification)

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: (
            item["score"],
            len(item["matched"]),
        ),
        reverse=True,
    )

    return candidates[0]


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
        cpe_names = collect_nvd_cpe_names(cve)

        product = classify_product(
            title=cve_id,
            description=description,
            cpe_names=cpe_names,
        )

        if not product:
            continue

        source = "NVD"
        matched = product["matched"]

        alerts.append({
            "alert_id": make_alert_id(
                source,
                cve_id,
                matched,
            ),
            "source": source,
            "category": product["category"],
            "product_key": product["product_key"],
            "confidence": product["confidence"],
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
        product = classify_product(
            title=title,
            description=description,
        )

        if not product:
            continue

        matched = product["matched"]

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
            "category": product["category"],
            "product_key": product["product_key"],
            "confidence": product["confidence"],
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
