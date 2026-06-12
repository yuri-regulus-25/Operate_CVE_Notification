import json
import re
from pathlib import Path

import watch

ALERTS_PATH = Path("docs") / "alerts.json"

KNOWN_PRODUCTS = [
    ("Laravel Passport", "laravel/passport", "Composer / PHP", "direct_package"),
    ("Laravel Framework", "laravel/framework", "Composer / PHP", "direct_package"),
    ("Symfony", "symfony/symfony", "Composer / PHP", "direct_package"),
    ("Composer", "composer/composer", "Composer / PHP", "direct_product"),
    ("MikroORM", "@mikro-orm/*", "npm / Node.js", "direct_package"),
    ("Kysely", "kysely", "npm / Node.js", "direct_package"),
    ("systeminformation", "systeminformation", "npm / Node.js", "direct_package"),
    ("OpenTelemetry JavaScript", "@opentelemetry/*", "npm / Node.js", "direct_package"),
    ("DangerJS", "danger", "npm / Node.js", "direct_package"),
    ("esm.sh", "esm.sh", "npm / Node.js", "direct_product"),
    ("OneUptime", "oneuptime", "npm / Node.js", "runtime_context"),
    ("CloudNativePG", "cloudnative-pg", "PostgreSQL ecosystem", "ecosystem_package"),
    ("Marten", "marten", "PostgreSQL ecosystem", "ecosystem_package"),
    ("PostgreSQL Anonymizer", "postgresql_anonymizer", "PostgreSQL ecosystem", "ecosystem_package"),
    ("PostgreSQL", "postgresql", "PostgreSQL", "direct_product"),
    ("Samba", "samba", "SMB / Samba", "direct_product"),
    ("Apache HTTP Server", "httpd", "Apache", "direct_product"),
    ("Apache Tomcat", "tomcat", "Apache", "direct_product"),
    ("Google Chrome", "chrome", "Google Chrome", "direct_product"),
]

ECOSYSTEM_BY_CATEGORY = {
    "OS": "OS / Platform",
    "WEB": "Web / Network",
    "DB": "Database",
    "PHP": "Composer / PHP",
    "JS": "npm / Node.js",
}

NOISE_HINTS = [
    "supports vue",
    "vue, react, angular",
    "vue/react/angular",
    "for windows",
    "on windows",
    "windows/macos/linux",
    "linux, unix and windows",
]


def norm(value):
    return re.sub(r"\s+", " ", value or "").strip()


def has(text, phrase):
    return phrase.lower() in text.lower()


def extract_subject(description):
    description = norm(description)
    patterns = [
        r"^([A-Za-z0-9_.@/+#()\- ]{2,80}?)\s+(?:is|are)\s+",
        r"^([A-Za-z0-9_.@/+#()\- ]{2,80}?)\s+contains?\s+",
        r"^([A-Za-z0-9_.@/+#()\- ]{2,80}?)\s+(?:prior to|before)\s+",
        r"^In\s+([A-Za-z0-9_.@/+#()\- ]{2,80}?),",
    ]
    for pattern in patterns:
        matched = re.search(pattern, description, flags=re.IGNORECASE)
        if matched:
            subject = norm(matched.group(1))
            subject = re.sub(r"^(?:the|a|an)\s+", "", subject, flags=re.IGNORECASE)
            if subject.lower() not in {"this vulnerability", "the vulnerability", "a vulnerability", "a flaw"}:
                return subject
    return None


def detect_keyword(alert):
    text = norm(f"{alert.get('title', '')} {alert.get('description', '')}")
    for keyword in watch.NVD_KEYWORDS:
        if has(text, keyword):
            return keyword
    return ""


def detect_product(alert):
    text = norm(f"{alert.get('title', '')} {alert.get('description', '')}")
    for product, package_name, ecosystem, relation_type in KNOWN_PRODUCTS:
        if has(text, product):
            return product, package_name, ecosystem, relation_type, "known_product_pattern"

    subject = extract_subject(alert.get("description", ""))
    if subject:
        return subject, "", ECOSYSTEM_BY_CATEGORY.get(alert.get("category"), "UNKNOWN"), "direct_product", "description_subject"

    return alert.get("matched") or alert.get("product_key") or "UNKNOWN", "", ECOSYSTEM_BY_CATEGORY.get(alert.get("category"), "UNKNOWN"), "keyword_only", "fallback_matched"


def detect_noise_risk(alert, actual_product, relation_type):
    text = norm(f"{alert.get('title', '')} {alert.get('description', '')}").lower()
    if any(hint in text for hint in NOISE_HINTS):
        return "high"

    confidence = alert.get("confidence", "")
    matched = (alert.get("matched") or "").lower()
    actual = (actual_product or "").lower()

    if confidence in {"description_alias", "description_formal"} and relation_type == "keyword_only":
        return "high"

    if matched and actual and matched not in actual and actual not in matched:
        if confidence in {"description_alias", "description_formal"}:
            return "medium"

    if relation_type in {"runtime_context", "platform_context", "ecosystem_package"}:
        return "medium"

    return "low"


def enrich_alert(alert):
    actual_product, package_name, ecosystem, relation_type, reason = detect_product(alert)
    result = dict(alert)
    result.update({
        "actual_product": actual_product,
        "package_name": package_name,
        "ecosystem": ecosystem,
        "relation_type": relation_type,
        "classification_reason": reason,
        "tracked_keyword": detect_keyword(alert),
        "noise_risk": detect_noise_risk(alert, actual_product, relation_type),
    })
    return result


def enrich_alerts_file(path=ALERTS_PATH):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    data["alerts"] = [enrich_alert(alert) for alert in data.get("alerts", [])]
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main():
    watch.main()
    enrich_alerts_file()


if __name__ == "__main__":
    main()
