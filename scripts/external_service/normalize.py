import hashlib
import re
from datetime import datetime, timezone


SECURITY_WORDS = ("security", "vulnerability", "cve-", "advisory", "bulletin")
AUTH_WORDS = ("oauth", "authentication", "authorization", "token", "scope")
BREAKING_WORDS = ("breaking change", "breaking", "migration required", "required action")
DEPRECATION_WORDS = ("deprecated", "deprecation", "retirement", "retired", "sunset")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def clean_text(value):
    return re.sub(r"\s+", " ", value or "").strip()


def stable_hash(*parts):
    text = "|".join(clean_text(part).casefold() for part in parts if part)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def find_cve_ids(text):
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text or "", flags=re.IGNORECASE)))


def infer_type(title, description=""):
    text = f"{title} {description}".casefold()
    if "cve-" in text or "vulnerability" in text:
        return "VULNERABILITY"
    if any(word in text for word in ("security advisory", "security bulletin")):
        return "SECURITY_ADVISORY"
    if any(word in text for word in DEPRECATION_WORDS):
        return "DEPRECATION"
    if any(word in text for word in BREAKING_WORDS):
        return "BREAKING_CHANGE"
    if any(word in text for word in AUTH_WORDS):
        return "AUTH_CHANGE"
    if "security" in text:
        return "SECURITY_GUIDANCE"
    return None


def should_keep(title, description=""):
    return infer_type(title, description) is not None


def severity_level(score=None, level=None):
    if level:
        return str(level).upper()
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def make_event(
    source,
    service,
    title,
    description="",
    url="",
    published_at="",
    updated_at="",
    raw=None,
    event_id=None,
):
    title = clean_text(title)
    description = clean_text(description)
    cve_ids = find_cve_ids(f"{title} {description}")
    alert_type = infer_type(title, description)

    if not alert_type:
        return None

    event_id = event_id or (
        cve_ids[0].upper()
        if cve_ids
        else f"vendor:{service}:{published_at[:10] or 'unknown'}:{stable_hash(source, service, title, url)}"
    )

    return {
        "id": event_id,
        "service": service,
        "services": [service],
        "type": alert_type,
        "title": title,
        "description": description,
        "published_at": published_at,
        "updated_at": updated_at or published_at,
        "severity": {"level": "UNKNOWN", "cvss": None},
        "sources": [{"name": source, "url": url, "raw_id": event_id}],
        "raw": raw or {},
    }


def merge_events(events):
    merged = {}
    for event in events:
        key = event["id"].upper() if event["id"].upper().startswith("CVE-") else event["id"]
        if key not in merged:
            merged[key] = dict(event)
            continue

        current = merged[key]
        current["description"] = current.get("description") or event.get("description", "")
        current["published_at"] = min(filter(None, [current.get("published_at"), event.get("published_at")]), default="")
        current["updated_at"] = max(filter(None, [current.get("updated_at"), event.get("updated_at")]), default="")
        current["sources"].extend(event.get("sources", []))
        current["services"] = sorted(set(current.get("services", [current.get("service")]) + event.get("services", [event.get("service")])))
        if current["severity"].get("cvss") is None and event.get("severity", {}).get("cvss") is not None:
            current["severity"] = event["severity"]

    for event in merged.values():
        seen = set()
        sources = []
        for source in event.get("sources", []):
            key = (source.get("name"), source.get("url"))
            if key in seen:
                continue
            seen.add(key)
            sources.append(source)
        event["sources"] = sources

    return sorted(merged.values(), key=lambda item: (item.get("published_at") or "", item["id"]), reverse=True)
