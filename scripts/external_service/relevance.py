from external_service.normalize import clean_text


def _contains_any(text, values):
    return [value for value in values or [] if value.casefold() in text]


def decide(event, service):
    text = clean_text(
        f"{event.get('title', '')} {event.get('description', '')} "
        f"{' '.join(event.get('raw', {}).get('affected', []))}"
    ).casefold()
    matched = []

    negative = _contains_any(text, service.get("exclude_keywords", []))
    positive = _contains_any(text, service.get("keywords", []))
    endpoints = _contains_any(text, service.get("endpoints", []))
    products = _contains_any(text, service.get("products", []))
    sdk = service.get("sdk") or {}

    if sdk and sdk.get("package", "").casefold() in text:
        matched.append(sdk["package"])

    matched.extend(positive + endpoints + products)

    if negative and not (endpoints or matched[:1] == [sdk.get("package")]):
        return {
            "status": "NOT_RELEVANT",
            "confidence": "HIGH",
            "matched_targets": sorted(set(matched)),
            "reason": f"Affected product appears outside monitored usage: {', '.join(negative)}.",
        }

    if event.get("type") in {"DEPRECATION", "BREAKING_CHANGE"} and matched:
        return {
            "status": "INFORMATIONAL",
            "confidence": "MEDIUM",
            "matched_targets": sorted(set(matched)),
            "reason": "Change notice matches monitored service/API terms.",
        }

    if endpoints or products or matched:
        return {
            "status": "RELEVANT",
            "confidence": "MEDIUM",
            "matched_targets": sorted(set(matched)),
            "reason": "Event text matches monitored service, endpoint, product, or SDK terms.",
        }

    if event.get("id", "").upper().startswith("CVE-"):
        return {
            "status": "REVIEW",
            "confidence": "LOW",
            "matched_targets": [],
            "reason": "CVE/source hit mentions the vendor but rules cannot confirm affected API surface.",
        }

    return {
        "status": "NOT_RELEVANT",
        "confidence": "MEDIUM",
        "matched_targets": [],
        "reason": "No monitored service, endpoint, product, or SDK terms matched.",
    }
