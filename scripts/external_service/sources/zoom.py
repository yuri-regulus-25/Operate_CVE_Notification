import re
from urllib.parse import urljoin
from html.parser import HTMLParser

from external_service.model import SCHEMA_CHANGED, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event, severity_level


class TextTableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.links = []
        self._href = None

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        attrs = dict(attrs)
        self._href = attrs.get("href")

    def handle_endtag(self, tag):
        if tag == "a":
            self._href = None

    def handle_data(self, data):
        value = data.strip()
        if value:
            self.text.append(value)
            if self._href:
                self.links.append((value, self._href))


def _detail_url(parser, zsb_id, fallback_url):
    for text, href in parser.links:
        if zsb_id in text or zsb_id in href:
            return urljoin(fallback_url, href)
    return fallback_url


def _affected(window):
    affected = []
    joined = " ".join(window)
    patterns = [
        r"Zoom Workplace for [A-Za-z]+",
        r"Zoom Clients? for [A-Za-z]+",
        r"Zoom Rooms",
        r"VDI Plugin",
        r"Zoom REST API",
        r"Meetings?",
        r"Users?",
        r"Recordings?",
    ]
    for pattern in patterns:
        affected.extend(re.findall(pattern, joined, flags=re.I))
    return sorted(set(affected))


def parse_security_bulletin(html_text, url):
    parser = TextTableParser()
    parser.feed(html_text)
    text = "\n".join(parser.text)
    zsb_ids = re.findall(r"ZSB-\d{5}", text)

    if "ZSB-" in text and not zsb_ids:
        return [], {"status": SCHEMA_CHANGED, "message": "ZSB markers exist but no bulletin IDs matched."}
    if "ZSB-" not in text:
        return [], {"status": SCHEMA_CHANGED, "message": "No ZSB markers found in Zoom bulletin page."}

    events = []
    lines = parser.text
    for index, value in enumerate(lines):
        if not re.fullmatch(r"ZSB-\d{5}", value):
            continue
        window = lines[index:index + 8]
        detail_url = _detail_url(parser, value, url)
        title = " ".join(window[:2])
        description = " ".join(window[1:5])
        if "security" not in description.casefold() and "vulnerability" not in description.casefold():
            description = f"Zoom Security Bulletin {value}. {description}"
        event = make_event(
            "Zoom Security Bulletin",
            "zoom",
            title,
            description,
            detail_url,
            raw={"zsb": value, "affected": _affected(window)},
            event_id=f"vendor:zoom:{value}",
        )
        if event:
            for token in window:
                if token in {"Critical", "High", "Medium", "Low"}:
                    event["severity"] = {"level": severity_level(level=token), "cvss": None}
            events.append(event)

    if zsb_ids and not events:
        return [], {"status": SCHEMA_CHANGED, "raw_count": len(zsb_ids), "count": 0, "message": "ZSB IDs were found but no security events were normalized."}

    return events, {
        "status": SUCCESS if events else SUCCESS_NO_RESULTS,
        "raw_count": len(zsb_ids),
        "count": len(events),
    }
