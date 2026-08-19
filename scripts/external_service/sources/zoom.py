import re
from html.parser import HTMLParser

from external_service.model import SCHEMA_CHANGED, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event, severity_level


class TextTableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []

    def handle_data(self, data):
        value = data.strip()
        if value:
            self.text.append(value)


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
        title = " ".join(window[:2])
        description = " ".join(window[1:5])
        event = make_event("Zoom Security Bulletin", "zoom", title, description, url, raw={"zsb": value})
        if event:
            for token in window:
                if token in {"Critical", "High", "Medium", "Low"}:
                    event["severity"] = {"level": severity_level(level=token), "cvss": None}
            events.append(event)

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}
