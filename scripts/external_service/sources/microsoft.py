import json
import re
from html.parser import HTMLParser

from external_service.model import SCHEMA_CHANGED, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event


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

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}


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

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}
