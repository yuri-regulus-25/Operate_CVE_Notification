import xml.etree.ElementTree as ET

from external_service.model import PARSE_ERROR, SCHEMA_CHANGED, SUCCESS, SUCCESS_NO_RESULTS
from external_service.normalize import make_event


def _text(element, names):
    for name in names:
        child = element.find(name)
        if child is not None and child.text:
            return child.text
    return ""


def parse_feed(xml_text, source_name, service_key, url):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        return [], {"status": PARSE_ERROR, "message": str(error)}

    items = root.findall(".//item")
    if not items:
        items = root.findall("{http://www.w3.org/2005/Atom}entry")

    if not items:
        return [], {"status": SCHEMA_CHANGED, "message": "Feed parsed but no item/entry nodes were found."}

    events = []
    for item in items:
        title = _text(item, ["title", "{http://www.w3.org/2005/Atom}title"])
        description = _text(item, ["description", "summary", "{http://www.w3.org/2005/Atom}summary", "content", "{http://www.w3.org/2005/Atom}content"])
        link = _text(item, ["link"])
        if not link:
            link_node = item.find("{http://www.w3.org/2005/Atom}link")
            link = link_node.attrib.get("href", "") if link_node is not None else ""
        published = _text(item, ["pubDate", "published", "updated", "{http://www.w3.org/2005/Atom}published", "{http://www.w3.org/2005/Atom}updated"])
        event = make_event(source_name, service_key, title, description, link or url, published, raw={"feed_url": url})
        if event:
            events.append(event)

    return events, {"status": SUCCESS if events else SUCCESS_NO_RESULTS, "count": len(events)}
