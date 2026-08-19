import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from external_service.http import fetch_text
from external_service.model import ACTIVE_RELEVANCE, FETCH_ERROR, PARSE_ERROR, SCHEMA_CHANGED
from external_service.normalize import merge_events, now_iso
from external_service.relevance import decide
from external_service.sources import feed, jvn, microsoft, nvd, osv, zoom


BASE_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = BASE_DIR / "config" / "external_services.json"
OUTPUT_DIR = BASE_DIR / "docs" / "external_service"
ALERTS_PATH = OUTPUT_DIR / "alerts.json"
HISTORY_PATH = OUTPUT_DIR / "history.json"
STATE_PATH = OUTPUT_DIR / "state.json"


def load_config(path=CONFIG_PATH):
    return json.loads(path.read_text(encoding="utf-8"))


def load_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_json_if_changed(path, data):
    current = load_json(path, None)
    if current:
        comparable_current = dict(current)
        comparable_data = dict(data)
        comparable_current.pop("generated_at", None)
        comparable_data.pop("generated_at", None)
        if comparable_current == comparable_data:
            return False
    write_json(path, data)
    return True


def failure_flag_path():
    value = os.getenv("EXTERNAL_SERVICE_WATCH_FAILURE_FLAG")
    return Path(value) if value else None


def nvd_dates(lookback_days):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return start.strftime(fmt), end.strftime(fmt)


def collect_vendor_feeds(service):
    events = []
    health = {}
    source_urls = []
    sources = service.get("sources", {})
    source_urls.extend(sources.get("feed_urls", []))
    source_urls.extend(sources.get("graph_feed_urls", []))
    source_urls.extend(sources.get("developer_feed_urls", []))

    for url in source_urls:
        key = f"feed:{service['key']}:{url}"
        try:
            xml_text = fetch_text(url)
            parsed, status = feed.parse_feed(xml_text, f"{service['display']} Feed", service["key"], url)
            events.extend(parsed)
            health[key] = status
        except Exception as error:
            health[key] = {"status": FETCH_ERROR, "message": str(error)}

    return events, health


def collect_zoom_security(service):
    url = service.get("sources", {}).get("security_bulletin_url")
    if not url:
        return [], {}
    try:
        html_text = fetch_text(url)
        events, status = zoom.parse_security_bulletin(html_text, url)
        return events, {"zoom_security_bulletin": status}
    except Exception as error:
        return [], {"zoom_security_bulletin": {"status": FETCH_ERROR, "message": str(error)}}


def collect_microsoft_sources(service):
    sources = service.get("sources", {})
    return microsoft.fetch_for_service(
        service,
        sources.get("graph_html_urls", []),
        sources.get("msrc_url"),
        lookback_days=45,
    )


def collect_all(config):
    events = []
    health = {}
    start_iso, end_iso = nvd_dates(config.get("lookback_days", 14))

    for service in config["services"]:
        nvd_events, nvd_status = nvd.fetch_for_service(service, start_iso, end_iso)
        events.extend(nvd_events)
        health[f"nvd:{service['key']}"] = nvd_status

        jvn_events, jvn_status = jvn.fetch_for_service(service, config.get("lookback_days", 14))
        events.extend(jvn_events)
        health[f"jvn:{service['key']}"] = jvn_status

        vendor_events, vendor_health = collect_vendor_feeds(service)
        events.extend(vendor_events)
        health.update(vendor_health)

        if service["key"] == "zoom":
            zoom_events, zoom_health = collect_zoom_security(service)
            events.extend(zoom_events)
            health.update(zoom_health)

        if service["key"].startswith("microsoft_graph"):
            microsoft_events, microsoft_health = collect_microsoft_sources(service)
            events.extend(microsoft_events)
            health.update(microsoft_health)

    osv_events, osv_status = osv.fetch_for_services(config["services"])
    events.extend(osv_events)
    health["osv:batch"] = osv_status
    return events, health


def strongest_relevance(event, services):
    priority = {
        "RELEVANT": 4,
        "REVIEW": 3,
        "INFORMATIONAL": 2,
        "NOT_RELEVANT": 1,
    }
    decisions = []

    for service_key in event.get("services", [event.get("service")]):
        service = services.get(service_key)
        if not service:
            continue
        service_decision = decide(event, service)
        service_decision["service"] = service_key
        decisions.append(service_decision)

    if not decisions:
        return decide(event, services[event["service"]])

    decisions.sort(key=lambda item: priority.get(item["status"], 0), reverse=True)
    selected = dict(decisions[0])
    selected["service_results"] = decisions
    return selected


def update_outputs(events, health, config):
    services = {service["key"]: service for service in config["services"]}
    history = load_json(HISTORY_PATH, {"generated_at": "", "count": 0, "alerts": []})
    previous = {item["id"]: item for item in history.get("alerts", [])}

    enriched = []
    for event in merge_events(events):
        event["relevance"] = strongest_relevance(event, services)
        old = previous.get(event["id"], {})
        event["first_seen_at"] = old.get("first_seen_at") or now_iso()
        event["last_seen_at"] = now_iso()
        enriched.append(event)

    combined = {**previous, **{event["id"]: event for event in enriched}}
    history_alerts = sorted(combined.values(), key=lambda item: (item.get("last_seen_at") or "", item["id"]), reverse=True)
    active_alerts = [item for item in history_alerts if item.get("relevance", {}).get("status") in ACTIVE_RELEVANCE]

    generated_at = now_iso()
    write_json_if_changed(ALERTS_PATH, {"generated_at": generated_at, "count": len(active_alerts), "alerts": active_alerts})
    write_json_if_changed(HISTORY_PATH, {"generated_at": generated_at, "count": len(history_alerts), "alerts": history_alerts})
    write_json(STATE_PATH, {"generated_at": generated_at, "sources": health})

    bad = [
        f"{key}={value.get('status')}"
        for key, value in health.items()
        if value.get("status") in {FETCH_ERROR, PARSE_ERROR, SCHEMA_CHANGED}
    ]
    if bad:
        flag = failure_flag_path()
        if flag:
            flag.write_text("\n".join(bad) + "\n", encoding="utf-8")
        raise SystemExit("Source adapter failures: " + ", ".join(bad))


def main():
    flag = failure_flag_path()
    if flag and flag.exists():
        flag.unlink()
    config = load_config()
    events, health = collect_all(config)
    update_outputs(events, health, config)


if __name__ == "__main__":
    main()
