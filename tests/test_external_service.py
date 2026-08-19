import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from external_service.normalize import make_event, merge_events
from external_service.relevance import decide
from external_service.sources import feed, microsoft, nvd, osv, zoom


FIXTURES = ROOT / "tests" / "fixtures"


class ExternalServiceWatchTests(unittest.TestCase):
    def service(self, **values):
        base = {
            "key": "zoom",
            "keywords": ["zoom", "rest api", "meetings", "oauth"],
            "endpoints": ["meetings"],
            "products": ["rest_api"],
            "exclude_keywords": ["zoom workplace for windows"],
        }
        base.update(values)
        return base

    def test_rss_parsing_drops_plain_features(self):
        xml_text = (FIXTURES / "slack_feed.xml").read_text(encoding="utf-8")
        events, status = feed.parse_feed(xml_text, "Slack Feed", "slack", "https://example.test/rss")
        self.assertEqual(status["status"], "SUCCESS")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "DEPRECATION")

    def test_atom_xml_parsing(self):
        xml_text = (FIXTURES / "google_calendar_feed.xml").read_text(encoding="utf-8")
        events, status = feed.parse_feed(xml_text, "Google Calendar Feed", "google_calendar", "https://example.test/atom")
        self.assertEqual(status["status"], "SUCCESS")
        self.assertEqual(events[0]["type"], "AUTH_CHANGE")

    def test_zoom_html_parsing_and_schema_change(self):
        html_text = (FIXTURES / "zoom_security.html").read_text(encoding="utf-8")
        events, status = zoom.parse_security_bulletin(html_text, "https://zoom.test/security")
        self.assertEqual(status["status"], "SUCCESS")
        self.assertEqual(len(events), 2)

        empty_events, empty_status = zoom.parse_security_bulletin("<html>No table</html>", "https://zoom.test/security")
        self.assertEqual(empty_events, [])
        self.assertEqual(empty_status["status"], "SCHEMA_CHANGED")

    def test_nvd_normalization(self):
        item = {
            "cve": {
                "id": "CVE-2026-12345",
                "published": "2026-08-18T00:00:00.000Z",
                "lastModified": "2026-08-18T01:00:00.000Z",
                "descriptions": [{"lang": "en", "value": "Zoom REST API meetings vulnerability."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]},
            }
        }
        event = nvd.normalize_item(item, "zoom", "Zoom")
        self.assertEqual(event["id"], "CVE-2026-12345")
        self.assertEqual(event["severity"]["level"], "HIGH")

    def test_microsoft_graph_html_parsing(self):
        html_text = (FIXTURES / "microsoft_graph.html").read_text(encoding="utf-8")
        events, status = microsoft.parse_graph_changelog_html(
            html_text,
            "microsoft_graph_calendar",
            "https://developer.microsoft.com/en-us/graph/changelog?filterBy=Calendar",
        )
        self.assertEqual(status["status"], "SUCCESS")
        self.assertEqual(events[0]["type"], "DEPRECATION")

    def test_osv_normalization(self):
        event = osv.normalize_vuln(
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "aliases": ["CVE-2026-45678"],
                "summary": "microsoft/microsoft-graph security issue",
                "details": "Affects microsoft/microsoft-graph package.",
                "modified": "2026-08-18T00:00:00Z",
            },
            {"key": "microsoft_graph_calendar", "sdk": {"package": "microsoft/microsoft-graph"}},
        )
        self.assertEqual(event["id"], "CVE-2026-45678")

    def test_deduplication_by_cve(self):
        first = make_event("NVD", "zoom", "CVE-2026-10000", "Zoom REST API vulnerability")
        second = make_event("JVN", "zoom", "CVE-2026-10000", "Zoom REST API vulnerability")
        merged = merge_events([first, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]["sources"]), 2)

    def test_relevance_statuses(self):
        relevant = make_event("NVD", "zoom", "CVE-2026-1", "Zoom REST API meetings vulnerability")
        self.assertEqual(decide(relevant, self.service())["status"], "RELEVANT")

        not_relevant = make_event("Zoom", "zoom", "CVE-2026-2", "Zoom Workplace for Windows vulnerability")
        self.assertEqual(decide(not_relevant, self.service())["status"], "NOT_RELEVANT")

        review = make_event("NVD", "zoom", "CVE-2026-3000", "Vendor vulnerability with unclear affected product")
        self.assertEqual(decide(review, self.service())["status"], "REVIEW")

        informational = make_event("Slack", "slack", "Deprecation for Slack OAuth", "OAuth migration required")
        service = self.service(key="slack", keywords=["slack", "oauth"], endpoints=[], products=[], exclude_keywords=[])
        self.assertEqual(decide(informational, service)["status"], "INFORMATIONAL")


if __name__ == "__main__":
    unittest.main()
