import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import external_service.run as runner
from external_service.normalize import make_event, merge_events
from external_service.relevance import decide
from external_service.sources import feed, jvn, microsoft, nvd, osv, zoom


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
        self.assertEqual(status["raw_count"], 2)
        self.assertEqual(status["dropped_count"], 1)
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
        self.assertEqual(events[0]["id"], "vendor:zoom:ZSB-26005")
        self.assertIn("Zoom Workplace for Windows", events[0]["raw"]["affected"])

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

    def test_nvd_fetch_paginates_published_and_modified(self):
        pages = [
            {
                "totalResults": 2,
                "resultsPerPage": 1,
                "vulnerabilities": [{"cve": {"id": "CVE-2026-1000", "descriptions": [{"lang": "en", "value": "Zoom REST API vulnerability"}]}}],
            },
            {
                "totalResults": 2,
                "resultsPerPage": 1,
                "vulnerabilities": [{"cve": {"id": "CVE-2026-1001", "descriptions": [{"lang": "en", "value": "Zoom REST API vulnerability"}]}}],
            },
            {"totalResults": 0, "resultsPerPage": 1, "vulnerabilities": []},
        ]
        service = {"key": "zoom", "sources": {"nvd_keywords": ["Zoom"]}}
        with mock.patch("external_service.sources.nvd.fetch_json", side_effect=pages) as fetch:
            with mock.patch("external_service.sources.nvd.time.sleep"):
                events, status = nvd.fetch_for_service(service, "2026-08-01T00:00:00.000Z", "2026-08-19T00:00:00.000Z", results_per_page=1)
        self.assertEqual(status["status"], "SUCCESS")
        self.assertEqual(len(events), 2)
        self.assertEqual(fetch.call_count, 3)

    def test_nvd_pagination_guard(self):
        service = {"key": "zoom", "sources": {"nvd_keywords": ["Zoom"]}}
        page = {
            "totalResults": 2,
            "resultsPerPage": 0,
            "vulnerabilities": [{"cve": {"id": "CVE-2026-1000", "descriptions": [{"lang": "en", "value": "Zoom REST API vulnerability"}]}}],
        }
        with mock.patch("external_service.sources.nvd.fetch_json", return_value=page):
            events, status = nvd.fetch_for_service(service, "2026-08-01T00:00:00.000Z", "2026-08-19T00:00:00.000Z", results_per_page=1)
        self.assertEqual(status["status"], "SCHEMA_CHANGED")

    def test_jvn_fetch_uses_published_and_modified_date_windows(self):
        service = {"key": "zoom", "sources": {"nvd_keywords": ["Zoom"]}}
        empty_jvn = """<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:rss="http://purl.org/rss/1.0/" />"""
        with mock.patch("external_service.sources.jvn.fetch_text", return_value=empty_jvn) as fetch:
            events, status = jvn.fetch_for_service(service, lookback_days=14)
        urls = [call.args[0] for call in fetch.call_args_list]
        self.assertEqual(events, [])
        self.assertEqual(status["status"], "SUCCESS_NO_RESULTS")
        self.assertEqual(len(urls), 2)
        self.assertIn("dateFirstPublishedStartY", urls[0])
        self.assertIn("datePublishedStartY", urls[1])

    def test_microsoft_graph_html_parsing(self):
        html_text = (FIXTURES / "microsoft_graph.html").read_text(encoding="utf-8")
        events, status = microsoft.parse_graph_changelog_html(
            html_text,
            "microsoft_graph_calendar",
            "https://developer.microsoft.com/en-us/graph/changelog?filterBy=Calendar",
        )
        self.assertEqual(status["status"], "SUCCESS")
        self.assertEqual(events[0]["type"], "DEPRECATION")

    def test_msrc_cvrf_detail_parsing(self):
        updates = (FIXTURES / "msrc_updates.json").read_text(encoding="utf-8")
        ids, update_status = microsoft.recent_update_ids(updates, lookback_days=999)
        self.assertEqual(ids, ["2026-Aug"])
        self.assertEqual(update_status["raw_count"], 1)

        cvrf = (FIXTURES / "msrc_cvrf.json").read_text(encoding="utf-8")
        events, status = microsoft.parse_cvrf_document(cvrf, "microsoft_graph_teams", "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Aug")
        self.assertEqual(status["status"], "SUCCESS")
        self.assertEqual(events[0]["id"], "CVE-2026-55555")
        self.assertIn("Microsoft Graph Teams online meetings", events[0]["raw"]["affected"])

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

    def test_deduplication_preserves_multiple_services(self):
        first = make_event("OSV", "microsoft_graph_calendar", "CVE-2026-20000", "microsoft/microsoft-graph security issue")
        second = make_event("OSV", "microsoft_graph_teams", "CVE-2026-20000", "microsoft/microsoft-graph security issue")
        merged = merge_events([first, second])
        self.assertEqual(merged[0]["services"], ["microsoft_graph_calendar", "microsoft_graph_teams"])

    def test_relevance_statuses(self):
        relevant = make_event("NVD", "zoom", "CVE-2026-1001", "Zoom REST API meetings vulnerability")
        self.assertEqual(decide(relevant, self.service())["status"], "RELEVANT")

        not_relevant = make_event("Zoom", "zoom", "CVE-2026-1002", "Zoom Workplace for Windows vulnerability")
        self.assertEqual(decide(not_relevant, self.service())["status"], "NOT_RELEVANT")

        review = make_event("NVD", "zoom", "CVE-2026-3000", "Vendor vulnerability with unclear affected product")
        self.assertEqual(decide(review, self.service())["status"], "REVIEW")

        vendor_only = make_event("NVD", "zoom", "CVE-2026-3001", "Zoom vulnerability; affected surface unclear")
        self.assertEqual(decide(vendor_only, self.service())["status"], "REVIEW")

        vendor_platform = make_event("NVD", "zoom", "CVE-2026-3002", "Zoom Workplace for macOS vulnerability")
        self.assertNotEqual(decide(vendor_platform, self.service())["status"], "RELEVANT")

        ambiguous = make_event("NVD", "zoom", "CVE-2026-3003", "Zoom Workplace for Windows vulnerability also mentions meetings")
        self.assertEqual(decide(ambiguous, self.service())["status"], "REVIEW")

        informational = make_event("Slack", "slack", "Deprecation for Slack OAuth", "OAuth migration required")
        service = self.service(key="slack", keywords=["slack", "oauth"], endpoints=[], products=[], exclude_keywords=[])
        self.assertEqual(decide(informational, service)["status"], "INFORMATIONAL")

    def test_zoom_affected_product_not_relevant(self):
        event = make_event(
            "Zoom Security Bulletin",
            "zoom",
            "ZSB-26005",
            "Zoom Security Bulletin ZSB-26005",
            raw={"affected": ["Zoom Workplace for Windows"]},
            event_id="vendor:zoom:ZSB-26005",
        )
        self.assertEqual(decide(event, self.service())["status"], "NOT_RELEVANT")

    def test_source_failure_writes_state_before_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            failure_flag = temp_path / "failed"
            with mock.patch.object(runner, "ALERTS_PATH", temp_path / "alerts.json"):
                with mock.patch.object(runner, "HISTORY_PATH", temp_path / "history.json"):
                    with mock.patch.object(runner, "STATE_PATH", temp_path / "state.json"):
                        with mock.patch.dict("os.environ", {"EXTERNAL_SERVICE_WATCH_FAILURE_FLAG": str(failure_flag)}):
                            with self.assertRaises(SystemExit):
                                runner.update_outputs(
                                    [],
                                    {"feed:slack": {"status": "FETCH_ERROR", "message": "timeout"}},
                                    {"services": [{"key": "slack", "display": "Slack", "keywords": [], "endpoints": [], "products": []}]},
                                )
                            state = json.loads((temp_path / "state.json").read_text(encoding="utf-8"))
                            self.assertTrue(failure_flag.exists())
        self.assertEqual(state["sources"]["feed:slack"]["status"], "FETCH_ERROR")

    def test_osv_post_retries_transient_errors(self):
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock(return_value=None)
        response.read.return_value = b'{"results":[]}'
        transient = TimeoutError("temporary")
        with mock.patch("external_service.sources.osv.urllib.request.urlopen", side_effect=[transient, response]) as urlopen:
            with mock.patch("external_service.sources.osv.time.sleep"):
                result = osv._post_json("https://api.osv.dev/v1/querybatch", {"queries": []})
        self.assertEqual(result, {"results": []})
        self.assertEqual(urlopen.call_count, 2)


if __name__ == "__main__":
    unittest.main()
