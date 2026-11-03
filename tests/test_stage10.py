"""Stage 10 tests: log viewer, alerts page and alert investigation page."""
import io
import re

import config
from tests.test_stage9 import PageTestCase

LOG_IDS = ["filterForm", "q", "source_ip", "username", "event_type", "severity", "date_from",
           "date_to", "anomalies_only", "scopeSelect", "per_page", "resetBtn", "logsBody",
           "pager", "statusBox"]
ALERT_IDS = ["filterForm", "q", "source_ip", "username", "severity", "status", "threat_type",
             "detection_method", "date_from", "date_to", "scopeSelect", "per_page", "resetBtn",
             "alertsBody", "pager", "statusBox"]
DETAIL_IDS = ["alertRoot", "alertContent", "statusBox", "dAlertId", "dSeverity", "dThreatType",
              "dTimestamp", "dSourceIp", "dDestIp", "dUsername", "dEventId", "dMethod",
              "dMlScore", "dThreatScore", "dScoreBar", "dRelatedCount", "dReason",
              "dSeverityReason", "dSteps", "dOriginalLog", "dRelatedBody", "statusSelect",
              "saveStatusBtn", "logsLink"]
ALERT_KEYS = ["id", "timestamp", "severity", "threat_type", "source_ip", "destination_ip",
              "username", "event_id", "detection_method", "ml_anomaly_score", "threat_score",
              "original_log", "reason", "severity_reason", "recommended_steps", "related_logs",
              "related_total", "status"]
JS_DIR = config.BASE_DIR / "static" / "js"


class Stage10Tests(PageTestCase):
    def generate(self, **extra):
        body = {"events": 300, "seed": 3}
        body.update(extra)
        r = self.client.post("/api/generate-sample", json=body)
        self.assertEqual(r.status_code, 201)
        return r.get_json()

    def test_logs_page_has_every_control(self):
        page = self.html("/logs")
        for element_id in LOG_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        self.assertIn("js/listpage.js", page)
        self.assertIn("js/logs.js", page)
        self.assertIn('class="soc-nav-link active" href="/logs"', page)

    def test_alerts_page_has_every_control(self):
        page = self.html("/alerts")
        for element_id in ALERT_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        self.assertIn("js/listpage.js", page)
        self.assertIn("js/alerts.js", page)
        self.assertIn('class="soc-nav-link active" href="/alerts"', page)

    def test_alert_page_and_api_have_every_field_the_page_shows(self):
        self.generate()
        page = self.html("/alerts/1")
        self.assertIn('data-alert-id="1"', page)
        self.assertIn("Alert investigation", page)
        self.assertIn("js/alert_details.js", page)
        for element_id in DETAIL_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        detail = self.client.get("/api/alerts/1").get_json()
        js = (JS_DIR / "alert_details.js").read_text(encoding="utf-8")
        for key in ALERT_KEYS:
            self.assertIn(key, detail)
            self.assertIn("a." + key, js, f"alert_details.js never uses a.{key}")
        # An unknown alert: the page opens, the API says 404, and the JS shows the message
        self.assertEqual(self.client.get("/alerts/999999").status_code, 200)
        self.assertEqual(self.client.get("/api/alerts/999999").status_code, 404)

    def test_every_sortable_column_is_accepted_by_the_api(self):
        self.generate()
        for page_path, api_path in (("/logs", "/api/logs"), ("/alerts", "/api/alerts")):
            keys = re.findall(r'data-sort="([a-z_]+)"', self.html(page_path))
            self.assertGreaterEqual(len(keys), 8, page_path)
            for key in keys:
                for order in ("asc", "desc"):
                    r = self.client.get(api_path, query_string={"sort": key, "order": order})
                    self.assertEqual(r.status_code, 200, f"{api_path} sort={key} {order}")

    def test_dashboard_card_links_open_working_pages_and_queries(self):
        self.generate()
        links = re.findall(r'href="(/(?:alerts|logs)\?[^"]+)"', self.html("/"))
        self.assertGreaterEqual(len(links), 5)
        for link in links:
            self.assertEqual(self.client.get(link).status_code, 200, link)
            self.assertEqual(self.client.get("/api" + link).status_code, 200, link)

    def test_filters_used_by_the_pages_are_accepted_by_the_api(self):
        uid = self.generate()["upload_id"]
        common = {"q": "a", "source_ip": "203.0.113.", "username": "a", "date_from": "2000-01-01",
                  "date_to": "2099-12-31", "upload_id": uid, "page": 1, "per_page": 25,
                  "sort": "timestamp", "order": "desc"}
        logs_query = dict(common, event_type="login_failure", severity="NONE", anomalies_only="1")
        alerts_query = dict(common, severity="HIGH", status="New", threat_type="Brute Force",
                            detection_method="RULE")
        for path, query in (("/api/logs", logs_query), ("/api/alerts", alerts_query)):
            r = self.client.get(path, query_string=query)
            self.assertEqual(r.status_code, 200, path)
            body = r.get_json()
            for key in ("items", "total", "page", "pages", "per_page"):
                self.assertIn(key, body)
        filters = self.client.get("/api/filters").get_json()
        for key in ("event_types", "log_severities", "severities", "statuses",
                    "threat_types", "detection_methods"):
            self.assertIn(key, filters)

    def test_status_change_is_saved_and_visible_everywhere(self):
        self.generate()
        r = self.client.post("/api/alerts/1/status", json={"status": "Investigating"})
        self.assertEqual(r.status_code, 200)
        listing = self.client.get("/api/alerts", query_string={"status": "Investigating"}).get_json()
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["id"], 1)
        self.assertEqual(self.client.get("/api/alerts/1").get_json()["status"], "Investigating")

    def test_scripts_escape_output_and_shared_helpers_exist(self):
        for name in ("alerts.js", "alert_details.js"):
            text = (JS_DIR / name).read_text(encoding="utf-8")
            self.assertIn("esc(", text, name)
        for name in ("listpage.js", "logs.js", "alerts.js", "alert_details.js", "soc.js"):
            text = (JS_DIR / name).read_text(encoding="utf-8")
            self.assertNotIn("eval(", text, name)
            self.assertNotIn("document.write(", text, name)
        self.assertIn("logRowHtml", (JS_DIR / "logs.js").read_text(encoding="utf-8"))
        shared = (JS_DIR / "soc.js").read_text(encoding="utf-8")
        for helper in ("function debounce", "function queryString", "function fillSelect",
                       "function fillUploads", "function renderPager", "function mlBadge",
                       "function logRowHtml", "function esc("):
            self.assertIn(helper, shared, helper)
        pages = {n: (JS_DIR / n).read_text(encoding="utf-8") for n in ("logs.js", "alerts.js")}
        self.assertIn("log_severities", pages["logs.js"])
        self.assertIn("detection_methods", pages["alerts.js"])

    def test_hostile_username_is_returned_as_plain_json(self):
        rows = [f"2026-01-14 10:00:0{i},203.0.113.9,<img src=x onerror=alert(1)>,login_failure"
                for i in range(8)]
        data = ("timestamp,source_ip,username,event_type\n" + "\n".join(rows) + "\n").encode()
        r = self.client.post("/api/upload", data={"file": (io.BytesIO(data), "xss.csv")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201)
        logs = self.client.get("/api/logs", query_string={"q": "onerror"})
        self.assertTrue(logs.content_type.startswith("application/json"))
        self.assertEqual(logs.get_json()["items"][0]["username"], "<img src=x onerror=alert(1)>")
        alert = self.client.get("/api/alerts/1").get_json()
        self.assertIn("onerror", alert["original_log"])

    def test_finished_pages_are_no_longer_placeholders(self):
        for path in ("/logs", "/alerts", "/alerts/1", "/threats", "/analytics",
                     "/reports", "/settings"):
            self.assertNotIn("Planned for Stage", self.html(path), path)