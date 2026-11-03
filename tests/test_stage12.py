"""Stage 12 tests: CSV exports, threat summary report, settings view, Reports and Settings pages."""
import copy
import csv
import io
from unittest.mock import patch

import config
from database import db
from services import reports
from tests.test_stage9 import PageTestCase

JS_DIR = config.BASE_DIR / "static" / "js"
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

REPORT_IDS = ["scopeSelect", "alertSeverity", "alertStatus", "logSeverity", "logAnomalies",
              "alertsCsvLink", "logsCsvLink", "summaryViewLink", "summaryDownloadLink",
              "summaryJsonLink", "uploadsBody", "statusBox"]
SETTINGS_IDS = ["statusBox", "validationBox", "rulesBox", "mlBox", "bandsBox", "limitsBox",
                "scoringBox", "reanalyzeSelect", "reanalyzeBtn"]


def parse(response):
    """(column names, list of row dicts) from a CSV response."""
    text = response.get_data(as_text=True)
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    return reader.fieldnames, list(reader)


class Stage12Tests(PageTestCase):
    def generate(self, **extra):
        body = {"events": 300, "seed": 3}
        body.update(extra)
        r = self.client.post("/api/generate-sample", json=body)
        self.assertEqual(r.status_code, 201)
        return r.get_json()

    def upload_csv(self, rows, name):
        data = ("timestamp,source_ip,username,event_type\n" + "\n".join(rows) + "\n").encode()
        r = self.client.post("/api/upload", data={"file": (io.BytesIO(data), name)},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201)
        return r.get_json()["upload_id"]

    # ---------- CSV exports ----------
    def test_alerts_csv_export(self):
        self.generate()
        stats = self.client.get("/api/stats").get_json()
        r = self.client.get("/api/export/alerts.csv")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content_type.startswith("text/csv"))
        self.assertRegex(r.headers["Content-Disposition"],
                         r'attachment; filename="alerts_all_\d{8}_\d{6}\.csv"')
        self.assertTrue(r.get_data(as_text=True).startswith("\ufeff"))
        fields, rows = parse(r)
        self.assertEqual(fields, reports.ALERT_COLUMNS)
        self.assertEqual(len(rows), stats["total_alerts"])
        self.assertEqual({int(row["id"]) for row in rows},
                         {x["id"] for x in db.query_all("SELECT id FROM alerts")})
        for row in rows:
            self.assertIn(row["severity"], SEVERITIES)
            self.assertTrue(0 <= float(row["threat_score"]) <= 100)
            self.assertTrue(row["reason"])
            self.assertIn("Threat score", row["severity_reason"])
        brute = next(row for row in rows if row["threat_type"] == "Brute Force")
        self.assertIn(" | ", brute["recommended_steps"])

    def test_alerts_csv_filters_and_errors(self):
        uid = self.generate()["upload_id"]
        self.client.post("/api/alerts/1/status", json={"status": "Resolved"})
        _, rows = parse(self.client.get("/api/export/alerts.csv", query_string={"status": "resolved"}))
        self.assertEqual([row["id"] for row in rows], ["1"])

        severity = self.client.get("/api/alerts/1").get_json()["severity"]
        _, rows = parse(self.client.get("/api/export/alerts.csv", query_string={"severity": severity}))
        expected = self.client.get("/api/alerts", query_string={"severity": severity,
                                                                "per_page": 200}).get_json()["total"]
        self.assertEqual(len(rows), expected)

        scoped = self.client.get("/api/export/alerts.csv", query_string={"upload_id": uid})
        self.assertIn(f"alerts_upload{uid}_", scoped.headers["Content-Disposition"])
        scoped.get_data()
        self.assertEqual(self.client.get("/api/export/alerts.csv",
                                         query_string={"severity": "EXTREME"}).status_code, 400)
        self.assertEqual(self.client.get("/api/export/alerts.csv",
                                         query_string={"upload_id": "abc"}).status_code, 400)
        self.assertEqual(self.client.get("/api/export/alerts.csv",
                                         query_string={"upload_id": 9999}).status_code, 404)

    def test_logs_csv_export(self):
        self.generate(events=1200)                  # more than one 500-row chunk
        stats = self.client.get("/api/stats").get_json()
        self.assertGreater(stats["total_logs"], reports.CHUNK_ROWS)
        fields, rows = parse(self.client.get("/api/export/logs.csv"))
        self.assertEqual(fields, reports.LOG_COLUMNS)
        self.assertEqual(len(rows), stats["total_logs"])
        linked = sum(1 for row in rows if row["alert_ids"])
        expected = db.query_one("SELECT COUNT(DISTINCT log_id) AS c FROM threat_events")["c"]
        self.assertEqual(linked, expected)

        _, flagged = parse(self.client.get("/api/export/logs.csv", query_string={"anomalies_only": "1"}))
        self.assertEqual(len(flagged), stats["anomalies"])
        self.assertTrue(all(row["is_anomaly"] == "1" for row in flagged))

        level = db.query_one("SELECT severity FROM logs WHERE severity != 'NONE' LIMIT 1")["severity"]
        _, by_level = parse(self.client.get("/api/export/logs.csv", query_string={"severity": level}))
        in_db = db.query_one("SELECT COUNT(*) AS c FROM logs WHERE severity = ?", (level,))["c"]
        self.assertEqual(len(by_level), in_db)
        self.assertEqual(self.client.get("/api/export/logs.csv",
                                         query_string={"severity": "EXTREME"}).status_code, 400)
        self.assertEqual(self.client.get("/api/export/logs.csv",
                                         query_string={"upload_id": 9999}).status_code, 404)

    def test_formula_text_is_neutralised_in_both_exports(self):
        rows = [f"2026-01-14 10:00:0{i},203.0.113.9,=1+1,login_failure" for i in range(8)]
        self.upload_csv(rows, "formula.csv")
        for url in ("/api/export/alerts.csv", "/api/export/logs.csv"):
            _, data = parse(self.client.get(url))
            self.assertTrue(data, url)
            for row in data:
                for key, value in row.items():
                    self.assertFalse(value.startswith(("=", "+", "-", "@")), f"{url} {key}={value!r}")
            self.assertTrue(any(row["username"] == "'=1+1" for row in data), url)

    def test_safe_cell(self):
        self.assertEqual(reports.safe_cell("=1+1"), "'=1+1")
        self.assertEqual(reports.safe_cell("+cmd"), "'+cmd")
        self.assertEqual(reports.safe_cell("-1"), "'-1")
        self.assertEqual(reports.safe_cell("@SUM(1)"), "'@SUM(1)")
        self.assertEqual(reports.safe_cell("\tx"), "'\tx")
        self.assertEqual(reports.safe_cell("alice"), "alice")
        self.assertEqual(reports.safe_cell(""), "")
        self.assertEqual(reports.safe_cell(-5), -5)
        self.assertEqual(reports.safe_cell(1.5), 1.5)
        self.assertIsNone(reports.safe_cell(None))

    def test_export_row_cap(self):
        self.generate()
        with patch.object(reports, "MAX_EXPORT_ROWS", 5):
            _, rows = parse(self.client.get("/api/export/alerts.csv"))
        self.assertEqual(len(rows), 5)

    # ---------- summary report ----------
    def test_summary_json(self):
        self.generate()
        stats = self.client.get("/api/stats").get_json()
        r = self.client.get("/api/reports/summary")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        for key in ("generated_at", "scope", "totals", "severity_counts", "status_counts",
                    "detection_methods", "key_findings", "top_alerts", "threat_types",
                    "top_attackers", "targeted_users", "ml", "ml_runs", "uploads", "configuration"):
            self.assertIn(key, body)
        t = body["totals"]
        self.assertEqual((t["logs"], t["alerts"], t["anomalies"]),
                         (stats["total_logs"], stats["total_alerts"], stats["anomalies"]))
        self.assertEqual(sum(body["severity_counts"].values()), t["alerts"])
        self.assertTrue(body["key_findings"])
        top = body["top_alerts"]
        self.assertTrue(0 < len(top) <= 10)
        scores = [a["threat_score"] for a in top]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertLessEqual(len(body["top_attackers"]), 10)
        self.assertEqual(body["ml"]["logs"], stats["total_logs"])
        self.assertIn("brute_force", [x["name"] for x in body["configuration"]["detection_rules"]])
        self.assertEqual(body["scope"]["label"], "All uploads")

    def test_summary_scope_and_errors(self):
        first = self.generate(seed=3)["upload_id"]
        second = self.generate(seed=4)["upload_id"]
        one = self.client.get("/api/reports/summary", query_string={"upload_id": first}).get_json()
        two = self.client.get("/api/reports/summary", query_string={"upload_id": second}).get_json()
        both = self.client.get("/api/reports/summary").get_json()
        self.assertEqual(one["totals"]["alerts"] + two["totals"]["alerts"], both["totals"]["alerts"])
        self.assertIn(f"Upload #{first}", one["scope"]["label"])
        self.assertEqual(len(one["uploads"]), 1)
        for path in ("/api/reports/summary", "/reports/summary"):
            self.assertEqual(self.client.get(path, query_string={"upload_id": "abc"}).status_code, 400, path)
            self.assertEqual(self.client.get(path, query_string={"upload_id": 9999}).status_code, 404, path)

    def test_summary_html_page_and_download(self):
        self.generate()
        page = self.html("/reports/summary")
        for text in ("Threat Summary Report", "Key findings", "Highest-scoring alerts",
                     "Methodology", "Limitations", "not an accuracy measure"):
            self.assertIn(text, page)
        self.assertNotIn("<script", page)
        r = self.client.get("/reports/summary", query_string={"download": "1"})
        self.assertRegex(r.headers["Content-Disposition"],
                         r'attachment; filename="threat_summary_all_\d{8}_\d{6}\.html"')
        r.get_data()
        self.assertNotIn("Content-Disposition", self.client.get("/reports/summary").headers)

    def test_summary_escapes_hostile_log_values(self):
        evil = "<script>alert(1)</script>"
        rows = [f"2026-01-14 10:00:0{i},203.0.113.9,{evil},login_failure" for i in range(8)]
        self.upload_csv(rows, "evil.csv")
        page = self.html("/reports/summary")
        self.assertNotIn(evil, page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script", page)

    def test_empty_database_reports(self):
        body = self.client.get("/api/reports/summary").get_json()
        self.assertEqual((body["totals"]["logs"], body["totals"]["alerts"]), (0, 0))
        self.assertEqual(body["top_alerts"], [])
        self.assertIn("no alerts were raised", body["key_findings"][0])
        self.assertIn("No alerts", self.html("/reports/summary"))
        for url in ("/api/export/alerts.csv", "/api/export/logs.csv"):
            fields, rows = parse(self.client.get(url))
            self.assertTrue(fields)
            self.assertEqual(rows, [])

    # ---------- settings ----------
    def test_settings_api(self):
        r = self.client.get("/api/settings")
        self.assertEqual(r.status_code, 200)
        s = r.get_json()
        self.assertIn("brute_force", s["detection_rules"])
        self.assertEqual(s["detection_rules"]["brute_force"]["failed_attempts_threshold"], 5)
        self.assertEqual(s["ml"]["contamination"], config.ML_SETTINGS["contamination"])
        self.assertEqual(set(s["severity_bands"]), SEVERITIES)
        self.assertEqual(s["limits"]["max_upload_mb"], 10)
        self.assertIn("csv", s["limits"]["allowed_extensions"])
        self.assertIn("base_scores", s["scoring"])
        self.assertTrue(s["validation"]["all_valid"])
        text = r.get_data(as_text=True)
        self.assertNotIn(self.app.config["SECRET_KEY"], text)
        self.assertNotIn("secret", text.lower())

    def test_settings_validation_reports_bad_values(self):
        bad_rules = copy.deepcopy(config.DETECTION_RULES)
        bad_rules["brute_force"]["failed_attempts_threshold"] = 0
        with patch.object(config, "DETECTION_RULES", bad_rules):
            v = self.client.get("/api/settings").get_json()["validation"]
        self.assertFalse(v["detection_rules"]["valid"])
        self.assertIn("brute_force", v["detection_rules"]["error"])
        self.assertTrue(v["ml"]["valid"])
        self.assertFalse(v["all_valid"])

        with patch.object(config, "ML_SETTINGS", dict(config.ML_SETTINGS, contamination=0.9)):
            v = self.client.get("/api/settings").get_json()["validation"]
        self.assertFalse(v["ml"]["valid"])
        self.assertIn("contamination", v["ml"]["error"])

        bad_scoring = dict(config.SCORING_SETTINGS, ml_low=0.9, ml_high=0.5)
        with patch.object(config, "SCORING_SETTINGS", bad_scoring):
            v = self.client.get("/api/settings").get_json()["validation"]
        self.assertFalse(v["scoring"]["valid"])

        gap = {"LOW": (0, 29), "MEDIUM": (31, 59), "HIGH": (60, 79), "CRITICAL": (80, 100)}
        with patch.object(config, "SEVERITY_BANDS", gap):
            v = self.client.get("/api/settings").get_json()["validation"]
        self.assertFalse(v["severity_bands"]["valid"])

    # ---------- pages and scripts ----------
    def test_reports_page(self):
        page = self.html("/reports")
        for element_id in REPORT_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        self.assertIn("js/reports.js", page)
        self.assertIn('class="soc-nav-link active" href="/reports"', page)
        self.assertNotIn("Planned for Stage", page)

    def test_settings_page(self):
        page = self.html("/settings")
        for element_id in SETTINGS_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        self.assertIn("js/settings.js", page)
        self.assertIn('class="soc-nav-link active" href="/settings"', page)
        self.assertNotIn("Planned for Stage", page)

    def test_scripts(self):
        reports_js = (JS_DIR / "reports.js").read_text(encoding="utf-8")
        settings_js = (JS_DIR / "settings.js").read_text(encoding="utf-8")
        for needle in ("/api/export/alerts.csv", "/api/export/logs.csv", "/reports/summary",
                       "/api/reports/summary"):
            self.assertIn(needle, reports_js)
        for needle in ("/api/settings", "/analyze"):
            self.assertIn(needle, settings_js)
        for name, text in (("reports.js", reports_js), ("settings.js", settings_js)):
            self.assertIn("esc(", text, name)
            self.assertNotIn("eval(", text, name)
            self.assertNotIn("document.write(", text, name)
        for element_id in REPORT_IDS:
            self.assertIn(element_id, reports_js, element_id)