"""Stage 13 tests: end-to-end journey, edge cases, robustness, answer-key check, doctor."""
import io
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import config
import doctor
from analysis import answer_key_check
from database import db
from generators import sample_logs as sl
from parser import log_normalizer
from services import queries
from tests.test_stage12 import parse
from tests.test_stage9 import PageTestCase

FORMATS = (("csv", "sample_generic.csv"), ("json", "sample_generic.json"),
           ("windows_csv", "sample_windows_security.csv"), ("linux_auth", "sample_linux_auth.log"))

HOSTILE = ["' OR 1=1 --", "'; DROP TABLE alerts; --", "%", "_", "\\", "<script>alert(1)</script>",
           "../../etc/passwd", "日本語", "9" * 40, "-1", "0", "1e9", " ", "null", "NaN"]
PARAMS = ["q", "source_ip", "username", "event_type", "severity", "status", "threat_type",
          "detection_method", "date_from", "date_to", "sort", "order", "page", "per_page",
          "upload_id", "anomalies_only"]


class AppCase(PageTestCase):
    """Shared helpers. Each test gets its own temporary database and upload folder."""

    def upload(self, content, name):
        return self.client.post("/api/upload", data={"file": (io.BytesIO(content), name)},
                                content_type="multipart/form-data")

    def fetch(self, path, method="get", **kwargs):
        response = getattr(self.client, method)(path, **kwargs)
        response.get_data()                      # consume streamed CSV so connections close
        return response

    def generate(self, **extra):
        body = {"events": 300, "seed": 7}
        body.update(extra)
        r = self.client.post("/api/generate-sample", json=body)
        self.assertEqual(r.status_code, 201)
        return r.get_json()

    def make_files(self, events=300, seed=7):
        start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=2)
        return sl.generate_all(out_dir=self.root / "samples", seed=seed,
                               normal_events=events, start=start)

    def assert_nothing_stored(self):
        self.assertEqual(db.query_one("SELECT COUNT(*) AS c FROM uploads")["c"], 0)
        self.assertEqual(list((self.root / "uploads").iterdir()), [])


# ======================================================================
class JourneyTests(AppCase):
    def test_full_journey(self):
        """Logs -> analysis -> alerts -> investigation -> status -> exports -> report -> delete."""
        uid = self.generate(events=400, seed=11)["upload_id"]
        stats = self.fetch("/api/stats", query_string={"upload_id": uid}).get_json()
        self.assertGreater(stats["total_alerts"], 0)

        top = self.fetch("/api/alerts", query_string={
            "upload_id": uid, "sort": "threat_score", "order": "desc", "per_page": 1}).get_json()["items"][0]
        alert = self.fetch(f"/api/alerts/{top['id']}").get_json()
        for key in ("id", "timestamp", "severity", "threat_type", "threat_score", "reason",
                    "severity_reason", "recommended_steps", "related_logs", "original_log"):
            self.assertIn(key, alert)
        self.assertTrue(alert["related_logs"])
        self.assertTrue(alert["recommended_steps"])
        self.assertIn(f"{int(alert['threat_score'])}/100", alert["severity_reason"])

        for status in ("Investigating", "Resolved"):
            r = self.fetch(f"/api/alerts/{alert['id']}/status", method="post", json={"status": status})
            self.assertEqual(r.status_code, 200)

        if alert["source_ip"]:
            logs = self.fetch("/api/logs", query_string={
                "upload_id": uid, "source_ip": alert["source_ip"]}).get_json()
            self.assertGreaterEqual(logs["total"], 1)

        _, rows = parse(self.fetch("/api/export/alerts.csv", query_string={"upload_id": uid}))
        row = next(r for r in rows if int(r["id"]) == alert["id"])
        self.assertEqual(row["status"], "Resolved")
        _, log_rows = parse(self.fetch("/api/export/logs.csv", query_string={"upload_id": uid}))
        self.assertEqual(len(log_rows), stats["total_logs"])

        self.assertIn("Threat Summary Report",
                      self.fetch("/reports/summary", query_string={"upload_id": uid}).get_data(as_text=True))
        self.assertEqual(self.fetch(f"/alerts/{alert['id']}").status_code, 200)

        self.assertEqual(self.fetch(f"/api/uploads/{uid}", method="delete").status_code, 200)
        after = self.fetch("/api/stats").get_json()
        self.assertEqual((after["total_logs"], after["total_alerts"]), (0, 0))
        self.assertEqual(self.fetch(f"/api/alerts/{alert['id']}").status_code, 404)

    def test_every_page_and_get_endpoint_responds(self):
        self.generate(events=150, seed=4)
        for path in ("/", "/logs", "/alerts", "/alerts/1", "/threats", "/analytics",
                     "/reports", "/settings", "/reports/summary", "/health",
                     "/api/stats", "/api/filters", "/api/uploads", "/api/logs", "/api/alerts",
                     "/api/alerts/1", "/api/threats", "/api/analytics", "/api/settings",
                     "/api/reports/summary", "/api/export/alerts.csv", "/api/export/logs.csv"):
            with self.subTest(path=path):
                self.assertEqual(self.fetch(path).status_code, 200, path)

    def test_all_four_log_formats_through_the_upload_api(self):
        generated = self.make_files(events=300)
        files, injected = generated["files"], generated["injected"]
        for key, name in FORMATS:
            with self.subTest(format=key):
                r = self.upload(Path(files[key]).read_bytes(), name)
                self.assertEqual(r.status_code, 201)
                body = r.get_json()
                self.assertEqual(body["ingest"]["skipped"], 0)
                self.assertGreater(body["analysis"]["total_alerts"], 0)
                self.assertGreaterEqual(body["analysis"]["rule_counts"]["brute_force"],
                                        injected["brute_force"])
        kinds = {u["file_type"] for u in self.fetch("/api/uploads").get_json()["items"]}
        self.assertEqual(kinds, {"csv", "json", "windows_csv", "linux_auth"})


# ======================================================================
class EdgeCaseTests(AppCase):
    def test_unreadable_files_are_rejected_cleanly(self):
        cases = [
            ("binary garbage", bytes(range(256)) * 20, "garbage.csv"),
            ("html saved as csv", b"<html><body><h1>hello</h1></body></html>", "page.csv"),
            ("html saved as json", b"<html><body>hello</body></html>", "page.json"),
            ("plain text", b"just some words\nand more words\n", "notes.txt"),
            ("header only", b"timestamp,source_ip,username\n", "header.csv"),
            ("empty json list", b"[]", "empty.json"),
            ("deeply nested json", b"[" * 100000 + b"]" * 100000, "deep.json"),
            ("log with no security events",
             b"Jan 14 01:00:00 server01 CRON[1]: session opened for user root\n", "cron.log"),
        ]
        for label, content, name in cases:
            with self.subTest(case=label):
                r = self.upload(content, name)
                self.assertIn(r.status_code, (400, 422), label)
                self.assertIn("error", r.get_json())
                self.assertNotIn("Traceback", r.get_data(as_text=True))
                self.assert_nothing_stored()

    def test_unicode_crlf_and_bom_are_handled(self):
        header = "timestamp,source_ip,username,event_type\r\n"
        rows = "".join(f"2026-01-14 10:00:{i:02d},203.0.113.9,ålice_日本語,login_failure\r\n"
                       for i in range(8))
        r = self.upload((header + rows).encode("utf-8-sig"), "unicode.csv")
        self.assertEqual(r.status_code, 201)
        found = self.fetch("/api/logs", query_string={"q": "日本語"}).get_json()
        self.assertEqual(found["total"], 8)
        self.assertEqual(found["items"][0]["username"], "ålice_日本語")
        _, exported = parse(self.fetch("/api/export/logs.csv"))
        self.assertTrue(all(row["username"] == "ålice_日本語" for row in exported))
        self.assertEqual(self.fetch("/api/alerts").get_json()["items"][0]["threat_type"], "Brute Force")

    def test_bad_rows_are_counted_not_fatal(self):
        good = [f"2026-01-14 10:00:{i:02d},10.0.0.5,user{i % 5},login_success" for i in range(60)]
        bad = ["not-a-date,10.0.0.1,bob,login_success", "also bad,10.0.0.2,bob,login_success", ",,,"]
        data = ("timestamp,source_ip,username,event_type\n" + "\n".join(good + bad) + "\n").encode()
        r = self.upload(data, "mixed.csv")
        self.assertEqual(r.status_code, 201)
        ingest = r.get_json()["ingest"]
        self.assertEqual((ingest["stored"], ingest["skipped"]), (60, 2))
        self.assertEqual(len(ingest["errors"]), 2)

    def test_row_limit_is_enforced(self):
        rows = "\n".join(f"2026-01-14 10:00:{i % 60:02d},10.0.0.5,bob,login_success" for i in range(100))
        data = ("timestamp,source_ip,username,event_type\n" + rows + "\n").encode()
        with patch.object(log_normalizer, "MAX_ROWS_PER_FILE", 50):
            r = self.upload(data, "toomany.csv")
        self.assertEqual(r.status_code, 422)
        self.assertIn("more than 50", r.get_json()["error"])
        self.assert_nothing_stored()

    def test_large_file_is_analysed_and_paginated(self):
        content = Path(self.make_files(events=12000, seed=5)["files"]["csv"]).read_bytes()
        self.assertLess(len(content), 10 * 1024 * 1024)
        r = self.upload(content, "big.csv")
        self.assertEqual(r.status_code, 201)
        analysis = r.get_json()["analysis"]
        self.assertGreater(analysis["total_logs"], 12000)
        self.assertTrue(analysis["ml_trained"])
        self.assertLess(analysis["duration_seconds"], 120)
        first = self.fetch("/api/logs", query_string={"per_page": 200, "page": 1}).get_json()
        self.assertEqual(len(first["items"]), 200)
        self.assertGreaterEqual(first["pages"], 60)
        last = self.fetch("/api/logs", query_string={"per_page": 200, "page": first["pages"]}).get_json()
        self.assertTrue(last["items"])

    def test_same_file_twice_stays_separate(self):
        content = Path(self.make_files(events=300)["files"]["csv"]).read_bytes()
        first = self.upload(content, "a.csv").get_json()
        second = self.upload(content, "a.csv").get_json()
        self.assertNotEqual(first["upload_id"], second["upload_id"])
        alerts = first["analysis"]["total_alerts"]
        self.assertEqual(alerts, second["analysis"]["total_alerts"])
        self.assertEqual(self.fetch("/api/stats").get_json()["total_alerts"], 2 * alerts)
        self.assertEqual(self.fetch("/api/delete-check").status_code, 404)
        self.fetch(f"/api/uploads/{first['upload_id']}", method="delete")
        remaining = self.fetch("/api/stats").get_json()
        self.assertEqual(remaining["total_alerts"], alerts)
        self.assertEqual(remaining["uploads"], 1)

    def test_filename_with_only_non_ascii_letters_is_refused_politely(self):
        r = self.upload(b"timestamp,source_ip\n2026-01-14 10:00:00,10.0.0.1\n", "日本.csv")
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())
        self.assert_nothing_stored()


# ======================================================================
class RobustnessTests(AppCase):
    def test_hostile_query_values_never_cause_a_server_error(self):
        self.generate(events=100, seed=2)
        alerts_before = db.query_one("SELECT COUNT(*) AS c FROM alerts")["c"]
        for path in ("/api/logs", "/api/alerts"):
            for param in PARAMS:
                for value in HOSTILE:
                    r = self.fetch(path, query_string={param: value})
                    self.assertIn(r.status_code, (200, 400), f"{path} {param}={value!r} -> {r.status_code}")
        for path in ("/api/stats", "/api/threats", "/api/analytics", "/api/reports/summary",
                     "/api/export/alerts.csv", "/api/export/logs.csv"):
            for value in HOSTILE:
                r = self.fetch(path, query_string={"upload_id": value})
                self.assertIn(r.status_code, (200, 400), f"{path} upload_id={value!r} -> {r.status_code}")
        self.assertIn("alerts", db.list_tables())
        self.assertEqual(db.query_one("SELECT COUNT(*) AS c FROM alerts")["c"], alerts_before)

    def test_huge_numbers_do_not_cause_a_server_error(self):
        self.generate(events=100, seed=2)
        alerts_before = db.query_one("SELECT COUNT(*) AS c FROM alerts")["c"]
        big = "9" * 30
        calls = [("get", f"/api/alerts/{big}", {}),
                 ("post", f"/api/alerts/{big}/status", {"json": {"status": "New"}}),
                 ("delete", f"/api/uploads/{big}", {}),
                 ("post", f"/api/uploads/{big}/analyze", {}),
                 ("get", f"/alerts/{big}", {})]
        for method, path, kwargs in calls:
            r = self.fetch(path, method=method, **kwargs)
            self.assertIn(r.status_code, (200, 400, 404), f"{method} {path} -> {r.status_code}")
        self.assertEqual(db.query_one("SELECT COUNT(*) AS c FROM alerts")["c"], alerts_before)

    def test_server_errors_do_not_leak_details(self):
        self.app.config["PROPAGATE_EXCEPTIONS"] = False     # behave like the real server
        with patch.object(queries, "dashboard_stats", side_effect=RuntimeError("boom secret detail")):
            r = self.client.get("/api/stats")
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.get_json(), {"error": "Internal server error"})
        self.assertNotIn("boom", r.get_data(as_text=True))

    def test_private_files_are_not_served(self):
        for path in ("/static/../config.py", "/static/..%2Fconfig.py", "/static/css/../../config.py",
                     "/data/soc_analyzer.db", "/config.py", "/app.py"):
            r = self.fetch(path)
            self.assertIn(r.status_code, (400, 404), path)
            self.assertNotIn("SECRET_KEY", r.get_data(as_text=True), path)

    def test_wrong_methods_give_json_405(self):
        self.generate(events=100, seed=2)
        for method, path in (("delete", "/api/alerts/1"), ("get", "/api/upload"),
                             ("put", "/api/stats"), ("post", "/api/logs")):
            r = self.fetch(path, method=method)
            self.assertEqual(r.status_code, 405, f"{method} {path}")
            self.assertIn("error", r.get_json())


# ======================================================================
class AnswerKeyTests(unittest.TestCase):
    STRICT = ("brute_force", "port_scan", "off_hours_login", "multi_ip_login")

    def test_rules_find_at_least_as_many_scenarios_as_injected(self):
        for seed in (1, 2, 3):
            result = answer_key_check.evaluate(seed=seed, events=400)
            rows = {r["scenario"]: r for r in result["rows"]}
            for name in self.STRICT:
                self.assertGreater(rows[name]["injected"], 0, f"seed {seed}: {name}")
                self.assertGreaterEqual(rows[name]["detected"], rows[name]["injected"],
                                        f"seed {seed}: {name}")
            self.assertEqual(result["internal_network_findings"], 0, f"seed {seed}")


# ======================================================================
class DoctorTests(unittest.TestCase):
    def test_fresh_database_matches_the_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fresh.db"
            with patch.object(config, "DATABASE_PATH", path):
                db.init_db()
            self.assertEqual(doctor.check_schema(path), [])

    def test_old_database_layout_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, analysis_id INTEGER, timestamp TEXT)")
            conn.commit()
            conn.close()
            problems = doctor.check_schema(path)
        self.assertTrue(any("logs" in p and "upload_id" in p for p in problems), problems)

    def test_file_that_is_not_a_database_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fake.db"
            path.write_text("this is not a database " * 50, encoding="utf-8")
            problems = doctor.check_schema(path)
        self.assertTrue(problems)

    def test_all_project_files_are_present(self):
        missing = [text for level, text in doctor.check_project_files() if level == "FAIL"]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()