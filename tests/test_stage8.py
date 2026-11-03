"""Stage 8 tests: schema migration, analysis pipeline, query helpers and the JSON API."""
import copy
import io
import json
import math
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import config
from analysis.threat_scoring import severity_for_score
from app import create_app
from database import db
from generators import sample_logs as sl
from services import queries
from services.analysis_pipeline import AnalysisError, analyze_upload, delete_upload, process_file
from services.queries import QueryError

START = datetime(2026, 1, 15)
RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class TempEnvTestCase(unittest.TestCase):
    """Every test gets its own temporary database and upload folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)          # runs last
        self.root = Path(self.tmp.name)
        self.upload_dir = self.root / "uploads"
        self.upload_dir.mkdir()
        for name, value in (("DATABASE_PATH", self.root / "test.db"),
                            ("UPLOAD_DIR", self.upload_dir)):
            patcher = patch.object(config, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()

    def make_samples(self, events=800, seed=42):
        return sl.generate_all(out_dir=self.root / "samples", seed=seed,
                               normal_events=events, start=START)

    def count(self, sql, params=()):
        return db.query_one(sql, params)["c"]


# ======================================================================
class MigrationTests(unittest.TestCase):
    def columns(self):
        conn = db.get_connection()
        try:
            return {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
        finally:
            conn.close()

    def test_old_database_gets_severity_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, upload_id "
                         "INTEGER, threat_type TEXT, severity TEXT, source_ip TEXT, status TEXT)")
            conn.commit()
            conn.close()
            with patch.object(config, "DATABASE_PATH", path):
                db.init_db()
                db.init_db()                       # running twice must not fail
                self.assertIn("severity_reason", self.columns())

    def test_new_database_has_severity_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(config, "DATABASE_PATH", Path(tmp) / "new.db"):
                db.init_db()
                self.assertIn("severity_reason", self.columns())


# ======================================================================
class PipelineTests(TempEnvTestCase):
    def setUp(self):
        super().setUp()
        gen = self.make_samples()
        self.files, self.injected = gen["files"], gen["injected"]
        self.result = process_file(self.files["csv"])
        self.uid = self.result["ingest"]["upload_id"]
        self.analysis = self.result["analysis"]

    def test_summary_matches_database(self):
        a = self.analysis
        self.assertEqual(a["total_logs"], self.result["ingest"]["stored"])
        n = self.count("SELECT COUNT(*) AS c FROM alerts WHERE upload_id = ?", (self.uid,))
        self.assertEqual(n, a["total_alerts"])
        self.assertGreater(n, 0)
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            in_db = self.count("SELECT COUNT(*) AS c FROM alerts WHERE severity = ?", (level,))
            self.assertEqual(in_db, a["severity_counts"][level], level)
        row = db.query_one("SELECT * FROM analysis_results WHERE upload_id = ?", (self.uid,))
        self.assertEqual(row["total_alerts"], n)
        self.assertEqual(row["critical_count"], a["severity_counts"]["CRITICAL"])
        self.assertEqual(row["ml_trained"], 1)
        self.assertTrue(row["ml_note"])
        self.assertEqual(db.query_one("SELECT status FROM uploads WHERE id = ?", (self.uid,))["status"],
                         "analyzed")

    def test_injected_attacks_became_alerts(self):
        def n(threat):
            return self.count("SELECT COUNT(*) AS c FROM alerts WHERE threat_type = ?", (threat,))
        self.assertGreaterEqual(n("Brute Force"), self.injected["brute_force"])
        self.assertGreaterEqual(n("Port Scan"), self.injected["port_scan"])
        self.assertGreaterEqual(n("Suspicious Account Activity"), self.injected["account_activity"])
        self.assertGreaterEqual(n("Privilege Escalation Activity"), self.injected["privilege_activity"])

    def test_threat_events_link_alerts_to_real_logs(self):
        mismatched = self.count(
            "SELECT COUNT(*) AS c FROM alerts a WHERE a.related_event_count != "
            "(SELECT COUNT(*) FROM threat_events t WHERE t.alert_id = a.id)")
        self.assertEqual(mismatched, 0)
        self.assertEqual(self.count("SELECT COUNT(*) AS c FROM threat_events WHERE log_id IS NULL"), 0)

    def test_each_log_keeps_the_highest_severity_of_its_alerts(self):
        expected = {}
        for r in db.query_all("SELECT t.log_id, a.severity FROM threat_events t "
                              "JOIN alerts a ON a.id = t.alert_id"):
            if RANK[r["severity"]] > RANK[expected.get(r["log_id"], "NONE")]:
                expected[r["log_id"]] = r["severity"]
        self.assertTrue(expected)
        for r in db.query_all("SELECT id, severity FROM logs"):
            self.assertEqual(r["severity"], expected.get(r["id"], "NONE"), r["id"])

    def test_ml_flags_are_stored_on_logs(self):
        self.assertTrue(self.analysis["ml_trained"])
        flagged = self.count("SELECT COUNT(*) AS c FROM logs WHERE is_anomaly = 1")
        self.assertEqual(flagged, self.analysis["anomaly_count"])
        self.assertGreater(flagged, 0)
        self.assertEqual(self.count("SELECT COUNT(*) AS c FROM logs WHERE anomaly_score IS NULL"), 0)

    def test_alert_fields_are_complete(self):
        for a in db.query_all("SELECT * FROM alerts"):
            self.assertTrue(a["reason"])
            self.assertIn(f"{int(a['threat_score'])}/100", a["severity_reason"])
            steps = json.loads(a["recommended_steps"])
            self.assertIsInstance(steps, list)
            self.assertTrue(steps)
            self.assertEqual(a["severity"], severity_for_score(a["threat_score"]))
            self.assertIn(a["detection_method"], ("RULE", "ML", "RULE+ML"))
            self.assertEqual(a["status"], "New")
            self.assertTrue(a["timestamp"])
            self.assertIsNotNone(a["ml_anomaly_score"])

    def test_reanalysis_replaces_previous_results(self):
        alerts = self.count("SELECT COUNT(*) AS c FROM alerts")
        events = self.count("SELECT COUNT(*) AS c FROM threat_events")
        again = analyze_upload(self.uid)
        self.assertEqual(again["total_alerts"], alerts)
        self.assertEqual(self.count("SELECT COUNT(*) AS c FROM alerts"), alerts)
        self.assertEqual(self.count("SELECT COUNT(*) AS c FROM threat_events"), events)
        self.assertEqual(self.count("SELECT COUNT(*) AS c FROM analysis_results"), 1)

    def test_delete_upload_removes_everything(self):
        stored = self.upload_dir / "abc_copy.csv"
        shutil.copyfile(self.files["csv"], stored)
        second = process_file(stored, original_name="copy.csv", stored_name="abc_copy.csv")
        sid = second["ingest"]["upload_id"]
        self.assertTrue(delete_upload(sid, self.upload_dir))
        self.assertFalse(stored.exists())
        for table in ("logs", "alerts", "analysis_results", "uploads"):
            column = "id" if table == "uploads" else "upload_id"
            self.assertEqual(self.count(f"SELECT COUNT(*) AS c FROM {table} WHERE {column} = ?", (sid,)),
                             0, table)
        self.assertGreater(self.count("SELECT COUNT(*) AS c FROM alerts WHERE upload_id = ?", (self.uid,)), 0)
        self.assertFalse(delete_upload(99999, self.upload_dir))

    def test_missing_upload_raises(self):
        with self.assertRaises(AnalysisError):
            analyze_upload(99999)

    def test_invalid_settings_fail_cleanly_and_keep_old_results(self):
        before = self.count("SELECT COUNT(*) AS c FROM alerts")
        bad = copy.deepcopy(config.DETECTION_RULES)
        bad["brute_force"]["failed_attempts_threshold"] = 0
        with patch.object(config, "DETECTION_RULES", bad):
            with self.assertRaises(AnalysisError) as ctx:
                analyze_upload(self.uid)
        self.assertIn("brute_force", str(ctx.exception))
        self.assertEqual(db.query_one("SELECT status FROM uploads WHERE id = ?", (self.uid,))["status"],
                         "analysis_failed")
        self.assertEqual(self.count("SELECT COUNT(*) AS c FROM alerts"), before)

    def test_small_file_skips_ml_but_still_raises_alerts(self):
        path = self.root / "small.csv"
        rows = [f"2026-01-14 10:00:{i:02d},203.0.113.9,admin,login_failure" for i in range(8)]
        path.write_text("timestamp,source_ip,username,event_type\n" + "\n".join(rows) + "\n",
                        encoding="utf-8")
        a = process_file(path)["analysis"]
        self.assertFalse(a["ml_trained"])
        self.assertIn("at least", a["ml_note"])
        self.assertEqual(a["anomaly_count"], 0)
        alerts = db.query_all("SELECT * FROM alerts WHERE upload_id = ?", (a["upload_id"],))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["threat_type"], "Brute Force")
        self.assertEqual(alerts[0]["detection_method"], "RULE")
        self.assertIsNone(alerts[0]["ml_anomaly_score"])
        row = db.query_one("SELECT ml_trained FROM analysis_results WHERE upload_id = ?", (a["upload_id"],))
        self.assertEqual(row["ml_trained"], 0)


# ======================================================================
class QueryTests(TempEnvTestCase):
    def setUp(self):
        super().setUp()
        self.files = self.make_samples()["files"]
        self.result = process_file(self.files["csv"])
        self.uid = self.result["ingest"]["upload_id"]
        self.analysis = self.result["analysis"]

    def test_log_pagination(self):
        total = self.result["ingest"]["stored"]
        first = queries.search_logs({"per_page": "20", "page": "1"})
        second = queries.search_logs({"per_page": "20", "page": "2"})
        self.assertEqual(len(first["items"]), 20)
        self.assertEqual(first["total"], total)
        self.assertEqual(first["pages"], math.ceil(total / 20))
        self.assertFalse({i["id"] for i in first["items"]} & {i["id"] for i in second["items"]})
        last = queries.search_logs({"per_page": "20", "page": str(first["pages"])})
        self.assertEqual(len(last["items"]), total - 20 * (first["pages"] - 1))
        self.assertEqual(queries.search_logs({}, 50)["per_page"], 50)

    def test_per_page_is_capped(self):
        self.assertEqual(queries.search_logs({"per_page": "9999"})["per_page"], queries.MAX_PER_PAGE)

    def test_log_filters(self):
        r = queries.search_logs({"source_ip": "203.0.113.", "per_page": "200"})
        self.assertGreater(r["total"], 0)
        self.assertTrue(all("203.0.113." in i["source_ip"] for i in r["items"]))

        r = queries.search_logs({"username": "ALI", "per_page": "200"})
        self.assertGreater(r["total"], 0)
        self.assertTrue(all("ali" in i["username"].lower() for i in r["items"]))

        r = queries.search_logs({"event_type": "login_failure", "per_page": "200"})
        self.assertTrue(all(i["event_type"] == "login_failure" for i in r["items"]))
        self.assertGreater(r["total"], 0)

        sev = db.query_one("SELECT severity FROM logs WHERE severity != 'NONE' LIMIT 1")["severity"]
        r = queries.search_logs({"severity": sev.lower(), "per_page": "200"})
        self.assertEqual(r["total"], self.count("SELECT COUNT(*) AS c FROM logs WHERE severity = ?", (sev,)))
        self.assertTrue(all(i["severity"] == sev for i in r["items"]))

        r = queries.search_logs({"anomalies_only": "1", "per_page": "200"})
        self.assertEqual(r["total"], self.analysis["anomaly_count"])
        self.assertTrue(all(i["is_anomaly"] == 1 for i in r["items"]))

        r = queries.search_logs({"date_from": "2026-01-15", "date_to": "2026-01-15", "per_page": "200"})
        self.assertGreater(r["total"], 0)
        self.assertTrue(all(i["timestamp"].startswith("2026-01-15") for i in r["items"]))

        self.assertEqual(queries.search_logs({"upload_id": "9999"})["total"], 0)

    def test_log_sorting(self):
        r = queries.search_logs({"sort": "timestamp", "order": "desc", "per_page": "100"})
        stamps = [i["timestamp"] for i in r["items"]]
        self.assertEqual(stamps, sorted(stamps, reverse=True))
        r = queries.search_logs({"sort": "severity", "order": "desc", "per_page": "100"})
        ranks = [RANK[i["severity"]] for i in r["items"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_bad_filters_are_rejected(self):
        bad = [{"severity": "EXTREME"}, {"date_from": "yesterday"}, {"sort": "password_hash"},
               {"order": "sideways"}, {"page": "abc"}, {"page": "0"}, {"upload_id": "x"},
               {"q": "x" * 500}]
        for args in bad:
            with self.subTest(args=args):
                with self.assertRaises(QueryError):
                    queries.search_logs(args)

    def test_search_is_injection_and_wildcard_safe(self):
        self.assertEqual(queries.search_logs({"q": "'; DROP TABLE logs; --"})["total"], 0)
        self.assertIn("logs", db.list_tables())
        self.assertEqual(queries.search_logs({"q": "%"})["total"], 0)               # literal %
        self.assertEqual(queries.search_logs({"q": "login%failure"})["total"], 0)   # % is not a wildcard
        self.assertGreater(queries.search_logs({"q": "login_failure"})["total"], 0)

    def test_alert_search_and_filters(self):
        everything = queries.search_alerts({"per_page": "200"})
        total = everything["total"]
        self.assertEqual(total, self.analysis["total_alerts"])
        self.assertNotIn("original_log", everything["items"][0])
        self.assertEqual(queries.search_alerts({})["per_page"], 25)

        sev = everything["items"][0]["severity"]
        r = queries.search_alerts({"severity": sev.lower(), "per_page": "200"})
        self.assertTrue(all(i["severity"] == sev for i in r["items"]))
        self.assertEqual(r["total"], self.count("SELECT COUNT(*) AS c FROM alerts WHERE severity = ?", (sev,)))

        self.assertEqual(queries.search_alerts({"status": "new"})["total"], total)
        self.assertEqual(queries.search_alerts({"status": "resolved"})["total"], 0)

        r = queries.search_alerts({"threat_type": "brute force", "per_page": "200"})
        self.assertGreater(r["total"], 0)
        self.assertTrue(all(i["threat_type"] == "Brute Force" for i in r["items"]))

        r = queries.search_alerts({"sort": "threat_score", "order": "desc", "per_page": "200"})
        scores = [i["threat_score"] for i in r["items"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

        ip = db.query_one("SELECT source_ip FROM alerts WHERE source_ip IS NOT NULL LIMIT 1")["source_ip"]
        self.assertGreaterEqual(queries.search_alerts({"q": ip})["total"], 1)
        with self.assertRaises(QueryError):
            queries.search_alerts({"status": "Banana"})

    def test_get_alert_detail(self):
        aid = db.query_one("SELECT id FROM alerts WHERE threat_type = 'Brute Force' ORDER BY id")["id"]
        alert = queries.get_alert(aid)
        self.assertTrue(alert["recommended_steps"])
        self.assertIsInstance(alert["recommended_steps"], list)
        self.assertTrue(alert["severity_reason"])
        self.assertEqual(alert["related_total"], alert["related_event_count"])
        self.assertEqual(len(alert["related_logs"]), min(100, alert["related_event_count"]))
        stamps = [r["timestamp"] for r in alert["related_logs"]]
        self.assertEqual(stamps, sorted(stamps))
        self.assertIsNone(queries.get_alert(999999))

    def test_update_alert_status(self):
        aid = db.query_one("SELECT id FROM alerts ORDER BY id")["id"]
        self.assertEqual(queries.update_alert_status(aid, "investigating"), "Investigating")
        self.assertEqual(queries.get_alert(aid)["status"], "Investigating")
        for status in ("New", "Resolved", "False Positive"):
            self.assertEqual(queries.update_alert_status(aid, status), status)
        for bad in ("Banana", "", None, 5):
            with self.subTest(status=bad):
                with self.assertRaises(QueryError):
                    queries.update_alert_status(aid, bad)
        self.assertIsNone(queries.update_alert_status(999999, "Resolved"))

    def test_dashboard_stats_are_consistent(self):
        s = queries.dashboard_stats()
        self.assertEqual(s["total_logs"], self.result["ingest"]["stored"])
        self.assertEqual(set(s["severity_counts"]), {"LOW", "MEDIUM", "HIGH", "CRITICAL"})
        self.assertEqual(sum(s["severity_counts"].values()), s["total_alerts"])
        self.assertEqual(s["anomalies"], self.analysis["anomaly_count"])
        self.assertEqual(sum(t["count"] for t in s["threat_types"]), s["total_alerts"])
        self.assertEqual(s["status_counts"]["New"], s["total_alerts"])
        counts = [x["alerts"] for x in s["top_ips"]]
        self.assertEqual(counts, sorted(counts, reverse=True))
        self.assertLessEqual(len(s["recent_alerts"]), 10)
        self.assertIn(s["timeline"]["bucket"], ("hour", "day"))
        self.assertEqual(sum(p["total"] for p in s["timeline"]["points"]), s["total_alerts"])

    def test_stats_can_be_scoped_to_one_upload(self):
        second = process_file(self.files["json"])
        sid = second["ingest"]["upload_id"]
        first_scope = queries.dashboard_stats(self.uid)
        self.assertEqual(first_scope["total_logs"], self.result["ingest"]["stored"])
        self.assertEqual(first_scope["total_alerts"], self.analysis["total_alerts"])
        self.assertEqual(queries.dashboard_stats(sid)["total_alerts"], second["analysis"]["total_alerts"])
        both = queries.dashboard_stats()
        self.assertEqual(both["total_logs"],
                         self.result["ingest"]["stored"] + second["ingest"]["stored"])
        self.assertEqual(both["uploads"], 2)

    def test_uploads_and_filter_options(self):
        uploads = queries.list_uploads()
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["total_alerts"], self.analysis["total_alerts"])
        self.assertEqual(uploads[0]["status"], "analyzed")
        self.assertNotIn("stored_name", uploads[0])
        opts = queries.filter_options()
        self.assertIn("login_failure", opts["event_types"])
        self.assertIn("Brute Force", opts["threat_types"])
        self.assertEqual(opts["severities"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertEqual(opts["statuses"], ["New", "Investigating", "Resolved", "False Positive"])


class EmptyDatabaseTests(TempEnvTestCase):
    def test_empty_database_gives_zeros_not_errors(self):
        s = queries.dashboard_stats()
        self.assertEqual((s["total_logs"], s["total_alerts"], s["anomalies"]), (0, 0, 0))
        self.assertEqual(s["top_ips"], [])
        self.assertEqual(s["recent_alerts"], [])
        self.assertEqual(s["timeline"]["points"], [])
        r = queries.search_logs({})
        self.assertEqual((r["total"], r["pages"], r["items"]), (0, 1, []))
        self.assertEqual(queries.search_alerts({})["total"], 0)


# ======================================================================
class ApiTests(TempEnvTestCase):
    def setUp(self):
        super().setUp()
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def upload(self, content, name="logs.csv"):
        return self.client.post("/api/upload", data={"file": (io.BytesIO(content), name)},
                                content_type="multipart/form-data")

    def generate(self, **body):
        payload = {"events": 300, "attacks": 1, "seed": 5}
        payload.update(body)
        return self.client.post("/api/generate-sample", json=payload)

    def test_upload_analyzes_the_file(self):
        data = Path(self.make_samples(events=200)["files"]["csv"]).read_bytes()
        r = self.upload(data, "my logs.csv")
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["filename"], "my_logs.csv")
        self.assertGreater(body["analysis"]["total_alerts"], 0)
        stored = list(self.upload_dir.iterdir())
        self.assertEqual(len(stored), 1)
        self.assertTrue(stored[0].name.endswith("_my_logs.csv"))
        stats = self.client.get("/api/stats").get_json()
        self.assertEqual(stats["total_alerts"], body["analysis"]["total_alerts"])

    def test_upload_rejections(self):
        self.assertEqual(self.client.post("/api/upload", data={}).status_code, 400)
        self.assertEqual(self.upload(b"hi", "malware.exe").status_code, 400)
        self.assertEqual(self.upload(b"hi", "noextension").status_code, 400)
        self.assertEqual(self.upload(b"", "empty.csv").status_code, 400)
        r = self.upload(b"hello\nworld\n", "garbage.csv")
        self.assertEqual(r.status_code, 422)
        self.assertIn("error", r.get_json())
        self.assertEqual(self.count("SELECT COUNT(*) AS c FROM uploads"), 0)
        self.assertEqual(list(self.upload_dir.iterdir()), [])          # no leftover file

    def test_path_traversal_filename_is_neutralised(self):
        data = Path(self.make_samples(events=100)["files"]["csv"]).read_bytes()
        r = self.upload(data, "../../evil.csv")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["filename"], "evil.csv")
        stored = db.query_one("SELECT stored_name FROM uploads")["stored_name"]
        self.assertNotIn("/", stored)
        self.assertNotIn("\\", stored)
        self.assertTrue((self.upload_dir / stored).exists())

    def test_oversized_upload_returns_413(self):
        self.app.config["MAX_CONTENT_LENGTH"] = 200
        r = self.upload(b"a" * 5000, "big.csv")
        self.assertEqual(r.status_code, 413)
        self.assertIn("error", r.get_json())

    def test_generate_sample_in_every_format(self):
        r = self.generate()
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["seed"], 5)
        self.assertGreaterEqual(body["injected"]["brute_force"], 1)
        self.assertGreater(body["analysis"]["total_alerts"], 0)
        for kind in ("json", "windows_csv", "linux_auth"):
            self.assertEqual(self.generate(kind=kind, events=100).status_code, 201, kind)

    def test_generate_sample_validation(self):
        for body in ({"kind": "exe"}, {"events": 10 ** 7}, {"events": "abc"}, {"events": True},
                     {"attacks": 0}, {"seed": "x"}):
            with self.subTest(body=body):
                r = self.generate(**body)
                self.assertEqual(r.status_code, 400)
                self.assertIn("error", r.get_json())

    def test_alert_list_and_detail(self):
        self.generate()
        r = self.client.get("/api/alerts", query_string={"per_page": 5, "sort": "threat_score",
                                                         "order": "desc"})
        self.assertEqual(r.status_code, 200)
        page = r.get_json()
        self.assertEqual(len(page["items"]), min(5, page["total"]))
        detail = self.client.get(f"/api/alerts/{page['items'][0]['id']}").get_json()
        self.assertIsInstance(detail["recommended_steps"], list)
        self.assertTrue(detail["severity_reason"])
        self.assertTrue(detail["related_logs"])
        self.assertEqual(self.client.get("/api/alerts/999999").status_code, 404)

    def test_alert_status_endpoint(self):
        self.generate()
        aid = self.client.get("/api/alerts").get_json()["items"][0]["id"]
        r = self.client.post(f"/api/alerts/{aid}/status", json={"status": "Resolved"})
        self.assertEqual((r.status_code, r.get_json()["status"]), (200, "Resolved"))
        r = self.client.patch(f"/api/alerts/{aid}/status", json={"status": "False Positive"})
        self.assertEqual(r.status_code, 200)
        r = self.client.get("/api/alerts", query_string={"status": "False Positive"})
        self.assertEqual(r.get_json()["total"], 1)
        self.assertEqual(self.client.get(f"/api/alerts/{aid}").get_json()["status"], "False Positive")
        self.assertEqual(self.client.post(f"/api/alerts/{aid}/status",
                                          json={"status": "Banana"}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/alerts/{aid}/status", data="not json").status_code, 400)
        self.assertEqual(self.client.post("/api/alerts/999999/status",
                                          json={"status": "Resolved"}).status_code, 404)

    def test_log_endpoint(self):
        self.generate()
        r = self.client.get("/api/logs", query_string={"per_page": 10, "sort": "timestamp",
                                                       "order": "desc"})
        body = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(body["items"]), 10)
        self.assertGreater(body["total"], 10)
        for args in ({"severity": "EXTREME"}, {"upload_id": "abc"}, {"sort": "raw_log"}):
            r = self.client.get("/api/logs", query_string=args)
            self.assertEqual(r.status_code, 400, args)
            self.assertIn("error", r.get_json())

    def test_stats_filters_and_uploads_endpoints(self):
        self.generate()
        stats = self.client.get("/api/stats").get_json()
        for key in ("total_logs", "total_alerts", "anomalies", "severity_counts", "top_ips",
                    "threat_types", "recent_alerts", "timeline"):
            self.assertIn(key, stats)
        self.assertEqual(self.client.get("/api/stats?upload_id=abc").status_code, 400)
        self.assertIn("event_types", self.client.get("/api/filters").get_json())
        self.assertEqual(len(self.client.get("/api/uploads").get_json()["items"]), 1)

    def test_reanalyze_and_delete(self):
        uid = self.generate().get_json()["upload_id"]
        r = self.client.post(f"/api/uploads/{uid}/analyze")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.get_json()["total_alerts"], 0)
        self.assertEqual(self.client.post("/api/uploads/9999/analyze").status_code, 404)
        self.assertEqual(self.client.delete(f"/api/uploads/{uid}").status_code, 200)
        self.assertEqual(list(self.upload_dir.iterdir()), [])
        self.assertEqual(self.client.get("/api/alerts").get_json()["total"], 0)
        self.assertEqual(self.client.delete(f"/api/uploads/{uid}").status_code, 404)

    def test_security_headers(self):
        r = self.client.get("/api/stats")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_wrong_method_returns_json_405(self):
        r = self.client.get("/api/upload")
        self.assertEqual(r.status_code, 405)
        self.assertIn("error", r.get_json())

    def test_test_console_page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"SOC Log Analyzer", r.data)


if __name__ == "__main__":
    unittest.main()