"""Stage 2 tests. They use a temporary database, so your real data is never touched."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from database import db
from database.db import DatabaseError


class Stage2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = patch.object(config, "DATABASE_PATH", Path(self.tmp.name) / "test.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        db.init_db()

    def _make_upload(self):
        return db.execute(
            "INSERT INTO uploads (original_name, stored_name, file_type) VALUES (?,?,?)",
            ("a.csv", "x_a.csv", "csv"),
        )

    def _make_alert(self, upload_id, status="New", severity="HIGH"):
        return db.execute(
            "INSERT INTO alerts (upload_id, threat_type, severity, detection_method, status) "
            "VALUES (?,?,?,?,?)",
            (upload_id, "Brute Force", severity, "RULE", status),
        )

    def test_all_tables_created(self):
        expected = {"users", "uploads", "logs", "alerts", "threat_events", "analysis_results"}
        self.assertTrue(expected.issubset(set(db.list_tables())))

    def test_init_is_idempotent(self):
        db.init_db()
        db.init_db()   # must not raise

    def test_insert_and_read_log(self):
        uid = self._make_upload()
        db.execute("INSERT INTO logs (upload_id, source_ip, username) VALUES (?,?,?)",
                   (uid, "10.0.0.5", "alice"))
        row = db.query_one("SELECT * FROM logs WHERE source_ip = ?", ("10.0.0.5",))
        self.assertEqual(row["username"], "alice")
        self.assertEqual(row["severity"], "NONE")      # default
        self.assertEqual(row["is_anomaly"], 0)         # default

    def test_alert_default_status_is_new(self):
        aid = self._make_alert(self._make_upload())
        self.assertEqual(db.query_one("SELECT status FROM alerts WHERE id=?", (aid,))["status"], "New")

    def test_invalid_status_rejected(self):
        with self.assertRaises(DatabaseError):
            self._make_alert(self._make_upload(), status="Banana")

    def test_invalid_severity_rejected(self):
        with self.assertRaises(DatabaseError):
            self._make_alert(self._make_upload(), severity="EXTREME")

    def test_foreign_key_enforced(self):
        with self.assertRaises(DatabaseError):
            self._make_alert(upload_id=9999)           # upload 9999 doesn't exist

    def test_cascade_delete(self):
        uid = self._make_upload()
        self._make_alert(uid)
        db.execute("DELETE FROM uploads WHERE id = ?", (uid,))
        self.assertEqual(db.query_one("SELECT COUNT(*) AS c FROM alerts")["c"], 0)

    def test_threat_event_links_alert_and_log(self):
        uid = self._make_upload()
        log_id = db.execute("INSERT INTO logs (upload_id, source_ip) VALUES (?,?)", (uid, "1.2.3.4"))
        aid = self._make_alert(uid)
        db.execute("INSERT INTO threat_events (alert_id, log_id, rule_name) VALUES (?,?,?)",
                   (aid, log_id, "brute_force"))
        row = db.query_one(
            "SELECT l.source_ip FROM threat_events t JOIN logs l ON l.id = t.log_id WHERE t.alert_id=?",
            (aid,))
        self.assertEqual(row["source_ip"], "1.2.3.4")

    def test_sql_injection_is_harmless(self):
        db.create_user("alice", "StrongPass123")
        evil = "x'; DROP TABLE users; --"
        self.assertIsNone(db.get_user(evil))           # treated as plain text
        self.assertIn("users", db.list_tables())       # table still exists
        self.assertIsNotNone(db.get_user("alice"))

    def test_execute_many(self):
        uid = self._make_upload()
        rows = [(uid, f"10.0.0.{i}") for i in range(100)]
        db.execute_many("INSERT INTO logs (upload_id, source_ip) VALUES (?,?)", rows)
        self.assertEqual(db.query_one("SELECT COUNT(*) AS c FROM logs")["c"], 100)

    def test_user_password_is_hashed_and_verifiable(self):
        db.create_user("bob_analyst", "MyPassword99")
        user = db.get_user("bob_analyst")
        self.assertNotIn("MyPassword99", user["password_hash"])
        self.assertTrue(db.verify_user("bob_analyst", "MyPassword99"))
        self.assertFalse(db.verify_user("bob_analyst", "wrong-password"))
        self.assertFalse(db.verify_user("nobody", "whatever123"))

    def test_user_validation(self):
        with self.assertRaises(ValueError):
            db.create_user("ab", "StrongPass123")      # username too short
        with self.assertRaises(ValueError):
            db.create_user("validname", "short")       # password too short
        with self.assertRaises(ValueError):
            db.create_user("validname", "StrongPass123", role="hacker")

    def test_duplicate_username_rejected(self):
        db.create_user("carol", "StrongPass123")
        with self.assertRaises(DatabaseError):
            db.create_user("carol", "AnotherPass123")


if __name__ == "__main__":
    unittest.main()