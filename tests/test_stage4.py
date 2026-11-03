"""Stage 4 tests: normalizer, parsers, format detection and database ingestion."""
import json
import tempfile
import unittest
from collections import Counter
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import config
from database import db
from generators import sample_logs as sl
from parser import ingest
from parser import log_normalizer as ln
from parser.csv_parser import parse_csv
from parser.json_parser import parse_json
from parser.linux_parser import parse_linux_auth
from parser.log_normalizer import ParseError

START = datetime(2026, 1, 15)
NOW = datetime(2026, 6, 1)


class NormalizerTests(unittest.TestCase):
    def test_timestamp_formats(self):
        expected = "2026-01-14 08:03:12"
        cases = {
            "2026-01-14 08:03:12": expected,
            "2026-01-14T08:03:12Z": expected,
            "2026-01-14T08:03:12.1234567Z": expected,       # Windows 7-digit fraction
            "2026-01-14T10:00:00+05:30": "2026-01-14 04:30:00",
            "14/01/2026 08:03:12": expected,
            "01/14/2026 08:03:12": expected,                 # month-first fallback
            1700000000: "2023-11-14 22:13:20",
            "1700000000": "2023-11-14 22:13:20",
        }
        for raw, want in cases.items():
            self.assertEqual(ln.parse_timestamp(raw), want, raw)

    def test_timestamp_invalid(self):
        for bad in ["", None, "-", "garbage", "2026-13-45 99:99:99",
                    "0000-00-00 00:00:00", "1850-01-01 00:00:00"]:
            self.assertIsNone(ln.parse_timestamp(bad), bad)

    def test_clean_ip(self):
        self.assertEqual(ln.clean_ip("10.0.0.1"), "10.0.0.1")
        self.assertEqual(ln.clean_ip("::ffff:10.0.0.1"), "10.0.0.1")
        self.assertEqual(ln.clean_ip("1.2.3.4:5555"), "1.2.3.4")
        self.assertEqual(ln.clean_ip("::1"), "::1")
        for bad in ["999.1.1.1", "-", "", None, "not an ip", "1.2.3"]:
            self.assertIsNone(ln.clean_ip(bad), bad)

    def test_clean_int_ports(self):
        self.assertEqual(ln.clean_int("443", 0, 65535), 443)
        self.assertEqual(ln.clean_int(80.0, 0, 65535), 80)
        for bad in ["70000", "abc", "", "-1", None, True]:
            self.assertIsNone(ln.clean_int(bad, 0, 65535), bad)

    def test_protocol(self):
        for raw, want in [("6", "TCP"), ("udp", "UDP"), ("17", "UDP"), ("icmp", "ICMP"),
                          ("<script>", None), ("", None), (None, None)]:
            self.assertEqual(ln.normalize_protocol(raw), want, raw)

    def test_status(self):
        for raw, want in [("Audit Failure", "failure"), ("Audit Success", "success"),
                          ("BLOCKED", "blocked"), ("Allowed", "allowed"),
                          (None, None), ("weird", "weird")]:
            self.assertEqual(ln.normalize_status(raw), want, raw)

    def test_missing_fields_are_safe(self):
        rec, reason = ln.normalize_row({"timestamp": "2026-01-14 10:00:00"})
        self.assertIsNone(reason)
        for key in ("source_ip", "destination_ip", "username", "event_id", "protocol",
                    "source_port", "destination_port", "action", "status", "message"):
            self.assertIsNone(rec[key], key)
        self.assertEqual(rec["event_type"], "unknown")

    def test_row_without_timestamp_rejected(self):
        rec, reason = ln.normalize_row({"source_ip": "1.1.1.1"})
        self.assertIsNone(rec)
        self.assertTrue(reason)

    def test_aliases_map_to_standard_fields(self):
        rec, _ = ln.normalize_row({
            "Time": "2026-01-14 10:00:00", "SrcIP": "1.2.3.4", "User": "bob",
            "DstPort": "22", "Result": "Failed", "msg": "hi"})
        self.assertEqual(rec["source_ip"], "1.2.3.4")
        self.assertEqual(rec["username"], "bob")
        self.assertEqual(rec["destination_port"], 22)
        self.assertEqual(rec["status"], "failure")
        self.assertEqual(rec["message"], "hi")

    def test_event_type_from_event_id(self):
        rec, _ = ln.normalize_row({"timestamp": "2026-01-14 10:00:00", "EventID": "4625"})
        self.assertEqual(rec["event_type"], "login_failure")
        self.assertEqual(rec["action"], "login")
        self.assertEqual(rec["status"], "failure")
        rec, _ = ln.normalize_row({"timestamp": "2026-01-14 10:00:00", "event_id": 5157})
        self.assertEqual(rec["event_type"], "firewall_block")
        self.assertEqual(rec["status"], "blocked")

    def test_event_type_from_message(self):
        ts = "2026-01-14 10:00:00"
        rec, _ = ln.normalize_row({"timestamp": ts, "message": "Failed logon for bob from 1.2.3.4"})
        self.assertEqual(rec["event_type"], "login_failure")
        rec, _ = ln.normalize_row({"timestamp": ts, "message": "User account x was locked out"})
        self.assertEqual(rec["event_type"], "account_lockout")

    def test_text_is_cleaned_and_truncated(self):
        rec, _ = ln.normalize_row({"timestamp": "2026-01-14 10:00:00", "message": "a\nb\x00c"})
        self.assertEqual(rec["message"], "a b c")
        rec, _ = ln.normalize_row({"timestamp": "2026-01-14 10:00:00", "message": "x" * 5000})
        self.assertEqual(len(rec["message"]), ln.MAX_TEXT_LENGTH)


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        gen = sl.generate_all(out_dir=self.dir, seed=42, normal_events=300, start=START)
        self.files, self.counts = gen["files"], gen["counts"]

    def write(self, name, text, encoding="utf-8"):
        path = self.dir / name
        path.write_bytes(text.encode(encoding))
        return path

    def test_csv_and_json_give_identical_records(self):
        csv_res = parse_csv(self.files["csv"])
        json_res = parse_json(self.files["json"])
        strip = lambda recs: [{k: v for k, v in r.items() if k != "raw_log"} for r in recs]
        self.assertEqual(len(csv_res.records), self.counts["csv"])
        self.assertEqual(csv_res.skipped, 0)
        self.assertEqual(strip(csv_res.records), strip(json_res.records))

    def test_windows_csv_normalization(self):
        win = parse_csv(self.files["windows_csv"])
        generic = parse_csv(self.files["csv"])
        self.assertEqual(win.format_name, "windows_csv")
        self.assertEqual(generic.format_name, "csv")
        self.assertEqual(win.skipped, 0)
        self.assertEqual(len(win.records), self.counts["windows_csv"])
        expected = Counter(r["event_type"] for r in generic.records
                           if r["event_type"] != "sudo_command")   # sudo has no Windows id
        got = Counter(r["event_type"] for r in win.records)
        self.assertEqual(got, expected)
        self.assertNotIn("unknown", got)
        self.assertTrue(all(r["protocol"] in (None, "TCP", "UDP") for r in win.records))

    def test_linux_parser(self):
        res = parse_linux_auth(self.files["linux_auth"], now=NOW)
        generic = parse_csv(self.files["csv"])
        self.assertEqual(res.skipped, 0)
        self.assertEqual(res.ignored, 0)
        self.assertEqual(len(res.records), self.counts["linux_auth"])
        wanted = {"login_failure", "login_success", "logout", "sudo_command",
                  "account_created", "group_member_added", "password_reset"}
        expected = Counter(r["event_type"] for r in generic.records if r["event_type"] in wanted)
        self.assertEqual(Counter(r["event_type"] for r in res.records), expected)
        self.assertTrue(all(r["timestamp"].startswith("2026-") for r in res.records))
        failures = [r for r in res.records if r["event_type"] == "login_failure"]
        self.assertTrue(all(r["source_ip"] and r["destination_port"] == 22 for r in failures))

    def test_csv_bad_rows_counted(self):
        path = self.write("bad.csv",
            "timestamp,source_ip,username,event_type\n"
            "2026-01-14 10:00:00,10.0.0.1,alice,login_success\n"
            "not-a-date,10.0.0.2,bob,login_success\n"
            ",,,\n"
            "2026-01-14 10:05:00,999.9.9.9,carol,login_failure\n")
        res = parse_csv(path)
        self.assertEqual(res.total_rows, 3)
        self.assertEqual(len(res.records), 2)
        self.assertEqual(res.skipped, 1)
        self.assertIn("Row 3", res.errors[0])
        self.assertIsNone(res.records[1]["source_ip"])        # invalid IP -> NULL, row kept

    def test_csv_without_timestamp_column_rejected(self):
        with self.assertRaises(ParseError):
            parse_csv(self.write("a.csv", "foo,bar\n1,2\n"))
        with self.assertRaises(ParseError):
            parse_csv(self.write("b.csv", "source_ip,username\n1.1.1.1,bob\n"))

    def test_csv_semicolon_delimiter_and_bom(self):
        path = self.write("semi.csv",
            "timestamp;source_ip;username;event_type\n"
            "2026-01-14 10:00:00;10.0.0.1;alice;login_success\n", encoding="utf-8-sig")
        res = parse_csv(path)
        self.assertEqual(len(res.records), 1)
        self.assertEqual(res.records[0]["username"], "alice")

    def test_json_wrapped_and_jsonl(self):
        wrapped = self.write("w.json", json.dumps({"events": [
            {"timestamp": "2026-01-14 10:00:00", "source_ip": "10.0.0.1"},
            {"timestamp": "2026-01-14 10:00:05", "source_ip": "10.0.0.2"}]}))
        self.assertEqual(len(parse_json(wrapped).records), 2)

        lines = self.write("l.json",
            '{"timestamp": "2026-01-14 10:00:00", "username": "a"}\n'
            '{"timestamp": "2026-01-14 10:00:01", "username": "b"}\n')
        res = parse_json(lines)
        self.assertEqual(res.format_name, "jsonl")
        self.assertEqual(len(res.records), 2)

        mixed = self.write("m.json", json.dumps([
            {"timestamp": "2026-01-14 10:00:00"}, "oops", 5]))
        res = parse_json(mixed)
        self.assertEqual((len(res.records), res.skipped), (1, 2))

    def test_json_invalid_rejected(self):
        with self.assertRaises(ParseError):
            parse_json(self.write("bad.json", "this is not json"))
        with self.assertRaises(ParseError):
            parse_json(self.write("odd.json", '{"a": 1}'))

    def test_json_nested_fields(self):
        path = self.write("n.json", json.dumps([{
            "@timestamp": "2026-01-14T10:00:00Z",
            "source": {"ip": "10.0.0.9"},
            "event": {"code": 4625},
            "user": {"name": "bob"}}]))
        rec = parse_json(path).records[0]
        self.assertEqual(rec["source_ip"], "10.0.0.9")
        self.assertEqual(rec["event_id"], 4625)
        self.assertEqual(rec["username"], "bob")
        self.assertEqual(rec["event_type"], "login_failure")

    def test_linux_unknown_lines(self):
        path = self.write("auth.log",
            "Jan 14 01:00:00 server01 sshd[1]: Failed password for root from 203.0.113.5 port 4444 ssh2\n"
            "Jan 14 01:00:05 server01 CRON[22]: pam_unix(cron:session): session opened for user root\n"
            "this is not a log line\n")
        res = parse_linux_auth(path, now=NOW)
        self.assertEqual(len(res.records), 1)
        self.assertEqual(res.ignored, 1)       # valid syslog, not a tracked event
        self.assertEqual(res.skipped, 1)       # not syslog at all
        self.assertEqual(res.total_rows, 3)

    def test_detect_format(self):
        self.assertEqual(ingest.detect_format(self.files["csv"]), "csv")
        self.assertEqual(ingest.detect_format(self.files["json"]), "json")
        self.assertEqual(ingest.detect_format(self.files["windows_csv"]), "csv")
        self.assertEqual(ingest.detect_format(self.files["linux_auth"]), "linux_auth")
        self.assertEqual(ingest.detect_format(self.write("x.txt", '{"timestamp": "2026-01-01"}')), "json")
        with self.assertRaises(ParseError):
            ingest.detect_format(self.write("y.txt", "hello world"))

    def test_row_limit_enforced(self):
        rows = "".join(f"2026-01-14 10:00:{i:02d},10.0.0.1\n" for i in range(10))
        path = self.write("big.csv", "timestamp,source_ip\n" + rows)
        with patch.object(ln, "MAX_ROWS_PER_FILE", 5):
            with self.assertRaises(ParseError):
                parse_csv(path)


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = patch.object(config, "DATABASE_PATH", Path(self.tmp.name) / "test.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        db.init_db()

    def test_ingest_all_four_formats(self):
        gen = sl.generate_all(out_dir=self.dir, seed=42, normal_events=150, start=START)
        files = gen["files"]
        summaries = [ingest.ingest_file(files[k])
                     for k in ("csv", "json", "windows_csv", "linux_auth")]
        self.assertEqual({s["format"] for s in summaries},
                         {"csv", "json", "windows_csv", "linux_auth"})
        self.assertEqual(db.query_one("SELECT COUNT(*) AS c FROM uploads")["c"], 4)
        for s in summaries:
            stored = db.query_one("SELECT COUNT(*) AS c FROM logs WHERE upload_id=?",
                                  (s["upload_id"],))["c"]
            self.assertEqual(stored, s["stored"])
            self.assertGreater(stored, 0)

    def test_hostile_values_are_stored_as_plain_text(self):
        path = self.dir / "evil.csv"
        path.write_text(
            "timestamp,source_ip,username,event_type,message\n"
            "2026-01-14 10:00:00,10.0.0.1,\"x'; DROP TABLE logs; --\",login_failure,"
            "<script>alert(1)</script>\n", encoding="utf-8")
        summary = ingest.ingest_file(path)
        row = db.query_one("SELECT * FROM logs WHERE upload_id=?", (summary["upload_id"],))
        self.assertEqual(row["username"], "x'; DROP TABLE logs; --")
        self.assertEqual(row["message"], "<script>alert(1)</script>")
        self.assertEqual(row["severity"], "NONE")
        self.assertIn("logs", db.list_tables())
        self.assertIn("login_failure", row["raw_log"])

    def test_file_with_no_valid_rows_creates_nothing(self):
        path = self.dir / "empty.csv"
        path.write_text("timestamp,source_ip\n", encoding="utf-8")
        with self.assertRaises(ParseError):
            ingest.ingest_file(path)
        self.assertEqual(db.query_one("SELECT COUNT(*) AS c FROM uploads")["c"], 0)


if __name__ == "__main__":
    unittest.main()