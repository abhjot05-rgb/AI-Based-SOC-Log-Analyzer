"""Stage 5 tests: rule-based detection engine."""
import copy
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import config
from database import db
from detection import rule_engine
from detection.common import TS_FORMAT, find_bursts, prepare_events
from generators import sample_logs as sl
from parser import ingest
from parser.csv_parser import parse_csv
from parser.linux_parser import parse_linux_auth

BASE = datetime(2026, 1, 15, 10, 0, 0)      # 10:00 = normal business hours
START = datetime(2026, 1, 15)
NOW = datetime(2026, 6, 1)
EXTERNAL = ("203.0.113.", "198.51.100.")

# Explicit settings so these tests do not depend on edits to config.py
TEST_CFG = {
    "brute_force": {"enabled": True, "failed_attempts_threshold": 5,
                    "time_window_seconds": 120, "success_check_seconds": 300},
    "port_scan": {"enabled": True, "unique_ports_threshold": 15, "time_window_seconds": 60},
    "suspicious_login": {"enabled": True, "off_hours_enabled": True, "off_hours_start": 22,
                         "off_hours_end": 6, "multi_ip_enabled": True,
                         "max_distinct_ips_per_user": 3, "time_window_seconds": 3600},
    "account_activity": {"enabled": True, "event_ids": [4720, 4722, 4724, 4725, 4740],
                         "event_types": ["account_created", "account_enabled", "password_reset",
                                         "account_disabled", "account_lockout"],
                         "repeat_threshold": 3, "time_window_seconds": 300},
    "privilege_activity": {"enabled": True, "event_ids": [4672, 4728, 4732, 4756],
                           "event_types": ["privilege_assigned", "group_member_added", "sudo_command"],
                           "repeat_threshold": 2, "time_window_seconds": 300},
    "suspicious_ip": {"enabled": True, "suspicious_event_threshold": 10,
                      "time_window_seconds": 600,
                      "event_types": ["login_failure", "firewall_block", "account_lockout"],
                      "suppress_if_covered": True},
}


# ---------- helpers ----------
def E(offset=0, **kw):
    """One log event, `offset` seconds after BASE. Unspecified fields are None."""
    row = {"timestamp": (BASE + timedelta(seconds=offset)).strftime(TS_FORMAT),
           "source_ip": None, "destination_ip": None, "username": None, "event_id": None,
           "event_type": "unknown", "destination_port": None, "status": None,
           "message": None, "raw_log": None}
    row.update(kw)
    return row


def run(rows, **changes):
    cfg = copy.deepcopy(TEST_CFG)
    for rule, values in changes.items():
        cfg[rule].update(values)
    return rule_engine.run_rules(rows, cfg)


def of(result, rule):
    return [f for f in result.findings if f.rule_name == rule]


def failures(n, ip="203.0.113.9", user="admin", step=1, start=0):
    return [E(start + i * step, source_ip=ip, username=user,
              event_type="login_failure", event_id=4625) for i in range(n)]


def scan(ports, step=1, ip="203.0.113.7"):
    return [E(i * step, source_ip=ip, destination_ip="10.0.0.10", destination_port=p,
              event_type="firewall_block", status="blocked") for i, p in enumerate(ports)]


def login(offset, user="alice", ip="203.0.113.5"):
    return E(offset, source_ip=ip, username=user, event_type="login_success", event_id=4624)


def acct(offset, etype="account_created", user="tmp1", ip="192.168.1.5"):
    return E(offset, source_ip=ip, username=user, event_type=etype)


def blocks(n, step=30, ip="203.0.113.50"):
    return [E(i * step, source_ip=ip, destination_port=445,
              event_type="firewall_block", status="blocked") for i in range(n)]


def bursts_for(offsets, window, threshold, distinct=None):
    events, _ = prepare_events([E(o, destination_port=p) for o, p in offsets])
    key = (lambda e: e["destination_port"]) if distinct else None
    return find_bursts(events, window, threshold, key)


# ---------- sliding window ----------
class FindBurstsTests(unittest.TestCase):
    def test_threshold_is_exclusive(self):
        self.assertEqual(bursts_for([(i, 1) for i in range(5)], 120, 5), [])
        self.assertEqual(bursts_for([(i, 1) for i in range(6)], 120, 5), [(0, 5)])

    def test_overlapping_windows_merge_into_one(self):
        self.assertEqual(bursts_for([(i, 1) for i in range(30)], 10, 5), [(0, 29)])

    def test_separate_bursts_stay_separate(self):
        offsets = [(i, 1) for i in range(6)] + [(1000 + i, 1) for i in range(6)]
        self.assertEqual(len(bursts_for(offsets, 120, 5)), 2)

    def test_distinct_counting(self):
        self.assertEqual(bursts_for([(i, 80) for i in range(20)], 120, 5, distinct=True), [])
        self.assertEqual(bursts_for([(i, i + 1) for i in range(6)], 120, 5, distinct=True), [(0, 5)])


# ---------- brute force ----------
class BruteForceTests(unittest.TestCase):
    def test_threshold_is_more_than_five(self):
        self.assertEqual(of(run(failures(5)), "brute_force"), [])
        self.assertEqual(len(of(run(failures(6)), "brute_force")), 1)

    def test_slow_attempts_not_detected(self):
        self.assertEqual(of(run(failures(6, step=100)), "brute_force"), [])

    def test_finding_details(self):
        f = of(run(failures(8)), "brute_force")[0]
        self.assertEqual(f.threat_type, "Brute Force")
        self.assertEqual(f.source_ip, "203.0.113.9")
        self.assertEqual(f.username, "admin")
        self.assertEqual(f.indicators["failed_count"], 8)
        self.assertFalse(f.indicators["success_after"])
        self.assertIn("8 failed login attempts", f.reason)
        self.assertEqual(f.event_count, 8)
        self.assertEqual(len(f.log_ids), 8)
        self.assertEqual(f.start_time, "2026-01-15 10:00:00")
        self.assertEqual(f.end_time, "2026-01-15 10:00:07")
        self.assertTrue(f.recommended_steps)

    def test_success_after_attack_is_flagged(self):
        ok = dict(source_ip="203.0.113.9", username="admin", event_type="login_success")
        f = of(run(failures(7) + [E(60, **ok)]), "brute_force")[0]
        self.assertTrue(f.indicators["success_after"])
        self.assertIn("successful login", f.reason.lower())
        self.assertEqual(f.event_count, 8)
        late = of(run(failures(7) + [E(2000, **ok)]), "brute_force")[0]
        self.assertFalse(late.indicators["success_after"])

    def test_each_ip_is_separate(self):
        rows = failures(6, ip="203.0.113.1") + failures(6, ip="203.0.113.2")
        ips = {f.source_ip for f in of(run(rows), "brute_force")}
        self.assertEqual(ips, {"203.0.113.1", "203.0.113.2"})


# ---------- port scan ----------
class PortScanTests(unittest.TestCase):
    def test_many_distinct_ports_detected(self):
        self.assertEqual(of(run(scan(range(1, 11))), "port_scan"), [])
        f = of(run(scan(range(1, 21))), "port_scan")[0]
        self.assertEqual(f.indicators["unique_ports"], 20)
        self.assertIn("20 distinct ports", f.reason)
        self.assertEqual(f.source_ip, "203.0.113.7")

    def test_same_port_repeated_is_not_a_scan(self):
        self.assertEqual(of(run(scan([80] * 30)), "port_scan"), [])

    def test_slow_scan_not_detected(self):
        self.assertEqual(of(run(scan(range(1, 21), step=10)), "port_scan"), [])


# ---------- suspicious login ----------
class SuspiciousLoginTests(unittest.TestCase):
    def test_off_hours_login(self):
        found = of(run([login(-8 * 3600)]), "suspicious_login")      # 02:00
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].indicators["kind"], "off_hours")
        self.assertTrue(found[0].indicators["external_source"])
        self.assertEqual(of(run([login(0)]), "suspicious_login"), [])  # 10:00

    def test_off_hours_boundaries(self):
        self.assertEqual(of(run([login(-4 * 3600)]), "suspicious_login"), [])      # 06:00 is normal
        self.assertEqual(len(of(run([login(12 * 3600)]), "suspicious_login")), 1)  # 22:00 is off-hours

    def test_one_night_of_logins_is_one_finding(self):
        rows = [login(-8 * 3600 + i * 600) for i in range(3)]
        found = of(run(rows), "suspicious_login")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].indicators["login_count"], 3)

    def test_user_from_many_ips(self):
        def rows(n):
            return [login(i * 300, ip=f"203.0.113.{i + 1}") for i in range(n)]
        self.assertEqual(of(run(rows(3)), "suspicious_login"), [])
        found = of(run(rows(4)), "suspicious_login")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].indicators["kind"], "multiple_ips")
        self.assertEqual(found[0].indicators["distinct_ips"], 4)


# ---------- account and privilege ----------
class AccountPrivilegeTests(unittest.TestCase):
    def test_account_activity_threshold(self):
        self.assertEqual(of(run([acct(0), acct(30)]), "account_activity"), [])
        found = of(run([acct(0), acct(30), acct(60)]), "account_activity")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].indicators["event_count"], 3)
        self.assertIn("account-related", found[0].reason)

    def test_privilege_matches_event_type_and_event_id(self):
        sudo = [E(0, username="bob", event_type="sudo_command"),
                E(30, username="bob", event_type="sudo_command")]
        by_id = [E(0, username="carol", event_id=4672), E(20, username="carol", event_id=4728)]
        self.assertEqual(len(of(run(sudo), "privilege_activity")), 1)
        self.assertEqual(len(of(run(by_id), "privilege_activity")), 1)
        self.assertEqual(of(run(by_id[:1]), "privilege_activity"), [])

    def test_missing_information_is_safe(self):
        result = run([E(i) for i in range(10)])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.events_checked, 10)


# ---------- suspicious IP ----------
class SuspiciousIpTests(unittest.TestCase):
    def test_threshold_is_more_than_ten(self):
        self.assertEqual(of(run(blocks(10)), "suspicious_ip"), [])
        found = of(run(blocks(11)), "suspicious_ip")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].indicators["event_count"], 11)

    def test_suppressed_when_brute_force_explains_it(self):
        result = run(failures(12))
        self.assertEqual(len(of(result, "brute_force")), 1)
        self.assertEqual(of(result, "suspicious_ip"), [])
        self.assertEqual(result.suppressed, 1)
        result = run(failures(12), suspicious_ip={"suppress_if_covered": False})
        self.assertEqual(len(of(result, "suspicious_ip")), 1)
        self.assertEqual(result.suppressed, 0)


# ---------- engine ----------
class EngineTests(unittest.TestCase):
    def test_disabled_rule_is_skipped(self):
        result = run(failures(8), brute_force={"enabled": False})
        self.assertEqual(of(result, "brute_force"), [])
        self.assertIn("brute_force", result.rules_disabled)

    def test_invalid_settings_rejected(self):
        for bad in ("abc", 0, -5, True, 2.5):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError) as ctx:
                    run(failures(8), brute_force={"failed_attempts_threshold": bad})
                self.assertIn("brute_force", str(ctx.exception))

    def test_unreadable_timestamps_are_skipped(self):
        result = run([E(0), {"timestamp": "garbage"}, {"timestamp": None}])
        self.assertEqual(result.events_checked, 1)
        self.assertEqual(result.events_skipped, 2)

    def test_empty_input(self):
        result = run([])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.events_checked, 0)

    def test_findings_sorted_by_time(self):
        rows = failures(6, ip="203.0.113.1", start=500) + scan(range(1, 21))
        starts = [f.start_time for f in run(rows).findings]
        self.assertEqual(len(starts), 2)
        self.assertEqual(starts, sorted(starts))

    def test_real_config_works(self):
        result = rule_engine.run_rules(failures(8))     # uses config.DETECTION_RULES
        self.assertEqual(len(of(result, "brute_force")), 1)


# ---------- generated sample data ----------
class GeneratedDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        gen = sl.generate_all(out_dir=Path(self.tmp.name), seed=42, normal_events=800, start=START)
        self.files, self.injected = gen["files"], gen["injected"]

    def test_all_injected_scenarios_are_detected(self):
        result = rule_engine.run_rules(parse_csv(self.files["csv"]).records)
        inj = self.injected
        self.assertGreaterEqual(len(of(result, "brute_force")), inj["brute_force"])
        self.assertGreaterEqual(len(of(result, "port_scan")), inj["port_scan"])
        self.assertGreaterEqual(len(of(result, "account_activity")), inj["account_activity"])
        self.assertGreaterEqual(len(of(result, "privilege_activity")), inj["privilege_activity"])
        self.assertGreaterEqual(len(of(result, "suspicious_ip")), inj["suspicious_ip"])
        kinds = Counter(f.indicators["kind"] for f in of(result, "suspicious_login"))
        self.assertGreaterEqual(kinds["off_hours"], inj["off_hours_login"])
        self.assertGreaterEqual(kinds["multiple_ips"], inj["multi_ip_login"])

    def test_normal_users_do_not_trigger_network_rules(self):
        result = rule_engine.run_rules(parse_csv(self.files["csv"]).records)
        for rule in ("brute_force", "port_scan", "suspicious_ip"):
            for f in of(result, rule):
                self.assertTrue(f.source_ip.startswith(EXTERNAL), f"{rule}: {f.source_ip}")

    def test_linux_auth_log_detection(self):
        records = parse_linux_auth(self.files["linux_auth"], now=NOW).records
        result = rule_engine.run_rules(records)
        self.assertGreaterEqual(len(of(result, "brute_force")), self.injected["brute_force"])
        self.assertEqual(of(result, "port_scan"), [])       # auth.log has no network events


class DatabaseIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = patch.object(config, "DATABASE_PATH", Path(self.tmp.name) / "test.db")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        db.init_db()

    def test_finding_log_ids_are_real_database_rows(self):
        gen = sl.generate_all(out_dir=Path(self.tmp.name), seed=42, normal_events=200, start=START)
        summary = ingest.ingest_file(gen["files"]["csv"])
        logs = rule_engine.load_logs_from_db(summary["upload_id"])
        result = rule_engine.run_rules(logs)
        real_ids = {row["id"] for row in logs}
        self.assertGreater(len(result.findings), 0)
        for f in result.findings:
            self.assertTrue(set(f.log_ids) <= real_ids)
            self.assertEqual(f.event_count, len(f.log_ids))


if __name__ == "__main__":
    unittest.main()