"""Stage 7 tests: threat scoring, severity levels and explanations."""
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import config
from analysis.threat_scoring import (_ramp, detection_method_for, score_finding, score_findings,
                                     severity_counts, severity_for_score,
                                     validate_scoring_settings)
from detection import rule_engine
from detection.common import TS_FORMAT, Finding
from generators import sample_logs as sl
from ml.anomaly_detector import build_ml_findings, detect_anomalies
from parser.csv_parser import parse_csv

BASE = datetime(2026, 1, 15, 10, 0, 0)


def F(rule="brute_force", threat="Brute Force", ip="203.0.113.9", n=12, secs=55,
      username="admin", indicators=None, ids=None):
    return Finding(
        rule_name=rule, threat_type=threat,
        start_time=BASE.strftime(TS_FORMAT),
        end_time=(BASE + timedelta(seconds=secs)).strftime(TS_FORMAT),
        reason="test finding", source_ip=ip, username=username,
        log_ids=ids if ids is not None else list(range(1, n + 1)),
        event_count=n, indicators=indicators if indicators is not None else {})


def BF(failed=12, **extra):
    ind = {"failed_count": failed, "unique_accounts": 1, "threshold": 5, "success_after": False}
    ind.update(extra)
    return F(n=failed, indicators=ind)


def comp(result, key):
    return next(c for c in result.components if c.key == key)


class SeverityTests(unittest.TestCase):
    def test_band_boundaries(self):
        expected = {0: "LOW", 29: "LOW", 30: "MEDIUM", 59: "MEDIUM",
                    60: "HIGH", 79: "HIGH", 80: "CRITICAL", 100: "CRITICAL"}
        for score, name in expected.items():
            self.assertEqual(severity_for_score(score), name, score)

    def test_out_of_range_scores_are_clamped(self):
        self.assertEqual(severity_for_score(-5), "LOW")
        self.assertEqual(severity_for_score(250), "CRITICAL")

    def test_bands_come_from_config(self):
        bands = {"LOW": (0, 49), "MEDIUM": (50, 69), "HIGH": (70, 89), "CRITICAL": (90, 100)}
        with patch.object(config, "SEVERITY_BANDS", bands):
            self.assertEqual(severity_for_score(60), "MEDIUM")


class RampTests(unittest.TestCase):
    def test_ramp(self):
        self.assertEqual(_ramp(0, 5, 10), 0.0)
        self.assertEqual(_ramp(5, 5, 10), 0.0)
        self.assertEqual(_ramp(7.5, 5, 10), 0.5)
        self.assertEqual(_ramp(10, 5, 10), 1.0)
        self.assertEqual(_ramp(99, 5, 10), 1.0)


class ScoringTests(unittest.TestCase):
    def test_brute_force_breakdown(self):
        r = score_finding(BF(12))
        points = {c.key: c.points for c in r.components}
        self.assertEqual(points, {"base": 25, "attempts": 14, "frequency": 4, "accounts": 0,
                                  "ml": 0, "ip_behavior": 6, "escalation": 0})
        self.assertEqual(r.score, 49)
        self.assertEqual(r.severity, "MEDIUM")
        self.assertEqual(r.detection_method, "RULE")
        self.assertFalse(r.capped)

    def test_success_after_attack_escalates(self):
        r = score_finding(BF(12, success_after=True))
        self.assertEqual(comp(r, "escalation").points, 20)
        self.assertEqual(r.score, 69)
        self.assertEqual(r.severity, "HIGH")

    def test_more_failures_score_higher(self):
        low, mid, high = (score_finding(BF(n)).score for n in (6, 12, 30))
        self.assertLess(low, mid)
        self.assertLess(mid, high)

    def test_ml_points(self):
        def ctx(score):
            return {"max_anomaly_score": score, "anomalous_events": 4, "scored_events": 12}
        self.assertEqual(comp(score_finding(BF(), ctx(0.75)), "ml").points, 15)
        self.assertEqual(comp(score_finding(BF(), ctx(0.50)), "ml").points, 0)
        self.assertEqual(comp(score_finding(BF(), ctx(0.40)), "ml").points, 0)
        mid = comp(score_finding(BF(), ctx(0.65)), "ml").points
        self.assertTrue(0 < mid < 15)
        none = score_finding(BF(), None)
        self.assertEqual(comp(none, "ml").points, 0)
        self.assertIn("not available", comp(none, "ml").detail)
        self.assertGreater(score_finding(BF(), ctx(0.75)).score, none.score)

    def test_internal_source_gets_no_external_points(self):
        external = score_finding(BF())
        internal = score_finding(F(ip="192.168.1.20", n=12,
                                   indicators={"failed_count": 12, "unique_accounts": 1,
                                               "threshold": 5}))
        self.assertEqual(comp(external, "ip_behavior").points, 6)
        self.assertEqual(comp(internal, "ip_behavior").points, 0)

    def test_repeat_ip_adds_points(self):
        scan = F(rule="port_scan", threat="Port Scan", n=30, secs=20, username=None,
                 indicators={"unique_ports": 30, "threshold": 15, "unique_targets": 1,
                             "allowed_ports": []})
        alone = score_findings([BF(12)])[0]
        paired = score_findings([BF(12), scan])
        self.assertEqual(comp(alone, "ip_behavior").points, 6)
        self.assertEqual(comp(paired[0], "ip_behavior").points, 12)
        self.assertIn("2 findings", comp(paired[0], "ip_behavior").detail)

    def test_score_is_capped_at_100(self):
        ind = {"failed_count": 100, "unique_accounts": 10, "threshold": 5, "success_after": True}
        ctx = {"max_anomaly_score": 0.9, "anomalous_events": 50, "scored_events": 100}
        r = score_finding(F(n=100, secs=10, indicators=ind), ctx, ip_finding_count=2)
        self.assertEqual(sum(c.points for c in r.components), 112)
        self.assertEqual(r.score, 100)
        self.assertTrue(r.capped)
        self.assertEqual(r.severity, "CRITICAL")
        self.assertIn("capped", r.explanation)

    def test_components_add_up_to_the_score(self):
        for f in (BF(6), BF(12), BF(12, success_after=True), BF(40)):
            r = score_finding(f)
            self.assertEqual(sum(c.points for c in r.components), r.score)
            self.assertEqual(r.severity, severity_for_score(r.score))

    def test_explanation_text(self):
        r = score_finding(BF(12))
        self.assertIn("Threat score 49/100", r.explanation)
        self.assertIn("MEDIUM", r.explanation)
        self.assertIn("band 30-59", r.explanation)
        self.assertIn("12 failed login attempts against a threshold of 5 (+14)", r.explanation)
        self.assertIn("No points from:", r.explanation)

    def test_missing_data_is_safe(self):
        for rule in ("brute_force", "port_scan", "suspicious_login", "account_activity",
                     "privilege_activity", "suspicious_ip", "ml_anomaly", "something_new"):
            f = F(rule=rule, threat="Unknown Threat", ip=None, username=None, n=0, indicators={})
            f.start_time, f.end_time = "garbage", None
            r = score_finding(f)
            self.assertTrue(0 <= r.score <= 100, rule)
            self.assertIn(r.severity, config.SEVERITY_BANDS)
            self.assertTrue(r.explanation)

    def test_escalation_indicators_per_threat_type(self):
        cases = [
            (F(rule="suspicious_login", threat="Suspicious Login", n=1,
               indicators={"kind": "off_hours", "external_source": True}), 10),
            (F(rule="suspicious_login", threat="Suspicious Login", n=5,
               indicators={"kind": "multiple_ips", "distinct_ips": 5, "external_sources": 5}), 10),
            (F(rule="account_activity", threat="Suspicious Account Activity", n=5,
               indicators={"accounts_created": 1, "affected_accounts": 1}), 10),
            (F(rule="privilege_activity", threat="Privilege Escalation Activity", n=3,
               indicators={"privilege_assigned_count": 1, "group_change_count": 1}), 10),
            (F(rule="port_scan", threat="Port Scan", n=30,
               indicators={"unique_ports": 30, "allowed_ports": [22, 80]}), 8),
        ]
        for finding, expected in cases:
            r = score_finding(finding)
            self.assertEqual(comp(r, "escalation").points, expected, finding.rule_name)


class SettingsTests(unittest.TestCase):
    def test_invalid_settings_rejected(self):
        bad = [{"unknown_key": 1},
               {"ml_low": 0.9, "ml_high": 0.5},
               {"base_scores": {"Brute Force": 150}},
               {"max_points": {"ml": -1}},
               {"max_points": "x"},
               {"ip_points": {"bogus": 1}},
               {"attempts_full_at_multiple": 1},
               {"frequency_low_per_minute": 30, "frequency_high_per_minute": 2},
               {"default_base_score": True}]
        for settings in bad:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    validate_scoring_settings(settings)
                with self.assertRaises(ValueError):
                    score_finding(BF(), settings=settings)

    def test_custom_settings_change_the_score(self):
        base = score_finding(BF(12)).score
        custom = score_finding(BF(12), settings={"base_scores": {"Brute Force": 40}}).score
        self.assertEqual(custom - base, 15)
        self.assertEqual(validate_scoring_settings(config.SCORING_SETTINGS)["ml_high"], 0.75)


class MethodTests(unittest.TestCase):
    def test_detection_method_labels(self):
        ml_only = F(rule="ml_anomaly", threat="Anomalous Activity",
                    indicators={"ml_only": True, "anomalous_events": 3, "max_anomaly_score": 0.62})
        self.assertEqual(detection_method_for(ml_only, None), "ML")
        self.assertEqual(detection_method_for(BF(), {"anomalous_events": 2}), "RULE+ML")
        self.assertEqual(detection_method_for(BF(), {"anomalous_events": 0}), "RULE")
        self.assertEqual(detection_method_for(BF(), None), "RULE")
        r = score_finding(ml_only)                       # ML numbers come from its own indicators
        self.assertEqual(r.detection_method, "ML")
        self.assertGreater(comp(r, "ml").points, 0)

    def test_severity_counts(self):
        scores = score_findings([BF(6), BF(12), BF(12, success_after=True), BF(40)])
        counts = severity_counts(scores)
        self.assertEqual(set(counts), set(config.SEVERITY_BANDS))
        self.assertEqual(sum(counts.values()), 4)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        gen = sl.generate_all(out_dir=Path(self.tmp.name), seed=42, normal_events=800,
                              start=datetime(2026, 1, 15))
        logs = parse_csv(gen["files"]["csv"]).records
        for i, rec in enumerate(logs, start=1):
            rec["id"] = i
        rules = rule_engine.run_rules(logs)
        ml = detect_anomalies(logs)
        covered = set()
        for f in rules.findings:
            covered.update(f.log_ids)
        self.findings = rules.findings + build_ml_findings(logs, ml, covered_log_ids=covered)
        self.scores = score_findings(self.findings, ml.by_log_id())

    def test_every_finding_gets_a_valid_score(self):
        self.assertEqual(len(self.scores), len(self.findings))
        self.assertGreater(len(self.findings), 0)
        for sc in self.scores:
            self.assertTrue(0 <= sc.score <= 100)
            self.assertEqual(sc.severity, severity_for_score(sc.score))
            self.assertIn(sc.detection_method, ("RULE", "ML", "RULE+ML"))
            self.assertTrue(sc.explanation)
        self.assertTrue(any(sc.severity != "LOW" for sc in self.scores))

    def test_rule_findings_receive_ml_context(self):
        for f, sc in zip(self.findings, self.scores):
            if f.rule_name == "ml_anomaly":
                self.assertEqual(sc.detection_method, "ML")
            else:
                self.assertIsNotNone(sc.ml_context)

    def test_brute_force_with_success_gets_escalation_points(self):
        for f, sc in zip(self.findings, self.scores):
            if f.rule_name == "brute_force" and f.indicators["success_after"]:
                self.assertEqual(comp(sc, "escalation").points, 20)


if __name__ == "__main__":
    unittest.main()