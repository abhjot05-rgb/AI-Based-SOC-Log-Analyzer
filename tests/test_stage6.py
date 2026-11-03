"""Stage 6 tests: feature engineering, Isolation Forest wrapper, anomaly pipeline."""
import copy
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from detection import rule_engine
from detection.common import TS_FORMAT
from generators import sample_logs as sl
from ml.anomaly_detector import (ANOMALY_THREAT, ML_RULE_NAME, build_ml_findings,
                                 detect_anomalies, ml_context_for_finding)
from ml.feature_engineering import FEATURE_NAMES, build_features
from ml.model import AnomalyModel, validate_settings
from parser.csv_parser import parse_csv

BASE = datetime(2026, 1, 15, 10, 0, 0)
START = datetime(2026, 1, 15)


def L(offset=0, **kw):
    """One log event, `offset` seconds after BASE."""
    row = {"timestamp": (BASE + timedelta(seconds=offset)).strftime(TS_FORMAT),
           "source_ip": None, "destination_ip": None, "username": None, "event_id": None,
           "event_type": "unknown", "destination_port": None, "status": None}
    row.update(kw)
    return row


def generated_logs(tmp, seed=42, events=800):
    """Sample CSV -> parsed records, each with a stand-in id."""
    gen = sl.generate_all(out_dir=Path(tmp), seed=seed, normal_events=events, start=START)
    logs = parse_csv(gen["files"]["csv"]).records
    for i, rec in enumerate(logs, start=1):
        rec["id"] = i
    return logs


class FeatureTests(unittest.TestCase):
    def test_columns_alignment_and_no_nan(self):
        logs = [L(i, source_ip="10.0.0.1", destination_port=80) for i in range(5)]
        features, skipped = build_features(logs)
        self.assertEqual(list(features.columns), FEATURE_NAMES)
        self.assertEqual(len(features), 5)
        self.assertEqual(skipped, 0)
        self.assertTrue(np.isfinite(features.to_numpy()).all())

    def test_recent_window_counts(self):
        logs = [L(i, source_ip="10.0.0.1") for i in range(10)]
        features, _ = build_features(logs, window_seconds=300)
        np.testing.assert_allclose(features["ip_events_recent"].to_numpy(),
                                   np.log1p(np.arange(1, 11)))
        np.testing.assert_allclose(features["ip_events_total"].to_numpy(), np.log1p(10))

    def test_window_excludes_old_events(self):
        logs = [L(0, source_ip="10.0.0.1"), L(1000, source_ip="10.0.0.1")]
        features, _ = build_features(logs, window_seconds=300)
        np.testing.assert_allclose(features["ip_events_recent"].to_numpy(), np.log1p(1))

    def test_external_ip_flag(self):
        logs = [L(0, source_ip="192.168.1.10"), L(1, source_ip="203.0.113.5"), L(2)]
        features, _ = build_features(logs)
        self.assertEqual(features["is_external_ip"].tolist(), [0.0, 1.0, 0.0])

    def test_failure_flag(self):
        logs = [L(0, event_type="login_failure"), L(1, status="blocked"),
                L(2, event_type="login_success", status="success")]
        features, _ = build_features(logs)
        self.assertEqual(features["is_failure"].tolist(), [1.0, 1.0, 0.0])

    def test_unreadable_timestamps_skipped(self):
        logs = [L(0), {"timestamp": "garbage"}, {"timestamp": None}, L(1)]
        features, skipped = build_features(logs)
        self.assertEqual(skipped, 2)
        self.assertEqual(list(features.index), [0, 3])

    def test_empty_input(self):
        features, skipped = build_features([])
        self.assertEqual(len(features), 0)
        self.assertEqual(list(features.columns), FEATURE_NAMES)
        self.assertEqual(skipped, 0)

    def test_rows_with_only_a_timestamp_are_safe(self):
        features, _ = build_features([L(i) for i in range(20)])
        self.assertEqual(len(features), 20)
        self.assertTrue(np.isfinite(features.to_numpy()).all())


class SettingsTests(unittest.TestCase):
    def test_defaults_are_valid(self):
        self.assertEqual(validate_settings()["contamination"], 0.05)

    def test_auto_contamination_allowed(self):
        self.assertEqual(validate_settings({"contamination": "auto"})["contamination"], "auto")

    def test_invalid_values_rejected(self):
        bad = [{"contamination": 0}, {"contamination": 0.9}, {"contamination": "abc"},
               {"contamination": True}, {"n_estimators": 0}, {"n_estimators": 2.5},
               {"min_rows_to_train": 3}, {"max_ml_alerts": -1}, {"random_state": "x"}]
        for settings in bad:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    validate_settings(settings)


class SmallDetectorTests(unittest.TestCase):
    def test_too_little_data_is_skipped_safely(self):
        result = detect_anomalies([L(i, source_ip="10.0.0.1") for i in range(10)])
        self.assertFalse(result.trained)
        self.assertIn("at least", result.note)
        self.assertEqual(result.anomaly_count, 0)
        self.assertEqual(len(result.items), 10)

    def test_rows_with_only_a_timestamp_train_without_crashing(self):
        result = detect_anomalies([L(i) for i in range(60)])
        self.assertTrue(result.trained)
        self.assertEqual(len(result.items), 60)


class GeneratedDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.logs = generated_logs(self.tmp.name)
        self.result = detect_anomalies(self.logs)
        rules = rule_engine.run_rules(self.logs)
        self.rules = rules
        self.rule_ids = set()
        for f in rules.findings:
            self.rule_ids.update(f.log_ids)

    def test_trains_and_flags_expected_share(self):
        r = self.result
        self.assertTrue(r.trained)
        self.assertGreater(r.anomaly_count, 0)
        self.assertLessEqual(r.anomaly_count, 0.10 * len(self.logs))   # setting is 5%
        self.assertIsNotNone(r.threshold)

    def test_rule_events_score_higher_than_the_rest(self):
        inside = [it.anomaly_score for row, it in zip(self.logs, self.result.items)
                  if row["id"] in self.rule_ids]
        outside = [it.anomaly_score for row, it in zip(self.logs, self.result.items)
                   if row["id"] not in self.rule_ids]
        self.assertGreater(np.mean(inside), np.mean(outside))
        flagged_inside = sum(1 for row, it in zip(self.logs, self.result.items)
                             if it.is_anomaly and row["id"] in self.rule_ids)
        self.assertGreater(flagged_inside, 0)

    def test_reproducible(self):
        again = detect_anomalies(self.logs)
        first = [(i.is_anomaly, i.anomaly_score) for i in self.result.items]
        second = [(i.is_anomaly, i.anomaly_score) for i in again.items]
        self.assertEqual(first, second)

    def test_contamination_controls_how_many_are_flagged(self):
        few = detect_anomalies(self.logs, {"contamination": 0.02}).anomaly_count
        many = detect_anomalies(self.logs, {"contamination": 0.10}).anomaly_count
        self.assertGreater(many, few)

    def test_every_anomaly_has_an_explanation(self):
        anomalies = [i for i in self.result.items if i.is_anomaly]
        self.assertTrue(anomalies)
        for item in anomalies:
            self.assertTrue(item.top_features)
            self.assertTrue(all(name in FEATURE_NAMES for name, _ in item.top_features))
            self.assertTrue(item.reasons())
        normal = next(i for i in self.result.items if not i.is_anomaly)
        self.assertEqual(normal.top_features, [])

    def test_items_stay_aligned_and_unscorable_rows_have_no_score(self):
        bad = {"timestamp": "garbage", "id": 99999}
        logs = self.logs[:50] + [bad] + self.logs[50:150]
        result = detect_anomalies(logs)
        self.assertEqual(len(result.items), len(logs))
        self.assertEqual(result.events_skipped, 1)
        self.assertIsNone(result.items[50].anomaly_score)
        self.assertFalse(result.items[50].is_anomaly)
        self.assertEqual(result.items[50].log_id, 99999)
        self.assertEqual(result.items[51].log_id, self.logs[50]["id"])

    def test_save_and_load_model(self):
        features, _ = build_features(self.logs)
        model = AnomalyModel().fit(features)
        path = Path(self.tmp.name) / "model.joblib"
        model.save(path)
        loaded = AnomalyModel.load(path)
        np.testing.assert_allclose(model.score(features)[0], loaded.score(features)[0])
        result = detect_anomalies(self.logs, model=loaded)
        self.assertTrue(result.trained)
        self.assertIn("pre-trained", result.note)

    def test_input_is_not_modified(self):
        before = copy.deepcopy(self.logs)
        detect_anomalies(self.logs)
        self.assertEqual(self.logs, before)

    def test_ml_findings_cover_every_anomaly_when_nothing_is_excluded(self):
        findings = build_ml_findings(self.logs, self.result, max_findings=1000)
        self.assertGreater(len(findings), 0)
        self.assertEqual(sum(f.event_count for f in findings), self.result.anomaly_count)
        for f in findings:
            self.assertEqual(f.rule_name, ML_RULE_NAME)
            self.assertEqual(f.threat_type, ANOMALY_THREAT)
            self.assertTrue(f.recommended_steps)
            self.assertTrue(f.indicators["ml_only"])

    def test_ml_findings_exclude_covered_logs_and_respect_the_cap(self):
        findings = build_ml_findings(self.logs, self.result,
                                     covered_log_ids=self.rule_ids, max_findings=3)
        self.assertLessEqual(len(findings), 3)
        for f in findings:
            self.assertFalse(set(f.log_ids) & self.rule_ids)
        scores = [f.indicators["max_anomaly_score"] for f in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(build_ml_findings(self.logs, self.result, max_findings=0), [])

    def test_ml_context_for_rule_findings(self):
        by_id = self.result.by_log_id()
        finding = self.rules.findings[0]
        ctx = ml_context_for_finding(finding, by_id)
        self.assertEqual(ctx["scored_events"], len(finding.log_ids))
        self.assertGreaterEqual(ctx["max_anomaly_score"], 0)
        self.assertLessEqual(ctx["anomalous_events"], ctx["scored_events"])
        finding.log_ids = [123456789]                     # id that was never scored
        self.assertIsNone(ml_context_for_finding(finding, by_id))


if __name__ == "__main__":
    unittest.main()