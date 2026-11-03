"""
Anomaly detection pipeline: features -> train -> score -> explain.

Command line (nothing is written to the database):
    python -m ml.anomaly_detector --file data/samples/sample_generic.csv
    python -m ml.anomaly_detector --upload-id 1 --top 20
"""
import argparse
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

import config
from detection.common import build_finding, plural, prepare_events
from ml.feature_engineering import FEATURE_LABELS, build_features
from ml.model import AnomalyModel, NotEnoughDataError, validate_settings

log = logging.getLogger("soc.ml")

ML_RULE_NAME = "ml_anomaly"
ANOMALY_THREAT = "Anomalous Activity"
ANOMALY_RECOMMENDATIONS = [
    "Treat this as an unusual-behaviour lead, not a confirmed attack: no detection rule matched it.",
    "Review the flagged events and compare them with the source's normal behaviour.",
    "Check whether the source IP or account is known and whether the activity was expected.",
    "Look for related events before and after the flagged ones.",
    "If the activity is legitimate, mark the alert as False Positive.",
]


@dataclass
class AnomalyItem:
    index: int                                   # position in the input list
    log_id: Optional[int] = None                 # database id, when the log has one
    is_anomaly: bool = False
    anomaly_score: Optional[float] = None        # None = event could not be scored
    top_features: list = field(default_factory=list)   # [(feature_name, std_devs)]

    def reasons(self):
        return describe_features(self.top_features)


@dataclass
class AnomalyResult:
    items: list = field(default_factory=list)    # one per input log, same order
    trained: bool = False
    note: str = ""
    threshold: Optional[float] = None
    events_scored: int = 0
    events_skipped: int = 0
    settings: dict = field(default_factory=dict)

    @property
    def anomaly_count(self):
        return sum(1 for item in self.items if item.is_anomaly)

    def by_log_id(self):
        return {item.log_id: item for item in self.items if item.log_id is not None}


def describe_features(top_features):
    return [f"{FEATURE_LABELS.get(name, name)} ({z:+.1f} std dev from this file's average)"
            for name, z in top_features]


def _top_features(z_row, names, k=3, min_abs=1.0):
    """The features sitting furthest from the file's average (always at least one)."""
    order = np.argsort(-np.abs(z_row))
    picked = [(names[i], float(z_row[i])) for i in order[:k] if abs(z_row[i]) >= min_abs]
    if not picked:
        picked = [(names[order[0]], float(z_row[order[0]]))]
    return picked


def detect_anomalies(logs, settings=None, model=None):
    """
    Score every log event. `logs` are dicts / sqlite3.Row with normalized fields.
    settings: dict like config.ML_SETTINGS (defaults to the real config).
    model:    an already-trained AnomalyModel (otherwise one is trained on these logs).
    Raises ValueError if a setting is invalid. Never raises for too little data:
    the result just has trained=False and an explanatory note.
    """
    rows = [dict(r) for r in logs]
    cfg = validate_settings(config.ML_SETTINGS if settings is None else settings)
    features, skipped = build_features(rows, cfg["feature_window_seconds"])

    result = AnomalyResult(
        items=[AnomalyItem(index=i, log_id=row.get("id")) for i, row in enumerate(rows)],
        events_scored=len(features), events_skipped=skipped, settings=cfg)

    if model is None:
        model = AnomalyModel(cfg)
        try:
            model.fit(features)
        except NotEnoughDataError as exc:
            result.note = str(exc)
            return result
        c = cfg["contamination"]
        share = ("only events past the standard 0.5 anomaly cutoff"
                 if c == "auto" else f"roughly the most unusual {c:.0%} of events")
        result.note = (
            f"Isolation Forest trained on {len(features)} events (unsupervised: it learns "
            f"what is typical in this file). It flags {share}; this is a setting, not a "
            f"measured attack rate.")
    else:
        result.note = "Scored with a pre-trained Isolation Forest model."

    scores, flags, Z = model.score(features)
    result.trained = True
    result.threshold = model.threshold

    for k, position in enumerate(features.index):
        item = result.items[position]
        item.anomaly_score = float(scores[k])
        item.is_anomaly = bool(flags[k])
        if item.is_anomaly:
            item.top_features = _top_features(Z[k], model.feature_names)

    log.info("ML finished: %d scored, %d anomalies", result.events_scored, result.anomaly_count)
    return result


# ======================================================================
# Connecting ML results to alerts
# ======================================================================
def ml_context_for_finding(finding, by_log_id):
    """
    ML summary for a rule finding (Stage 8 stores this with the alert).
    by_log_id: result.by_log_id(). Returns None if none of the finding's logs were scored.
    """
    scored = [by_log_id[i] for i in finding.log_ids
              if i in by_log_id and by_log_id[i].anomaly_score is not None]
    if not scored:
        return None
    return {
        "max_anomaly_score": max(item.anomaly_score for item in scored),
        "anomalous_events": sum(1 for item in scored if item.is_anomaly),
        "scored_events": len(scored),
    }


def build_ml_findings(logs, result, covered_log_ids=(), max_findings=None):
    """
    Group anomalies that NO rule explains into findings (one per source IP, or per user
    when there is no IP). Strongest first, at most `max_findings`.
    covered_log_ids: log ids already inside rule findings; only logs with a database id
    can be matched against it.
    """
    rows = [dict(r) for r in logs]
    covered = set(covered_log_ids)
    if max_findings is None:
        max_findings = result.settings.get("max_ml_alerts", 20)

    groups = defaultdict(list)
    for row, item in zip(rows, result.items):
        if not item.is_anomaly:
            continue
        if row.get("id") is not None and row["id"] in covered:
            continue
        if row.get("source_ip"):
            key = ("ip", row["source_ip"])
        elif row.get("username"):
            key = ("user", row["username"])
        else:
            key = ("none", "")
        groups[key].append((row, item))

    findings = []
    for (kind, value), members in groups.items():
        events, _ = prepare_events([row for row, _ in members])
        if not events:
            continue
        scores = [item.anomaly_score for _, item in members]
        traits = Counter(name for _, item in members for name, _z in item.top_features)
        top = [name for name, _ in traits.most_common(3)]
        trait_text = ", ".join(FEATURE_LABELS.get(n, n) for n in top)
        origin = {"ip": f"from {value}", "user": f"for user {value}",
                  "none": "with no source information"}[kind]

        reason = (f"{plural(len(members), 'event')} {origin} were flagged as statistically "
                  f"unusual by the Isolation Forest model (highest anomaly score "
                  f"{max(scores):.3f}). Most unusual traits: {trait_text}. No detection rule "
                  f"matched these events, so this is an anomaly lead, not a confirmed attack.")
        finding = build_finding(
            ML_RULE_NAME, ANOMALY_THREAT, events, reason,
            source_ip=value if kind == "ip" else None,
            username=value if kind == "user" else None,
            indicators={
                "ml_only": True,
                "anomalous_events": len(members),
                "max_anomaly_score": max(scores),
                "mean_anomaly_score": float(np.mean(scores)),
                "threshold": result.threshold,
                "top_features": top,
            })
        finding.recommended_steps = list(ANOMALY_RECOMMENDATIONS)
        findings.append(finding)

    findings.sort(key=lambda f: f.indicators["max_anomaly_score"], reverse=True)
    return findings[:max_findings]


# ======================================================================
# Command line
# ======================================================================
def _print_report(logs, result, top):
    from detection.rule_engine import run_rules

    print(f"\nEvents: {len(logs)} (scored: {result.events_scored}, skipped: {result.events_skipped})")
    print(result.note)
    if not result.trained:
        return
    print(f"Anomaly threshold: {result.threshold:.3f}   Anomalies flagged: {result.anomaly_count}")

    rules = run_rules(logs)
    rule_ids = set()
    for f in rules.findings:
        rule_ids.update(f.log_ids)
    inside = [it for row, it in zip(logs, result.items) if row.get("id") in rule_ids]
    flagged_inside = sum(1 for it in inside if it.is_anomaly)
    outside = result.anomaly_count - flagged_inside
    print("\nAgreement with the rule engine (agreement between two methods, NOT accuracy):")
    print(f"  events inside rule findings:       {len(inside)}")
    print(f"  ...of which ML also flagged:       {flagged_inside}")
    print(f"  ML anomalies outside any finding:  {outside}")

    ml_only = build_ml_findings(logs, result, covered_log_ids=rule_ids)
    print(f"  ML-only findings (grouped by IP):  {len(ml_only)}")

    print(f"\nTop {top} most unusual events:")
    ranked = sorted((it for it in result.items if it.is_anomaly),
                    key=lambda it: it.anomaly_score, reverse=True)[:top]
    for it in ranked:
        row = logs[it.index]
        print(f"  {it.anomaly_score:.3f}  {row.get('timestamp')}  {row.get('source_ip') or '-':<16} "
              f"{row.get('username') or '-':<10} {row.get('event_type')}")
        print(f"         why: {'; '.join(it.reasons())}")


def main():
    ap = argparse.ArgumentParser(description="Run ML anomaly detection (no database writes).")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="log file to parse and analyse")
    group.add_argument("--upload-id", type=int, help="analyse an upload already in the database")
    ap.add_argument("--top", type=int, default=10, help="anomalies to print (default 10)")
    args = ap.parse_args()

    if args.file:
        from parser.ingest import parse_file
        from parser.log_normalizer import ParseError
        try:
            logs = parse_file(args.file).records
        except ParseError as exc:
            raise SystemExit(f"Cannot parse file: {exc}")
        for i, rec in enumerate(logs, start=1):
            rec["id"] = i                      # stand-in ids so rule and ML results line up
    else:
        from detection.rule_engine import load_logs_from_db
        logs = load_logs_from_db(args.upload_id)
        if not logs:
            raise SystemExit(f"No logs found for upload id {args.upload_id}.")

    _print_report(logs, detect_anomalies(logs), args.top)


if __name__ == "__main__":
    main()