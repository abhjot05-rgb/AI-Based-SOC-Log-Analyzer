"""
Threat scoring: turns a detection Finding (plus optional ML result) into a 0-100 score,
a severity level (LOW / MEDIUM / HIGH / CRITICAL) and a plain-language explanation.

The score is a sum of whole-number points from 7 components, so the explanation always
adds up to the score. Weights live in config.SCORING_SETTINGS and are heuristics chosen
for this project: they are not learned from labelled data and carry no accuracy figure.

Command line (nothing is written to the database):
    python -m analysis.threat_scoring --file data/samples/sample_generic.csv
    python -m analysis.threat_scoring --upload-id 1 --top 20 --explain 5
"""
import argparse
import copy
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional

import config
from detection.common import TS_FORMAT, human_duration, is_internal_ip, plural
from ml.anomaly_detector import ml_context_for_finding

# Built-in defaults: used to fill anything missing from config.SCORING_SETTINGS
DEFAULT_SETTINGS = {
    "base_scores": {
        "Brute Force": 25, "Port Scan": 20, "Suspicious Login": 15,
        "Suspicious Account Activity": 20, "Privilege Escalation Activity": 25,
        "Suspicious IP Activity": 15, "Anomalous Activity": 10,
    },
    "default_base_score": 10,
    "max_points": {"attempts": 20, "frequency": 10, "accounts": 10,
                   "ml": 15, "ip_behavior": 15, "escalation": 20},
    "attempts_full_at_multiple": 3,
    "frequency_low_per_minute": 2,
    "frequency_high_per_minute": 30,
    "ml_low": 0.50,
    "ml_high": 0.75,
    "ip_points": {"external": 6, "repeat": 6, "multi_target": 3},
    "escalation_points": {"brute_force_success": 20, "off_hours_external": 10,
                          "multi_ip_external": 10, "accounts_created": 10,
                          "privilege_combo": 10, "scan_allowed_ports": 8},
}

# "One user, many IPs" findings have no threshold in their indicators, so we use this range
MULTI_IP_LOW, MULTI_IP_HIGH = 3, 8


# ======================================================================
# Settings validation
# ======================================================================
def _number(value, name, low, high=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Scoring setting '{name}' must be a number (got {value!r})")
    if value < low or (high is not None and value > high):
        limit = f"between {low} and {high}" if high is not None else f"{low} or more"
        raise ValueError(f"Scoring setting '{name}' must be {limit} (got {value})")
    return value


def validate_scoring_settings(settings=None):
    """Merge with defaults and check every value. Raises ValueError with a clear message."""
    merged = copy.deepcopy(DEFAULT_SETTINGS)
    for key, value in (settings or {}).items():
        if key not in merged:
            raise ValueError(f"Unknown scoring setting '{key}'")
        if isinstance(merged[key], dict):
            if not isinstance(value, dict):
                raise ValueError(f"Scoring setting '{key}' must be a dictionary (got {value!r})")
            for sub, sub_value in value.items():
                if key != "base_scores" and sub not in merged[key]:
                    raise ValueError(f"Unknown scoring setting '{key}.{sub}'")
                merged[key][sub] = sub_value
        else:
            merged[key] = value

    for name, value in merged["base_scores"].items():
        _number(value, f"base_scores.{name}", 0, 100)
    _number(merged["default_base_score"], "default_base_score", 0, 100)
    for group in ("max_points", "ip_points", "escalation_points"):
        for name, value in merged[group].items():
            _number(value, f"{group}.{name}", 0, 100)

    if _number(merged["attempts_full_at_multiple"], "attempts_full_at_multiple", 0) <= 1:
        raise ValueError("Scoring setting 'attempts_full_at_multiple' must be greater than 1")
    low = _number(merged["frequency_low_per_minute"], "frequency_low_per_minute", 0)
    high = _number(merged["frequency_high_per_minute"], "frequency_high_per_minute", 0)
    if high <= low:
        raise ValueError("Scoring setting 'frequency_high_per_minute' must be above "
                         "'frequency_low_per_minute'")
    ml_low = _number(merged["ml_low"], "ml_low", 0, 1)
    ml_high = _number(merged["ml_high"], "ml_high", 0, 1)
    if ml_high <= ml_low:
        raise ValueError("Scoring setting 'ml_high' must be above 'ml_low'")
    return merged


# ======================================================================
# Results
# ======================================================================
@dataclass
class ScoreComponent:
    key: str
    label: str
    points: int
    max_points: int
    detail: str


@dataclass
class ThreatScore:
    score: int
    severity: str
    components: list
    explanation: str
    detection_method: str                  # RULE, ML or RULE+ML
    capped: bool = False
    ml_context: Optional[dict] = field(default=None)

    def to_dict(self):
        return asdict(self)


# ======================================================================
# Severity
# ======================================================================
def severity_for_score(score, bands=None):
    """Map a 0-100 score to a severity name using config.SEVERITY_BANDS."""
    bands = config.SEVERITY_BANDS if bands is None else bands
    value = int(round(max(0, min(100, score))))
    for name, (low, high) in bands.items():
        if low <= value <= high:
            return name
    raise ValueError(f"No severity band covers the score {value}")


def severity_counts(scores):
    """{'LOW': n, 'MEDIUM': n, ...} for a list of ThreatScore objects (all levels present)."""
    counts = {name: 0 for name in config.SEVERITY_BANDS}
    for item in scores:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    return counts


def detection_method_for(finding, ml_context):
    """ML = only the model found it; RULE+ML = a rule found it and ML flagged events inside it."""
    if finding.indicators.get("ml_only"):
        return "ML"
    if ml_context and ml_context.get("anomalous_events", 0) > 0:
        return "RULE+ML"
    return "RULE"


# ======================================================================
# Helpers
# ======================================================================
def _ramp(value, low, high):
    """0.0 at or below `low`, 1.0 at or above `high`, straight line in between."""
    if high <= low:
        return 1.0 if value >= high else 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def _num(mapping, key, default=0):
    value = mapping.get(key, default)
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else default


def _points(max_points, fraction):
    return int(round(max_points * fraction))


def _duration_seconds(finding):
    try:
        start = datetime.strptime(finding.start_time, TS_FORMAT)
        end = datetime.strptime(finding.end_time, TS_FORMAT)
        return max(0.0, (end - start).total_seconds())
    except (TypeError, ValueError):
        return 0.0


# ======================================================================
# Components
# ======================================================================
def _base_component(f, s):
    base = int(round(s["base_scores"].get(f.threat_type, s["default_base_score"])))
    top = int(round(max(s["base_scores"].values())))
    return ScoreComponent("base", "Threat type", base, top,
                          f"'{f.threat_type}' has a base weight")


def _attempts_component(f, s, max_pts):
    ind, k = f.indicators, s["attempts_full_at_multiple"]

    def over(value_key, threshold_key, default, label):
        threshold = _num(ind, threshold_key, default)
        if threshold <= 0:
            threshold = default
        value = _num(ind, value_key, 0)
        return value, threshold, threshold * k, f"{value} {label} against a threshold of {threshold}"

    spec = None
    if f.rule_name == "brute_force":
        spec = over("failed_count", "threshold", 5, "failed login attempts")
    elif f.rule_name == "port_scan":
        spec = over("unique_ports", "threshold", 15, "distinct ports probed")
    elif f.rule_name == "suspicious_ip":
        spec = over("event_count", "threshold", 10, "suspicious events")
    elif f.rule_name == "account_activity":
        spec = over("event_count", "repeat_threshold", 3, "account events")
    elif f.rule_name == "privilege_activity":
        spec = over("event_count", "repeat_threshold", 2, "privilege events")
    elif f.rule_name == "suspicious_login" and ind.get("kind") == "multiple_ips":
        n = _num(ind, "distinct_ips", 0)
        spec = (n, MULTI_IP_LOW, MULTI_IP_HIGH, f"{n} distinct IP addresses for one user")

    if spec is None:
        return ScoreComponent("attempts", "Failed attempts / volume", 0, max_pts,
                              "not applicable to this threat type")
    value, low, high, detail = spec
    return ScoreComponent("attempts", "Failed attempts / volume",
                          _points(max_pts, _ramp(value, low, high)), max_pts, detail)


def _frequency_component(f, s, max_pts):
    label = "Event frequency"
    if f.event_count < 3:
        return ScoreComponent("frequency", label, 0, max_pts, "too few events to measure a rate")
    seconds = _duration_seconds(f)
    rate = f.event_count / max(seconds, 1.0) * 60
    fraction = _ramp(rate, s["frequency_low_per_minute"], s["frequency_high_per_minute"])
    return ScoreComponent(
        "frequency", label, _points(max_pts, fraction), max_pts,
        f"{f.event_count} events in {human_duration(seconds)} (about {rate:.1f} per minute)")


def _account_count(f):
    for key in ("unique_accounts", "affected_accounts"):
        value = f.indicators.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return 1 if f.username else 0


def _accounts_component(f, s, max_pts):
    n = _account_count(f)
    return ScoreComponent("accounts", "Affected accounts",
                          _points(max_pts, _ramp(n, 1, 5)), max_pts,
                          f"{plural(n, 'account')} affected")


def _ml_component(ctx, s, max_pts):
    label = "ML anomaly score"
    if not ctx:
        return ScoreComponent("ml", label, 0, max_pts,
                              "ML anomaly detection was not available for this finding")
    score = _num(ctx, "max_anomaly_score", 0.0)
    anomalous = int(_num(ctx, "anomalous_events", 0))
    scored = int(_num(ctx, "scored_events", anomalous))
    points = _points(max_pts, _ramp(score, s["ml_low"], s["ml_high"]))
    return ScoreComponent(
        "ml", label, points, max_pts,
        f"highest anomaly score {score:.2f} ({anomalous} of {scored} events flagged as unusual)")


def _ip_component(f, ip_count, s, max_pts):
    label, ip = "Source IP behaviour", f.source_ip
    ip_pts, points, notes = s["ip_points"], 0, []
    if ip and not is_internal_ip(ip):
        points += ip_pts["external"]
        notes.append(f"external source IP {ip}")
    elif ip:
        notes.append(f"internal source IP {ip}")
    if ip and ip_count >= 2:
        points += ip_pts["repeat"]
        notes.append(f"the same IP appears in {ip_count} findings")
    targets = max(_num(f.indicators, "unique_targets", 0), _num(f.indicators, "distinct_targets", 0))
    if targets > 1:
        points += ip_pts["multi_target"]
        notes.append(f"{int(targets)} target hosts")
    points = min(int(round(points)), max_pts)
    return ScoreComponent("ip_behavior", label, points, max_pts,
                          "; ".join(notes) if notes else "no source IP information")


def _escalation_component(f, s, max_pts):
    ep, ind, rule = s["escalation_points"], f.indicators, f.rule_name
    points, notes = 0, []
    if rule == "brute_force" and ind.get("success_after"):
        points += ep["brute_force_success"]
        notes.append("a successful login from the same IP followed the failures (possible compromise)")
    if rule == "suspicious_login":
        if ind.get("kind") == "off_hours" and ind.get("external_source"):
            points += ep["off_hours_external"]
            notes.append("login outside normal hours from an external IP")
        if ind.get("kind") == "multiple_ips" and _num(ind, "external_sources", 0) > 0:
            points += ep["multi_ip_external"]
            notes.append("the user logged in from external IPs as well")
    if rule == "account_activity" and _num(ind, "accounts_created", 0) > 0:
        points += ep["accounts_created"]
        notes.append("new accounts were created")
    if rule == "privilege_activity" and _num(ind, "privilege_assigned_count", 0) > 0 and (
            _num(ind, "group_change_count", 0) > 0 or _num(ind, "sudo_count", 0) > 0):
        points += ep["privilege_combo"]
        notes.append("special privileges were assigned together with group changes or sudo use")
    if rule == "port_scan" and ind.get("allowed_ports"):
        points += ep["scan_allowed_ports"]
        notes.append("some probed ports were allowed through the firewall")
    points = min(int(round(points)), max_pts)
    return ScoreComponent("escalation", "Escalation indicators", points, max_pts,
                          "; ".join(notes) if notes else "none found")


# ======================================================================
# Scoring
# ======================================================================
def _explain(total, severity, components, capped):
    low, high = config.SEVERITY_BANDS[severity]
    lines = [f"Threat score {total}/100 = {severity} (band {low}-{high})."]
    active = [c for c in components if c.points > 0]
    if active:
        lines.append("Contributing factors: " + "; ".join(
            f"{c.label}: {c.detail} (+{c.points})" for c in active) + ".")
    quiet = [c.label for c in components if c.points == 0]
    if quiet:
        lines.append("No points from: " + ", ".join(quiet) + ".")
    if capped:
        lines.append("The points added up to more than 100, so the score was capped at 100.")
    return " ".join(lines)


def _score(finding, ml_context, ip_count, s):
    """Score one finding using already-validated settings."""
    if ml_context is None and finding.indicators.get("ml_only"):
        # ML-only findings carry their own ML numbers
        anomalous = int(_num(finding.indicators, "anomalous_events", 0))
        ml_context = {"max_anomaly_score": _num(finding.indicators, "max_anomaly_score", 0.0),
                      "anomalous_events": anomalous, "scored_events": anomalous}

    mp = s["max_points"]
    components = [
        _base_component(finding, s),
        _attempts_component(finding, s, mp["attempts"]),
        _frequency_component(finding, s, mp["frequency"]),
        _accounts_component(finding, s, mp["accounts"]),
        _ml_component(ml_context, s, mp["ml"]),
        _ip_component(finding, ip_count, s, mp["ip_behavior"]),
        _escalation_component(finding, s, mp["escalation"]),
    ]
    raw = sum(c.points for c in components)
    total = max(0, min(100, raw))
    capped = raw > 100
    severity = severity_for_score(total)
    return ThreatScore(
        score=total, severity=severity, components=components,
        explanation=_explain(total, severity, components, capped),
        detection_method=detection_method_for(finding, ml_context),
        capped=capped, ml_context=ml_context)


def score_finding(finding, ml_context=None, ip_finding_count=1, settings=None):
    """
    Score a single finding.
    ml_context: dict from ml.anomaly_detector.ml_context_for_finding (or None if ML did not run).
    ip_finding_count: how many findings in this analysis share the finding's source IP.
    """
    s = validate_scoring_settings(config.SCORING_SETTINGS if settings is None else settings)
    return _score(finding, ml_context, max(1, ip_finding_count), s)


def score_findings(findings, ml_by_log_id=None, settings=None):
    """
    Score a whole analysis. Returns a list of ThreatScore in the same order as `findings`.
    ml_by_log_id: AnomalyResult.by_log_id() (or None if ML did not run).
    """
    s = validate_scoring_settings(config.SCORING_SETTINGS if settings is None else settings)
    ip_counts = Counter(f.source_ip for f in findings if f.source_ip)
    results = []
    for f in findings:
        ctx = ml_context_for_finding(f, ml_by_log_id) if ml_by_log_id else None
        count = ip_counts[f.source_ip] if f.source_ip else 1
        results.append(_score(f, ctx, count, s))
    return results


# ======================================================================
# Command line
# ======================================================================
def _print_report(findings, scores, ml, top, explain):
    print(f"\nFindings scored: {len(findings)}")
    counts = severity_counts(scores)
    print("Severity counts: " + "   ".join(f"{name}={counts[name]}" for name in reversed(list(counts))))
    print(f"ML: {ml.note}")

    ranked = sorted(zip(findings, scores), key=lambda pair: pair[1].score, reverse=True)
    print(f"\nTop {top} findings by threat score:")
    for f, sc in ranked[:top]:
        print(f"  {sc.score:>3}  {sc.severity:<8} {sc.detection_method:<8} "
              f"{f.threat_type:<31} {f.source_ip or '-':<16} {f.start_time}")

    print(f"\nWhy these severities (top {explain}):")
    for f, sc in ranked[:explain]:
        print(f"\n[{f.threat_type}] {f.reason}")
        print(f"  {sc.explanation}")


def main():
    from detection.rule_engine import run_rules
    from ml.anomaly_detector import build_ml_findings, detect_anomalies

    ap = argparse.ArgumentParser(description="Score detections (no database writes).")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="log file to parse and analyse")
    group.add_argument("--upload-id", type=int, help="analyse an upload already in the database")
    ap.add_argument("--top", type=int, default=15, help="findings to list (default 15)")
    ap.add_argument("--explain", type=int, default=3, help="explanations to print (default 3)")
    args = ap.parse_args()

    if args.file:
        from parser.ingest import parse_file
        from parser.log_normalizer import ParseError
        try:
            logs = parse_file(args.file).records
        except ParseError as exc:
            raise SystemExit(f"Cannot parse file: {exc}")
        for i, rec in enumerate(logs, start=1):
            rec["id"] = i                       # stand-in ids so rule and ML results line up
    else:
        from detection.rule_engine import load_logs_from_db
        logs = load_logs_from_db(args.upload_id)
        if not logs:
            raise SystemExit(f"No logs found for upload id {args.upload_id}.")

    rules = run_rules(logs)
    ml = detect_anomalies(logs)
    covered = set()
    for f in rules.findings:
        covered.update(f.log_ids)
    ml_findings = build_ml_findings(logs, ml, covered_log_ids=covered) if ml.trained else []

    findings = rules.findings + ml_findings
    scores = score_findings(findings, ml.by_log_id() if ml.trained else None)
    _print_report(findings, scores, ml, args.top, args.explain)


if __name__ == "__main__":
    main()