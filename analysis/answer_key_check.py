"""
Compares what the detection rules found with what the sample generator injected (the answer key).

    python -m analysis.answer_key_check
    python -m analysis.answer_key_check --seeds 1 2 3 --events 1500 --attacks 2

This compares COUNTS per scenario. It is not an accuracy figure: the generator does not say which
exact log rows belong to each attack, so precision and recall per event cannot be computed.
"""
import argparse
import tempfile
from datetime import datetime

from detection.common import is_internal_ip
from detection.rule_engine import run_rules
from generators import sample_logs as sl
from parser.csv_parser import parse_csv

START = datetime(2026, 1, 15)

# (name in the generator's answer key, rule that should find it, indicator "kind" or None)
SCENARIOS = [
    ("brute_force", "brute_force", None),
    ("port_scan", "port_scan", None),
    ("off_hours_login", "suspicious_login", "off_hours"),
    ("multi_ip_login", "suspicious_login", "multiple_ips"),
    ("account_activity", "account_activity", None),
    ("privilege_activity", "privilege_activity", None),
    ("suspicious_ip", "suspicious_ip", None),
]
# Rules about network behaviour: normal internal users should never trigger these
NETWORK_RULES = ("brute_force", "port_scan", "suspicious_ip")


def evaluate(seed=42, events=800, attacks=1):
    """Generate data, run the rules, and compare. Returns a dict (nothing is stored anywhere)."""
    with tempfile.TemporaryDirectory() as tmp:
        generated = sl.generate_all(out_dir=tmp, seed=seed, normal_events=events,
                                    attack_multiplier=attacks, start=START)
        records = parse_csv(generated["files"]["csv"]).records
    injected = generated["injected"]
    result = run_rules(records)

    def detected(rule, kind=None):
        return sum(1 for f in result.findings
                   if f.rule_name == rule and (kind is None or f.indicators.get("kind") == kind))

    rows = [{"scenario": key, "injected": injected.get(key, 0), "detected": detected(rule, kind)}
            for key, rule, kind in SCENARIOS]
    rows.append({
        "scenario": "brute_force_followed_by_success",
        "injected": injected.get("brute_force_followed_by_success", 0),
        "detected": sum(1 for f in result.findings
                        if f.rule_name == "brute_force" and f.indicators.get("success_after")),
    })
    internal = sum(1 for f in result.findings
                   if f.rule_name in NETWORK_RULES and is_internal_ip(f.source_ip))
    return {"seed": seed, "events": len(records), "total_findings": len(result.findings),
            "rows": rows, "internal_network_findings": internal}


def main():
    ap = argparse.ArgumentParser(description="Compare rule detections with the generator's answer key.")
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--events", type=int, default=800, help="normal events per run (default 800)")
    ap.add_argument("--attacks", type=int, default=1, help="attack multiplier (default 1)")
    args = ap.parse_args()

    covered = total = 0
    for seed in args.seeds:
        try:
            r = evaluate(seed, args.events, args.attacks)
        except ValueError as exc:
            ap.error(str(exc))
        print(f"\nSeed {seed}: {r['events']} events, {r['total_findings']} findings")
        print(f"  {'scenario':<34}{'injected':>9}{'detected':>10}")
        for row in r["rows"]:
            mark = "" if row["detected"] >= row["injected"] else "   <-- fewer than injected"
            print(f"  {row['scenario']:<34}{row['injected']:>9}{row['detected']:>10}{mark}")
            if row["injected"]:
                total += 1
                covered += row["detected"] >= row["injected"]
        print(f"  findings from internal IPs on network rules: {r['internal_network_findings']}")

    print(f"\nDetected at least as many as injected in {covered} of {total} scenario checks.")
    print("This compares counts only. It is not an accuracy percentage.")
    print("Two scenarios of the same kind that overlap in time can legitimately merge into one finding.")


if __name__ == "__main__":
    main()