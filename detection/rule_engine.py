"""
Rule engine: runs every enabled rule over a list of normalized logs.

Command line (nothing is written to the database):
    python -m detection.rule_engine --file data/samples/sample_generic.csv
    python -m detection.rule_engine --upload-id 1
"""
import argparse
import logging
from collections import defaultdict
from dataclasses import dataclass, field

import config
from detection import (account_privilege, brute_force, port_scan,
                       suspicious_ip, suspicious_login)
from detection.common import prepare_events

log = logging.getLogger("soc.rules")

# Order matters: suspicious_ip runs last so it can see what the others already explained.
RULES = {
    "brute_force": brute_force.detect,
    "port_scan": port_scan.detect,
    "suspicious_login": suspicious_login.detect,
    "account_activity": account_privilege.detect_account_activity,
    "privilege_activity": account_privilege.detect_privilege_activity,
    "suspicious_ip": suspicious_ip.detect,
}


@dataclass
class EngineResult:
    findings: list = field(default_factory=list)
    rule_counts: dict = field(default_factory=dict)
    rules_disabled: list = field(default_factory=list)
    events_checked: int = 0
    events_skipped: int = 0
    suppressed: int = 0


def _drop_covered(candidates, existing):
    """Drop suspicious-IP findings fully explained by a brute-force/port-scan finding of that IP."""
    covered = defaultdict(set)
    for f in existing:
        if f.rule_name in ("brute_force", "port_scan") and f.source_ip:
            covered[f.source_ip].update(f.log_ids)
    kept = [f for f in candidates
            if not (f.source_ip in covered and set(f.log_ids) <= covered[f.source_ip])]
    return kept, len(candidates) - len(kept)


def run_rules(logs, rules_config=None):
    """
    logs: list of dicts or sqlite3.Row (normalized fields).
    rules_config: dict like config.DETECTION_RULES (defaults to the real config).
    Raises ValueError if a rule's settings are invalid.
    """
    cfg = config.DETECTION_RULES if rules_config is None else rules_config
    events, skipped = prepare_events(logs)
    result = EngineResult(events_checked=len(events), events_skipped=skipped)

    for name, detect in RULES.items():
        rule_cfg = cfg.get(name, {})
        if not rule_cfg.get("enabled", True):
            result.rules_disabled.append(name)
            result.rule_counts[name] = 0
            continue
        try:
            found = detect(events, rule_cfg)
        except ValueError as exc:
            raise ValueError(f"Invalid settings for rule '{name}': {exc}") from exc

        if name == "suspicious_ip" and rule_cfg.get("suppress_if_covered", True):
            found, dropped = _drop_covered(found, result.findings)
            result.suppressed += dropped

        result.findings.extend(found)
        result.rule_counts[name] = len(found)

    result.findings.sort(key=lambda f: (f.start_time, f.rule_name))
    log.info("Rules finished: %d events, %d findings", result.events_checked, len(result.findings))
    return result


def load_logs_from_db(upload_id):
    """Read one upload's logs from SQLite as plain dicts (with their database ids)."""
    from database.db import query_all
    rows = query_all("SELECT * FROM logs WHERE upload_id = ? ORDER BY timestamp, id", (upload_id,))
    return [dict(r) for r in rows]


def _print_report(result, limit):
    print(f"\nEvents checked: {result.events_checked} (skipped: {result.events_skipped})")
    print("\nFindings per rule:")
    for name, count in result.rule_counts.items():
        note = "  (disabled)" if name in result.rules_disabled else ""
        print(f"  {name:<20} {count}{note}")
    if result.suppressed:
        print(f"  (duplicate suspicious_ip findings suppressed: {result.suppressed})")
    print(f"\nTotal findings: {len(result.findings)}\n")
    for f in result.findings[:limit]:
        print(f"[{f.start_time}] {f.threat_type:<30} {f.source_ip or '-':<16} {f.reason}")
    if len(result.findings) > limit:
        print(f"... and {len(result.findings) - limit} more (use --limit to show more)")


def main():
    ap = argparse.ArgumentParser(description="Run the detection rules (no database writes).")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="log file to parse and analyse")
    group.add_argument("--upload-id", type=int, help="analyse an upload already in the database")
    ap.add_argument("--limit", type=int, default=15, help="findings to print (default 15)")
    args = ap.parse_args()

    if args.file:
        from parser.ingest import parse_file
        from parser.log_normalizer import ParseError
        try:
            logs = parse_file(args.file).records
        except ParseError as exc:
            raise SystemExit(f"Cannot parse file: {exc}")
    else:
        logs = load_logs_from_db(args.upload_id)
        if not logs:
            raise SystemExit(f"No logs found for upload id {args.upload_id}.")

    _print_report(run_rules(logs), args.limit)


if __name__ == "__main__":
    main()