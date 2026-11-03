"""Suspicious-IP rule: repeated suspicious events (failures, blocks, lockouts) from one IP."""
from collections import Counter, defaultdict

from detection.common import (SUSPICIOUS_IP, build_finding, find_bursts, get_int, get_list,
                              human_duration, is_internal_ip)

RULE_NAME = "suspicious_ip"
_DEFAULT_TYPES = ["login_failure", "firewall_block", "account_lockout"]


def detect(events, cfg):
    threshold = get_int(cfg, "suspicious_event_threshold", 10)
    window = get_int(cfg, "time_window_seconds", 600)
    types = set(get_list(cfg, "event_types", _DEFAULT_TYPES))

    by_ip = defaultdict(list)
    for ev in events:
        if ev.get("source_ip") and ev.get("event_type") in types:
            by_ip[ev["source_ip"]].append(ev)

    findings = []
    for ip, evs in by_ip.items():
        for start, end in find_bursts(evs, window, threshold):
            burst = evs[start:end + 1]
            kinds = Counter(e["event_type"] for e in burst)
            summary = ", ".join(f"{n}x {t}" for t, n in kinds.most_common())
            ports = {e["destination_port"] for e in burst if e.get("destination_port") is not None}
            targets = {e["destination_ip"] for e in burst if e.get("destination_ip")}
            seconds = (burst[-1]["_dt"] - burst[0]["_dt"]).total_seconds()

            reason = (f"{len(burst)} suspicious events ({summary}) from {ip} within "
                      f"{human_duration(seconds)}.")
            findings.append(build_finding(
                RULE_NAME, SUSPICIOUS_IP, burst, reason, source_ip=ip,
                indicators={
                    "event_count": len(burst),
                    "event_types": dict(kinds),
                    "distinct_ports": len(ports),
                    "distinct_targets": len(targets),
                    "internal_source": is_internal_ip(ip),
                    "duration_seconds": int(seconds),
                    "threshold": threshold,
                    "window_seconds": window,
                }))
    return findings