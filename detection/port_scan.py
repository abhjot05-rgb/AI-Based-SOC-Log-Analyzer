"""Port-scan rule: one source IP touches many distinct destination ports quickly."""
from collections import defaultdict

from detection.common import PORT_SCAN, build_finding, find_bursts, get_int, human_duration, plural

RULE_NAME = "port_scan"


def detect(events, cfg):
    threshold = get_int(cfg, "unique_ports_threshold", 15)
    window = get_int(cfg, "time_window_seconds", 60)

    by_ip = defaultdict(list)
    for ev in events:
        if ev.get("source_ip") and ev.get("destination_port") is not None:
            by_ip[ev["source_ip"]].append(ev)

    findings = []
    for ip, evs in by_ip.items():
        bursts = find_bursts(evs, window, threshold,
                             distinct_key=lambda e: e["destination_port"])
        for start, end in bursts:
            burst = evs[start:end + 1]
            ports = {e["destination_port"] for e in burst}
            targets = {e["destination_ip"] for e in burst if e.get("destination_ip")}
            blocked = sum(1 for e in burst
                          if e.get("event_type") == "firewall_block" or e.get("status") == "blocked")
            allowed_ports = {e["destination_port"] for e in burst if e.get("status") == "allowed"}
            seconds = (burst[-1]["_dt"] - burst[0]["_dt"]).total_seconds()

            reason = (f"{ip} probed {len(ports)} distinct ports on "
                      f"{plural(max(len(targets), 1), 'host')} within {human_duration(seconds)}; "
                      f"{blocked} connection(s) blocked, {len(allowed_ports)} port(s) allowed.")
            findings.append(build_finding(
                RULE_NAME, PORT_SCAN, burst, reason, source_ip=ip,
                indicators={
                    "unique_ports": len(ports),
                    "blocked_count": blocked,
                    "allowed_ports": sorted(allowed_ports)[:20],
                    "unique_targets": len(targets),
                    "duration_seconds": int(seconds),
                    "threshold": threshold,
                    "window_seconds": window,
                }))
    return findings