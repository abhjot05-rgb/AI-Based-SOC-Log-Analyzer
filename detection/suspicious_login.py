"""Suspicious-login rules: logins outside normal hours, and one user from many IPs."""
from collections import defaultdict

from detection.common import (SUSPICIOUS_LOGIN, build_finding, find_bursts, get_int,
                              human_duration, is_internal_ip)

RULE_NAME = "suspicious_login"


def _is_off_hours(hour, start, end):
    """The period may wrap midnight (e.g. 22 -> 6). 'end' is exclusive."""
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _off_hours(events, cfg):
    start = get_int(cfg, "off_hours_start", 22, minimum=0, maximum=23)
    end = get_int(cfg, "off_hours_end", 6, minimum=0, maximum=23)

    # One finding per user + IP + day, so a night of activity is not 50 alerts
    groups = defaultdict(list)
    for ev in events:
        if ev.get("event_type") != "login_success":
            continue
        if _is_off_hours(ev["_dt"].hour, start, end):
            key = (ev.get("username") or "unknown user", ev.get("source_ip") or "", ev["_dt"].date())
            groups[key].append(ev)

    findings = []
    for (user, ip, _day), evs in groups.items():
        first_t, last_t = evs[0]["_dt"], evs[-1]["_dt"]
        where = f" from {ip}" if ip else ""
        hours = f"outside normal hours ({start:02d}:00-{end:02d}:00)"
        if len(evs) == 1:
            reason = f"Successful login for {user}{where} at {first_t:%Y-%m-%d %H:%M:%S}, {hours}."
        else:
            reason = (f"{len(evs)} successful logins for {user}{where} between "
                      f"{first_t:%H:%M:%S} and {last_t:%H:%M:%S}, {hours}.")
        findings.append(build_finding(
            RULE_NAME, SUSPICIOUS_LOGIN, evs, reason, source_ip=ip or None,
            indicators={
                "kind": "off_hours",
                "login_count": len(evs),
                "hour": first_t.hour,
                "external_source": bool(ip) and not is_internal_ip(ip),
            }))
    return findings


def _multiple_ips(events, cfg):
    max_ips = get_int(cfg, "max_distinct_ips_per_user", 3)
    window = get_int(cfg, "time_window_seconds", 3600)

    by_user = defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "login_success" and ev.get("username") and ev.get("source_ip"):
            by_user[ev["username"]].append(ev)

    findings = []
    for user, evs in by_user.items():
        for start, end in find_bursts(evs, window, max_ips,
                                      distinct_key=lambda e: e["source_ip"]):
            burst = evs[start:end + 1]
            ips = list(dict.fromkeys(e["source_ip"] for e in burst))   # keeps first-seen order
            seconds = (burst[-1]["_dt"] - burst[0]["_dt"]).total_seconds()
            shown = ", ".join(ips[:5]) + (", ..." if len(ips) > 5 else "")
            reason = (f"User {user} logged in successfully from {len(ips)} different IP "
                      f"addresses within {human_duration(seconds)}: {shown}.")
            findings.append(build_finding(
                RULE_NAME, SUSPICIOUS_LOGIN, burst, reason, username=user,
                indicators={
                    "kind": "multiple_ips",
                    "distinct_ips": len(ips),
                    "login_count": len(burst),
                    "ips": ips[:20],
                    "external_sources": sum(1 for ip in ips if not is_internal_ip(ip)),
                }))
    return findings


def detect(events, cfg):
    findings = []
    if cfg.get("off_hours_enabled", True):
        findings += _off_hours(events, cfg)
    if cfg.get("multi_ip_enabled", True):
        findings += _multiple_ips(events, cfg)
    return findings