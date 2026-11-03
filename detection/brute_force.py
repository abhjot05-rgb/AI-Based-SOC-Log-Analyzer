"""Brute-force rule: many failed logins from one source IP in a short time."""
from collections import defaultdict
from datetime import timedelta

from detection.common import (BRUTE_FORCE, TS_FORMAT, build_finding, find_bursts,
                              get_int, human_duration, plural)

RULE_NAME = "brute_force"


def detect(events, cfg):
    threshold = get_int(cfg, "failed_attempts_threshold", 5)
    window = get_int(cfg, "time_window_seconds", 120)
    success_window = get_int(cfg, "success_check_seconds", 300)

    failures, successes = defaultdict(list), defaultdict(list)
    for ev in events:
        ip = ev.get("source_ip")
        if not ip:
            continue
        if ev.get("event_type") == "login_failure":
            failures[ip].append(ev)
        elif ev.get("event_type") == "login_success":
            successes[ip].append(ev)

    findings = []
    for ip, fails in failures.items():
        for start, end in find_bursts(fails, window, threshold):
            burst = fails[start:end + 1]
            first_t, last_t = burst[0]["_dt"], burst[-1]["_dt"]
            accounts = sorted({e["username"] for e in burst if e.get("username")})

            # Did the same IP log in successfully during or shortly after the attack?
            limit = last_t + timedelta(seconds=success_window)
            success = next((s for s in successes.get(ip, [])
                            if first_t <= s["_dt"] <= limit), None)

            span = human_duration((last_t - first_t).total_seconds())
            reason = f"{len(burst)} failed login attempts from {ip} within {span}"
            if accounts:
                shown = ", ".join(accounts[:5]) + (", ..." if len(accounts) > 5 else "")
                reason += f", targeting {plural(len(accounts), 'account')} ({shown})"
            reason += "."
            if success:
                who = success.get("username") or "unknown user"
                when = success["_dt"].strftime(TS_FORMAT)
                reason += (f" A successful login for {who} from the same IP followed at "
                           f"{when}, so the account may be compromised.")

            related = sorted(burst + ([success] if success else []), key=lambda e: e["_dt"])
            findings.append(build_finding(
                RULE_NAME, BRUTE_FORCE, related, reason, source_ip=ip,
                indicators={
                    "failed_count": len(burst),
                    "unique_accounts": len(accounts),
                    "duration_seconds": int((last_t - first_t).total_seconds()),
                    "success_after": success is not None,
                    "threshold": threshold,
                    "window_seconds": window,
                }))
    return findings