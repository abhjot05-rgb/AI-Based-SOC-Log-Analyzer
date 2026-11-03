"""
Account-activity and privilege-activity rules.

Both flag AT LEAST `repeat_threshold` matching events within the time window.
An event matches if its event_id is in the configured list OR its event_type is in the
configured types, so Linux logs (no Windows event ids) work too.
If the logs contain no such events, the rules simply find nothing.
"""
from collections import Counter, defaultdict

from detection.common import (ACCOUNT_ACTIVITY, PRIVILEGE_ACTIVITY, build_finding, find_bursts,
                              get_int, get_list, human_duration, most_common, plural)

ACCOUNT_RULE = "account_activity"
PRIVILEGE_RULE = "privilege_activity"

_ACCOUNT_IDS = [4720, 4722, 4724, 4725, 4740]
_ACCOUNT_TYPES = ["account_created", "account_enabled", "password_reset",
                  "account_disabled", "account_lockout"]
_PRIVILEGE_IDS = [4672, 4728, 4732, 4756]
_PRIVILEGE_TYPES = ["privilege_assigned", "group_member_added", "sudo_command"]


def _bursts(events, cfg, default_ids, default_types, group_fn):
    """Yield (group_key, burst_events) for each repeated-activity burst."""
    ids = set(get_list(cfg, "event_ids", default_ids))
    types = set(get_list(cfg, "event_types", default_types))
    repeat = get_int(cfg, "repeat_threshold", 3)
    window = get_int(cfg, "time_window_seconds", 300)

    groups = defaultdict(list)
    for ev in events:
        if ev.get("event_id") in ids or ev.get("event_type") in types:
            groups[group_fn(ev)].append(ev)

    for key, evs in groups.items():
        # "at least N" == "more than N-1"
        for start, end in find_bursts(evs, window, repeat - 1):
            yield key, evs[start:end + 1], repeat, window


def _type_summary(burst):
    types = Counter(e.get("event_type") or "unknown" for e in burst)
    return types, ", ".join(f"{n}x {t}" for t, n in types.most_common())


def detect_account_activity(events, cfg):
    # Group by the acting IP; fall back to the account name (Linux logs have no IP)
    group_fn = lambda e: e.get("source_ip") or e.get("username") or "(unknown)"
    findings = []
    for _key, burst, repeat, window in _bursts(events, cfg, _ACCOUNT_IDS, _ACCOUNT_TYPES, group_fn):
        types, summary = _type_summary(burst)
        accounts = {e["username"] for e in burst if e.get("username")}
        ip = most_common(e.get("source_ip") for e in burst)
        seconds = (burst[-1]["_dt"] - burst[0]["_dt"]).total_seconds()
        origin = f" from {ip}" if ip else ""
        reason = (f"{len(burst)} account-related events ({summary}){origin} within "
                  f"{human_duration(seconds)}, affecting {plural(len(accounts), 'account')}.")
        findings.append(build_finding(
            ACCOUNT_RULE, ACCOUNT_ACTIVITY, burst, reason,
            indicators={
                "event_count": len(burst),
                "affected_accounts": len(accounts),
                "event_types": dict(types),
                "accounts_created": types.get("account_created", 0),
                "duration_seconds": int(seconds),
                "repeat_threshold": repeat,
                "window_seconds": window,
            }))
    return findings


def detect_privilege_activity(events, cfg):
    group_fn = lambda e: e.get("username") or e.get("source_ip") or "(unknown)"
    findings = []
    for key, burst, repeat, window in _bursts(events, cfg, _PRIVILEGE_IDS, _PRIVILEGE_TYPES, group_fn):
        types, summary = _type_summary(burst)
        seconds = (burst[-1]["_dt"] - burst[0]["_dt"]).total_seconds()
        reason = (f"{len(burst)} privilege-related events ({summary}) for {key} within "
                  f"{human_duration(seconds)}.")
        findings.append(build_finding(
            PRIVILEGE_RULE, PRIVILEGE_ACTIVITY, burst, reason,
            indicators={
                "event_count": len(burst),
                "event_types": dict(types),
                "privilege_assigned_count": types.get("privilege_assigned", 0),
                "group_change_count": types.get("group_member_added", 0),
                "sudo_count": types.get("sudo_command", 0),
                "duration_seconds": int(seconds),
                "repeat_threshold": repeat,
                "window_seconds": window,
            }))
    return findings