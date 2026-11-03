"""Shared building blocks for all detection rules."""
import ipaddress
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# Threat type names (shown in the dashboard and alerts)
BRUTE_FORCE = "Brute Force"
PORT_SCAN = "Port Scan"
SUSPICIOUS_LOGIN = "Suspicious Login"
ACCOUNT_ACTIVITY = "Suspicious Account Activity"
PRIVILEGE_ACTIVITY = "Privilege Escalation Activity"
SUSPICIOUS_IP = "Suspicious IP Activity"

RECOMMENDATIONS = {
    BRUTE_FORCE: [
        "Check whether the source IP is known or belongs to your organisation.",
        "Review all login events from this IP and for the targeted accounts.",
        "Check whether a successful login occurred after the failed attempts.",
        "Consider blocking the IP at the firewall and resetting affected passwords.",
        "Investigate the source system if it is internal.",
    ],
    PORT_SCAN: [
        "Check whether the source IP is an authorised vulnerability scanner.",
        "Identify which ports and hosts were probed, and which were allowed through.",
        "Review later traffic from the same IP for follow-up exploitation attempts.",
        "Consider blocking the IP and reviewing firewall rules for exposed services.",
    ],
    SUSPICIOUS_LOGIN: [
        "Contact the user to confirm whether the login was theirs.",
        "Check the source IP location and reputation.",
        "Review what the account did after logging in.",
        "Reset the password and revoke active sessions if the login was not legitimate.",
    ],
    ACCOUNT_ACTIVITY: [
        "Identify who performed the account changes and whether they were authorised.",
        "Check any newly created accounts and what permissions they hold.",
        "Review whether the changes match an approved change request.",
        "Disable unrecognised accounts and review recent activity from the acting account.",
    ],
    PRIVILEGE_ACTIVITY: [
        "Confirm that the privilege or group changes were approved.",
        "Review what the user did after receiving elevated rights.",
        "Check the source host and the account that made the change.",
        "Remove unneeded privileges and review related events.",
    ],
    SUSPICIOUS_IP: [
        "Check whether the source IP is known.",
        "Review every event from this IP, including allowed traffic.",
        "Check targeted hosts and accounts for signs of compromise.",
        "Consider blocking the IP while the investigation continues.",
    ],
}

# Internal ranges. Python's own is_private would also include the RFC 5737 demo ranges
# (203.0.113.x etc.), which our sample attackers use, so we keep our own list.
_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def is_internal_ip(ip):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


# ======================================================================
# Findings
# ======================================================================
@dataclass
class Finding:
    rule_name: str
    threat_type: str
    start_time: str
    end_time: str
    reason: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    event_id: Optional[int] = None
    log_ids: list = field(default_factory=list)     # DB ids of the triggering logs
    event_count: int = 0
    indicators: dict = field(default_factory=dict)  # numbers the scoring stage will use
    sample_log: Optional[str] = None                # original log line of the first event
    recommended_steps: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def most_common(values):
    """Most frequent non-empty value, or None."""
    counts = Counter(v for v in values if v not in (None, ""))
    return counts.most_common(1)[0][0] if counts else None


def build_finding(rule_name, threat_type, events, reason, indicators=None,
                  source_ip=None, destination_ip=None, username=None):
    """events must be non-empty and sorted by time."""
    first, last = events[0], events[-1]
    return Finding(
        rule_name=rule_name,
        threat_type=threat_type,
        start_time=first["_dt"].strftime(TS_FORMAT),
        end_time=last["_dt"].strftime(TS_FORMAT),
        reason=reason,
        source_ip=source_ip or most_common(e.get("source_ip") for e in events),
        destination_ip=destination_ip or most_common(e.get("destination_ip") for e in events),
        username=username or most_common(e.get("username") for e in events),
        event_id=first.get("event_id"),
        log_ids=[e["_key"] for e in events],
        event_count=len(events),
        indicators=indicators or {},
        sample_log=first.get("raw_log") or first.get("message"),
        recommended_steps=list(RECOMMENDATIONS.get(threat_type, [])),
    )


# ======================================================================
# Preparing events
# ======================================================================
def _to_datetime(value):
    if isinstance(value, datetime):
        dt = value
    elif not value:
        return None
    else:
        try:
            dt = datetime.fromisoformat(str(value).strip())
        except ValueError:
            return None
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def prepare_events(logs):
    """
    Copy the logs (dicts or sqlite3.Row), add a parsed time '_dt' and an id '_key',
    and sort by time. Returns (events, skipped_count). Rows without a readable
    timestamp are skipped. '_key' is the database id when present, else the row position.
    """
    events, skipped = [], 0
    for index, row in enumerate(logs):
        ev = dict(row)
        dt = _to_datetime(ev.get("timestamp"))
        if dt is None:
            skipped += 1
            continue
        ev["_dt"] = dt
        ev["_key"] = ev["id"] if ev.get("id") is not None else index
        events.append(ev)
    events.sort(key=lambda e: e["_dt"])          # stable sort
    return events, skipped


# ======================================================================
# Sliding window
# ======================================================================
def find_bursts(events, window_seconds, threshold, distinct_key=None):
    """
    events: sorted by '_dt'. Finds periods where, within any window of `window_seconds`,
    the metric is MORE THAN `threshold`. The metric is the event count, or the number of
    distinct values of distinct_key(event) when a key function is given.

    Overlapping flagged windows are merged. Returns a list of (first_index, last_index).
    """
    counts = Counter()
    left = 0
    flagged = []
    for right, ev in enumerate(events):
        counts[distinct_key(ev) if distinct_key else right] += 1
        while (ev["_dt"] - events[left]["_dt"]).total_seconds() > window_seconds:
            old = distinct_key(events[left]) if distinct_key else left
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
            left += 1
        if len(counts) > threshold:
            flagged.append((left, right))

    bursts = []
    for lo, hi in flagged:
        if bursts and lo <= bursts[-1][1]:
            bursts[-1][1] = max(bursts[-1][1], hi)
        else:
            bursts.append([lo, hi])
    return [(lo, hi) for lo, hi in bursts]


# ======================================================================
# Config validation and text helpers
# ======================================================================
def get_int(cfg, key, default, minimum=1, maximum=None):
    value = cfg.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"'{key}' must be a whole number (got {value!r})")
    if value < minimum or (maximum is not None and value > maximum):
        limit = f"{minimum} and {maximum}" if maximum is not None else f"{minimum} or more"
        raise ValueError(f"'{key}' must be {limit} (got {value})")
    return value


def get_list(cfg, key, default):
    value = cfg.get(key, default)
    if not isinstance(value, (list, tuple, set)):
        raise ValueError(f"'{key}' must be a list (got {value!r})")
    return list(value)


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def human_duration(seconds):
    seconds = max(0, int(round(seconds)))
    if seconds < 120:
        return plural(max(seconds, 1), "second")
    if seconds < 7200:
        return plural(round(seconds / 60), "minute")
    return f"{seconds / 3600:.1f} hours"