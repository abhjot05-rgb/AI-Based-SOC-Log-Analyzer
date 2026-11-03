"""
Feature engineering: turns normalized log events into numeric features for the
Isolation Forest. Every feature is computed from the logs of ONE file (one upload).
Missing fields never crash anything: they simply contribute 0.
"""
import numpy as np
import pandas as pd

from detection.common import is_internal_ip

FEATURE_NAMES = [
    "hour_sin", "hour_cos",
    "is_failure", "is_external_ip", "is_sensitive_event",
    "ip_events_total", "ip_events_recent", "ip_failure_ratio",
    "ip_unique_ports", "ip_unique_users", "user_unique_ips",
    "port_rarity", "event_type_rarity",
]

# Human-readable names, used when explaining why an event was flagged
FEATURE_LABELS = {
    "hour_sin": "time of day",
    "hour_cos": "time of day",
    "is_failure": "failed or blocked event",
    "is_external_ip": "external source IP",
    "is_sensitive_event": "account/privilege event",
    "ip_events_total": "total events from this IP",
    "ip_events_recent": "burst of events from this IP",
    "ip_failure_ratio": "share of failures from this IP",
    "ip_unique_ports": "distinct ports touched by this IP",
    "ip_unique_users": "distinct usernames tried by this IP",
    "user_unique_ips": "distinct IPs used by this user",
    "port_rarity": "rare destination port",
    "event_type_rarity": "rare event type",
}

SENSITIVE_TYPES = {
    "account_created", "account_enabled", "password_reset", "account_disabled",
    "account_lockout", "privilege_assigned", "group_member_added", "sudo_command",
}

_INPUT_COLUMNS = ["timestamp", "source_ip", "username", "event_type", "status",
                  "destination_port"]
_EPOCH = pd.Timestamp("1970-01-01")


def _is_text(value):
    return isinstance(value, str) and value.strip() != ""


def _clean_text_column(series):
    return series.map(lambda v: v.strip() if _is_text(v) else None)


def _group_stat(d, key_col, value_col, how):
    """
    Per-row group statistic (e.g. number of distinct ports for this row's IP).
    Rows whose key is missing get 0.
    """
    out = pd.Series(0.0, index=d.index)
    mask = d[key_col].map(_is_text)
    if mask.any():
        sub = d[mask]
        out.loc[sub.index] = sub.groupby(key_col)[value_col].transform(how).astype(float)
    return out


def _recent_counts(d, window_seconds):
    """Events from the same IP in the window ending at each event (including itself)."""
    recent = pd.Series(0.0, index=d.index)
    sub = d[d["source_ip"].map(_is_text)]
    for _ip, group in sub.groupby("source_ip", sort=False):
        group = group.sort_values("_ts", kind="mergesort")
        t = (group["_ts"] - _EPOCH).dt.total_seconds().to_numpy()
        # index of the first event that is still inside the window
        first_inside = np.searchsorted(t, t - window_seconds, side="left")
        recent.loc[group.index] = np.arange(1, len(t) + 1) - first_inside
    return recent


def build_features(logs, window_seconds=300):
    """
    logs: list of dicts / sqlite3.Row with normalized fields.
    Returns (features, skipped):
      features - DataFrame with FEATURE_NAMES columns; its index is each row's POSITION
                 in `logs`, so results can be matched back to the original events.
      skipped  - number of rows dropped because their timestamp was unreadable.
    """
    rows = [dict(r) for r in logs]
    empty = pd.DataFrame(columns=FEATURE_NAMES, dtype=float)
    if not rows:
        return empty, 0

    df = pd.DataFrame(rows)
    for col in _INPUT_COLUMNS:
        if col not in df.columns:
            df[col] = None

    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["_ts"] = ts.dt.tz_localize(None)
    valid = df["_ts"].notna()
    skipped = int((~valid).sum())
    if not valid.any():
        return empty, skipped

    d = df.loc[valid].copy()                      # keeps original positions as index
    d["source_ip"] = _clean_text_column(d["source_ip"])
    d["username"] = _clean_text_column(d["username"])
    d["destination_port"] = pd.to_numeric(d["destination_port"], errors="coerce")

    status = d["status"].fillna("").astype(str).str.lower()
    etype = d["event_type"].fillna("unknown").astype(str)

    # ---- time of day (cyclic) ----
    hour = d["_ts"].dt.hour + d["_ts"].dt.minute / 60.0
    d["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    d["hour_cos"] = np.cos(2 * np.pi * hour / 24)

    # ---- event flags ----
    d["is_failure"] = (status.isin(["failure", "blocked"]) | etype.eq("login_failure")).astype(float)
    d["is_external_ip"] = d["source_ip"].map(
        lambda ip: 1.0 if _is_text(ip) and not is_internal_ip(ip) else 0.0)
    d["is_sensitive_event"] = etype.isin(SENSITIVE_TYPES).astype(float)

    # ---- per-IP behaviour ----
    d["ip_events_total"] = np.log1p(_group_stat(d, "source_ip", "is_failure", "count"))
    d["ip_events_recent"] = np.log1p(_recent_counts(d, window_seconds))
    d["ip_failure_ratio"] = _group_stat(d, "source_ip", "is_failure", "mean")
    d["ip_unique_ports"] = np.log1p(_group_stat(d, "source_ip", "destination_port", "nunique"))
    d["ip_unique_users"] = np.log1p(_group_stat(d, "source_ip", "username", "nunique"))

    # ---- per-user behaviour ----
    d["user_unique_ips"] = np.log1p(_group_stat(d, "username", "source_ip", "nunique"))

    # ---- rarity (how uncommon is this port / event type in this file) ----
    ports = d["destination_port"]
    total_ports = int(ports.notna().sum())
    if total_ports:
        freq = ports.map(ports.value_counts()) / total_ports
        d["port_rarity"] = (-np.log(freq)).fillna(0.0)
    else:
        d["port_rarity"] = 0.0
    d["event_type_rarity"] = -np.log(etype.map(etype.value_counts()) / len(d))

    features = d[FEATURE_NAMES].astype(float)
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return features, skipped