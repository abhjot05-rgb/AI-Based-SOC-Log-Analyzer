"""
Read-side helpers for the API (and, later, the HTML pages).

Safety rules: every value is a '?' parameter; sort columns and directions come from fixed
whitelists; '%' and '_' typed by the user are escaped so they match literally.
"""
import json
import math
from datetime import datetime

from database.db import db_session, query_all, query_one
from database.schema import (ALERT_STATUSES, DETECTION_METHODS, LOG_SEVERITY_LEVELS,
                             SEVERITY_LEVELS)

MAX_PER_PAGE = 200
MAX_TEXT_FILTER = 100
TRUE_VALUES = {"1", "true", "yes", "on"}
_ESCAPE = " ESCAPE '\\'"


class QueryError(ValueError):
    """A filter value sent by the client is invalid (becomes HTTP 400)."""


_RANK_SQL = ("CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
             "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END")

LOG_COLUMN_LIST = ["id", "upload_id", "timestamp", "source_ip", "destination_ip", "username",
                   "event_id", "event_type", "protocol", "source_port", "destination_port",
                   "action", "status", "message", "severity", "is_anomaly", "anomaly_score"]
LOG_COLUMNS = ", ".join(LOG_COLUMN_LIST)

ALERT_LIST_COLUMNS = ("id, upload_id, timestamp, threat_type, severity, threat_score, source_ip, "
                      "destination_ip, username, event_id, detection_method, ml_anomaly_score, "
                      "reason, related_event_count, status, created_at, updated_at")

LOG_SORTS = {
    "timestamp": "timestamp", "source_ip": "source_ip", "destination_ip": "destination_ip",
    "username": "username", "event_type": "event_type", "event_id": "event_id",
    "severity": _RANK_SQL, "anomaly_score": "anomaly_score", "id": "id",
}
ALERT_SORTS = {
    "timestamp": "timestamp", "severity": _RANK_SQL, "threat_score": "threat_score",
    "threat_type": "threat_type", "source_ip": "source_ip", "username": "username",
    "status": "status", "id": "id",
}


# ======================================================================
# Argument helpers (args = request.args or a plain dict)
# ======================================================================
def _text(args, key):
    value = str(args.get(key) or "").strip()
    if len(value) > MAX_TEXT_FILTER:
        raise QueryError(f"'{key}' is too long (maximum {MAX_TEXT_FILTER} characters)")
    return value


def _like(value):
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"

MAX_INT = 2_147_483_647      # keeps numbers inside SQLite's range

def _int(args, key, default=None, low=1):
    raw = args.get(key)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise QueryError(f"'{key}' must be a whole number") from None
    if value < low:
        raise QueryError(f"'{key}' must be {low} or more")
    if value > MAX_INT:
        raise QueryError(f"'{key}' is too large")
    return value


def _choice(args, key, allowed):
    value = _text(args, key)
    if not value:
        return None
    lookup = {item.lower(): item for item in allowed}
    if value.lower() not in lookup:
        raise QueryError(f"'{key}' must be one of: {', '.join(allowed)}")
    return lookup[value.lower()]


def _date(args, key):
    value = _text(args, key)
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise QueryError(f"'{key}' must be a date like 2026-01-15") from None
    return value


def optional_upload_id(args):
    return _int(args, "upload_id", None)


def _where(conds):
    return " WHERE " + " AND ".join(conds) if conds else ""


def _add_text_search(args, conds, params, columns):
    q = _text(args, "q")
    if q:
        conds.append("(" + " OR ".join(f"{c} LIKE ?{_ESCAPE}" for c in columns) + ")")
        params.extend([_like(q)] * len(columns))


def _add_like_filter(args, key, column, conds, params):
    value = _text(args, key)
    if value:
        conds.append(f"{column} LIKE ?{_ESCAPE}")
        params.append(_like(value))


def _add_date_filters(args, conds, params):
    date_from, date_to = _date(args, "date_from"), _date(args, "date_to")
    if date_from:
        conds.append("timestamp >= ?")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        conds.append("timestamp <= ?")
        params.append(f"{date_to} 23:59:59")


def _order(args, sorts, default_key, default_dir):
    key = _text(args, "sort") or default_key
    if key not in sorts:
        raise QueryError(f"'sort' must be one of: {', '.join(sorts)}")
    direction = (_text(args, "order") or default_dir).lower()
    if direction not in ("asc", "desc"):
        raise QueryError("'order' must be 'asc' or 'desc'")
    d = direction.upper()
    return f"{sorts[key]} {d}, id {d}"


def _paginate(table, columns, where, params, order, args, default_per_page, convert=dict):
    page = _int(args, "page", 1)
    per_page = min(_int(args, "per_page", default_per_page), MAX_PER_PAGE)
    total = query_one(f"SELECT COUNT(*) AS c FROM {table}{where}", tuple(params))["c"]
    rows = query_all(
        f"SELECT {columns} FROM {table}{where} ORDER BY {order} LIMIT ? OFFSET ?",
        tuple(params) + (per_page, (page - 1) * per_page))
    return {"items": [convert(r) for r in rows], "total": total, "page": page,
            "per_page": per_page, "pages": max(1, math.ceil(total / per_page))}


# ======================================================================
# Logs
# ======================================================================
def search_logs(args, default_per_page=50):
    conds, params = [], []
    upload_id = optional_upload_id(args)
    if upload_id is not None:
        conds.append("upload_id = ?")
        params.append(upload_id)
    _add_text_search(args, conds, params,
                     ["message", "username", "source_ip", "destination_ip", "event_type"])
    _add_like_filter(args, "source_ip", "source_ip", conds, params)
    _add_like_filter(args, "username", "username", conds, params)
    event_type = _text(args, "event_type").lower()
    if event_type:
        conds.append("event_type = ?")
        params.append(event_type)
    severity = _choice(args, "severity", LOG_SEVERITY_LEVELS)
    if severity:
        conds.append("severity = ?")
        params.append(severity)
    if _text(args, "anomalies_only").lower() in TRUE_VALUES:
        conds.append("is_anomaly = 1")
    _add_date_filters(args, conds, params)
    order = _order(args, LOG_SORTS, "timestamp", "asc")
    return _paginate("logs", LOG_COLUMNS, _where(conds), params, order, args, default_per_page)


# ======================================================================
# Alerts
# ======================================================================
def _decode_steps(value):
    if not value:
        return []
    try:
        data = json.loads(value)
        if isinstance(data, list):
            return [str(item) for item in data]
    except (TypeError, ValueError):
        pass
    return [line for line in str(value).splitlines() if line.strip()]


def alert_to_dict(row):
    alert = dict(row)
    if "recommended_steps" in alert:
        alert["recommended_steps"] = _decode_steps(alert["recommended_steps"])
    return alert


def search_alerts(args, default_per_page=25):
    conds, params = [], []
    upload_id = optional_upload_id(args)
    if upload_id is not None:
        conds.append("upload_id = ?")
        params.append(upload_id)
    _add_text_search(args, conds, params,
                     ["threat_type", "source_ip", "destination_ip", "username", "reason"])
    _add_like_filter(args, "source_ip", "source_ip", conds, params)
    _add_like_filter(args, "username", "username", conds, params)
    threat_type = _text(args, "threat_type").lower()
    if threat_type:
        conds.append("LOWER(threat_type) = ?")
        params.append(threat_type)
    for key, allowed in (("severity", SEVERITY_LEVELS), ("status", ALERT_STATUSES),
                         ("detection_method", DETECTION_METHODS)):
        value = _choice(args, key, allowed)
        if value:
            conds.append(f"{key} = ?")
            params.append(value)
    _add_date_filters(args, conds, params)
    order = _order(args, ALERT_SORTS, "timestamp", "desc")
    return _paginate("alerts", ALERT_LIST_COLUMNS, _where(conds), params, order, args,
                     default_per_page)


def get_alert(alert_id, related_limit=100):
    """Full alert with its related logs, or None if it does not exist."""
    row = query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if row is None:
        return None
    alert = alert_to_dict(row)
    columns = ", ".join("l." + c for c in LOG_COLUMN_LIST)
    related = query_all(
        f"SELECT {columns} FROM threat_events t JOIN logs l ON l.id = t.log_id "
        f"WHERE t.alert_id = ? ORDER BY l.timestamp, l.id LIMIT ?", (alert_id, related_limit))
    alert["related_logs"] = [dict(r) for r in related]
    alert["related_total"] = query_one(
        "SELECT COUNT(*) AS c FROM threat_events WHERE alert_id = ?", (alert_id,))["c"]
    return alert


def update_alert_status(alert_id, status):
    """Returns the saved status, or None if the alert does not exist. Raises QueryError if invalid."""
    if not isinstance(status, str):
        raise QueryError(f"'status' must be text, one of: {', '.join(ALERT_STATUSES)}")
    lookup = {s.lower(): s for s in ALERT_STATUSES}
    canonical = lookup.get(status.strip().lower())
    if canonical is None:
        raise QueryError(f"'status' must be one of: {', '.join(ALERT_STATUSES)}")
    with db_session() as conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ?, updated_at = datetime('now') WHERE id = ?",
            (canonical, alert_id))
        return canonical if cursor.rowcount > 0 else None


# ======================================================================
# Uploads and filter options
# ======================================================================
def upload_exists(upload_id):
    return query_one("SELECT id FROM uploads WHERE id = ?", (upload_id,)) is not None


def list_uploads():
    rows = query_all(
        "SELECT u.id, u.original_name, u.file_type, u.total_rows, u.status, u.uploaded_at, "
        "ar.total_alerts, ar.critical_count, ar.high_count, ar.medium_count, ar.low_count, "
        "ar.anomaly_count, ar.ml_trained, ar.duration_seconds "
        "FROM uploads u LEFT JOIN analysis_results ar ON ar.upload_id = u.id "
        "ORDER BY u.id DESC")
    return [dict(r) for r in rows]


def filter_options():
    return {
        "event_types": [r["event_type"] for r in query_all(
            "SELECT DISTINCT event_type FROM logs WHERE event_type IS NOT NULL ORDER BY event_type")],
        "threat_types": [r["threat_type"] for r in query_all(
            "SELECT DISTINCT threat_type FROM alerts ORDER BY threat_type")],
        "severities": list(SEVERITY_LEVELS),
        "log_severities": list(LOG_SEVERITY_LEVELS),
        "statuses": list(ALERT_STATUSES),
        "detection_methods": list(DETECTION_METHODS),
    }


# ======================================================================
# Dashboard statistics
# ======================================================================
def dashboard_stats(upload_id=None):
    scope = "WHERE upload_id = ?" if upload_id is not None else ""
    params = (upload_id,) if upload_id is not None else ()
    joiner = "AND" if scope else "WHERE"

    total_logs = query_one(f"SELECT COUNT(*) AS c FROM logs {scope}", params)["c"]
    anomalies = query_one(f"SELECT COUNT(*) AS c FROM logs {scope} {joiner} is_anomaly = 1", params)["c"]
    total_alerts = query_one(f"SELECT COUNT(*) AS c FROM alerts {scope}", params)["c"]
    uploads = (query_one("SELECT COUNT(*) AS c FROM uploads WHERE id = ?", params)["c"]
               if upload_id is not None else query_one("SELECT COUNT(*) AS c FROM uploads")["c"])

    def grouped(column, levels):
        counts = {name: 0 for name in levels}
        for r in query_all(f"SELECT {column} AS k, COUNT(*) AS c FROM alerts {scope} GROUP BY {column}", params):
            counts[r["k"]] = r["c"]
        return counts

    top_ips = [dict(r) for r in query_all(
        f"SELECT source_ip, COUNT(*) AS alerts, MAX(threat_score) AS max_score FROM alerts "
        f"{scope} {joiner} source_ip IS NOT NULL GROUP BY source_ip "
        f"ORDER BY alerts DESC, max_score DESC, source_ip LIMIT 10", params)]
    threat_types = [dict(r) for r in query_all(
        f"SELECT threat_type, COUNT(*) AS count FROM alerts {scope} "
        f"GROUP BY threat_type ORDER BY count DESC, threat_type", params)]
    recent = [dict(r) for r in query_all(
        f"SELECT id, timestamp, threat_type, severity, threat_score, source_ip, username, status "
        f"FROM alerts {scope} ORDER BY timestamp DESC, id DESC LIMIT 10", params)]

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "anomalies": anomalies,
        "uploads": uploads,
        "severity_counts": grouped("severity", SEVERITY_LEVELS),
        "status_counts": grouped("status", ALERT_STATUSES),
        "detection_methods": grouped("detection_method", DETECTION_METHODS),
        "top_ips": top_ips,
        "threat_types": threat_types,
        "recent_alerts": recent,
        "timeline": _timeline(scope, joiner, params),
    }


def _timeline(scope, joiner, params):
    """Alerts per hour (or per day when the data spans more than 3 days), split by severity."""
    bounds = query_one(f"SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi FROM alerts {scope}", params)
    if not bounds["lo"]:
        return {"bucket": "hour", "points": []}
    try:
        span = (datetime.strptime(bounds["hi"], "%Y-%m-%d %H:%M:%S")
                - datetime.strptime(bounds["lo"], "%Y-%m-%d %H:%M:%S")).days
    except ValueError:
        span = 0
    length, name = (13, "hour") if span <= 3 else (10, "day")   # constants, safe in the SQL text

    points = {}
    for r in query_all(
            f"SELECT substr(timestamp, 1, {length}) AS bucket, severity, COUNT(*) AS c FROM alerts "
            f"{scope} {joiner} timestamp IS NOT NULL GROUP BY bucket, severity ORDER BY bucket", params):
        point = points.setdefault(r["bucket"], {"bucket": r["bucket"], "total": 0,
                                                **{level: 0 for level in SEVERITY_LEVELS}})
        point[r["severity"]] += r["c"]
        point["total"] += r["c"]
    return {"bucket": name, "points": list(points.values())}