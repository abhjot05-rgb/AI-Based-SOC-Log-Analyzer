"""
Read-side summaries for the Threats and Analytics pages.

Only SELECT queries. Values are '?' parameters; the SQL text only ever contains our own
constants (column names, severity levels), never user input.
"""
from database.db import query_all, query_one
from database.schema import ALERT_STATUSES, DETECTION_METHODS, SEVERITY_LEVELS
from detection.common import is_internal_ip
from services.queries import _timeline

SEVERITY_FROM_RANK = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
_RANK_SQL = ("CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
             "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END")


def _scope(upload_id):
    """(WHERE clause, parameters, word to chain further conditions with)."""
    if upload_id is None:
        return "", (), "WHERE"
    return "WHERE upload_id = ?", (upload_id,), "AND"


def _grouped(column, levels, scope, params):
    """{level: count} with every level present, even when its count is 0."""
    counts = {name: 0 for name in levels}
    for r in query_all(f"SELECT {column} AS k, COUNT(*) AS c FROM alerts {scope} GROUP BY {column}", params):
        counts[r["k"]] = r["c"]
    return counts


# ======================================================================
# Threats page
# ======================================================================
def threat_summary(upload_id=None):
    scope, params, joiner = _scope(upload_id)

    severity_columns = ", ".join(
        f"SUM(CASE WHEN severity = '{level}' THEN 1 ELSE 0 END) AS {level.lower()}"
        for level in SEVERITY_LEVELS)
    by_type = []
    for r in query_all(
            f"SELECT threat_type, COUNT(*) AS count, ROUND(AVG(threat_score), 1) AS avg_score, "
            f"MAX(threat_score) AS max_score, COUNT(DISTINCT source_ip) AS unique_ips, "
            f"SUM(related_event_count) AS events, {severity_columns} "
            f"FROM alerts {scope} GROUP BY threat_type ORDER BY count DESC, threat_type", params):
        item = dict(r)
        item["severity"] = {level: item.pop(level.lower()) for level in SEVERITY_LEVELS}
        by_type.append(item)

    totals = dict(query_one(
        f"SELECT COUNT(*) AS alerts, COUNT(DISTINCT source_ip) AS unique_ips, "
        f"COUNT(DISTINCT threat_type) AS threat_types FROM alerts {scope}", params))
    # A brute-force alert whose reason records a successful login from the same IP afterwards
    totals["possible_compromises"] = query_one(
        f"SELECT COUNT(*) AS c FROM alerts {scope} {joiner} threat_type = 'Brute Force' "
        f"AND reason LIKE '%successful login for%'", params)["c"]

    attackers = []
    for r in query_all(
            f"SELECT source_ip, COUNT(*) AS alerts, MAX(threat_score) AS max_score, "
            f"MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen, "
            f"MAX({_RANK_SQL}) AS sev_rank, GROUP_CONCAT(DISTINCT threat_type) AS threat_types "
            f"FROM alerts {scope} {joiner} source_ip IS NOT NULL GROUP BY source_ip "
            f"ORDER BY alerts DESC, max_score DESC, source_ip LIMIT 15", params):
        item = dict(r)
        item["highest_severity"] = SEVERITY_FROM_RANK.get(item.pop("sev_rank"), "LOW")
        item["threat_types"] = sorted(t for t in (item["threat_types"] or "").split(",") if t)
        item["internal"] = is_internal_ip(item["source_ip"])
        attackers.append(item)

    users = [dict(r) for r in query_all(
        f"SELECT username, COUNT(*) AS alerts, MAX(threat_score) AS max_score, "
        f"COUNT(DISTINCT source_ip) AS source_ips FROM alerts {scope} {joiner} username IS NOT NULL "
        f"GROUP BY username ORDER BY alerts DESC, max_score DESC, username LIMIT 10", params)]

    return {
        "totals": totals,
        "by_type": by_type,
        "top_attackers": attackers,
        "detection_methods": _grouped("detection_method", DETECTION_METHODS, scope, params),
        "targeted_users": users,
    }


# ======================================================================
# Analytics page
# ======================================================================
def analytics_data(upload_id=None):
    scope, params, joiner = _scope(upload_id)

    severity_counts = _grouped("severity", SEVERITY_LEVELS, scope, params)
    status_counts = _grouped("status", ALERT_STATUSES, scope, params)
    methods = _grouped("detection_method", DETECTION_METHODS, scope, params)
    total_alerts = sum(severity_counts.values())

    # Alert scores in 10-point buckets (0-9, 10-19, ... 90-100)
    buckets = {r["b"]: r["c"] for r in query_all(
        f"SELECT MIN(CAST(threat_score / 10 AS INTEGER), 9) AS b, COUNT(*) AS c "
        f"FROM alerts {scope} GROUP BY b", params)}
    score_histogram = [{"label": "90-100" if i == 9 else f"{i * 10}-{i * 10 + 9}",
                        "count": buckets.get(i, 0)} for i in range(10)]

    # Log activity by hour of day
    hours = {r["h"]: r for r in query_all(
        f"SELECT CAST(substr(timestamp, 12, 2) AS INTEGER) AS h, COUNT(*) AS total, "
        f"SUM(CASE WHEN severity != 'NONE' THEN 1 ELSE 0 END) AS alerted, "
        f"SUM(is_anomaly) AS anomalies FROM logs {scope} {joiner} timestamp IS NOT NULL "
        f"GROUP BY h", params)}
    hourly = [{"hour": h,
               "total": hours[h]["total"] if h in hours else 0,
               "alerted": (hours[h]["alerted"] or 0) if h in hours else 0,
               "anomalies": (hours[h]["anomalies"] or 0) if h in hours else 0}
              for h in range(24)]

    event_types = [{"event_type": r["event_type"], "count": r["count"], "alerted": r["alerted"] or 0}
                   for r in query_all(
        f"SELECT COALESCE(event_type, 'unknown') AS event_type, COUNT(*) AS count, "
        f"SUM(CASE WHEN severity != 'NONE' THEN 1 ELSE 0 END) AS alerted "
        f"FROM logs {scope} GROUP BY event_type ORDER BY count DESC, event_type LIMIT 10", params)]

    # Distribution of ML anomaly scores (0.05-wide buckets), split by flagged or not
    ml_rows = {r["b"]: r for r in query_all(
        f"SELECT MIN(CAST(anomaly_score * 20 AS INTEGER), 20) AS b, COUNT(*) AS c, "
        f"SUM(is_anomaly) AS flagged FROM logs {scope} {joiner} anomaly_score IS NOT NULL "
        f"GROUP BY b", params)}
    ml_distribution = []
    if ml_rows:
        for b in range(min(ml_rows), max(ml_rows) + 1):
            row = ml_rows.get(b)
            count = row["c"] if row else 0
            flagged = (row["flagged"] or 0) if row else 0
            ml_distribution.append({"label": f"{b / 20:.2f}", "count": count, "flagged": flagged})

    # ML coverage: agreement with the rules (NOT an accuracy measure)
    log_row = query_one(
        f"SELECT COUNT(*) AS logs, SUM(is_anomaly) AS anomalies, "
        f"SUM(CASE WHEN anomaly_score IS NOT NULL THEN 1 ELSE 0 END) AS scored "
        f"FROM logs {scope}", params)
    logs_total, anomalies, scored = (log_row["logs"], log_row["anomalies"] or 0, log_row["scored"] or 0)
    log_scope = "AND l.upload_id = ?" if upload_id is not None else ""
    rule_row = query_one(
        f"SELECT COUNT(DISTINCT l.id) AS events, "
        f"COUNT(DISTINCT CASE WHEN l.is_anomaly = 1 THEN l.id END) AS flagged "
        f"FROM logs l JOIN threat_events t ON t.log_id = l.id "
        f"WHERE t.rule_name != 'ml_anomaly' {log_scope}", params)

    return {
        "totals": {
            "alerts": total_alerts,
            "open_alerts": status_counts["New"] + status_counts["Investigating"],
            "logs": logs_total,
            "anomalies": anomalies,
        },
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "detection_methods": methods,
        "score_histogram": score_histogram,
        "timeline": _timeline(scope, joiner, params),
        "hourly": hourly,
        "event_types": event_types,
        "ml_score_distribution": ml_distribution,
        "ml_coverage": {
            "logs": logs_total,
            "scored": scored,
            "anomalies": anomalies,
            "rule_events": rule_row["events"],
            "rule_events_flagged": rule_row["flagged"],
            "anomalies_outside_rules": anomalies - rule_row["flagged"],
        },
    }