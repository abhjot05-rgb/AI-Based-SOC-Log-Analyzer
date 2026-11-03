"""
CSV exports and the threat summary report. Read-only: only SELECT queries.

Safety: every value is a '?' parameter, and column names come from our own constants.
CSV cells that could be run as a spreadsheet formula are neutralised (see safe_cell).
"""
import csv
import io
from datetime import datetime

from database.db import get_connection, query_all, query_one
from database.schema import ALERT_STATUSES, LOG_SEVERITY_LEVELS, SEVERITY_LEVELS
from services import analytics, queries, settings_view
from services.queries import TRUE_VALUES

FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r", "\n")
MAX_EXPORT_ROWS = 500_000      # safety cap per export
CHUNK_ROWS = 500               # rows sent to the browser at a time

ALERT_COLUMNS = [
    "id", "upload_id", "timestamp", "threat_type", "severity", "threat_score", "status",
    "detection_method", "source_ip", "destination_ip", "username", "event_id",
    "ml_anomaly_score", "related_event_count", "reason", "severity_reason",
    "recommended_steps", "original_log", "created_at", "updated_at",
]
_LOG_PLAIN = [
    "id", "upload_id", "timestamp", "source_ip", "destination_ip", "username", "event_id",
    "event_type", "protocol", "source_port", "destination_port", "action", "status",
    "severity", "is_anomaly", "anomaly_score", "message",
]
LOG_COLUMNS = _LOG_PLAIN + ["alert_ids"]

_ALERT_SQL = f"SELECT {', '.join(ALERT_COLUMNS)} FROM alerts"
_LOG_SQL = (f"SELECT {', '.join(_LOG_PLAIN)}, "
            "(SELECT GROUP_CONCAT(t.alert_id) FROM threat_events t WHERE t.log_id = logs.id) "
            "AS alert_ids FROM logs")


# ======================================================================
# CSV export
# ======================================================================
def safe_cell(value):
    """
    Text that starts with = + - @ (or a tab/line break) could be run as a formula when the CSV
    is opened in Excel. A leading ' makes spreadsheets treat it as plain text. Numbers are untouched.
    """
    if isinstance(value, str) and value.startswith(FORMULA_STARTS):
        return "'" + value
    return value


def export_filename(kind, upload_id=None, extension="csv"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scope = f"upload{upload_id}" if upload_id is not None else "all"
    return f"{kind}_{scope}_{stamp}.{extension}"


def csv_stream(sql, params, columns, make_row):
    """Generator of CSV text chunks. The database connection is closed even if the client disconnects."""
    conn = get_connection()
    try:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\r\n")
        writer.writerow(columns)
        yield "\ufeff" + buffer.getvalue()               # BOM: Excel reads the file as UTF-8
        buffer.seek(0)
        buffer.truncate(0)

        cursor = conn.execute(f"{sql} LIMIT ?", tuple(params) + (MAX_EXPORT_ROWS,))
        for count, row in enumerate(cursor, start=1):
            writer.writerow([safe_cell(v) for v in make_row(row)])
            if count % CHUNK_ROWS == 0:
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)
        yield buffer.getvalue()
    finally:
        conn.close()


def _alert_row(row):
    values = [row[c] for c in ALERT_COLUMNS]
    steps = ALERT_COLUMNS.index("recommended_steps")
    values[steps] = " | ".join(queries._decode_steps(row["recommended_steps"]))
    return values


def alerts_export(args):
    """Returns (upload_id, stream). Invalid filters raise QueryError before anything is streamed."""
    conds, params = [], []
    upload_id = queries.optional_upload_id(args)
    if upload_id is not None:
        conds.append("upload_id = ?")
        params.append(upload_id)
    for key, allowed in (("severity", SEVERITY_LEVELS), ("status", ALERT_STATUSES)):
        value = queries._choice(args, key, allowed)
        if value:
            conds.append(f"{key} = ?")
            params.append(value)
    sql = f"{_ALERT_SQL}{queries._where(conds)} ORDER BY id"
    return upload_id, csv_stream(sql, params, ALERT_COLUMNS, _alert_row)


def logs_export(args):
    conds, params = [], []
    upload_id = queries.optional_upload_id(args)
    if upload_id is not None:
        conds.append("upload_id = ?")
        params.append(upload_id)
    severity = queries._choice(args, "severity", LOG_SEVERITY_LEVELS)
    if severity:
        conds.append("severity = ?")
        params.append(severity)
    if queries._text(args, "anomalies_only").lower() in TRUE_VALUES:
        conds.append("is_anomaly = 1")
    sql = f"{_LOG_SQL}{queries._where(conds)} ORDER BY upload_id, timestamp, id"
    return upload_id, csv_stream(sql, params, LOG_COLUMNS,
                                 lambda row: [row[c] for c in LOG_COLUMNS])


# ======================================================================
# Threat summary report
# ======================================================================
def _key_findings(stats, threats, an):
    if stats["total_alerts"] == 0:
        return [f"{stats['total_logs']:,} log events were analyzed and no alerts were raised."]

    sev = stats["severity_counts"]
    items = [
        f"{stats['total_logs']:,} log events were analyzed and {stats['total_alerts']:,} alerts "
        f"were raised across {threats['totals']['threat_types']} threat type(s) and "
        f"{threats['totals']['unique_ips']} source IP address(es).",
        f"{sev['CRITICAL'] + sev['HIGH']} alert(s) are CRITICAL or HIGH "
        f"({sev['CRITICAL']} critical, {sev['HIGH']} high); {sev['MEDIUM']} medium, {sev['LOW']} low.",
    ]
    if threats["by_type"]:
        top = threats["by_type"][0]
        items.append(f"The most frequent threat type is {top['threat_type']} ({top['count']} alerts).")
    if threats["top_attackers"]:
        a = threats["top_attackers"][0]
        items.append(f"The source IP with the most alerts is {a['source_ip']} ({a['alerts']} alerts, "
                     f"highest severity {a['highest_severity']}).")
    compromised = threats["totals"]["possible_compromises"]
    if compromised:
        items.append(f"{compromised} brute-force alert(s) were followed by a successful login from the "
                     f"same IP address. Review those accounts first: they may be compromised.")
    items.append(f"{an['totals']['open_alerts']} alert(s) are still open (New or Investigating).")
    ml = an["ml_coverage"]
    items.append(f"The ML model flagged {an['totals']['anomalies']} unusual event(s); "
                 f"{ml['anomalies_outside_rules']} of them are outside any rule-based alert. "
                 f"The number flagged follows the contamination setting, so it is not a count of attacks.")
    return items


def build_summary(upload_id=None):
    """Everything the threat summary report shows, as plain JSON-friendly data."""
    stats = queries.dashboard_stats(upload_id)
    threats = analytics.threat_summary(upload_id)
    an = analytics.analytics_data(upload_id)

    where = "WHERE upload_id = ?" if upload_id is not None else ""
    params = (upload_id,) if upload_id is not None else ()

    top_alerts = [dict(r) for r in query_all(
        f"SELECT id, timestamp, threat_type, severity, threat_score, source_ip, username, "
        f"detection_method, status, reason FROM alerts {where} "
        f"ORDER BY threat_score DESC, id LIMIT 10", params)]
    ml_runs = [dict(r) for r in query_all(
        f"SELECT upload_id, ml_trained, ml_note FROM analysis_results {where} ORDER BY upload_id", params)]
    uploads = [u for u in queries.list_uploads() if upload_id is None or u["id"] == upload_id]

    if upload_id is None:
        label = "All uploads"
    else:
        row = query_one("SELECT original_name FROM uploads WHERE id = ?", (upload_id,))
        label = f"Upload #{upload_id}" + (f" ({row['original_name']})" if row else "")

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scope": {"upload_id": upload_id, "label": label},
        "totals": {
            "logs": stats["total_logs"],
            "alerts": stats["total_alerts"],
            "open_alerts": an["totals"]["open_alerts"],
            "anomalies": stats["anomalies"],
            "threat_types": threats["totals"]["threat_types"],
            "source_ips": threats["totals"]["unique_ips"],
            "possible_compromises": threats["totals"]["possible_compromises"],
            "uploads": stats["uploads"],
        },
        "severity_counts": stats["severity_counts"],
        "status_counts": stats["status_counts"],
        "detection_methods": stats["detection_methods"],
        "key_findings": _key_findings(stats, threats, an),
        "top_alerts": top_alerts,
        "threat_types": threats["by_type"],
        "top_attackers": threats["top_attackers"][:10],
        "targeted_users": threats["targeted_users"],
        "ml": an["ml_coverage"],
        "ml_runs": ml_runs,
        "uploads": uploads,
        "configuration": settings_view.configuration_lines(),
    }