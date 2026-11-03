"""Read/update queries used by the API. All values are passed as SQL parameters."""
import json
import re

from database.schema import ALERT_STATUSES

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SEV_RANK = ("CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
             "WHEN 'MEDIUM' THEN 2 ELSE 1 END")

ALERT_SORTS = {"time": "first_seen", "score": "threat_score", "id": "id",
               "severity": _SEV_RANK, "type": "threat_type", "status": "status",
               "ip": "source_ip"}
LOG_SORTS = {"time": "timestamp", "ip": "source_ip", "username": "username",
             "event_type": "event_type", "score": "anomaly_score", "id": "id"}


# ------------------------------------------------------------- helpers
def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _like(text):
    """Escape LIKE wildcards in user input (used with ESCAPE '\\')."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _paging(args):
    page = max(_int(args.get("page"), 1), 1)
    per_page = min(max(_int(args.get("per_page"), 50), 1), 200)
    return page, per_page


def _order(args, allowed, default):
    key = allowed.get(args.get("sort"), allowed[default])
    direction = "ASC" if str(args.get("order", "desc")).lower() == "asc" else "DESC"
    return f"{key} {direction}, id DESC"


def _where(conds):
    return (" WHERE " + " AND ".join(conds)) if conds else ""


def _pack(items, total, page, per_page):
    return {"items": items, "total": total, "page": page, "per_page": per_page,
            "pages": max((total + per_page - 1) // per_page, 1)}


def _alert_dict(row):
    d = dict(row)
    for key in ("score_breakdown", "evidence"):
        try:
            d[key] = json.loads(d.get(key) or "null")
        except json.JSONDecodeError:
            d[key] = None
    return d


def latest_analysis_id(conn):
    row = conn.execute("SELECT MAX(id) FROM analysis_results WHERE status='completed'").fetchone()
    return row[0]


def resolve_analysis(conn, value):
    """None/'' -> latest analysis, 'all' -> no filter (returns None), number -> that id."""
    if value in (None, ""):
        return latest_analysis_id(conn)
    if str(value).lower() == "all":
        return None
    return _int(value, latest_analysis_id(conn))


def _date_conds(args, column, conds, params):
    d1, d2 = args.get("date_from", ""), args.get("date_to", "")
    if _DATE.match(d1 or ""):
        conds.append(f"{column} >= ?")
        params.append(d1 + " 00:00:00")
    if _DATE.match(d2 or ""):
        conds.append(f"{column} <= ?")
        params.append(d2 + " 23:59:59")


# ------------------------------------------------------------- analyses
def list_analyses(conn, limit=20):
    rows = conn.execute("SELECT * FROM analysis_results ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(r) for r in rows]


# ------------------------------------------------------------- summary
def get_summary(conn, analysis_id=None):
    aid = resolve_analysis(conn, analysis_id)

    def scope(*extra):
        conds, params = list(extra), []
        if aid:
            conds.append("analysis_id = ?")
            params.append(aid)
        return _where(conds), params

    w, p = scope()
    sev = {s: 0 for s in SEVERITIES}
    for r in conn.execute(f"SELECT severity, COUNT(*) c FROM alerts{w} GROUP BY severity", p):
        sev[r["severity"]] = r["c"]

    total_logs = conn.execute(f"SELECT COUNT(*) FROM logs{w}", p).fetchone()[0]
    anomalies = conn.execute(
        f"SELECT COUNT(*) FROM logs{_where(['is_anomaly = 1'] + (['analysis_id = ?'] if aid else []))}",
        p).fetchone()[0]

    wi, pi = scope("source_ip != ''")
    top_ips = [dict(r) for r in conn.execute(
        f"SELECT source_ip, COUNT(*) AS alerts, MAX(threat_score) AS max_score "
        f"FROM alerts{wi} GROUP BY source_ip ORDER BY alerts DESC, max_score DESC LIMIT 10", pi)]
    threat_types = [dict(r) for r in conn.execute(
        f"SELECT threat_type, COUNT(*) AS count FROM alerts{w} "
        f"GROUP BY threat_type ORDER BY count DESC", p)]
    recent = [_alert_dict(r) for r in conn.execute(
        f"SELECT id, first_seen, threat_type, severity, threat_score, source_ip, status "
        f"FROM alerts{w} ORDER BY first_seen DESC, id DESC LIMIT 10", p)]
    timeline = [dict(r) for r in conn.execute(
        f"SELECT substr(first_seen, 1, 13) || ':00' AS hour, COUNT(*) AS count "
        f"FROM alerts{w} GROUP BY hour ORDER BY hour", p)]
    analysis = conn.execute("SELECT * FROM analysis_results WHERE id = ?", (aid,)).fetchone() if aid else None

    return {"analysis": dict(analysis) if analysis else None,
            "totals": {"logs": total_logs, "alerts": sum(sev.values()), "anomalies": anomalies},
            "severity": sev, "top_ips": top_ips, "threat_types": threat_types,
            "recent_alerts": recent, "timeline": timeline}


# ------------------------------------------------------------- alerts
def search_alerts(conn, args):
    aid = resolve_analysis(conn, args.get("analysis_id"))
    conds, params = [], []
    if aid:
        conds.append("analysis_id = ?"); params.append(aid)
    sev = str(args.get("severity", "")).upper()
    if sev in SEVERITIES:
        conds.append("severity = ?"); params.append(sev)
    if args.get("status") in ALERT_STATUSES:
        conds.append("status = ?"); params.append(args["status"])
    if args.get("threat_type"):
        conds.append("threat_type = ?"); params.append(args["threat_type"])
    if args.get("ip"):
        conds.append("source_ip LIKE ? ESCAPE '\\'"); params.append(_like(args["ip"].strip()) + "%")
    if args.get("q"):
        like = "%" + _like(args["q"].strip()) + "%"
        conds.append("(reason LIKE ? ESCAPE '\\' OR threat_type LIKE ? ESCAPE '\\' "
                     "OR source_ip LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\')")
        params += [like] * 4
    _date_conds(args, "first_seen", conds, params)

    where = _where(conds)
    page, per_page = _paging(args)
    total = conn.execute(f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM alerts{where} ORDER BY {_order(args, ALERT_SORTS, 'time')} LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page])
    return _pack([_alert_dict(r) for r in rows], total, page, per_page)


def get_alert(conn, alert_id):
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        return None
    alert = _alert_dict(row)
    logs = [dict(r) for r in conn.execute(
        "SELECT l.* FROM threat_events te JOIN logs l ON l.id = te.log_id "
        "WHERE te.alert_id = ? ORDER BY l.timestamp, l.id LIMIT 100", (alert_id,))]
    alert["related_logs"] = logs
    alert["related_log_count"] = conn.execute(
        "SELECT COUNT(*) FROM threat_events WHERE alert_id = ?", (alert_id,)).fetchone()[0]
    alert["original_log"] = logs[0]["raw_log"] if logs else ""
    return alert


def update_alert_status(conn, alert_id, status):
    """Returns True if the alert exists. Caller must validate `status` first."""
    cur = conn.execute("UPDATE alerts SET status = ?, updated_at = datetime('now') WHERE id = ?",
                       (status, alert_id))
    return cur.rowcount > 0


# ------------------------------------------------------------- logs
def search_logs(conn, args):
    aid = resolve_analysis(conn, args.get("analysis_id"))
    conds, params = [], []
    if aid:
        conds.append("analysis_id = ?"); params.append(aid)
    if args.get("ip"):
        like = _like(args["ip"].strip()) + "%"
        conds.append("(source_ip LIKE ? ESCAPE '\\' OR destination_ip LIKE ? ESCAPE '\\')")
        params += [like, like]
    if args.get("username"):
        conds.append("username LIKE ? ESCAPE '\\'"); params.append("%" + _like(args["username"].strip()) + "%")
    if args.get("event_type"):
        conds.append("event_type = ?"); params.append(args["event_type"])
    if args.get("q"):
        like = "%" + _like(args["q"].strip()) + "%"
        conds.append("(message LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR source_ip LIKE ? ESCAPE '\\')")
        params += [like] * 3
    if str(args.get("anomalies_only", "")).lower() in ("1", "true", "yes"):
        conds.append("is_anomaly = 1")
    sev = str(args.get("severity", "")).upper()
    if sev in SEVERITIES:     # logs that belong to at least one alert of this severity
        conds.append("EXISTS (SELECT 1 FROM threat_events te JOIN alerts a ON a.id = te.alert_id "
                     "WHERE te.log_id = logs.id AND a.severity = ?)")
        params.append(sev)
    _date_conds(args, "timestamp", conds, params)

    where = _where(conds)
    page, per_page = _paging(args)
    total = conn.execute(f"SELECT COUNT(*) FROM logs{where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM logs{where} ORDER BY {_order(args, LOG_SORTS, 'time')} LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page])
    return _pack([dict(r) for r in rows], total, page, per_page)