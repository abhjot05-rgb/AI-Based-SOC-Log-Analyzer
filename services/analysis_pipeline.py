"""
Analysis pipeline: logs in the database -> rules + ML -> scoring -> alerts in the database.

Everything is saved in ONE transaction: either the whole analysis is stored, or nothing is.
Running the analysis again replaces the previous results of that upload.
"""
import json
import logging
import time
from pathlib import Path

from analysis.threat_scoring import score_findings, severity_counts
from database.db import DatabaseError, db_session, execute, query_one
from detection.rule_engine import load_logs_from_db, run_rules
from ml.anomaly_detector import build_ml_findings, detect_anomalies
from parser.ingest import ingest_file

log = logging.getLogger("soc.pipeline")

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_ALERT_COLUMNS = [
    "upload_id", "timestamp", "threat_type", "severity", "threat_score", "source_ip",
    "destination_ip", "username", "event_id", "detection_method", "ml_anomaly_score",
    "reason", "severity_reason", "recommended_steps", "original_log", "related_event_count",
]
_INSERT_ALERT = (f"INSERT INTO alerts ({', '.join(_ALERT_COLUMNS)}) "
                 f"VALUES ({', '.join('?' * len(_ALERT_COLUMNS))})")


class AnalysisError(Exception):
    """The analysis could not be completed (bad settings, missing upload, database problem)."""

    def __init__(self, message, upload_id=None):
        super().__init__(message)
        self.upload_id = upload_id


def _set_upload_status(upload_id, status):
    try:
        execute("UPDATE uploads SET status = ? WHERE id = ?", (status, upload_id))
    except DatabaseError:
        log.exception("Could not update the status of upload %s", upload_id)


def _clear_previous_results(conn, upload_id):
    """Remove earlier alerts/summary of this upload and reset the per-log flags."""
    conn.execute("DELETE FROM alerts WHERE upload_id = ?", (upload_id,))      # cascades to threat_events
    conn.execute("DELETE FROM analysis_results WHERE upload_id = ?", (upload_id,))
    conn.execute("UPDATE logs SET severity = 'NONE', is_anomaly = 0, anomaly_score = NULL "
                 "WHERE upload_id = ?", (upload_id,))


def analyze_upload(upload_id):
    """Analyse one stored upload. Returns a summary dict. Raises AnalysisError on failure."""
    started = time.perf_counter()
    if query_one("SELECT id FROM uploads WHERE id = ?", (upload_id,)) is None:
        raise AnalysisError(f"Upload {upload_id} does not exist.", upload_id)
    logs = load_logs_from_db(upload_id)
    if not logs:
        raise AnalysisError("This upload has no logs to analyse.", upload_id)

    # ---- 1. detect and score (in memory; nothing is written yet) ----
    try:
        rules = run_rules(logs)
        ml = detect_anomalies(logs)
        covered = {log_id for f in rules.findings for log_id in f.log_ids}
        ml_findings = build_ml_findings(logs, ml, covered_log_ids=covered) if ml.trained else []
        findings = rules.findings + ml_findings
        scores = score_findings(findings, ml.by_log_id() if ml.trained else None)
    except ValueError as exc:                    # invalid settings in config.py
        _set_upload_status(upload_id, "analysis_failed")
        raise AnalysisError(str(exc), upload_id) from exc

    pairs = sorted(zip(findings, scores), key=lambda p: p[0].start_time)   # alert ids follow time
    counts = severity_counts(scores)
    duration = round(time.perf_counter() - started, 3)

    # ---- 2. store everything atomically ----
    log_severity = {}                            # log id -> highest severity of its alerts
    try:
        with db_session() as conn:
            _clear_previous_results(conn, upload_id)

            for finding, score in pairs:
                ml_score = score.ml_context.get("max_anomaly_score") if score.ml_context else None
                alert_id = conn.execute(_INSERT_ALERT, (
                    upload_id, finding.start_time, finding.threat_type, score.severity,
                    float(score.score), finding.source_ip, finding.destination_ip,
                    finding.username, finding.event_id, score.detection_method,
                    None if ml_score is None else float(ml_score),
                    finding.reason, score.explanation,
                    json.dumps(finding.recommended_steps), finding.sample_log,
                    finding.event_count,
                )).lastrowid

                conn.executemany(
                    "INSERT INTO threat_events (alert_id, log_id, rule_name, details) VALUES (?,?,?,?)",
                    [(alert_id, log_id, finding.rule_name, finding.threat_type)
                     for log_id in finding.log_ids])

                for log_id in finding.log_ids:
                    if SEVERITY_RANK[score.severity] > SEVERITY_RANK[log_severity.get(log_id, "NONE")]:
                        log_severity[log_id] = score.severity

            if log_severity:
                conn.executemany("UPDATE logs SET severity = ? WHERE id = ?",
                                 [(sev, log_id) for log_id, sev in log_severity.items()])
            if ml.trained:
                conn.executemany(
                    "UPDATE logs SET is_anomaly = ?, anomaly_score = ? WHERE id = ?",
                    [(1 if it.is_anomaly else 0, it.anomaly_score, it.log_id)
                     for it in ml.items if it.log_id is not None])

            conn.execute(
                "INSERT INTO analysis_results (upload_id, total_logs, total_alerts, critical_count, "
                "high_count, medium_count, low_count, anomaly_count, ml_trained, ml_note, "
                "duration_seconds) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (upload_id, len(logs), len(pairs), counts["CRITICAL"], counts["HIGH"],
                 counts["MEDIUM"], counts["LOW"], ml.anomaly_count, 1 if ml.trained else 0,
                 ml.note, duration))
            conn.execute("UPDATE uploads SET status = 'analyzed' WHERE id = ?", (upload_id,))
    except DatabaseError as exc:
        _set_upload_status(upload_id, "analysis_failed")
        raise AnalysisError(f"Could not save the analysis: {exc}", upload_id) from exc

    log.info("Upload %s analysed: %d logs, %d alerts, %d anomalies, %.2fs",
             upload_id, len(logs), len(pairs), ml.anomaly_count, duration)
    return {
        "upload_id": upload_id,
        "total_logs": len(logs),
        "total_alerts": len(pairs),
        "severity_counts": counts,
        "anomaly_count": ml.anomaly_count,
        "ml_trained": ml.trained,
        "ml_note": ml.note,
        "rule_counts": dict(rules.rule_counts),
        "ml_only_alerts": len(ml_findings),
        "duration_seconds": duration,
    }


def process_file(path, original_name=None, stored_name=None):
    """Parse + store a file (Stage 4), then analyse it. Returns {'ingest': ..., 'analysis': ...}."""
    ingest = ingest_file(path, original_name=original_name, stored_name=stored_name)
    analysis = analyze_upload(ingest["upload_id"])
    return {"ingest": ingest, "analysis": analysis}


def delete_upload(upload_id, upload_dir):
    """Delete an upload with all its logs/alerts (cascade) and its stored file. False if unknown."""
    row = query_one("SELECT stored_name FROM uploads WHERE id = ?", (upload_id,))
    if row is None:
        return False
    with db_session() as conn:
        conn.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))

    folder = Path(upload_dir).resolve()
    candidate = (folder / row["stored_name"]).resolve()
    if candidate.parent == folder and candidate.is_file():     # never delete outside the upload folder
        try:
            candidate.unlink()
        except OSError as exc:
            log.warning("Could not delete %s: %s", candidate, exc)
    return True