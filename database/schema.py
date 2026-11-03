"""
Database schema for the SOC Log Analyzer.
Pure definitions only: no connections are opened here.
"""

SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
LOG_SEVERITY_LEVELS = ("NONE",) + SEVERITY_LEVELS     # logs without an alert use NONE
ALERT_STATUSES = ("New", "Investigating", "Resolved", "False Positive")
DETECTION_METHODS = ("RULE", "ML", "RULE+ML")
USER_ROLES = ("admin", "analyst")


def _in_list(values):
    """Build a SQL list like ('A','B') for CHECK constraints (values are our own constants)."""
    return "(" + ",".join(f"'{v}'" for v in values) + ")"


SCHEMA_STATEMENTS = [
    # ---------- users ----------
    f"""
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL DEFAULT 'analyst'
                      CHECK (role IN {_in_list(USER_ROLES)}),
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # ---------- uploads ----------
    """
    CREATE TABLE IF NOT EXISTS uploads (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        original_name TEXT NOT NULL,
        stored_name   TEXT NOT NULL,
        file_type     TEXT,
        total_rows    INTEGER NOT NULL DEFAULT 0,
        status        TEXT NOT NULL DEFAULT 'uploaded',
        uploaded_at   TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # ---------- logs ----------
    f"""
    CREATE TABLE IF NOT EXISTS logs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        upload_id        INTEGER NOT NULL
                         REFERENCES uploads(id) ON DELETE CASCADE,
        timestamp        TEXT,
        source_ip        TEXT,
        destination_ip   TEXT,
        username         TEXT,
        event_id         INTEGER,
        event_type       TEXT,
        protocol         TEXT,
        source_port      INTEGER,
        destination_port INTEGER,
        action           TEXT,
        status           TEXT,
        message          TEXT,
        raw_log          TEXT,
        severity         TEXT NOT NULL DEFAULT 'NONE'
                         CHECK (severity IN {_in_list(LOG_SEVERITY_LEVELS)}),
        is_anomaly       INTEGER NOT NULL DEFAULT 0 CHECK (is_anomaly IN (0, 1)),
        anomaly_score    REAL
    )
    """,

    # ---------- alerts ----------
    f"""
    CREATE TABLE IF NOT EXISTS alerts (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        upload_id             INTEGER NOT NULL
                              REFERENCES uploads(id) ON DELETE CASCADE,
        timestamp             TEXT,
        threat_type           TEXT NOT NULL,
        severity              TEXT NOT NULL
                              CHECK (severity IN {_in_list(SEVERITY_LEVELS)}),
        threat_score          REAL NOT NULL DEFAULT 0,
        source_ip             TEXT,
        destination_ip        TEXT,
        username              TEXT,
        event_id              INTEGER,
        detection_method      TEXT NOT NULL
                              CHECK (detection_method IN {_in_list(DETECTION_METHODS)}),
        ml_anomaly_score      REAL,
        reason                TEXT,
        severity_reason       TEXT,
        recommended_steps     TEXT,
        original_log          TEXT,
        related_event_count   INTEGER NOT NULL DEFAULT 1,
        status                TEXT NOT NULL DEFAULT 'New'
                              CHECK (status IN {_in_list(ALERT_STATUSES)}),
        created_at            TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # ---------- threat_events (alert <-> log link) ----------
    """
    CREATE TABLE IF NOT EXISTS threat_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id   INTEGER NOT NULL
                   REFERENCES alerts(id) ON DELETE CASCADE,
        log_id     INTEGER
                   REFERENCES logs(id) ON DELETE SET NULL,
        rule_name  TEXT,
        details    TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # ---------- analysis_results ----------
    """
    CREATE TABLE IF NOT EXISTS analysis_results (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        upload_id        INTEGER NOT NULL
                         REFERENCES uploads(id) ON DELETE CASCADE,
        total_logs       INTEGER NOT NULL DEFAULT 0,
        total_alerts     INTEGER NOT NULL DEFAULT 0,
        critical_count   INTEGER NOT NULL DEFAULT 0,
        high_count       INTEGER NOT NULL DEFAULT 0,
        medium_count     INTEGER NOT NULL DEFAULT 0,
        low_count        INTEGER NOT NULL DEFAULT 0,
        anomaly_count    INTEGER NOT NULL DEFAULT 0,
        ml_trained       INTEGER NOT NULL DEFAULT 0 CHECK (ml_trained IN (0, 1)),
        ml_note          TEXT,
        duration_seconds REAL,
        created_at       TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # ---------- indexes (speed up the log viewer and alert filters) ----------
    "CREATE INDEX IF NOT EXISTS idx_logs_upload    ON logs(upload_id)",
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_logs_username  ON logs(username)",
    "CREATE INDEX IF NOT EXISTS idx_logs_severity  ON logs(severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_threat    ON alerts(threat_type)",
    "CREATE INDEX IF NOT EXISTS idx_threat_events_alert ON threat_events(alert_id)",
    "CREATE INDEX IF NOT EXISTS idx_threat_events_log ON threat_events(log_id)",
]
# Columns added after the first release. init_db() adds them to databases created earlier,
# so existing data is never lost.
COLUMN_MIGRATIONS = [
    ("alerts", "severity_reason", "TEXT"),
]