"""
Central configuration for the SOC Log Analyzer.
Detection thresholds live here so rules are NOT hard-coded in the engine.
"""
import os
import secrets
from pathlib import Path

# ---------- Paths ----------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"
DATABASE_PATH = DATA_DIR / "soc_analyzer.db"
LOG_FILE = DATA_DIR / "app.log"


class Config:
    # Secret key comes from an environment variable. If none is set, a random
    # one is generated at startup (sessions reset on restart, which is fine here).
    SECRET_KEY = os.environ.get("SOC_SECRET_KEY") or secrets.token_hex(32)

    # ---------- Upload security ----------
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024          # 10 MB max upload
    ALLOWED_EXTENSIONS = {"csv", "json", "log", "txt"}

    # ---------- Pagination ----------
    LOGS_PER_PAGE = 50
    ALERTS_PER_PAGE = 25

    # ---------- Server ----------
    HOST = os.environ.get("SOC_HOST", "127.0.0.1")
    PORT = int(os.environ.get("SOC_PORT", "5000"))
    DEBUG = os.environ.get("SOC_DEBUG", "0") == "1"

# ---------- Rule-based detection thresholds ----------
# brute_force / port_scan / suspicious_ip: flagged when MORE THAN the threshold is seen.
# account_activity / privilege_activity:   flagged when AT LEAST repeat_threshold events are seen.
DETECTION_RULES = {
    "brute_force": {
        "enabled": True,
        "failed_attempts_threshold": 5,     # more than this many failures...
        "time_window_seconds": 120,         # ...within this window, same IP
        "success_check_seconds": 300,       # look for a successful login this long after the attack
    },
    "port_scan": {
        "enabled": True,
        "unique_ports_threshold": 15,       # more than this many distinct ports...
        "time_window_seconds": 60,          # ...within this window, same IP
    },
    "suspicious_login": {
        "enabled": True,
        "off_hours_enabled": True,
        "off_hours_start": 22,              # 22:00 (inclusive)
        "off_hours_end": 6,                 # 06:00 (exclusive)
        "multi_ip_enabled": True,
        "max_distinct_ips_per_user": 3,     # more than this many IPs for one user...
        "time_window_seconds": 3600,        # ...within this window
    },
    "account_activity": {
        "enabled": True,
        # created, enabled, password reset, disabled, locked out
        "event_ids": [4720, 4722, 4724, 4725, 4740],
        "event_types": ["account_created", "account_enabled", "password_reset",
                        "account_disabled", "account_lockout"],
        "repeat_threshold": 3,              # at least this many events...
        "time_window_seconds": 300,         # ...within this window
    },
    "privilege_activity": {
        "enabled": True,
        # special privileges assigned, member added to privileged groups
        "event_ids": [4672, 4728, 4732, 4756],
        "event_types": ["privilege_assigned", "group_member_added", "sudo_command"],
        "repeat_threshold": 2,
        "time_window_seconds": 300,
    },
    "suspicious_ip": {
        "enabled": True,
        "suspicious_event_threshold": 10,   # more than this many suspicious events...
        "time_window_seconds": 600,         # ...within this window, same IP
        "event_types": ["login_failure", "firewall_block", "account_lockout"],
        "suppress_if_covered": True,        # hide if brute force / port scan already explains it
    },
}

# ---------- Severity bands (threat score is 0-100) ----------
SEVERITY_BANDS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}
# ---------- Machine learning settings ----------
ML_SETTINGS = {
    # Share of events the model flags as unusual. This is a setting, NOT a measured
    # attack rate. Use a number in (0, 0.5], or "auto".
    "contamination": 0.05,
    "n_estimators": 100,
    "random_state": 42,
    "min_rows_to_train": 50,       # too little data -> skip ML safely
    "max_ml_alerts": 20,           # cap on ML-only findings (anomalies no rule explains)
    "feature_window_seconds": 300, # window for the "recent events from this IP" feature
}
# ---------- Threat scoring (score is 0-100, see SEVERITY_BANDS) ----------
# Points are heuristic weights chosen for this project, not learned from labelled data.
SCORING_SETTINGS = {
    # Starting points by threat type
    "base_scores": {
        "Brute Force": 25,
        "Port Scan": 20,
        "Suspicious Login": 15,
        "Suspicious Account Activity": 20,
        "Privilege Escalation Activity": 25,
        "Suspicious IP Activity": 15,
        "Anomalous Activity": 10,        # ML-only findings
    },
    "default_base_score": 10,            # for threat types not listed above

    # Maximum points each factor can add
    "max_points": {
        "attempts": 20,                  # failed attempts / volume over the rule threshold
        "frequency": 10,                 # events per minute
        "accounts": 10,                  # affected accounts
        "ml": 15,                        # Isolation Forest anomaly score
        "ip_behavior": 15,               # source IP behaviour
        "escalation": 20,                # signs that the attack went further
    },

    "attempts_full_at_multiple": 3,      # full attempt points at 3x the rule threshold
    "frequency_low_per_minute": 2,       # 0 frequency points at or below this rate
    "frequency_high_per_minute": 30,     # full frequency points at or above this rate
    "ml_low": 0.50,                      # 0 ML points at or below this anomaly score
    "ml_high": 0.75,                     # full ML points at or above this anomaly score

    "ip_points": {"external": 6, "repeat": 6, "multi_target": 3},
    "escalation_points": {
        "brute_force_success": 20,       # successful login from the same IP after the failures
        "off_hours_external": 10,        # off-hours login from an external IP
        "multi_ip_external": 10,         # one user logging in from several IPs incl. external
        "accounts_created": 10,          # new accounts created in the burst
        "privilege_combo": 10,           # privileges assigned + group change or sudo
        "scan_allowed_ports": 8,         # some probed ports were allowed through
    },
}