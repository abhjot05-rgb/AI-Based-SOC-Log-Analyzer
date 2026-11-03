"""
Project health check. Run from the project folder:   python doctor.py

It only reads things: it never changes your files or your database.
Levels: OK = fine, WARN = worth knowing, FAIL = must be fixed before the app can work.
"""
import importlib.metadata as metadata
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

import config
from database.schema import SCHEMA_STATEMENTS

MIN_PYTHON = (3, 10)
PACKAGES = ["Flask", "pandas", "numpy", "scikit-learn", "joblib"]

REQUIRED_FILES = [
    "app.py", "config.py", "requirements.txt",
    "database/db.py", "database/schema.py",
    "parser/log_normalizer.py", "parser/csv_parser.py", "parser/json_parser.py",
    "parser/linux_parser.py", "parser/ingest.py",
    "detection/common.py", "detection/brute_force.py", "detection/port_scan.py",
    "detection/suspicious_login.py", "detection/account_privilege.py",
    "detection/suspicious_ip.py", "detection/rule_engine.py",
    "ml/feature_engineering.py", "ml/model.py", "ml/anomaly_detector.py",
    "analysis/threat_scoring.py", "analysis/answer_key_check.py",
    "generators/sample_logs.py",
    "services/analysis_pipeline.py", "services/queries.py", "services/analytics.py",
    "services/reports.py", "services/settings_view.py",
    "routes/api.py", "routes/pages.py",
    "templates/base.html", "templates/dashboard.html", "templates/logs.html",
    "templates/alerts.html", "templates/alert_details.html", "templates/threats.html",
    "templates/analytics.html", "templates/reports.html", "templates/settings.html",
    "templates/report_summary.html",
    "static/css/soc.css",
    "static/js/soc.js", "static/js/dashboard.js", "static/js/listpage.js",
    "static/js/logs.js", "static/js/alerts.js", "static/js/alert_details.js",
    "static/js/charts.js", "static/js/threats.js", "static/js/analytics.js",
    "static/js/reports.js", "static/js/settings.js",
]
VENDOR_FILES = ["bootstrap.min.css", "bootstrap.bundle.min.js", "chart.umd.js"]


# ---------------------------------------------------------------- database layout
def expected_schema():
    """{table: set of column names} built from database/schema.py in a throw-away memory database."""
    conn = sqlite3.connect(":memory:")
    try:
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        return {t: {r[1] for r in conn.execute(f"PRAGMA table_info({t})")} for t in tables}
    finally:
        conn.close()


def check_schema(db_path):
    """List of problems between a real database file and the expected layout ([] = fine)."""
    path = Path(db_path)
    if not path.exists():
        return []                                   # created automatically on first start
    problems = []
    conn = sqlite3.connect(path)
    try:
        for table, wanted in expected_schema().items():
            have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            if not have:
                problems.append(f"table '{table}' is missing")
            elif wanted - have:
                problems.append(f"table '{table}' lacks columns: {', '.join(sorted(wanted - have))}")
    except sqlite3.DatabaseError as exc:
        problems.append(f"the file is not a usable SQLite database ({exc})")
    finally:
        conn.close()
    return problems


# ---------------------------------------------------------------- individual checks
def check_python():
    v = sys.version_info
    text = f"Python {v.major}.{v.minor}.{v.micro}"
    if (v.major, v.minor) < MIN_PYTHON:
        return [("FAIL", f"{text}: version {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required")]
    return [("OK", text)]


def check_packages():
    results = []
    for name in PACKAGES:
        try:
            results.append(("OK", f"{name} {metadata.version(name)}"))
        except metadata.PackageNotFoundError:
            results.append(("FAIL", f"{name} is not installed (run: pip install -r requirements.txt)"))
    return results


def check_project_files():
    missing = [name for name in REQUIRED_FILES if not (config.BASE_DIR / name).is_file()]
    if missing:
        return [("FAIL", f"missing file: {name}") for name in missing]
    return [("OK", f"all {len(REQUIRED_FILES)} project files are present")]


def check_folders():
    results = []
    for folder in (config.DATA_DIR, config.UPLOAD_DIR, config.REPORTS_DIR):
        if not folder.is_dir():
            results.append(("WARN", f"{folder.name}/ does not exist yet (the app creates it on start)"))
            continue
        try:
            with tempfile.NamedTemporaryFile(dir=folder):
                pass
            results.append(("OK", f"{folder.name}/ exists and is writable"))
        except OSError as exc:
            results.append(("FAIL", f"{folder.name}/ is not writable: {exc}"))
    return results


def check_database():
    path = config.DATABASE_PATH
    if not Path(path).exists():
        return [("OK", "database file not created yet (it is created automatically on first start)")]
    problems = check_schema(path)
    if not problems:
        return [("OK", f"database layout matches the schema ({Path(path).name})")]
    results = [("FAIL", f"database: {p}") for p in problems]
    results.append(("FAIL", "fix: stop the app, delete data\\soc_analyzer.db (it only holds "
                            "demo data), then start the app again"))
    return results


def check_settings():
    from services import settings_view
    v = settings_view.validation()
    labels = {"detection_rules": "detection rules", "ml": "ML settings",
              "scoring": "scoring settings", "severity_bands": "severity bands"}
    results = []
    for key, label in labels.items():
        if v[key]["valid"]:
            results.append(("OK", f"{label} are valid"))
        else:
            results.append(("FAIL", f"{label}: {v[key]['error']}"))
    return results


def check_assets():
    vendor = config.BASE_DIR / "static" / "vendor"
    if all((vendor / name).is_file() for name in VENDOR_FILES):
        return [("OK", "Bootstrap and Chart.js are available offline (static/vendor/)")]
    return [("WARN", "no offline copies in static/vendor/: the pages load Bootstrap and Chart.js "
                     "from the internet (see Stage 9, section 6, to download them)")]


def check_port():
    host, port = config.Config.HOST, config.Config.PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return [("OK", f"port {port} on {host} is free")]
    except OSError:
        return [("WARN", f"port {port} is in use (normal if the app is already running; "
                         f"otherwise set SOC_PORT to another number)")]
    finally:
        sock.close()


CHECKS = [check_python, check_packages, check_project_files, check_folders,
          check_database, check_settings, check_assets, check_port]


def main():
    results = []
    for check in CHECKS:
        try:
            results.extend(check())
        except Exception as exc:                    # a broken check must not hide the others
            results.append(("FAIL", f"{check.__name__} could not run: {exc}"))
    for level, text in results:
        print(f"[{level:<4}] {text}")
    counts = {lvl: sum(1 for l, _ in results if l == lvl) for lvl in ("OK", "WARN", "FAIL")}
    print(f"\n{counts['OK']} ok, {counts['WARN']} warning(s), {counts['FAIL']} failure(s)")
    sys.exit(1 if counts["FAIL"] else 0)


if __name__ == "__main__":
    main()