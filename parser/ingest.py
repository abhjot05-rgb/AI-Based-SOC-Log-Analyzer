"""
Ingestion: detect the file format, parse it, and store the logs in SQLite.

Command line (stores into your real database):
    python -m parser.ingest data/samples/sample_windows_security.csv
"""
import argparse
import logging
from pathlib import Path

from database.db import db_session, init_db
from parser import log_normalizer as norm
from parser.csv_parser import parse_csv
from parser.json_parser import parse_json
from parser.linux_parser import SYSLOG_RE, ISO_RE, parse_linux_auth
from parser.log_normalizer import ParseError

log = logging.getLogger("soc.ingest")

# Column names come from our own constants (never from user input);
# the VALUES are always passed as ? parameters.
_LOG_COLUMNS = ["upload_id"] + norm.CANONICAL_FIELDS + ["raw_log"]
_INSERT_LOG_SQL = (
    f"INSERT INTO logs ({', '.join(_LOG_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_LOG_COLUMNS))})"
)


def _peek(path, size=4096):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        return f.read(size)


def detect_format(path):
    """Return 'csv', 'json' or 'linux_auth'. Raises ParseError if unknown."""
    ext = Path(path).suffix.lower()
    if ext == ".csv":
        return "csv"
    if ext == ".json":
        return "json"

    head = _peek(path)
    first_line = next((l for l in head.splitlines() if l.strip()), "")
    if first_line.lstrip().startswith(("{", "[")):
        return "json"
    if SYSLOG_RE.match(first_line) or ISO_RE.match(first_line):
        return "linux_auth"
    if "," in first_line:
        return "csv"
    raise ParseError("Could not recognise the log format (expected CSV, JSON or Linux auth log).")


def parse_file(path):
    """Detect the format and parse. Returns a ParseResult."""
    try:
        kind = detect_format(path)
        if kind == "csv":
            return parse_csv(path)
        if kind == "json":
            return parse_json(path)
        return parse_linux_auth(path)
    except OSError as exc:
        raise ParseError(f"Cannot read file: {exc}") from exc


def ingest_file(path, original_name=None, stored_name=None):
    """
    Parse a file and store everything in ONE transaction
    (an upload row + all its log rows, or nothing at all).
    """
    path = Path(path)
    result = parse_file(path)
    if not result.records:
        detail = f" First problem: {result.errors[0]}" if result.errors else ""
        raise ParseError("No valid log rows were found in this file." + detail)

    rows = [
        (None, *[rec[name] for name in norm.CANONICAL_FIELDS], rec["raw_log"])
        for rec in result.records
    ]

    with db_session() as conn:
        cursor = conn.execute(
            "INSERT INTO uploads (original_name, stored_name, file_type, total_rows, status) "
            "VALUES (?, ?, ?, ?, 'parsed')",
            (original_name or path.name, stored_name or path.name,
             result.format_name, len(result.records)),
        )
        upload_id = cursor.lastrowid
        conn.executemany(_INSERT_LOG_SQL, [(upload_id,) + row[1:] for row in rows])

    log.info("Ingested %s as %s: %d stored, %d skipped, %d ignored",
             path.name, result.format_name, len(result.records), result.skipped, result.ignored)
    return {
        "upload_id": upload_id,
        "format": result.format_name,
        "total_rows": result.total_rows,
        "stored": len(result.records),
        "skipped": result.skipped,
        "ignored": result.ignored,
        "errors": result.errors,
    }


def main():
    parser = argparse.ArgumentParser(description="Parse log files and store them in the database.")
    parser.add_argument("files", nargs="+", help="one or more log files")
    args = parser.parse_args()

    init_db()
    for name in args.files:
        print(f"\n{name}")
        try:
            s = ingest_file(name)
        except ParseError as exc:
            print(f"  FAILED: {exc}")
            continue
        print(f"  format: {s['format']} | rows read: {s['total_rows']} | stored: {s['stored']} "
              f"| skipped: {s['skipped']} | ignored: {s['ignored']}")
        print(f"  upload id: {s['upload_id']}")
        for err in s["errors"][:5]:
            print(f"  - {err}")


if __name__ == "__main__":
    main()