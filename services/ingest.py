"""
File ingestion: CSV / JSON / Linux auth log / Windows-style CSV
  -> normalized pandas DataFrame with the columns the detectors expect.

Missing fields become empty strings (ports become NaN), so partial logs never crash.
"""
import json
import logging
import re
from datetime import datetime, timedelta

import pandas as pd

from config import APP_CONFIG

logger = logging.getLogger(__name__)


class IngestError(ValueError):
    """Raised with a user-friendly message when a file cannot be used."""


TEXT_FIELDS = ["source_ip", "destination_ip", "username", "event_id",
               "event_type", "protocol", "action", "status", "message"]
PORT_FIELDS = ["source_port", "destination_port"]
OUTPUT_COLUMNS = (["timestamp", "source_ip", "destination_ip", "username", "event_id",
                   "event_type", "protocol", "source_port", "destination_port",
                   "action", "status", "message", "raw_log"])

# Column names found in real exports (lowercased, punctuation removed) -> our field.
_ALIAS_LISTS = {
    "timestamp": ["timestamp", "time", "timecreated", "datetime", "date", "eventtime",
                  "loggedat", "timegenerated", "createdat"],
    "source_ip": ["sourceip", "srcip", "src", "sourceaddress", "sourcenetworkaddress",
                  "ipaddress", "clientip", "remoteip", "ip", "srcaddr"],
    "destination_ip": ["destinationip", "destip", "dstip", "dst", "destinationaddress",
                       "targetip", "dstaddr"],
    "username": ["username", "user", "account", "accountname", "targetusername",
                 "subjectusername", "targetaccount"],
    "event_id": ["eventid", "eventcode", "eid"],
    "event_type": ["eventtype", "type", "category", "event", "eventname", "task",
                   "taskcategory"],
    "protocol": ["protocol", "proto"],
    "source_port": ["sourceport", "srcport", "sport"],
    "destination_port": ["destinationport", "destport", "dstport", "dport", "port",
                         "targetport"],
    "action": ["action"],
    "status": ["status", "result", "outcome"],
    "message": ["message", "description", "msg", "details", "rawmessage"],
}
ALIASES = {alias: field for field, lst in _ALIAS_LISTS.items() for alias in lst}

# Windows security event IDs -> readable type / status
EVENT_TYPES = {
    "4624": "login_success", "4625": "login_failed", "4634": "logoff",
    "4648": "explicit_credential_login", "4672": "special_privileges_assigned",
    "4720": "account_created", "4722": "account_enabled",
    "4723": "password_change_attempt", "4724": "password_reset",
    "4725": "account_disabled", "4726": "account_deleted",
    "4728": "member_added_to_group", "4732": "member_added_to_group",
    "4738": "account_changed", "4740": "account_locked", "4756": "member_added_to_group",
}
STATUS_BY_EVENT_ID = {"4624": "success", "4625": "failure"}
_EMPTY_MARKERS = {"-": "", "nan": "", "NaN": "", "None": "", "null": "", "NULL": ""}


# ----------------------------------------------------------------- shared
def _max_rows():
    return APP_CONFIG["max_rows"]


def _parse_times(series):
    try:
        t = pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
    except (TypeError, ValueError):               # older pandas without format="mixed"
        t = pd.to_datetime(series, errors="coerce", utc=True)
    return t.dt.tz_localize(None)


def _normalize(raw, fmt):
    """Map arbitrary column names onto the standard fields."""
    if raw.empty:
        raise IngestError("The file contains no log rows.")
    if len(raw) > _max_rows():
        raise IngestError(f"File has more than {_max_rows():,} rows. Split it or raise 'max_rows' in config.")

    raw = raw.fillna("").astype(str)
    raw_lines = raw.to_json(orient="records", lines=True, force_ascii=False).splitlines()

    mapping = {}
    for col in raw.columns:
        field = ALIASES.get(re.sub(r"[^a-z0-9]", "", str(col).lower()))
        if field and field not in mapping.values():
            mapping[col] = field
    if "timestamp" not in mapping.values():
        raise IngestError("No timestamp column found. Expected a column such as "
                          "'timestamp', 'time' or 'TimeCreated'.")

    out = pd.DataFrame(index=raw.index)
    for col, field in mapping.items():
        out[field] = raw[col]
    for field in TEXT_FIELDS:
        out[field] = (out[field] if field in out.columns else "")
        out[field] = out[field].astype(str).str.strip().replace(_EMPTY_MARKERS)
    for field in PORT_FIELDS:
        out[field] = pd.to_numeric(out[field], errors="coerce") if field in out.columns else float("nan")

    out["event_id"] = out["event_id"].str.replace(r"\.0$", "", regex=True)
    derived = out["event_id"].map(EVENT_TYPES).fillna("")
    out["event_type"] = out["event_type"].where(out["event_type"] != "", derived)
    out["status"] = out["status"].str.lower()
    out["status"] = out["status"].where(out["status"] != "", out["event_id"].map(STATUS_BY_EVENT_ID).fillna(""))
    out["action"] = out["action"].str.lower()
    out["timestamp"] = _parse_times(out["timestamp"]) if "timestamp" in out.columns else pd.NaT
    out["raw_log"] = raw_lines

    n_read = len(out)
    out = out.dropna(subset=["timestamp"])
    if out.empty:
        raise IngestError("No row had a readable timestamp.")
    return out[OUTPUT_COLUMNS].reset_index(drop=True), {"format": fmt, "rows_read": n_read,
                                                       "rows_skipped": n_read - len(out)}


# ----------------------------------------------------------------- CSV / JSON
def _read_csv(path):
    try:
        raw = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig",
                          encoding_errors="replace", on_bad_lines="skip",
                          nrows=_max_rows() + 1)
    except pd.errors.EmptyDataError:
        raise IngestError("The CSV file is empty.")
    except (pd.errors.ParserError, UnicodeError) as exc:
        raise IngestError(f"Could not read the CSV file: {exc}")
    return _normalize(raw, "csv")


def _read_json(path):
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:                 # maybe JSON Lines: one object per line
        data = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if isinstance(data, dict):
        for key in ("logs", "events", "records", "data", "items"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    data = [d for d in data if isinstance(d, dict)]
    if not data:
        raise IngestError("No JSON log objects found in the file.")
    return _normalize(pd.json_normalize(data), "json")


# ----------------------------------------------------------------- Linux auth.log
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
                     r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\S*\s+"
                  r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
_FAILED = re.compile(rf"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from {_IP} port (?P<port>\d+)")
_ACCEPTED = re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from {_IP} port (?P<port>\d+)")
_SUDO_DENIED = re.compile(r"^(?P<user>\S+)\s*:\s*.*?(NOT in sudoers|incorrect password attempts)")
_SUDO_CMD = re.compile(r"^(?P<user>\S+)\s*:\s*.*COMMAND=")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_USERDEL = re.compile(r"delete user '(?P<user>[^']+)'")


def _syslog_time(mon, day, clock):
    """auth.log has no year: assume this year, or last year if that would be in the future."""
    now = datetime.now()
    ts = datetime.strptime(f"{now.year} {mon} {int(day)} {clock}", "%Y %b %d %H:%M:%S")
    return ts - timedelta(days=365) if ts > now + timedelta(days=1) else ts


def _classify(proc, msg):
    """Returns (event_type, status, user, ip, port, protocol) or None to skip the line."""
    if m := _FAILED.search(msg):
        return "login_failed", "failure", m["user"], m["ip"], m["port"], "ssh"
    if m := _ACCEPTED.search(msg):
        return "login_success", "success", m["user"], m["ip"], m["port"], "ssh"
    if proc.startswith("sudo"):
        if m := _SUDO_DENIED.search(msg):
            return "sudo_denied", "failure", m["user"], "", None, ""
        if m := _SUDO_CMD.search(msg):
            return "sudo_command", "success", m["user"], "", None, ""
    if m := _USERADD.search(msg):
        return "account_created", "success", m["user"], "", None, ""
    if m := _USERDEL.search(msg):
        return "account_deleted", "success", m["user"], "", None, ""
    return None     # session lines etc. are skipped (they would double-count logins)


def _read_linux(path):
    rows, n_read = [], 0
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            n_read += 1
            if n_read > _max_rows():
                raise IngestError(f"File has more than {_max_rows():,} lines.")
            m = _SYSLOG.match(line)
            if m:
                ts = _syslog_time(m["mon"], m["day"], m["time"])
            elif (m := _ISO.match(line)):
                ts = pd.to_datetime(m["ts"], errors="coerce")
            else:
                continue
            result = _classify(m["proc"], m["msg"])
            if result is None or pd.isna(ts):
                continue
            etype, status, user, ip, port, proto = result
            rows.append({"timestamp": ts, "source_ip": ip, "destination_ip": "",
                         "username": user, "event_id": "", "event_type": etype,
                         "protocol": proto, "source_port": float(port) if port else float("nan"),
                         "destination_port": 22.0 if proto == "ssh" else float("nan"),
                         "action": "", "status": status, "message": m["msg"], "raw_log": line})
    if not rows:
        raise IngestError("No recognizable authentication events found. "
                          "Supported: sshd failed/accepted logins, sudo, useradd/userdel.")
    out = pd.DataFrame(rows, columns=OUTPUT_COLUMNS)
    return out, {"format": "linux", "rows_read": n_read, "rows_skipped": n_read - len(out)}


# ----------------------------------------------------------------- public API
def ingest_file(path, fmt="auto"):
    """Returns (DataFrame, info). Raises IngestError with a readable message."""
    if fmt == "auto":
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        fmt = {"csv": "csv", "json": "json"}.get(ext, "linux")
    readers = {"csv": _read_csv, "json": _read_json, "linux": _read_linux}
    if fmt not in readers:
        raise IngestError(f"Unknown format '{fmt}'.")
    df, info = readers[fmt](path)
    logger.info("Ingested %s: %d rows kept, %d skipped", fmt, len(df), info["rows_skipped"])
    return df, info