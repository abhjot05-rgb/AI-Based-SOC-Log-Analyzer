"""
Linux authentication log parser (/var/log/auth.log, /var/log/secure).

Understands: SSH failed/accepted logins, session closed, sudo, useradd,
usermod (group add) and passwd. Other valid syslog lines are 'ignored'.
"""
import re
from datetime import datetime, timedelta

from parser import log_normalizer as norm
from parser.log_normalizer import ParseError, ParseResult

_PROC = r"(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+" + _PROC)
ISO_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+" + _PROC)

FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
CLOSED_RE = re.compile(r"session closed for user (?P<user>\S+)")
SUDO_RE = re.compile(r"^(?P<user>\S+)\s+:\s+.*COMMAND=")
USERADD_RE = re.compile(r"new user: name=(?P<user>[^,\s]+)")
USERMOD_RE = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
PASSWD_RE = re.compile(r"password changed for (?P<user>\S+)")


def _syslog_timestamp(mon, day, hms, now):
    """Syslog has no year: use this year, or last year if that would be in the future."""
    for year in (now.year, now.year - 1):
        try:
            dt = datetime.strptime(f"{year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")
        except ValueError:                    # e.g. Feb 29 in a non-leap year
            continue
        if dt <= now + timedelta(days=1):
            return dt.strftime(norm.TS_OUT)
    return None


def _ssh_fields(event_type, m):
    return {"event_type": event_type, "username": m["user"], "source_ip": m["ip"],
            "source_port": m["port"], "protocol": "TCP", "destination_port": 22}


def _classify(msg, proc):
    """Return a dict of extracted fields, or None if this is not an event we track."""
    m = FAILED_RE.search(msg)
    if m:
        return _ssh_fields("login_failure", m)
    m = ACCEPTED_RE.search(msg)
    if m:
        return _ssh_fields("login_success", m)
    m = CLOSED_RE.search(msg)
    if m:
        return {"event_type": "logout", "username": m["user"]}
    m = SUDO_RE.match(msg)
    if m and proc == "sudo":
        return {"event_type": "sudo_command", "username": m["user"]}
    m = USERADD_RE.search(msg)
    if m:
        return {"event_type": "account_created", "username": m["user"]}
    m = USERMOD_RE.search(msg)
    if m:
        return {"event_type": "group_member_added", "username": m["user"]}
    m = PASSWD_RE.search(msg)
    if m:
        return {"event_type": "password_reset", "username": m["user"]}
    return None


def parse_linux_auth(path, now=None):
    now = now or datetime.now()
    result = ParseResult("linux_auth")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            result.total_rows += 1
            if result.total_rows > norm.MAX_ROWS_PER_FILE:
                raise ParseError(
                    f"File has more than {norm.MAX_ROWS_PER_FILE:,} lines; please split it.")

            match = SYSLOG_RE.match(line)
            if match:
                timestamp = _syslog_timestamp(match["mon"], match["day"], match["time"], now)
            else:
                match = ISO_RE.match(line)
                timestamp = match["ts"] if match else None

            if not match:
                result.add_error(line_no, "not a syslog-formatted line")
                continue
            if timestamp is None:
                result.add_error(line_no, "unreadable timestamp")
                continue

            fields = _classify(match["msg"], match["proc"])
            if fields is None:
                result.ignored += 1
                continue

            row = {"timestamp": timestamp, "message": match["msg"], **fields}
            record, reason = norm.normalize_row(row, raw_log=line)
            if record is None:
                result.add_error(line_no, reason)
            else:
                result.records.append(record)
    return result