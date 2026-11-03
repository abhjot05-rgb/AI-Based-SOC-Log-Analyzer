"""
Log normalizer: turns messy rows from any log source into ONE standard record.

Every parser (CSV, JSON, Linux) builds a plain dict of raw values and calls
normalize_row(). This is the only place where cleaning rules live.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

CANONICAL_FIELDS = [
    "timestamp", "source_ip", "destination_ip", "username", "event_id",
    "event_type", "protocol", "source_port", "destination_port",
    "action", "status", "message",
]

MAX_TEXT_LENGTH = 1000
MAX_RAW_LENGTH = 2000
MAX_ROWS_PER_FILE = 100_000
TS_OUT = "%Y-%m-%d %H:%M:%S"


class ParseError(Exception):
    """The whole file cannot be used (wrong format, no timestamp column, too big...)."""


@dataclass
class ParseResult:
    format_name: str
    records: list = field(default_factory=list)
    total_rows: int = 0        # non-blank rows/lines read
    skipped: int = 0           # malformed rows that were rejected
    ignored: int = 0           # valid lines that are not security events (Linux only)
    errors: list = field(default_factory=list)   # first few reasons, for the user

    MAX_ERRORS_KEPT = 20

    def add_error(self, location, reason):
        self.skipped += 1
        if len(self.errors) < self.MAX_ERRORS_KEPT:
            self.errors.append(f"Row {location}: {reason}")


# ======================================================================
# Field-name mapping
# ======================================================================
_ALIASES = {
    "timestamp": ["time", "timecreated", "datetime", "date", "eventtime",
                  "logtime", "systemtime", "@timestamp"],
    "source_ip": ["srcip", "src", "sourceaddress", "sourcenetworkaddress", "clientip",
                  "remoteip", "remoteaddress", "ip", "ipaddress", "ipaddr", "callerip"],
    "destination_ip": ["destip", "dstip", "dst", "destinationaddress", "destaddress",
                       "dest", "targetip", "serverip"],
    "username": ["user", "usr", "targetusername", "targetuser", "account",
                 "accountname", "subjectusername"],
    "event_id": ["eventid", "eventcode"],
    "event_type": ["eventtype", "type", "category", "eventname"],
    "protocol": ["proto", "ipprotocol"],
    "source_port": ["srcport", "sport", "clientport"],
    "destination_port": ["destport", "dstport", "dport", "serverport"],
    "action": ["act"],
    "status": ["result", "outcome"],
    "message": ["msg", "description", "details", "text", "info", "logmessage"],
}


def normalize_key(name):
    """'Target_User-Name' -> 'targetusername' (lowercase letters/digits only)."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


ALIAS_MAP = {}
for _canonical, _names in _ALIASES.items():
    for _name in [_canonical] + _names:
        ALIAS_MAP[normalize_key(_name)] = _canonical


def canonical_name(name):
    """Standard field name for a column header, or None if we don't recognise it."""
    return ALIAS_MAP.get(normalize_key(name))


# ======================================================================
# Small cleaning helpers
# ======================================================================
_BLANK_VALUES = {"", "-", "null", "none", "n/a", "nan"}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _is_blank(value):
    return value is None or str(value).strip().lower() in _BLANK_VALUES


def is_blank_row(row):
    """True if every value in the row is empty (the key None holds CSV overflow cells)."""
    return all(_is_blank(v) for k, v in row.items() if k is not None)


def map_fields(row):
    """Rename a raw row's keys to canonical names. First non-empty value wins."""
    mapped = {}
    for key, value in row.items():
        if key is None:
            continue
        canonical = canonical_name(key)
        if canonical and canonical not in mapped and not _is_blank(value):
            mapped[canonical] = value
    return mapped


def clean_text(value, max_len=MAX_TEXT_LENGTH):
    if _is_blank(value):
        return None
    text = _CONTROL_RE.sub(" ", str(value)).strip()
    return text[:max_len] or None


def clean_int(value, low, high):
    if _is_blank(value) or isinstance(value, bool):
        return None
    try:
        number = int(float(str(value).strip()))
    except (ValueError, OverflowError):
        return None
    return number if low <= number <= high else None


def clean_ip(value):
    """Return a valid IPv4/IPv6 address string, or None."""
    if _is_blank(value):
        return None
    text = str(value).strip().strip("[]")
    if text.lower().startswith("::ffff:"):               # Windows IPv4-mapped form
        text = text[7:]
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d+", text):  # '1.2.3.4:5555'
        text = text.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


_PROTO_NUMBERS = {"1": "ICMP", "6": "TCP", "17": "UDP"}


def normalize_protocol(value):
    if _is_blank(value):
        return None
    text = str(value).strip().upper()
    if text.endswith(".0"):
        text = text[:-2]
    text = _PROTO_NUMBERS.get(text, text)
    return text if re.fullmatch(r"[A-Z0-9_-]{1,10}", text) else None


_STATUS_MAP = {
    "success": "success", "succeeded": "success", "successful": "success",
    "ok": "success", "audit success": "success",
    "failure": "failure", "failed": "failure", "fail": "failure",
    "audit failure": "failure", "error": "failure", "denied": "failure",
    "blocked": "blocked", "block": "blocked", "drop": "blocked", "dropped": "blocked",
    "deny": "blocked", "reject": "blocked", "rejected": "blocked",
    "allowed": "allowed", "allow": "allowed", "permit": "allowed",
    "accept": "allowed", "accepted": "allowed",
}


def normalize_status(value):
    if _is_blank(value):
        return None
    text = " ".join(str(value).lower().split())
    return _STATUS_MAP.get(text, re.sub(r"[^a-z0-9_ ]", "", text)[:30] or None)


def clean_event_type(value):
    if _is_blank(value):
        return None
    text = re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")
    return text[:50] or None


# ======================================================================
# Timestamps
# ======================================================================
_EPOCH_RE = re.compile(r"^\d{10}(\.\d+)?$|^\d{13}$")
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")      # Windows writes 7 fractional digits
_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
    "%d-%b-%Y %H:%M:%S", "%b %d %Y %H:%M:%S",
)


def _from_epoch(number):
    try:
        if number > 1e11:                      # milliseconds
            number /= 1000
        return datetime.fromtimestamp(number, timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def parse_timestamp(value):
    """Return 'YYYY-MM-DD HH:MM:SS' (UTC if a timezone was given) or None."""
    if _is_blank(value):
        return None

    dt = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        dt = _from_epoch(value)
    else:
        text = str(value).strip()
        if _EPOCH_RE.match(text):
            dt = _from_epoch(float(text))
        else:
            iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
            iso = _FRACTION_RE.sub(r"\1", iso)
            try:
                dt = datetime.fromisoformat(iso)
            except ValueError:
                for fmt in _TS_FORMATS:
                    try:
                        dt = datetime.strptime(text, fmt)
                        break
                    except ValueError:
                        continue

    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    if not 1990 <= dt.year <= 2100:            # reject obviously wrong dates
        return None
    return dt.strftime(TS_OUT)


# ======================================================================
# Event type / action / status knowledge
# ======================================================================
EVENT_ID_TO_TYPE = {
    4624: "login_success", 4625: "login_failure", 4634: "logout", 4647: "logout",
    5156: "network_connection", 5157: "firewall_block",
    4720: "account_created", 4722: "account_enabled", 4724: "password_reset",
    4725: "account_disabled", 4740: "account_lockout",
    4672: "privilege_assigned",
    4728: "group_member_added", 4732: "group_member_added", 4756: "group_member_added",
}

# event_type -> (default action, default status)
TYPE_DEFAULTS = {
    "login_success": ("login", "success"),
    "login_failure": ("login", "failure"),
    "logout": ("logout", "success"),
    "network_connection": ("allow", "allowed"),
    "firewall_block": ("deny", "blocked"),
    "account_created": ("create_account", "success"),
    "account_enabled": ("enable_account", "success"),
    "password_reset": ("reset_password", "success"),
    "account_disabled": ("disable_account", "success"),
    "account_lockout": ("lockout", "success"),
    "privilege_assigned": ("assign_privileges", "success"),
    "group_member_added": ("add_to_group", "success"),
    "sudo_command": ("sudo", "success"),
}


def infer_type_from_message(message):
    """Last-resort guess from keywords. Returns None if nothing matches."""
    if not message:
        return None
    t = message.lower()
    has_auth = any(w in t for w in ("logon", "login", "log in", "password", "authentication"))
    if has_auth and any(w in t for w in ("fail", "invalid", "denied", "incorrect")):
        return "login_failure"
    if has_auth and any(w in t for w in ("success", "accepted")):
        return "login_success"
    if "logged off" in t or "logoff" in t or "session closed" in t:
        return "logout"
    if "locked out" in t or "lockout" in t:
        return "account_lockout"
    if "sudo" in t:
        return "sudo_command"
    if "privilege" in t and "assigned" in t:
        return "privilege_assigned"
    if "account" in t and "created" in t:
        return "account_created"
    if "account" in t and "disabled" in t:
        return "account_disabled"
    if "blocked" in t or "dropped" in t:
        return "firewall_block"
    return None


# ======================================================================
# Main entry point
# ======================================================================
def normalize_row(row, raw_log=None):
    """
    Convert one raw row (dict) into a standard record.
    Returns (record, None) on success or (None, reason) if the row must be skipped.
    """
    m = map_fields(row)

    timestamp = parse_timestamp(m.get("timestamp"))
    if timestamp is None:
        return None, "missing or unreadable timestamp"

    event_id = clean_int(m.get("event_id"), 0, 999_999)
    message = clean_text(m.get("message"))
    status = normalize_status(m.get("status"))

    event_type = clean_event_type(m.get("event_type"))
    if not event_type and event_id in EVENT_ID_TO_TYPE:
        event_type = EVENT_ID_TO_TYPE[event_id]
    if not event_type:
        event_type = infer_type_from_message(message) or "unknown"

    default_action, default_status = TYPE_DEFAULTS.get(event_type, (None, None))
    action = clean_text(m.get("action"), 50)
    action = action.lower() if action else default_action

    if event_type in ("firewall_block", "network_connection") and default_status:
        status = default_status        # Windows says 'Audit Failure' for blocked traffic
    elif status is None:
        status = default_status

    record = {
        "timestamp": timestamp,
        "source_ip": clean_ip(m.get("source_ip")),
        "destination_ip": clean_ip(m.get("destination_ip")),
        "username": clean_text(m.get("username"), 128),
        "event_id": event_id,
        "event_type": event_type,
        "protocol": normalize_protocol(m.get("protocol")),
        "source_port": clean_int(m.get("source_port"), 0, 65535),
        "destination_port": clean_int(m.get("destination_port"), 0, 65535),
        "action": action,
        "status": status,
        "message": message,
        "raw_log": clean_text(raw_log, MAX_RAW_LENGTH),
    }
    return record, None