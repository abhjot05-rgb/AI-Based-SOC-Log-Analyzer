"""JSON parser: JSON array, wrapped JSON, JSON Lines, and nested objects."""
import json
from pathlib import Path

from parser import log_normalizer as norm
from parser.log_normalizer import ParseError, ParseResult

WRAPPER_KEYS = ("events", "logs", "records", "data", "entries", "items")


def _flatten(obj, prefix="", out=None, depth=0):
    """
    {"source": {"ip": "1.2.3.4"}} -> {"source_ip": "1.2.3.4", "ip": "1.2.3.4"}
    Both the full path and the short name are kept so aliases can match either.
    """
    out = {} if out is None else out
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and depth < 3:
            _flatten(value, f"{name}_", out, depth + 1)
        else:
            out.setdefault(name, value)
            if prefix:
                out.setdefault(str(key), value)
    return out


def _extract_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in WRAPPER_KEYS:
            if isinstance(data.get(key), list):
                return data[key]
        if any(norm.canonical_name(k) == "timestamp" for k in data):
            return [data]                       # a single event object
    raise ParseError("JSON must be an array of events, an object with an "
                     "'events'/'logs' list, or JSON Lines.")


def parse_json(path):
    result = ParseResult("json")
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")

    try:
        items = _extract_items(json.loads(text))
    except json.JSONDecodeError:
        # Not one JSON document: try JSON Lines (one object per line)
        result.format_name = "jsonl"
        items = []
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                result.total_rows += 1
                result.add_error(number, "invalid JSON")
        if not items:
            raise ParseError("File is neither valid JSON nor JSON Lines.")

    if len(items) > norm.MAX_ROWS_PER_FILE:
        raise ParseError(f"File has more than {norm.MAX_ROWS_PER_FILE:,} events; please split it.")

    for number, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            result.total_rows += 1
            result.add_error(number, "not a JSON object")
            continue
        flat = _flatten(item)
        if norm.is_blank_row(flat):
            continue
        result.total_rows += 1
        record, reason = norm.normalize_row(flat, raw_log=json.dumps(item, default=str))
        if record is None:
            result.add_error(number, reason)
        else:
            result.records.append(record)
    return result