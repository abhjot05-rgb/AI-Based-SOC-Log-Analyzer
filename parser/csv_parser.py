"""CSV parser: handles generic CSV and Windows-style Security-event CSV exports."""
import csv
import itertools
import json

from parser import log_normalizer as norm
from parser.log_normalizer import ParseError, ParseResult


def _detect_delimiter(first_line):
    counts = {d: first_line.count(d) for d in (",", ";", "\t", "|")}
    best = max(counts, key=counts.get)
    return best if counts[best] > 0 else ","


def parse_csv(path):
    result = ParseResult("csv")
    try:
        # utf-8-sig silently removes the BOM that Excel adds
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            first_line = f.readline()
            if not first_line.strip():
                raise ParseError("The CSV file is empty.")
            reader = csv.DictReader(itertools.chain([first_line], f),
                                    delimiter=_detect_delimiter(first_line))
            headers = reader.fieldnames or []

            recognized = {norm.canonical_name(h) for h in headers} - {None}
            if "timestamp" not in recognized:
                raise ParseError(
                    "No timestamp column found. Expected a header such as "
                    "'timestamp', 'time', 'TimeCreated' or 'datetime'.")
            if len(recognized) < 2:
                raise ParseError("Too few recognizable columns to analyse this file.")

            header_keys = {norm.normalize_key(h) for h in headers}
            if header_keys & {"timecreated", "targetusername"}:
                result.format_name = "windows_csv"

            for row in reader:
                if norm.is_blank_row(row):
                    continue
                result.total_rows += 1
                if result.total_rows > norm.MAX_ROWS_PER_FILE:
                    raise ParseError(
                        f"File has more than {norm.MAX_ROWS_PER_FILE:,} rows; please split it.")
                record, reason = norm.normalize_row(row, raw_log=json.dumps(row, default=str))
                if record is None:
                    result.add_error(reader.line_num, reason)
                else:
                    result.records.append(record)
    except csv.Error as exc:
        raise ParseError(f"Malformed CSV file: {exc}") from exc
    return result