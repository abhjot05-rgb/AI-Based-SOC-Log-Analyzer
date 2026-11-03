"""Stage 3 tests: the generator produces valid, reproducible, attack-containing data."""
import csv
import ipaddress
import json
import re
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from generators import sample_logs as sl

START = datetime(2026, 1, 15)
EXTERNAL = ("203.0.113.", "198.51.100.")


def make(seed=42, **kwargs):
    gen = sl.SampleLogGenerator(seed=seed, start=START)
    return gen, gen.generate(**kwargs)


def window_max(times, seconds):
    """Largest number of events inside any sliding window of `seconds`."""
    times = sorted(times)
    best, j = 0, 0
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > seconds:
            j += 1
        best = max(best, i - j + 1)
    return best


class Stage3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.gen, self.records = make()

    def test_records_have_all_fields(self):
        for rec in self.records:
            self.assertEqual(set(rec.keys()), set(sl.FIELDS))

    def test_ips_are_valid(self):
        for rec in self.records:
            for key in ("source_ip", "destination_ip"):
                if rec[key] is not None:
                    ipaddress.ip_address(rec[key])          # raises if invalid

    def test_timestamps_sorted(self):
        stamps = [r["timestamp"] for r in self.records]
        self.assertEqual(stamps, sorted(stamps))

    def test_reproducible_with_same_seed(self):
        _, again = make(seed=42)
        self.assertEqual(self.records, again)

    def test_different_seed_gives_different_data(self):
        _, other = make(seed=7)
        self.assertNotEqual(self.records, other)

    def test_normal_and_suspicious_events_present(self):
        internal = [r for r in self.records if (r["source_ip"] or "").startswith("192.168.")]
        external = [r for r in self.records if (r["source_ip"] or "").startswith(EXTERNAL)]
        self.assertGreaterEqual(len(internal), 800)
        self.assertGreater(len(external), 50)

    def test_brute_force_pattern_exists(self):
        by_ip = {}
        for r in self.records:
            if r["event_type"] == "login_failure" and r["source_ip"].startswith(EXTERNAL):
                by_ip.setdefault(r["source_ip"], []).append(
                    datetime.strptime(r["timestamp"], sl.TS_FORMAT))
        self.assertGreater(max(window_max(t, 120) for t in by_ip.values()), 5)

    def test_port_scan_pattern_exists(self):
        ports = {}
        for r in self.records:
            if (r["event_type"] in ("firewall_block", "network_connection")
                    and r["source_ip"].startswith(EXTERNAL)):
                ports.setdefault(r["source_ip"], set()).add(r["destination_port"])
        self.assertGreaterEqual(max(len(p) for p in ports.values()), 25)

    def test_scenario_counts(self):
        self.assertEqual(self.gen.summary["brute_force"], 3)
        self.assertEqual(self.gen.summary["port_scan"], 2)
        self.assertEqual(self.gen.summary["multi_ip_login"], 1)

    def test_csv_output(self):
        path = self.dir / "a.csv"
        n = sl.write_csv(self.records, path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(reader.fieldnames, sl.FIELDS)
        self.assertEqual(len(rows), n)
        self.assertEqual(n, len(self.records))

    def test_json_output(self):
        path = self.dir / "a.json"
        sl.write_json(self.records, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data), len(self.records))
        self.assertEqual(set(data[0].keys()), set(sl.FIELDS))

    def test_linux_output(self):
        path = self.dir / "auth.log"
        n = sl.write_linux_auth(self.records, path)
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        self.assertEqual(len(lines), n)
        pattern = re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \S+ \S+")
        for line in lines:
            self.assertRegex(line, pattern)
        self.assertIn("Failed password for", text)
        self.assertIn("Accepted password for", text)
        self.assertIn("useradd", text)

    def test_windows_output(self):
        path = self.dir / "win.csv"
        n = sl.write_windows_csv(self.records, path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(reader.fieldnames, sl.WINDOWS_COLUMNS)
        self.assertEqual(len(rows), n)
        self.assertEqual(n, len([r for r in self.records if r["event_id"] is not None]))
        self.assertTrue(all(row["EventID"].isdigit() for row in rows))
        self.assertFalse(any("via sudo" in row["Message"] for row in rows))

    def test_generate_all_writes_every_file(self):
        result = sl.generate_all(out_dir=self.dir, seed=1, normal_events=200, start=START)
        for path in result["files"].values():
            self.assertTrue(path.exists(), f"{path} missing")
        self.assertGreater(result["total_events"], 200)
        key = json.loads(result["files"]["answer_key"].read_text(encoding="utf-8"))
        self.assertEqual(key["injected"]["brute_force"], 3)

    def test_invalid_arguments_rejected(self):
        gen = sl.SampleLogGenerator(seed=1, start=START)
        with self.assertRaises(ValueError):
            gen.generate(normal_events=-1)
        with self.assertRaises(ValueError):
            gen.generate(attack_multiplier=0)


if __name__ == "__main__":
    unittest.main()