"""
Sample security-log generator (for testing and demos only).

It builds ONE internal list of events (normal + attack scenarios), then writes it
in four formats: generic CSV, JSON, Linux auth.log and Windows-style CSV.
Nothing here touches a network; it only writes text files.

Run:  python -m generators.sample_logs
"""
import argparse
import csv
import json
import random
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import config

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# Fields of the internal ("canonical") event record
FIELDS = [
    "timestamp", "source_ip", "destination_ip", "username", "event_id",
    "event_type", "protocol", "source_port", "destination_port",
    "action", "status", "message",
]

# ---------- Simulated environment ----------
NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
ADMIN_USERS = ["admin", "svc_backup"]
VALID_USERS = set(NORMAL_USERS) | set(ADMIN_USERS) | {"root"}
SERVERS = ["10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.40"]
DOMAIN_CONTROLLER = "10.0.0.40"

# Every internal user gets a fixed workstation IP
USER_IP = {u: f"192.168.1.{10 + i}" for i, u in enumerate(NORMAL_USERS)}
USER_IP["admin"] = "192.168.1.5"
USER_IP["svc_backup"] = "192.168.1.6"

# Attackers use documentation-only ranges (RFC 5737), never real addresses
ATTACKER_PREFIXES = ("203.0.113.", "198.51.100.")

# event_type -> (default Windows-style event id, action, default status)
EVENT_CATALOG = {
    "login_success":      (4624, "login", "success"),
    "login_failure":      (4625, "login", "failure"),
    "logout":             (4634, "logout", "success"),
    "network_connection": (5156, "allow", "allowed"),
    "firewall_block":     (5157, "deny", "blocked"),
    "account_created":    (4720, "create_account", "success"),
    "account_enabled":    (4722, "enable_account", "success"),
    "password_reset":     (4724, "reset_password", "success"),
    "account_disabled":   (4725, "disable_account", "success"),
    "account_lockout":    (4740, "lockout", "success"),
    "privilege_assigned": (4672, "assign_privileges", "success"),
    "group_member_added": (4728, "add_to_group", "success"),
    "sudo_command":       (None, "sudo", "success"),   # Linux-only, has no Windows id
}

MESSAGES = {
    "login_success":      "Successful logon for {user} from {src}",
    "login_failure":      "Failed logon for {user} from {src}",
    "logout":             "User {user} logged off",
    "network_connection": "Connection allowed from {src}:{sport} to {dst}:{dport}",
    "firewall_block":     "Connection blocked from {src}:{sport} to {dst}:{dport}",
    "account_created":    "User account {user} was created",
    "account_enabled":    "User account {user} was enabled",
    "password_reset":     "Password for account {user} was reset",
    "account_disabled":   "User account {user} was disabled",
    "account_lockout":    "User account {user} was locked out",
    "privilege_assigned": "Special privileges assigned to {user}",
    "group_member_added": "Member {user} was added to a privileged group",
    "sudo_command":       "{user} ran a command as root via sudo",
}

MAX_NORMAL_EVENTS = 200_000
MAX_ATTACK_MULTIPLIER = 50


class SampleLogGenerator:
    """Builds a list of event dictionaries. Same seed + start = identical output."""

    def __init__(self, seed=42, start=None):
        self.rng = random.Random(seed)
        # The simulated day: default is yesterday 00:00 (so dates look realistic)
        if start is None:
            start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
        self.day_start = start
        self.records = []
        self.summary = Counter()          # how many of each scenario we injected
        self._used_attackers = set()

    # ---------- small helpers ----------
    def _ephemeral_port(self):
        return self.rng.randint(49152, 65535)

    def _random_time(self, hour_min, hour_max):
        hour = self.rng.randint(hour_min, hour_max)
        return self.day_start + timedelta(
            hours=hour, minutes=self.rng.randint(0, 59), seconds=self.rng.randint(0, 59)
        )

    def _attacker_ip(self):
        """A unique documentation-range IP for each attack."""
        while True:
            ip = f"{self.rng.choice(ATTACKER_PREFIXES)}{self.rng.randint(2, 250)}"
            if ip not in self._used_attackers:
                self._used_attackers.add(ip)
                return ip

    def _event(self, ts, event_type, src=None, dst=None, user=None, protocol=None,
               sport=None, dport=None, status=None, event_id=None):
        default_id, action, default_status = EVENT_CATALOG[event_type]
        self.records.append({
            "timestamp": ts.strftime(TS_FORMAT),
            "source_ip": src,
            "destination_ip": dst,
            "username": user,
            "event_id": event_id if event_id is not None else default_id,
            "event_type": event_type,
            "protocol": protocol,
            "source_port": sport,
            "destination_port": dport,
            "action": action,
            "status": status or default_status,
            "message": MESSAGES[event_type].format(
                user=user or "-", src=src or "-", dst=dst or "-",
                sport=sport or "-", dport=dport or "-"),
        })

    # ---------- normal behaviour ----------
    def add_normal(self, count):
        users = NORMAL_USERS + ADMIN_USERS
        for _ in range(count):
            ts = self._random_time(7, 19)                 # business hours
            user = self.rng.choice(users)
            ip = USER_IP[user]
            server = self.rng.choice(SERVERS)
            kind = self.rng.choices(
                ["login_success", "logout", "network_connection", "login_failure"],
                weights=[28, 22, 45, 5])[0]

            if kind == "network_connection":
                dport = self.rng.choice([80, 443, 443, 53, 445, 8080])
                proto = "UDP" if dport == 53 else "TCP"
                # no username on purpose: network logs often lack one
                self._event(ts, kind, ip, server, None, proto, self._ephemeral_port(), dport)
            elif kind == "logout":
                self._event(ts, kind, ip, server, user)
            else:  # login_success, or a harmless single typo (login_failure)
                self._event(ts, kind, ip, server, user, "TCP",
                            self._ephemeral_port(), self.rng.choice([22, 3389]))

    # ---------- attack scenarios ----------
    def add_brute_force(self, attacks):
        for _ in range(attacks):
            attacker = self._attacker_ip()
            target = self.rng.choice(["admin", "root", "alice", "bob", "administrator"])
            server = self.rng.choice(SERVERS)
            ts = self._random_time(0, 22)
            for _i in range(self.rng.randint(8, 15)):
                self._event(ts, "login_failure", attacker, server, target, "TCP",
                            self._ephemeral_port(), 22)
                ts += timedelta(seconds=self.rng.randint(1, 6))
            if self.rng.random() < 0.5:                   # attacker eventually gets in
                ts += timedelta(seconds=self.rng.randint(5, 30))
                self._event(ts, "login_success", attacker, server, target, "TCP",
                            self._ephemeral_port(), 22)
                self.summary["brute_force_followed_by_success"] += 1
            self.summary["brute_force"] += 1

    def add_port_scan(self, attacks):
        for _ in range(attacks):
            attacker = self._attacker_ip()
            target = self.rng.choice(SERVERS)
            ts = self._random_time(0, 22)
            scan_port = self.rng.randint(40000, 60000)    # scanners reuse a source port
            for port in self.rng.sample(range(1, 1025), self.rng.randint(25, 45)):
                if port in (22, 80, 443):
                    self._event(ts, "network_connection", attacker, target, None,
                                "TCP", scan_port, port)
                else:
                    self._event(ts, "firewall_block", attacker, target, None,
                                "TCP", scan_port, port)
                ts += timedelta(seconds=self.rng.choice([0, 1]))
            self.summary["port_scan"] += 1

    def add_off_hours_logins(self, count):
        for _ in range(count):
            user = self.rng.choice(NORMAL_USERS)
            ts = self._random_time(0, 4)
            self._event(ts, "login_success", self._attacker_ip(), self.rng.choice(SERVERS),
                        user, "TCP", self._ephemeral_port(), 22)
            self.summary["off_hours_login"] += 1

    def add_multi_ip_logins(self, count):
        for _ in range(count):
            user = self.rng.choice(NORMAL_USERS)
            ts = self._random_time(9, 17)
            for _i in range(5):                            # 5 different IPs, ~40 min total
                self._event(ts, "login_success", self._attacker_ip(), self.rng.choice(SERVERS),
                            user, "TCP", self._ephemeral_port(), 22)
                ts += timedelta(seconds=self.rng.randint(180, 480))
            self.summary["multi_ip_login"] += 1

    def add_account_activity(self, count):
        types = ["account_created", "password_reset", "account_enabled",
                 "account_disabled", "account_lockout"]
        for _ in range(count):
            ts = self._random_time(1, 5)                   # unusual hours
            target = f"tmp_user{self.rng.randint(10, 99)}"
            for j in range(self.rng.randint(4, 6)):
                etype = "account_created" if j == 0 else self.rng.choice(types)
                self._event(ts, etype, USER_IP["admin"], DOMAIN_CONTROLLER, target)
                ts += timedelta(seconds=self.rng.randint(15, 45))
            self.summary["account_activity"] += 1

    def add_privilege_activity(self, count):
        for _ in range(count):
            user = self.rng.choice(NORMAL_USERS)
            ip = USER_IP[user]
            ts = self._random_time(8, 20)
            self._event(ts, "privilege_assigned", ip, DOMAIN_CONTROLLER, user)
            ts += timedelta(seconds=self.rng.randint(20, 60))
            self._event(ts, "group_member_added", ip, DOMAIN_CONTROLLER, user,
                        event_id=self.rng.choice([4728, 4732]))
            if self.rng.random() < 0.5:                    # Linux-style escalation
                for _i in range(self.rng.randint(2, 3)):
                    ts += timedelta(seconds=self.rng.randint(10, 40))
                    self._event(ts, "sudo_command", ip, self.rng.choice(SERVERS), user)
            self.summary["privilege_activity"] += 1

    def add_suspicious_ip(self, attacks):
        for _ in range(attacks):
            attacker = self._attacker_ip()
            ts = self._random_time(0, 22)
            for _i in range(self.rng.randint(12, 18)):
                if self.rng.random() < 0.7:
                    self._event(ts, "firewall_block", attacker, self.rng.choice(SERVERS), None,
                                "TCP", self._ephemeral_port(),
                                self.rng.choice([22, 23, 445, 3389, 8080, 1433]))
                else:
                    self._event(ts, "login_failure", attacker, self.rng.choice(SERVERS),
                                self.rng.choice(["guest", "test", "oracle", "postgres"]),
                                "TCP", self._ephemeral_port(), 22)
                ts += timedelta(seconds=self.rng.randint(10, 30))
            self.summary["suspicious_ip"] += 1

    # ---------- main entry ----------
    def generate(self, normal_events=800, attack_multiplier=1):
        if not 0 <= normal_events <= MAX_NORMAL_EVENTS:
            raise ValueError(f"normal_events must be between 0 and {MAX_NORMAL_EVENTS}")
        if not 1 <= attack_multiplier <= MAX_ATTACK_MULTIPLIER:
            raise ValueError(f"attack_multiplier must be between 1 and {MAX_ATTACK_MULTIPLIER}")

        m = attack_multiplier
        self.add_normal(normal_events)
        self.add_brute_force(3 * m)
        self.add_port_scan(2 * m)
        self.add_off_hours_logins(2 * m)
        self.add_multi_ip_logins(1 * m)
        self.add_account_activity(2 * m)
        self.add_privilege_activity(2 * m)
        self.add_suspicious_ip(2 * m)

        self.records.sort(key=lambda r: r["timestamp"])    # stable: keeps attack order
        return self.records


# ======================================================================
# Writers
# ======================================================================
def _prepare(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_csv(records, path):
    """Generic CSV with all normalized fields. Missing values become empty cells."""
    with open(_prepare(path), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)
    return len(records)


def write_json(records, path):
    """JSON array. Missing values become null."""
    with open(_prepare(path), "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    return len(records)


LINUX_HOST = "server01"


def _syslog_time(ts_string):
    """Syslog style 'Oct  4 10:15:32' (no year). Built manually: %e fails on Windows."""
    ts = datetime.strptime(ts_string, TS_FORMAT)
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"


def _linux_body(rec, index):
    """Return the part of the line after the hostname, or None if Linux wouldn't log it."""
    etype, user = rec["event_type"], rec["username"]
    ip, port = rec["source_ip"], rec["source_port"]
    pid = 1000 + (index * 37) % 30000                      # deterministic fake PID

    if etype == "login_failure":
        who = user if user in VALID_USERS else f"invalid user {user}"
        return f"sshd[{pid}]: Failed password for {who} from {ip} port {port} ssh2"
    if etype == "login_success":
        return f"sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"
    if etype == "logout":
        return f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}"
    if etype == "sudo_command":
        return f"sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"
    if etype == "account_created":
        uid = 1000 + index % 5000
        return (f"useradd[{pid}]: new user: name={user}, UID={uid}, GID={uid}, "
                f"home=/home/{user}, shell=/bin/bash")
    if etype == "group_member_added":
        return f"usermod[{pid}]: add '{user}' to group 'sudo'"
    if etype == "password_reset":
        return f"passwd[{pid}]: pam_unix(passwd:chauthtok): password changed for {user}"
    return None                                            # firewall/network events: not in auth.log


def write_linux_auth(records, path):
    """Linux auth.log style. Only authentication-related events are written."""
    written = 0
    with open(_prepare(path), "w", encoding="utf-8") as f:
        for i, rec in enumerate(records):
            body = _linux_body(rec, i)
            if body:
                f.write(f"{_syslog_time(rec['timestamp'])} {LINUX_HOST} {body}\n")
                written += 1
    return written


WINDOWS_COLUMNS = [
    "TimeCreated", "EventID", "Computer", "TargetUserName", "SourceAddress",
    "SourcePort", "DestAddress", "DestPort", "Protocol", "LogonType", "Status", "Message",
]
PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17}                   # Windows firewall logs use numbers


def write_windows_csv(records, path):
    """Windows Security-event style CSV. Events with no Windows id (sudo) are skipped."""
    written = 0
    with open(_prepare(path), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=WINDOWS_COLUMNS)
        writer.writeheader()
        for rec in records:
            if rec["event_id"] is None:
                continue
            ts = datetime.strptime(rec["timestamp"], TS_FORMAT)
            is_login = rec["event_type"] in ("login_success", "login_failure")
            internal = (rec["source_ip"] or "").startswith(("10.", "192.168."))
            failed = rec["status"] in ("failure", "blocked")
            writer.writerow({
                "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "EventID": rec["event_id"],
                "Computer": "WIN-DC01",
                "TargetUserName": rec["username"],
                "SourceAddress": rec["source_ip"],
                "SourcePort": rec["source_port"],
                "DestAddress": rec["destination_ip"],
                "DestPort": rec["destination_port"],
                "Protocol": PROTOCOL_NUMBERS.get(rec["protocol"], ""),
                "LogonType": (3 if internal else 10) if is_login else "",
                "Status": "Audit Failure" if failed else "Audit Success",
                "Message": rec["message"],
            })
            written += 1
    return written


# ======================================================================
# Convenience: generate everything
# ======================================================================
def generate_all(out_dir=None, seed=42, normal_events=800, attack_multiplier=1, start=None):
    out = Path(out_dir) if out_dir else config.DATA_DIR / "samples"
    gen = SampleLogGenerator(seed=seed, start=start)
    records = gen.generate(normal_events, attack_multiplier)

    files = {
        "csv": out / "sample_generic.csv",
        "json": out / "sample_generic.json",
        "linux_auth": out / "sample_linux_auth.log",
        "windows_csv": out / "sample_windows_security.csv",
        "answer_key": out / "injected_scenarios.json",
    }
    counts = {
        "csv": write_csv(records, files["csv"]),
        "json": write_json(records, files["json"]),
        "linux_auth": write_linux_auth(records, files["linux_auth"]),
        "windows_csv": write_windows_csv(records, files["windows_csv"]),
    }
    injected = dict(gen.summary)
    with open(files["answer_key"], "w", encoding="utf-8") as f:
        json.dump({
            "note": "Attacks injected by the generator. Compare with detected alerts.",
            "seed": seed,
            "injected": injected,
        }, f, indent=2)

    return {"files": files, "counts": counts, "injected": injected, "total_events": len(records)}


def main():
    parser = argparse.ArgumentParser(description="Generate sample security logs for testing.")
    parser.add_argument("--events", type=int, default=800, help="number of normal events (default 800)")
    parser.add_argument("--attacks", type=int, default=1, help="attack multiplier (default 1)")
    parser.add_argument("--seed", type=int, default=42, help="random seed (default 42)")
    parser.add_argument("--out", default=None, help="output folder (default data/samples)")
    args = parser.parse_args()

    try:
        result = generate_all(args.out, args.seed, args.events, args.attacks)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"\nGenerated {result['total_events']} events.\n")
    for key, path in result["files"].items():
        print(f"  {path.name:<30} {result['counts'].get(key, '-')!s:>6} lines/rows")
    print("\nInjected scenarios (answer key):")
    for name, n in sorted(result["injected"].items()):
        print(f"  {name:<34} {n}")
    print(f"\nSaved in: {Path(next(iter(result['files'].values()))).parent}")


if __name__ == "__main__":
    main()