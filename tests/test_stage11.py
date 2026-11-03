"""Stage 11 tests: /api/threats, /api/analytics and the Threats and Analytics pages."""
import io

import config
from database import db
from tests.test_stage9 import PageTestCase

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
JS_DIR = config.BASE_DIR / "static" / "js"

THREAT_IDS = ["scopeSelect", "refreshBtn", "statusBox", "th-types", "th-alerts", "th-ips",
              "th-compromised", "typeChart", "typeEmpty", "methodChart", "methodEmpty",
              "typesBody", "attackersBody", "usersBody"]
ANALYTICS_IDS = ["scopeSelect", "refreshBtn", "statusBox", "an-logs", "an-alerts", "an-open",
                 "an-anomalies", "severityChart", "severityEmpty", "statusChart", "statusEmpty",
                 "methodChart", "methodEmpty", "scoreChart", "scoreEmpty", "timelineChart",
                 "timelineEmpty", "hourlyChart", "hourlyEmpty", "eventChart", "eventEmpty",
                 "mlChart", "mlEmpty", "ml-scored", "ml-anomalies", "ml-rule-events",
                 "ml-rule-flagged", "ml-outside"]


class Stage11Tests(PageTestCase):
    def generate(self, **extra):
        body = {"events": 300, "seed": 3}
        body.update(extra)
        r = self.client.post("/api/generate-sample", json=body)
        self.assertEqual(r.status_code, 201)
        return r.get_json()

    def upload_csv(self, rows, name):
        data = ("timestamp,source_ip,username,event_type\n" + "\n".join(rows) + "\n").encode()
        r = self.client.post("/api/upload", data={"file": (io.BytesIO(data), name)},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201)
        return r.get_json()["upload_id"]

    def threats(self, **query):
        r = self.client.get("/api/threats", query_string=query)
        self.assertEqual(r.status_code, 200)
        return r.get_json()

    def analytics(self, **query):
        r = self.client.get("/api/analytics", query_string=query)
        self.assertEqual(r.status_code, 200)
        return r.get_json()

    # ---------- API ----------
    def test_empty_database_returns_zeros(self):
        t = self.threats()
        self.assertEqual(t["totals"], {"alerts": 0, "threat_types": 0, "unique_ips": 0,
                                       "possible_compromises": 0})
        self.assertEqual((t["by_type"], t["top_attackers"], t["targeted_users"]), ([], [], []))
        self.assertEqual(sum(t["detection_methods"].values()), 0)
        a = self.analytics()
        self.assertEqual(a["totals"], {"alerts": 0, "open_alerts": 0, "logs": 0, "anomalies": 0})
        self.assertEqual(len(a["hourly"]), 24)
        self.assertEqual(len(a["score_histogram"]), 10)
        self.assertEqual((a["event_types"], a["ml_score_distribution"]), ([], []))
        self.assertEqual(a["timeline"]["points"], [])
        self.assertEqual(a["ml_coverage"]["logs"], 0)

    def test_threat_summary_is_consistent(self):
        self.generate()
        stats = self.client.get("/api/stats").get_json()
        t = self.threats()
        self.assertEqual(t["totals"]["alerts"], stats["total_alerts"])
        self.assertEqual(t["totals"]["threat_types"], len(t["by_type"]))
        self.assertEqual(sum(x["count"] for x in t["by_type"]), stats["total_alerts"])
        counts = [x["count"] for x in t["by_type"]]
        self.assertEqual(counts, sorted(counts, reverse=True))
        for x in t["by_type"]:
            self.assertEqual(set(x["severity"]), SEVERITIES)
            self.assertEqual(sum(x["severity"].values()), x["count"])
            self.assertTrue(0 <= x["avg_score"] <= x["max_score"] <= 100)
        self.assertEqual(set(t["detection_methods"]), {"RULE", "ML", "RULE+ML"})
        self.assertEqual(sum(t["detection_methods"].values()), stats["total_alerts"])
        attackers = t["top_attackers"]
        self.assertTrue(attackers)
        self.assertLessEqual(len(attackers), 15)
        self.assertEqual([a["alerts"] for a in attackers],
                         sorted((a["alerts"] for a in attackers), reverse=True))
        for a in attackers:
            self.assertIn(a["highest_severity"], SEVERITIES)
            self.assertIsInstance(a["internal"], bool)
            self.assertIsInstance(a["threat_types"], list)
            self.assertTrue(a["threat_types"])
            self.assertLessEqual(a["first_seen"], a["last_seen"])
        users = t["targeted_users"]
        self.assertLessEqual(len(users), 10)
        self.assertEqual([u["alerts"] for u in users], sorted((u["alerts"] for u in users), reverse=True))

    def test_links_on_the_threats_page_match_the_alert_filters(self):
        self.generate()
        t = self.threats()
        for x in t["by_type"]:
            listing = self.client.get("/api/alerts", query_string={"threat_type": x["threat_type"]})
            self.assertEqual(listing.get_json()["total"], x["count"], x["threat_type"])
        for a in t["top_attackers"][:5]:
            listing = self.client.get("/api/alerts", query_string={"source_ip": a["source_ip"],
                                                                   "per_page": 200})
            self.assertGreaterEqual(listing.get_json()["total"], a["alerts"], a["source_ip"])

    def test_possible_compromise_counter(self):
        failures = [f"2026-01-14 10:00:0{i},203.0.113.9,admin,login_failure" for i in range(8)]
        success = "2026-01-14 10:00:30,203.0.113.9,admin,login_success"
        with_success = self.upload_csv(failures + [success], "with_success.csv")
        without = self.upload_csv(failures, "without_success.csv")
        self.assertEqual(self.threats(upload_id=with_success)["totals"]["possible_compromises"], 1)
        self.assertEqual(self.threats(upload_id=without)["totals"]["possible_compromises"], 0)
        self.assertEqual(self.threats()["totals"]["possible_compromises"], 1)

    def test_analytics_is_consistent(self):
        self.generate()
        self.assertEqual(self.client.post("/api/alerts/1/status", json={"status": "Resolved"}).status_code, 200)
        stats = self.client.get("/api/stats").get_json()
        a = self.analytics()
        totals = a["totals"]
        self.assertEqual(totals["alerts"], stats["total_alerts"])
        self.assertEqual(totals["logs"], stats["total_logs"])
        self.assertEqual(totals["anomalies"], stats["anomalies"])
        self.assertEqual(sum(a["severity_counts"].values()), totals["alerts"])
        self.assertEqual(sum(a["status_counts"].values()), totals["alerts"])
        self.assertEqual(sum(a["detection_methods"].values()), totals["alerts"])
        self.assertEqual(a["status_counts"]["Resolved"], 1)
        self.assertEqual(totals["open_alerts"],
                         a["status_counts"]["New"] + a["status_counts"]["Investigating"])
        self.assertEqual(totals["open_alerts"], totals["alerts"] - 1)
        self.assertEqual(len(a["score_histogram"]), 10)
        self.assertEqual(sum(b["count"] for b in a["score_histogram"]), totals["alerts"])
        self.assertEqual([h["hour"] for h in a["hourly"]], list(range(24)))
        self.assertEqual(sum(h["total"] for h in a["hourly"]), totals["logs"])
        for h in a["hourly"]:
            self.assertLessEqual(h["alerted"], h["total"])
            self.assertLessEqual(h["anomalies"], h["total"])
        events = a["event_types"]
        self.assertLessEqual(len(events), 10)
        self.assertEqual([e["count"] for e in events], sorted((e["count"] for e in events), reverse=True))
        for e in events:
            self.assertLessEqual(e["alerted"], e["count"])
        ml = a["ml_score_distribution"]
        self.assertEqual(sum(b["count"] for b in ml), totals["logs"])
        self.assertEqual(sum(b["flagged"] for b in ml), totals["anomalies"])
        for b in ml:
            self.assertLessEqual(b["flagged"], b["count"])
        self.assertEqual(sum(p["total"] for p in a["timeline"]["points"]), totals["alerts"])

    def test_ml_coverage_numbers(self):
        self.generate()
        stats = self.client.get("/api/stats").get_json()
        c = self.analytics()["ml_coverage"]
        self.assertEqual(c["logs"], stats["total_logs"])
        self.assertEqual(c["scored"], c["logs"])
        self.assertEqual(c["anomalies"], stats["anomalies"])
        self.assertGreater(c["rule_events"], 0)
        self.assertLessEqual(c["rule_events_flagged"], c["rule_events"])
        self.assertEqual(c["anomalies_outside_rules"], c["anomalies"] - c["rule_events_flagged"])
        expected = db.query_one(
            "SELECT COUNT(DISTINCT l.id) AS c FROM logs l JOIN threat_events t ON t.log_id = l.id "
            "WHERE t.rule_name != 'ml_anomaly'")["c"]
        self.assertEqual(c["rule_events"], expected)

    def test_scope_by_upload(self):
        first = self.generate(seed=3)["upload_id"]
        second = self.generate(seed=4)["upload_id"]
        for fetch in (self.threats, self.analytics):
            one = fetch(upload_id=first)["totals"]["alerts"]
            two = fetch(upload_id=second)["totals"]["alerts"]
            both = fetch()["totals"]["alerts"]
            self.assertGreater(one, 0)
            self.assertEqual(one + two, both)

    def test_bad_upload_id_is_rejected_and_unknown_id_is_empty(self):
        self.generate()
        for path in ("/api/threats", "/api/analytics"):
            for bad in ("abc", "0", "-1"):
                r = self.client.get(path, query_string={"upload_id": bad})
                self.assertEqual(r.status_code, 400, f"{path} upload_id={bad}")
                self.assertIn("error", r.get_json())
        self.assertEqual(self.threats(upload_id=9999)["totals"]["alerts"], 0)
        self.assertEqual(self.analytics(upload_id=9999)["totals"]["logs"], 0)

    # ---------- pages ----------
    def test_threats_page_has_every_element(self):
        page = self.html("/threats")
        for element_id in THREAT_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        self.assertLess(page.index("chart.umd.js"), page.index("js/charts.js"))
        self.assertLess(page.index("js/charts.js"), page.index("js/threats.js"))

    def test_analytics_page_has_every_element(self):
        page = self.html("/analytics")
        for element_id in ANALYTICS_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        self.assertLess(page.index("chart.umd.js"), page.index("js/charts.js"))
        self.assertLess(page.index("js/charts.js"), page.index("js/analytics.js"))
        self.assertIn("not an accuracy measure", page)

    def test_scripts_use_the_endpoints_and_escape_output(self):
        threats_js = (JS_DIR / "threats.js").read_text(encoding="utf-8")
        analytics_js = (JS_DIR / "analytics.js").read_text(encoding="utf-8")
        charts_js = (JS_DIR / "charts.js").read_text(encoding="utf-8")
        self.assertIn("/api/threats", threats_js)
        self.assertIn("/api/analytics", analytics_js)
        self.assertIn("function draw(", charts_js)
        self.assertIn("esc(", threats_js)
        for name, text in (("threats.js", threats_js), ("analytics.js", analytics_js),
                           ("charts.js", charts_js)):
            self.assertNotIn("eval(", text, name)
            self.assertNotIn("document.write(", text, name)
        for element_id in THREAT_IDS[3:]:
            self.assertIn(element_id, threats_js, element_id)

    def test_navigation_and_placeholders(self):
        self.assertIn('class="soc-nav-link active" href="/threats"', self.html("/threats"))
        self.assertIn('class="soc-nav-link active" href="/analytics"', self.html("/analytics"))
        for path in ("/threats", "/analytics"):
            self.assertNotIn("Planned for Stage", self.html(path), path)
        self.generate()
        self.assertIn("Threats", self.html("/threats"))