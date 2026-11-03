"""Stage 9 tests: dashboard pages, navigation, static files, security headers, asset fallback."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from app import create_app
from database import db
from routes import pages

SECTIONS = ["Dashboard", "Logs", "Alerts", "Threats", "Analytics", "Reports", "Settings"]
DASHBOARD_IDS = [
    "stat-total_logs", "stat-total_alerts", "stat-critical", "stat-high", "stat-medium",
    "stat-low", "stat-anomalies", "timelineChart", "distChart", "topIpsBody",
    "threatTypesList", "recentAlertsBody", "fileInput", "uploadBtn", "demoBtn",
    "scopeSelect", "deleteBtn",
]


class PageTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "uploads").mkdir()
        for name, value in (("DATABASE_PATH", self.root / "test.db"),
                            ("UPLOAD_DIR", self.root / "uploads")):
            patcher = patch.object(config, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def html(self, path="/"):
        r = self.client.get(path)
        self.assertEqual(r.status_code, 200, path)
        return r.get_data(as_text=True)


class DashboardPageTests(PageTestCase):
    def test_dashboard_renders_with_all_elements(self):
        page = self.html("/")
        self.assertIn("SOC Log Analyzer", page)
        for element_id in DASHBOARD_IDS:
            self.assertIn(f'id="{element_id}"', page, element_id)
        self.assertIn("js/dashboard.js", page)
        self.assertIn("js/soc.js", page)
        self.assertIn('data-bs-theme="dark"', page)

    def test_sidebar_lists_every_section_and_marks_the_active_one(self):
        page = self.html("/")
        for label in SECTIONS:
            self.assertIn(label, page)
        self.assertIn('class="soc-nav-link active" href="/"', page)
        self.assertNotIn('class="soc-nav-link active" href="/logs"', page)
        logs_page = self.html("/logs")
        self.assertIn('class="soc-nav-link active" href="/logs"', logs_page)

    def test_every_sidebar_page_opens(self):
        for path in ("/", "/logs", "/alerts", "/threats", "/analytics", "/reports", "/settings"):
            self.assertNotIn("Planned for Stage", self.html(path), path)

    def test_unknown_page_returns_json_404(self):
        r = self.client.get("/no-such-page")
        self.assertEqual(r.status_code, 404)
        self.assertIn("error", r.get_json())

    def test_dashboard_works_after_data_exists(self):
        r = self.client.post("/api/generate-sample", json={"events": 300, "seed": 3})
        self.assertEqual(r.status_code, 201)
        self.assertIn("SOC Log Analyzer", self.html("/"))
        stats = self.client.get("/api/stats").get_json()
        self.assertGreater(stats["total_alerts"], 0)
        self.assertIn("Alert investigation", self.html("/alerts/1"))


class AssetTests(PageTestCase):
    def test_static_files_are_served(self):
        for path in ("/static/css/soc.css", "/static/js/soc.js", "/static/js/dashboard.js"):
            with self.subTest(path=path):
                r = self.client.get(path)
                self.assertEqual(r.status_code, 200)
                self.assertGreater(len(r.data), 500)
                r.close()

    def test_scripts_use_the_api_and_escape_output(self):
        js_dir = config.BASE_DIR / "static" / "js"
        dashboard = (js_dir / "dashboard.js").read_text(encoding="utf-8")
        shared = (js_dir / "soc.js").read_text(encoding="utf-8")
        for endpoint in ("/api/stats", "/api/uploads", "/api/upload", "/api/generate-sample"):
            self.assertIn(endpoint, dashboard)
        self.assertIn("function esc(", shared)
        self.assertIn("esc(", dashboard)

    def test_cdn_is_used_when_no_local_copy_exists(self):
        with patch.object(pages, "vendor_dir", lambda: self.root / "no_vendor"):
            page = self.html("/")
        self.assertIn("cdn.jsdelivr.net/npm/bootstrap@5.3.3", page)
        self.assertIn("cdn.jsdelivr.net/npm/chart.js@4.4.3", page)

    def test_local_copy_is_used_when_present(self):
        vendor = self.root / "vendor"
        vendor.mkdir()
        for name in pages.LOCAL_NAMES.values():
            (vendor / name).write_text("/* test */", encoding="utf-8")
        with patch.object(pages, "vendor_dir", lambda: vendor):
            page = self.html("/")
        self.assertIn("/static/vendor/chart.umd.js", page)
        self.assertIn("/static/vendor/bootstrap.min.css", page)
        self.assertNotIn("cdn.jsdelivr.net", page)


class SecurityHeaderTests(PageTestCase):
    def test_pages_carry_security_headers(self):
        r = self.client.get("/")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)
        self.assertEqual(self.client.get("/api/stats").headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()