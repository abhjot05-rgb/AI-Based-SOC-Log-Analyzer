"""Stage 1 tests: app starts, config is sane."""
import unittest

import config
from app import create_app


class Stage1Tests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_home_page_loads(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"SOC Log Analyzer", r.data)

    def test_health_endpoint(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_unknown_route_returns_404_json(self):
        r = self.client.get("/does-not-exist")
        self.assertEqual(r.status_code, 404)
        self.assertIn("error", r.get_json())

    def test_runtime_folders_exist(self):
        self.assertTrue(config.UPLOAD_DIR.exists())
        self.assertTrue(config.REPORTS_DIR.exists())

    def test_severity_bands_cover_0_to_100(self):
        covered = set()
        for low, high in config.SEVERITY_BANDS.values():
            covered.update(range(low, high + 1))
        self.assertEqual(covered, set(range(0, 101)))


if __name__ == "__main__":
    unittest.main()