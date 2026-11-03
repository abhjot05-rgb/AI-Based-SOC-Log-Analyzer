"""Stage 14 tests: documentation files exist and contain the key sections."""
import unittest

import config

README = config.BASE_DIR / "README.md"
VIVA = config.BASE_DIR / "docs" / "VIVA_QA.md"
REQUIREMENTS = config.BASE_DIR / "requirements.txt"


class DocumentationTests(unittest.TestCase):
    def test_readme_has_the_key_sections(self):
        text = README.read_text(encoding="utf-8")
        for heading in ("Installation", "Running", "Detection rules", "Threat score",
                        "Machine learning", "Security", "Limitations", "Future work",
                        "Troubleshooting", "Project structure"):
            self.assertIn(heading, text, heading)
        self.assertIn("python app.py", text)
        self.assertIn("python doctor.py", text)

    def test_docs_make_no_accuracy_claims(self):
        text = (README.read_text(encoding="utf-8") + VIVA.read_text(encoding="utf-8")).lower()
        text = text.replace("*", "")                      # ignore bold markers
        self.assertIn("no accuracy figure", text)
        self.assertIn("not an attack classifier", text)
        # The only place "95% accurate" may appear is the "phrases to avoid" warning
        self.assertEqual(text.count("% accurate"), 1)
        self.assertIn('"it is 95% accurate."', text)

    def test_viva_sheet_and_requirements(self):
        viva = VIVA.read_text(encoding="utf-8")
        self.assertGreaterEqual(viva.count("**"), 40)
        self.assertIn("Isolation Forest", viva)
        requirements = REQUIREMENTS.read_text(encoding="utf-8")
        for package in ("Flask", "pandas", "numpy", "scikit-learn"):
            self.assertIn(package, requirements)


if __name__ == "__main__":
    unittest.main()