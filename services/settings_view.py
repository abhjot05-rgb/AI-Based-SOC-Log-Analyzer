"""Read-only view of the settings in use, with a validity check. Never exposes secrets."""
import config
from analysis.threat_scoring import validate_scoring_settings
from config import Config
from detection.rule_engine import run_rules
from ml.model import validate_settings as validate_ml_settings
from parser import log_normalizer


def _check(function):
    try:
        function()
        return {"valid": True, "error": None}
    except (ValueError, TypeError) as exc:
        return {"valid": False, "error": str(exc)}


def _check_bands():
    covered = set()
    for low, high in config.SEVERITY_BANDS.values():
        covered.update(range(low, high + 1))
    if covered != set(range(101)):
        raise ValueError("Severity bands must cover every score from 0 to 100 without gaps")


def validation():
    """Run each group's own validation. Settings are read at call time, so edits show up after a restart."""
    result = {
        # Running the rules on zero events checks every threshold without needing data
        "detection_rules": _check(lambda: run_rules([])),
        "ml": _check(lambda: validate_ml_settings(config.ML_SETTINGS)),
        "scoring": _check(lambda: validate_scoring_settings(config.SCORING_SETTINGS)),
        "severity_bands": _check(_check_bands),
    }
    result["all_valid"] = all(item["valid"] for item in result.values())
    return result


def current_settings():
    return {
        "detection_rules": {k: dict(v) for k, v in config.DETECTION_RULES.items()},
        "ml": dict(config.ML_SETTINGS),
        "scoring": {k: (dict(v) if isinstance(v, dict) else v)
                    for k, v in config.SCORING_SETTINGS.items()},
        "severity_bands": {k: list(v) for k, v in config.SEVERITY_BANDS.items()},
        "limits": {
            "max_upload_mb": Config.MAX_CONTENT_LENGTH // (1024 * 1024),
            "allowed_extensions": sorted(Config.ALLOWED_EXTENSIONS),
            "max_rows_per_file": log_normalizer.MAX_ROWS_PER_FILE,
            "logs_per_page": Config.LOGS_PER_PAGE,
            "alerts_per_page": Config.ALERTS_PER_PAGE,
        },
        "validation": validation(),
    }


def configuration_lines():
    """Compact text version of the settings, printed in the summary report."""
    return {
        "detection_rules": [
            {"name": name, "text": ", ".join(f"{k}={v}" for k, v in cfg.items())}
            for name, cfg in config.DETECTION_RULES.items()],
        "ml": ", ".join(f"{k}={v}" for k, v in config.ML_SETTINGS.items()),
        "severity_bands": ", ".join(f"{name} {low}-{high}"
                                    for name, (low, high) in config.SEVERITY_BANDS.items()),
    }