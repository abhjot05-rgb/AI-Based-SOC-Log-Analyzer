"""
Isolation Forest model wrapper: preprocessing (StandardScaler) + IsolationForest.

Unsupervised: there are no labels, so we never claim an accuracy figure.
"""
import logging

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

log = logging.getLogger("soc.ml")

DEFAULT_SETTINGS = {
    "contamination": 0.05,
    "n_estimators": 100,
    "random_state": 42,
    "min_rows_to_train": 50,
    "max_ml_alerts": 20,
    "feature_window_seconds": 300,
}


class NotEnoughDataError(Exception):
    """Too few events to train a meaningful model."""


def _whole_number(settings, key, low, high=None):
    value = settings[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < low \
            or (high is not None and value > high):
        limit = f"between {low} and {high}" if high is not None else f"{low} or more"
        raise ValueError(f"ML setting '{key}' must be a whole number {limit} (got {value!r})")


def validate_settings(settings=None):
    """Merge with defaults and check every value. Raises ValueError with a clear message."""
    merged = {**DEFAULT_SETTINGS, **(settings or {})}

    c = merged["contamination"]
    if c != "auto":
        if isinstance(c, bool) or not isinstance(c, (int, float)) or not 0 < c <= 0.5:
            raise ValueError(
                f"ML setting 'contamination' must be a number above 0 and at most 0.5, "
                f"or 'auto' (got {c!r})")

    _whole_number(merged, "n_estimators", 10, 1000)
    _whole_number(merged, "min_rows_to_train", 10)
    _whole_number(merged, "max_ml_alerts", 0)
    _whole_number(merged, "feature_window_seconds", 1)
    seed = merged["random_state"]
    if seed is not None and (isinstance(seed, bool) or not isinstance(seed, int)):
        raise ValueError(f"ML setting 'random_state' must be a whole number or None (got {seed!r})")
    return merged


class AnomalyModel:
    def __init__(self, settings=None):
        self.settings = validate_settings(settings)
        self.scaler = None
        self.forest = None
        self.feature_names = None

    @property
    def is_trained(self):
        return self.forest is not None

    @property
    def threshold(self):
        """Events with anomaly_score above this value are flagged."""
        return float(-self.forest.offset_)

    @staticmethod
    def _matrix(features, names):
        X = features.reindex(columns=names, fill_value=0.0).to_numpy(dtype=float)
        return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    def fit(self, features):
        minimum = self.settings["min_rows_to_train"]
        if len(features) < minimum:
            raise NotEnoughDataError(
                f"Only {len(features)} events: ML anomaly detection needs at least {minimum} "
                f"events to learn what is normal, so it was skipped.")
        self.feature_names = list(features.columns)
        X = self._matrix(features, self.feature_names)
        self.scaler = StandardScaler().fit(X)            # preprocessing
        self.forest = IsolationForest(
            n_estimators=self.settings["n_estimators"],
            contamination=self.settings["contamination"],
            random_state=self.settings["random_state"],
            n_jobs=1,
        ).fit(self.scaler.transform(X))
        log.info("Isolation Forest trained on %d events", len(features))
        return self

    def score(self, features):
        """
        Returns (anomaly_scores, is_anomaly_flags, scaled_matrix).
        Higher anomaly score = more unusual. Flags use the model's own threshold.
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet.")
        Z = self.scaler.transform(self._matrix(features, self.feature_names))
        scores = -self.forest.score_samples(Z)
        flags = self.forest.predict(Z) == -1
        return scores, flags, Z

    # ---- persistence (joblib files are pickles: only load files this app created) ----
    def save(self, path):
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained model.")
        joblib.dump({"settings": self.settings, "scaler": self.scaler,
                     "forest": self.forest, "feature_names": self.feature_names}, path)

    @classmethod
    def load(cls, path):
        data = joblib.load(path)
        model = cls(data["settings"])
        model.scaler = data["scaler"]
        model.forest = data["forest"]
        model.feature_names = data["feature_names"]
        return model