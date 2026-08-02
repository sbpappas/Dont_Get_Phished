"""Loads the trained RandomForest model and scores a feature vector."""
from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd

from .feature_schema import FEATURE_ORDER

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model.joblib"

_model_cache = {}


def load_model(path: Path = DEFAULT_MODEL_PATH):
    key = str(path)
    if key not in _model_cache:
        if not path.exists():
            _model_cache[key] = None
        else:
            _model_cache[key] = joblib.load(path)
    return _model_cache[key]


def predict_proba(features: dict, path: Path = DEFAULT_MODEL_PATH) -> float | None:
    """Return P(phishing) in [0, 1], or None if no model is available."""
    model = load_model(path)
    if model is None:
        return None
    row = pd.DataFrame([[features.get(name, -1) for name in FEATURE_ORDER]], columns=FEATURE_ORDER)
    proba = model.predict_proba(row)[0]
    classes = list(model.classes_)
    return float(proba[classes.index(1)])
