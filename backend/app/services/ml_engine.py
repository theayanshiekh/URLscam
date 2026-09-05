"""ML inference. Loads a serialized sklearn pipeline trained offline."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.core.config import get_settings
from app.services.features import FEATURE_ORDER, vectorize

LABELS = {0: "legitimate", 1: "suspicious", 2: "phishing"}


class ModelBundle:
    def __init__(self, payload: dict[str, Any]):
        self.model = payload["model"]
        self.feature_names: list[str] = payload.get("feature_names", FEATURE_ORDER)
        self.model_name: str = payload.get("model_name", "unknown")
        self.dataset: str = payload.get("dataset", "demo")
        self.trained_at: str = payload.get("trained_at", "")
        self.classes = payload.get("classes", [0, 1, 2])


@lru_cache
def load_bundle() -> ModelBundle | None:
    path = Path(get_settings().model_path)
    if not path.exists():
        return None
    payload = joblib.load(path)
    if not isinstance(payload, dict) or "model" not in payload:
        return None
    return ModelBundle(payload)


def model_available() -> bool:
    return load_bundle() is not None


def load_metrics() -> dict[str, Any]:
    path = Path(get_settings().metrics_path)
    if not path.exists():
        return {
            "available": False,
            "note": "No evaluation file found. Train the model to generate metrics.",
        }
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    data["available"] = True
    data.setdefault(
        "disclaimer",
        "These metrics are measured on the bundled training/evaluation split. They are not universal real-world accuracy.",
    )
    return data


def load_feature_importance() -> list[dict[str, Any]]:
    path = Path(get_settings().feature_importance_path)
    if path.exists():
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    bundle = load_bundle()
    if not bundle:
        return []
    model = bundle.model
    clf = model
    if hasattr(model, "named_steps"):
        clf = model.named_steps.get("clf", model)
    if hasattr(clf, "feature_importances_"):
        imps = clf.feature_importances_
        names = bundle.feature_names
        ranked = sorted(zip(names, imps), key=lambda x: x[1], reverse=True)
        return [{"feature": n, "importance": float(v)} for n, v in ranked]
    return []


def predict(features: dict[str, Any]) -> dict[str, Any]:
    bundle = load_bundle()
    if not bundle:
        return {
            "available": False,
            "label": None,
            "probabilities": {},
            "phishing_probability": None,
            "confidence": None,
            "model_name": None,
            "contributions": [],
            "note": "Model file missing. Local heuristics still run. Train with: python ml/training/train.py",
        }
    x = np.array([vectorize(features)], dtype=float)
    model = bundle.model
    proba = model.predict_proba(x)[0]
    pred = int(model.predict(x)[0])
    mapping = {}
    classes = getattr(model, "classes_", [0, 1, 2])
    for idx, cls in enumerate(classes):
        mapping[LABELS.get(int(cls), str(cls))] = float(proba[idx])
    confidence = float(max(proba))
    contributions = _local_contributions(model, x, bundle.feature_names)
    return {
        "available": True,
        "label": LABELS.get(pred, "suspicious"),
        "predicted_class": pred,
        "probabilities": mapping,
        "phishing_probability": mapping.get("phishing", 0.0),
        "suspicious_probability": mapping.get("suspicious", 0.0),
        "legitimate_probability": mapping.get("legitimate", 0.0),
        "confidence": confidence,
        "model_name": bundle.model_name,
        "dataset": bundle.dataset,
        "contributions": contributions,
        "note": "Model confidence is not a guarantee of safety.",
    }


def _local_contributions(model: Any, x: np.ndarray, names: list[str]) -> list[dict[str, Any]]:
    clf = model.named_steps["clf"] if hasattr(model, "named_steps") and "clf" in model.named_steps else model
    if not hasattr(clf, "feature_importances_"):
        return []
    imps = np.array(clf.feature_importances_)
    row = x[0]
    # Weighted deviation from a simple scale; values are translated by explainability layer.
    scaled = imps * (np.abs(row) / (np.abs(row).max() + 1e-9))
    order = np.argsort(scaled)[::-1]
    out = []
    for i in order[:8]:
        out.append(
            {
                "feature": names[i],
                "importance": float(imps[i]),
                "value": float(row[i]),
                "signal": float(scaled[i]),
            }
        )
    return out
