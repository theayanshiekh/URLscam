"""
detector.py
-----------
Production-grade URL Fraud & Phishing Detection Engine.
Wraps the trained Random Forest model and provides single & vectorized batch
inference, risk scoring, and threat indicator explainability.
"""

import json
import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

import joblib
import numpy as np
import pandas as pd

from app.core.extractor import extract_features, url_to_vector, FEATURE_NAMES
from app.core.explainability import analyze_threat_indicators

logger = logging.getLogger(__name__)


class URLFraudDetector:
    """
    Singleton-friendly URL Fraud Detector engine that loads machine learning
    artifacts once and performs high-throughput lexical inference.
    """

    def __init__(self, artifacts_dir: str = "model_artifacts", threshold_override: Optional[float] = None):
        self.artifacts_dir = Path(artifacts_dir)
        self.threshold_override = threshold_override
        self._load_artifacts()

    def _load_artifacts(self):
        model_path = self.artifacts_dir / "model.joblib"
        scaler_path = self.artifacts_dir / "scaler.joblib"
        meta_path = self.artifacts_dir / "metadata.json"

        if not model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {model_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata artifact not found at {meta_path}")

        logger.info("Loading model artifacts from %s ...", self.artifacts_dir)
        self.model = joblib.load(str(model_path))

        if scaler_path.exists():
            self.scaler = joblib.load(str(scaler_path))
        else:
            self.scaler = None

        with open(meta_path, "r", encoding="utf-8") as f:
            self.meta = json.load(f)

        self.needs_scaling = bool(self.meta.get("needs_scaling", False))
        
        # Determine active decision threshold
        if self.threshold_override is not None:
            self.threshold = float(self.threshold_override)
        else:
            self.threshold = float(self.meta.get("recommended_threshold", 0.7405))

        logger.info(
            "Model '%s' loaded successfully. Threshold=%.4f, Needs Scaling=%s",
            self.meta.get("model_name", "unknown"),
            self.threshold,
            self.needs_scaling,
        )

    def predict(
        self,
        url: str,
        include_features: bool = False,
        include_explainability: bool = True,
    ) -> Dict[str, Any]:
        """
        Infers fraud probability and risk metrics for a single URL.
        """
        start_t = time.perf_counter()
        clean_url = (url or "").strip()
        if not clean_url:
            raise ValueError("URL cannot be empty")

        raw_features = extract_features(clean_url)
        vector = [raw_features[name] for name in FEATURE_NAMES]
        
        df_vec = pd.DataFrame([vector], columns=FEATURE_NAMES)
        if self.needs_scaling and self.scaler is not None:
            df_vec = self.scaler.transform(df_vec)

        proba = float(self.model.predict_proba(df_vec)[0, 1])
        elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)

        result = {
            "url": clean_url,
            "is_flagged": proba >= self.threshold,
            "probability": round(proba, 4),
            "threshold": round(self.threshold, 4),
            "latency_ms": elapsed_ms,
        }

        if include_explainability:
            analysis = analyze_threat_indicators(clean_url, raw_features, proba, self.threshold)
            result.update(analysis)

        if include_features:
            result["features"] = raw_features

        return result

    def predict_batch(
        self,
        urls: List[str],
        include_features: bool = False,
        include_explainability: bool = True,
    ) -> Dict[str, Any]:
        """
        Performs high-throughput vectorised batch inference over an array of URLs.
        Builds a single 2D feature matrix and executes model.predict_proba in one call.
        """
        start_t = time.perf_counter()
        cleaned_urls = [str(u).strip() for u in urls if str(u).strip()]
        if not cleaned_urls:
            return {
                "summary": {
                    "total": 0,
                    "flagged_count": 0,
                    "safe_count": 0,
                    "avg_probability": 0.0,
                    "highest_risk_url": None,
                    "total_latency_ms": 0.0,
                },
                "results": [],
            }

        # Vectorized feature extraction
        extracted_list = [extract_features(u) for u in cleaned_urls]
        matrix = [[feats[name] for name in FEATURE_NAMES] for feats in extracted_list]

        df_batch = pd.DataFrame(matrix, columns=FEATURE_NAMES)
        if self.needs_scaling and self.scaler is not None:
            df_batch = self.scaler.transform(df_batch)

        # Single vectorised model prediction call
        probas = self.model.predict_proba(df_batch)[:, 1]

        results = []
        flagged_count = 0
        highest_proba = -1.0
        highest_url = None

        for u, proba, feats in zip(cleaned_urls, probas, extracted_list):
            p = float(proba)
            is_flagged = p >= self.threshold
            if is_flagged:
                flagged_count += 1
            if p > highest_proba:
                highest_proba = p
                highest_url = u

            item = {
                "url": u,
                "is_flagged": is_flagged,
                "probability": round(p, 4),
                "threshold": round(self.threshold, 4),
            }

            if include_explainability:
                analysis = analyze_threat_indicators(u, feats, p, self.threshold)
                item.update(analysis)

            if include_features:
                item["features"] = feats

            results.append(item)

        total_elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
        avg_proba = round(float(np.mean(probas)), 4) if len(probas) > 0 else 0.0

        return {
            "summary": {
                "total": len(cleaned_urls),
                "flagged_count": flagged_count,
                "safe_count": len(cleaned_urls) - flagged_count,
                "avg_probability": avg_proba,
                "highest_risk_url": highest_url,
                "highest_probability": round(highest_proba, 4) if highest_url else 0.0,
                "total_latency_ms": total_elapsed_ms,
            },
            "results": results,
        }

    def get_metadata(self) -> Dict[str, Any]:
        """Returns metadata about the active model, training performance, and feature schema."""
        return {
            "model_name": self.meta.get("model_name", "unknown"),
            "positive_class": self.meta.get("positive_class", "is_spam / fraud link"),
            "threshold": round(self.threshold, 4),
            "trained_rows": self.meta.get("trained_rows", 0),
            "feature_count": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
            "metrics": self.meta.get("metrics", {}),
            "all_candidate_metrics": self.meta.get("all_candidate_metrics", {}),
        }
