"""Transparent ensemble risk scoring.

Final risk is not a naive average. It is a documented weighted combination
with caps, then mapped through configurable thresholds.

Components (weights sum to 1.0):
  ML phishing-oriented score     0.38
  Heuristic / structural score   0.34
  Brand / impersonation cluster  0.16
  External / DNS / TLS intel     0.12

Confidence is separate: it measures agreement + model certainty.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings

WEIGHTS = {
    "ml": 0.38,
    "heuristics": 0.34,
    "brand": 0.16,
    "intel": 0.12,
}


def _ml_risk(ml: dict[str, Any]) -> float:
    if not ml.get("available"):
        return 0.0
    phish = float(ml.get("phishing_probability") or 0.0)
    sus = float(ml.get("suspicious_probability") or 0.0)
    return 100.0 * (phish + 0.55 * sus)


def _brand_cluster(factors: list[dict[str, Any]]) -> float:
    names = {f["name"] for f in factors}
    score = 0.0
    if any("Brand" in n or "Typosquat" in n or "Homograph" in n for n in names):
        score = sum(max(f["score"], 0) for f in factors if f["severity"] in {"high", "critical"})
    return min(score, 100.0)


def combine_risk(
    ml: dict[str, Any],
    heuristic_score: float,
    factors: list[dict[str, Any]],
    intel: dict[str, Any],
) -> dict[str, Any]:
    settings = get_settings()
    ml_part = _ml_risk(ml)
    heur_part = float(heuristic_score)
    brand_part = _brand_cluster(factors)
    intel_part = float(intel.get("intel_score") or 0.0)

    # If ML is unavailable, redistribute its weight to heuristics.
    weights = dict(WEIGHTS)
    if not ml.get("available"):
        weights["heuristics"] += weights["ml"]
        weights["ml"] = 0.0

    raw = (
        weights["ml"] * ml_part
        + weights["heuristics"] * heur_part
        + weights["brand"] * brand_part
        + weights["intel"] * intel_part
    )

    high_hits = [f for f in factors if f["severity"] in {"high", "critical"} and f["score"] > 0]
    if len(high_hits) >= 3:
        raw = min(100.0, raw + 6.0)
    if any(f["name"] == "HTTPS enabled" for f in factors) and raw > 50:
        # Padlock must not wash out impersonation.
        raw = max(raw - 1.0, raw * 0.99)

    risk = int(round(max(0.0, min(100.0, raw))))

    if risk <= settings.threshold_low:
        threat = "LOW"
        classification = "legitimate"
    elif risk <= settings.threshold_medium:
        threat = "MEDIUM"
        classification = "suspicious"
    elif risk <= settings.threshold_high:
        threat = "HIGH"
        # HIGH can be phishing when impersonation/typosquat evidence exists.
        impersonation = any(
            n in {f["name"] for f in high_hits}
            for n in (
                "Brand impersonation",
                "Typosquatting / lookalike domain",
                "Homograph / IDN risk",
                "IP address URL",
            )
        )
        classification = "phishing" if impersonation or (ml_part >= 70) else "suspicious"
    else:
        threat = "CRITICAL"
        classification = "phishing"

    ml_conf = float(ml.get("confidence") or 0.0) if ml.get("available") else 0.55
    agreement = 1.0
    if ml.get("available"):
        ml_label = ml.get("label")
        if ml_label and ml_label != classification:
            agreement = 0.62
        elif abs(ml_part - heur_part) > 40:
            agreement = 0.7
    confidence = max(0.35, min(0.99, 0.55 * ml_conf + 0.45 * agreement))
    if not ml.get("available"):
        confidence = max(0.4, min(0.8, 0.5 + 0.005 * len(high_hits)))
    if agreement < 0.7:
        low_conf = True
    else:
        low_conf = confidence < 0.6

    return {
        "risk_score": risk,
        "threat_level": threat,
        "classification": classification,
        "confidence": round(confidence, 4),
        "low_confidence": low_conf,
        "components": {
            "ml": round(ml_part, 2),
            "heuristics": round(heur_part, 2),
            "brand": round(brand_part, 2),
            "intel": round(intel_part, 2),
            "weights": weights,
            "raw": round(raw, 2),
        },
    }
