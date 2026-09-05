"""
explainability.py
-----------------
Threat heuristics and explainability engine that inspects extracted URL features
to generate human-readable security risk factors, severity ratings, and recommendations.
"""

from typing import List, Dict, Any
from app.core.extractor import SUSPICIOUS_WORDS, SHORTENER_DOMAINS


def analyze_threat_indicators(url: str, features: Dict[str, Any], probability: float, threshold: float) -> Dict[str, Any]:
    """
    Evaluates extracted features and model confidence to generate
    explainable security threat indicators and recommendations.
    """
    indicators = []
    url_lower = url.lower()
    
    # 1. IP Hostname Check
    if features.get("has_ip_address") == 1:
        indicators.append({
            "id": "RAW_IP_HOSTNAME",
            "severity": "CRITICAL",
            "title": "Raw IP Address as Hostname",
            "description": "The URL uses a numeric IP address instead of a domain name, commonly used to bypass domain reputation checks and domain takedowns."
        })

    # 2. URL Shortener Detection
    if features.get("has_shortener") == 1:
        indicators.append({
            "id": "URL_SHORTENER",
            "severity": "HIGH",
            "title": "Known URL Shortener Service",
            "description": "URL uses a shortening service that obscures the real destination server and target parameters."
        })

    # 3. Suspicious / Phishing Keywords
    found_words = [w for w in SUSPICIOUS_WORDS if w in url_lower]
    if found_words:
        indicators.append({
            "id": "PHISHING_KEYWORDS",
            "severity": "HIGH" if len(found_words) > 1 else "MEDIUM",
            "title": f"Sensitive Phishing Keywords ({len(found_words)} detected)",
            "description": f"Target URL contains high-risk keywords: {', '.join(found_words[:5])}."
        })

    # 4. Embedded @ Symbol (Credential Spoofing)
    if features.get("has_at_symbol") == 1:
        indicators.append({
            "id": "AT_SYMBOL_SPOOFING",
            "severity": "HIGH",
            "title": "Credential / Userinfo Delimiter (@)",
            "description": "URL includes an '@' character, frequently used in phishing attacks to mislead users about the true destination host."
        })

    # 5. Irregular Double Slash
    if features.get("has_double_slash") == 1:
        indicators.append({
            "id": "DOUBLE_SLASH_PATH",
            "severity": "MEDIUM",
            "title": "Abnormal Path Delimiters (//)",
            "description": "URL contains irregular consecutive slashes after the protocol, which can indicate path traversal or URL redirection evasion."
        })

    # 6. Shannon Entropy (Randomized / DGA Strings)
    entropy = features.get("shannon_entropy", 0.0)
    if entropy >= 4.5:
        indicators.append({
            "id": "HIGH_ENTROPY",
            "severity": "MEDIUM",
            "title": f"High Character Entropy ({entropy:.2f})",
            "description": "Character distribution exhibits high randomness, characteristic of algorithmic domain generation (DGA) or obfuscated tracking parameters."
        })

    # 7. Lack of HTTPS
    if features.get("has_https") == 0:
        indicators.append({
            "id": "UNENCRYPTED_HTTP",
            "severity": "LOW",
            "title": "Unencrypted HTTP Protocol",
            "description": "Traffic is sent unencrypted, making data susceptible to eavesdropping or tampering."
        })

    # 8. Excessive Subdomains
    subdomains = features.get("num_subdomains", 0)
    if subdomains >= 3:
        indicators.append({
            "id": "DEEP_SUBDOMAINS",
            "severity": "MEDIUM",
            "title": f"Excessive Subdomain Levels ({subdomains})",
            "description": "The URL stacks numerous subdomains to mimic legitimate branded domains."
        })

    # 9. Abnormal Special Character / Digit Ratios
    spec_ratio = features.get("special_char_ratio", 0.0)
    digit_ratio = features.get("digit_ratio", 0.0)
    if spec_ratio > 0.15 or digit_ratio > 0.25:
        indicators.append({
            "id": "HIGH_SYMBOL_DENSITY",
            "severity": "LOW",
            "title": "Unusually Dense Numeric or Special Characters",
            "description": f"URL exhibits dense non-alphabetic characters (digits: {digit_ratio*100:.1f}%, symbols: {spec_ratio*100:.1f}%)."
        })

    # Calculate overall risk level
    risk_score = round(probability * 100, 1)
    if probability >= threshold or any(ind["severity"] == "CRITICAL" for ind in indicators):
        risk_level = "CRITICAL" if probability >= 0.85 else "HIGH"
        verdict = "FRAUD_SUSPECTED"
        recommendation = "Do NOT visit or submit sensitive credentials/passwords. High probability of deceptive or malicious destination."
    elif probability >= 0.50 or len(indicators) >= 2:
        risk_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS"
        recommendation = "Exercise caution. Check domain spelling carefully before opening or authorizing actions."
    elif probability >= 0.30:
        risk_level = "LOW"
        verdict = "LOW_RISK"
        recommendation = "Low likelihood of malicious intent, but standard browsing precautions apply."
    else:
        risk_level = "SAFE"
        verdict = "CLEAN"
        recommendation = "No typical structural fraud indicators detected. Domain appears regular."

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "recommendation": recommendation,
        "indicators": indicators,
        "indicator_count": len(indicators)
    }
