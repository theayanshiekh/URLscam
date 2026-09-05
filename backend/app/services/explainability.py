"""Human-readable explanations. Never expose raw feature_17 style values."""

from __future__ import annotations

from typing import Any

FEATURE_LABELS = {
    "url_length": "URL length",
    "hostname_length": "Hostname length",
    "path_length": "Path length",
    "query_length": "Query length",
    "num_dots": "Dot count",
    "num_hyphens": "Hyphen count",
    "num_underscores": "Underscore count",
    "num_slashes": "Slash count",
    "num_at": "@ symbols",
    "num_question": "Query markers",
    "num_equals": "Equals signs",
    "num_percent": "Percent-encoded characters",
    "num_digits": "Digit count",
    "num_special": "Special character count",
    "num_subdomains": "Subdomain count",
    "num_query_params": "Query parameter count",
    "num_path_segments": "Path segment count",
    "contains_ip": "IP-based host",
    "contains_at_symbol": "Embedded @",
    "contains_double_slash": "Double slash in path",
    "contains_punycode": "Punycode hostname",
    "contains_encoded_characters": "URL encoding",
    "contains_suspicious_port": "Unusual port",
    "uses_https": "HTTPS",
    "contains_login_keyword": "Login-related wording",
    "contains_verify_keyword": "Verification wording",
    "contains_account_keyword": "Account wording",
    "contains_payment_keyword": "Payment wording",
    "contains_security_keyword": "Security wording",
    "contains_update_keyword": "Update wording",
    "contains_bank_keyword": "Banking wording",
    "contains_free_keyword": "Free/gift wording",
    "contains_reward_keyword": "Reward wording",
    "contains_wallet_keyword": "Wallet wording",
    "contains_otp_keyword": "OTP wording",
    "hostname_entropy": "Hostname entropy",
    "path_entropy": "Path entropy",
    "digit_ratio": "Digit ratio",
    "special_character_ratio": "Special character ratio",
    "subdomain_ratio": "Subdomain ratio",
    "untrusted_tld": "Uncommon TLD",
    "is_shortener": "Shortener domain",
    "has_userinfo": "Userinfo in URL",
    "mixed_script": "Mixed scripts",
    "hyphen_count_domain": "Hyphens in domain",
}

SUMMARIES = {
    "phishing": "Multiple indicators strongly suggest that this URL is attempting to impersonate a trusted service or collect sensitive information.",
    "suspicious": "Some characteristics require caution. The URL is not a confirmed phishing page from this analysis, but it should not be trusted blindly.",
    "legitimate": "No significant phishing indicators were detected in local analysis. Automated analysis cannot guarantee that a website is safe.",
}

RECS = {
    "phishing": (
        "DO NOT visit this website.\n"
        "DO NOT enter credentials.\n"
        "DO NOT provide OTP, PIN, or card information.\n"
        "Open the real service by typing its official address or using a saved bookmark."
    ),
    "suspicious": (
        "Proceed only if you independently recognize the destination.\n"
        "Do not enter passwords, OTPs, or payment data until you verify the domain.\n"
        "Prefer navigating to the service from an official app or bookmark."
    ),
    "legitimate": (
        "No strong phishing pattern was found, but this is not a safety guarantee.\n"
        "Still verify unexpected login or payment requests through a trusted channel."
    ),
}


def https_note() -> str:
    return (
        "HTTPS only encrypts the connection. It does not prove that the website is legitimate. "
        "A padlock can appear on phishing sites that obtained a free certificate."
    )


def confidence_note(low: bool) -> str:
    if low:
        return (
            "LOW CONFIDENCE: signals disagree or the model is uncertain. "
            "Treat this as a prompt for manual verification, not a final answer. "
            "Confidence is model certainty, not a guarantee of safety."
        )
    return "Confidence is the system's certainty in this assessment, not a guarantee of safety."


def humanize_ml_contributions(ml: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in ml.get("contributions") or []:
        key = item.get("feature")
        out.append(
            {
                "name": FEATURE_LABELS.get(key, key),
                "importance": round(float(item.get("importance") or 0), 4),
                "value": item.get("value"),
                "explanation": _feature_sentence(key, item.get("value")),
            }
        )
    return out


def _feature_sentence(key: str | None, value: Any) -> str:
    label = FEATURE_LABELS.get(key or "", key or "feature")
    if key in {"contains_login_keyword", "contains_verify_keyword", "contains_account_keyword"} and value:
        return f"{label} is present, which often appears on credential-harvesting pages."
    if key == "num_subdomains":
        return f"The model used subdomain count ({value}) as a structural signal."
    if key == "hostname_entropy":
        return f"Hostname entropy is {value}. Very irregular hostnames can indicate generated domains."
    if key == "uses_https":
        return "HTTPS is a weak positive signal and never overrides impersonation evidence."
    if key == "untrusted_tld" and value:
        return "An uncommon TLD contributed to the phishing-oriented score."
    return f"{label} contributed to the model decision (value={value})."


def build_summary(classification: str, factors: list[dict[str, Any]]) -> str:
    base = SUMMARIES[classification]
    top = [f["name"] for f in factors if f["severity"] in {"high", "critical"}][:3]
    if top:
        return f"{base} Leading signals: {', '.join(top)}."
    return base
