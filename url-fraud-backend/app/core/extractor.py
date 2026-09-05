"""
extractor.py
------------
Extracts lexical and structural features from URLs for the fraud/spam classifier.
Pure lexical features only (no network calls, no WHOIS, no DNS lookups) ensuring
sub-millisecond execution time per request.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "free", "click",
    "bank", "confirm", "signin", "sign-in", "password", "pay", "billing",
    "wallet", "unlock", "suspend", "urgent", "gift", "bonus", "prize",
    "winner", "claim", "offer", "limited", "invoice", "security", "alert",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorte.st", "bl.ink", "tiny.cc",
}

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_digits", "num_special_chars", "num_params", "num_subdomains",
    "digit_ratio", "special_char_ratio", "shannon_entropy",
    "has_ip_address", "has_https", "has_at_symbol", "has_double_slash",
    "has_shortener", "suspicious_word_count", "starts_with_https",
    "hostname_has_digits", "tld_length",
]


def shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(url: str) -> dict:
    """
    Extracts all 24 lexical features from a given URL string.
    Returns a dictionary mapping feature names to their numeric values.
    """
    url = (url or "").strip()
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("")

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    special_chars = re.findall(r"[!\*\'\(\);:@&=\+\$,\?%#\[\]]", url)
    subdomains = hostname.split(".")[:-2] if hostname.count(".") > 1 else []
    tld = hostname.split(".")[-1] if "." in hostname else ""

    features = {
        "url_length": len(url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": len(special_chars),
        "num_params": query.count("&") + (1 if query else 0),
        "num_subdomains": len(subdomains),
        "digit_ratio": round((sum(c.isdigit() for c in url) / len(url)), 4) if url else 0.0,
        "special_char_ratio": round((len(special_chars) / len(url)), 4) if url else 0.0,
        "shannon_entropy": round(shannon_entropy(url), 4),
        "has_ip_address": 1 if IP_PATTERN.match(hostname) else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_double_slash": 1 if url.rfind("//") > 7 else 0,  # beyond scheme
        "has_shortener": 1 if hostname in SHORTENER_DOMAINS else 0,
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
        "starts_with_https": 1 if url.lower().startswith("https") else 0,
        "hostname_has_digits": 1 if any(c.isdigit() for c in hostname) else 0,
        "tld_length": len(tld),
    }
    return features


def url_to_vector(url: str) -> list:
    """Extracts features and returns them as an ordered list matching FEATURE_NAMES."""
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]
