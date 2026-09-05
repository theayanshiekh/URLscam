"""Lexical and structural feature extraction."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from app.services.brands import KEYWORD_GROUPS, SHORTENER_DOMAINS, UNTRUSTED_TLDS
from app.utils.url_parser import ParsedURL

SUSPICIOUS_PORTS = {21, 22, 23, 25, 8080, 8443, 8888, 10443, 4443, 9000, 9090}

FEATURE_ORDER = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_at",
    "num_question",
    "num_equals",
    "num_percent",
    "num_digits",
    "num_special",
    "num_subdomains",
    "num_query_params",
    "num_path_segments",
    "contains_ip",
    "contains_at_symbol",
    "contains_double_slash",
    "contains_punycode",
    "contains_encoded_characters",
    "contains_suspicious_port",
    "uses_https",
    "contains_login_keyword",
    "contains_verify_keyword",
    "contains_account_keyword",
    "contains_payment_keyword",
    "contains_security_keyword",
    "contains_update_keyword",
    "contains_bank_keyword",
    "contains_free_keyword",
    "contains_reward_keyword",
    "contains_wallet_keyword",
    "contains_otp_keyword",
    "hostname_entropy",
    "path_entropy",
    "digit_ratio",
    "special_character_ratio",
    "subdomain_ratio",
    "untrusted_tld",
    "is_shortener",
    "has_userinfo",
    "mixed_script",
    "hyphen_count_domain",
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _bool_int(value: bool) -> int:
    return 1 if value else 0


def _haystack(parsed: ParsedURL) -> str:
    return " ".join(
        [
            parsed.normalized.lower(),
            parsed.hostname.lower(),
            parsed.path.lower(),
            parsed.query.lower(),
            parsed.unicode_hostname.lower(),
        ]
    )


def keyword_hits(parsed: ParsedURL) -> dict[str, bool]:
    blob = _haystack(parsed)
    hits: dict[str, bool] = {}
    for group, words in KEYWORD_GROUPS.items():
        hits[group] = any(w in blob for w in words)
    return hits


def extract_features(parsed: ParsedURL) -> dict[str, Any]:
    url = parsed.normalized
    host = parsed.hostname
    path = parsed.path
    query = parsed.query
    hits = keyword_hits(parsed)
    encoded = url.count("%")
    digits = sum(ch.isdigit() for ch in url)
    specials = sum(not ch.isalnum() for ch in url)
    path_segments = [p for p in path.split("/") if p]
    scripts = set()
    try:
        from app.services.similarity import scripts_in

        scripts = scripts_in(parsed.unicode_hostname)
    except Exception:
        scripts = set()

    tld = (parsed.tld or "").split(".")[-1].lower()
    features: dict[str, Any] = {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_equals": url.count("="),
        "num_percent": encoded,
        "num_digits": digits,
        "num_special": specials,
        "num_subdomains": len(parsed.subdomains),
        "num_query_params": len(parsed.query_params),
        "num_path_segments": len(path_segments),
        "contains_ip": _bool_int(parsed.is_ip),
        "contains_at_symbol": _bool_int("@" in url.split("://", 1)[-1].split("/", 1)[0] or parsed.username is not None),
        "contains_double_slash": _bool_int("//" in (path + query)),
        "contains_punycode": _bool_int(parsed.punycode),
        "contains_encoded_characters": _bool_int(encoded > 0),
        "contains_suspicious_port": _bool_int(parsed.port is not None and parsed.port in SUSPICIOUS_PORTS),
        "uses_https": _bool_int(parsed.scheme == "https"),
        "contains_login_keyword": _bool_int(hits["login"]),
        "contains_verify_keyword": _bool_int(hits["verify"]),
        "contains_account_keyword": _bool_int(hits["account"]),
        "contains_payment_keyword": _bool_int(hits["payment"]),
        "contains_security_keyword": _bool_int(hits["security"]),
        "contains_update_keyword": _bool_int(hits["update"]),
        "contains_bank_keyword": _bool_int(hits["bank"]),
        "contains_free_keyword": _bool_int(hits["free"]),
        "contains_reward_keyword": _bool_int(hits["reward"]),
        "contains_wallet_keyword": _bool_int(hits["wallet"]),
        "contains_otp_keyword": _bool_int(hits["otp"]),
        "hostname_entropy": round(_entropy(host), 4),
        "path_entropy": round(_entropy(path), 4),
        "digit_ratio": round(digits / max(len(url), 1), 4),
        "special_character_ratio": round(specials / max(len(url), 1), 4),
        "subdomain_ratio": round(len(parsed.subdomains) / max(host.count(".") + 1, 1), 4),
        "untrusted_tld": _bool_int(tld in UNTRUSTED_TLDS),
        "is_shortener": _bool_int(parsed.registrable_domain.lower() in SHORTENER_DOMAINS),
        "has_userinfo": _bool_int(parsed.username is not None or parsed.password_present),
        "mixed_script": _bool_int(len(scripts) > 1),
        "hyphen_count_domain": parsed.registrable_domain.count("-"),
        "character_distribution": dict(Counter(url.lower())),
        "keyword_groups": {k: v for k, v in hits.items() if v},
        "tld": parsed.tld,
        "registrable_domain": parsed.registrable_domain,
        "subdomains": parsed.subdomains,
    }
    return features


def vectorize(features: dict[str, Any]) -> list[float]:
    row: list[float] = []
    for name in FEATURE_ORDER:
        value = features.get(name, 0)
        if isinstance(value, bool):
            row.append(1.0 if value else 0.0)
        else:
            row.append(float(value or 0))
    return row
