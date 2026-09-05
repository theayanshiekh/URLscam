"""Heuristic / rule engine. Rules contribute weighted signals, never a lone verdict."""

from __future__ import annotations

from typing import Any

from app.services.brands import BRANDS, SHORTENER_DOMAINS, UNTRUSTED_TLDS
from app.services.similarity import levenshtein, normalized_distance, scripts_in, strip_confusables
from app.utils.url_parser import ParsedURL

EDUCATION: dict[str, dict[str, str]] = {
    "brand_impersonation": {
        "what": "The URL uses a well-known brand name, but the actual registered domain is not the official one.",
        "why": "Attackers place trusted names in subdomains or lookalike domains so the link feels familiar.",
        "do": "Open the official website by typing it yourself or using a saved bookmark. Do not log in from this link.",
    },
    "typosquatting": {
        "what": "The domain is a close misspelling or character substitution of a trusted brand domain.",
        "why": "Small visual changes (paypa1 vs paypal) are easy to miss under time pressure.",
        "do": "Compare the domain letter-by-letter with the official domain. If it differs, do not continue.",
    },
    "homograph": {
        "what": "The hostname uses Unicode / punycode characters that can look like Latin letters.",
        "why": "Internationalized domain names can hide lookalike letters from other scripts.",
        "do": "Treat punycode (xn--) domains with extra caution unless you fully trust the destination.",
    },
    "ip_url": {
        "what": "The site is addressed by a raw IP address instead of a normal domain name.",
        "why": "Legitimate consumer services almost never ask users to visit a raw IP for login.",
        "do": "Do not enter credentials. Use the organization's official domain.",
    },
    "subdomains": {
        "what": "The hostname has an unusually deep subdomain chain.",
        "why": "Extra labels (login.verify.account.example.com) can make the leftmost words look official.",
        "do": "Read the URL from the right: the registrable domain is what actually identifies the site.",
    },
    "keywords": {
        "what": "The URL contains authentication, payment, or urgency wording.",
        "why": "Phishing pages often advertise 'verify', 'login', or 'update' to create pressure.",
        "do": "Keywords alone are not proof. Combine this with domain ownership before you trust the page.",
    },
    "https": {
        "what": "The connection uses HTTPS.",
        "why": "HTTPS encrypts data in transit. It does not prove who operates the website.",
        "do": "A padlock is not a safety certificate. Still check the domain and the request context.",
    },
    "shortener": {
        "what": "The URL is served by a known shortening service.",
        "why": "Shorteners hide the final destination until you click.",
        "do": "Expand the link with a trusted preview tool, or navigate to the service directly.",
    },
    "untrusted_tld": {
        "what": "The domain uses a TLD frequently abused in phishing campaigns.",
        "why": "Cheap or loosely regulated TLDs appear more often in disposable phishing domains.",
        "do": "A rare TLD is a caution signal, not automatic proof. Verify the organization independently.",
    },
    "long_url": {
        "what": "The URL is unusually long or heavily encoded.",
        "why": "Length and encoding can hide the real destination or bury suspicious path segments.",
        "do": "Inspect the hostname separately from the path and query string.",
    },
}


def _factor(
    name: str,
    severity: str,
    score: float,
    explanation: str,
    evidence: str,
    education_key: str,
) -> dict[str, Any]:
    edu = EDUCATION.get(education_key, {})
    return {
        "name": name,
        "severity": severity,
        "score": round(score, 2),
        "explanation": explanation,
        "evidence": evidence,
        "what_it_means": edu.get("what", ""),
        "why_it_matters": edu.get("why", ""),
        "what_to_do": edu.get("do", ""),
        "education_key": education_key,
    }


def _official_domain(parsed: ParsedURL, official: str) -> bool:
    host = parsed.hostname.lower().rstrip(".")
    off = official.lower().rstrip(".")
    return host == off or host.endswith("." + off)


def analyze_brand_and_typo(parsed: ParsedURL) -> tuple[list[dict[str, Any]], float]:
    factors: list[dict[str, Any]] = []
    score = 0.0
    host = parsed.hostname.lower()
    domain = parsed.registrable_domain.lower()
    labels = [domain.replace("." + parsed.tld, "").split(".")[0] if parsed.tld else domain]
    labels += parsed.subdomains
    joined_sub = ".".join(parsed.subdomains).lower()
    domain_core = domain.split(".")[0] if domain else host

    for brand in BRANDS:
        keywords = [k.lower() for k in brand["keywords"]]
        officials = [d.lower() for d in brand["domains"]]
        if any(_official_domain(parsed, d) for d in officials):
            continue
        in_sub = any(k in joined_sub for k in keywords if len(k) > 2)
        in_domain = any(k in domain_core for k in keywords if len(k) > 2)
        if in_sub and not in_domain:
            bump = 28.0
            score += bump
            factors.append(
                _factor(
                    "Brand impersonation",
                    "high",
                    bump,
                    f"The hostname uses the {brand['name']} brand in a subdomain, but the registered domain is {parsed.registrable_domain}, which is not an official {brand['name']} domain.",
                    f"brand={brand['name']}; registrable_domain={parsed.registrable_domain}",
                    "brand_impersonation",
                )
            )
        elif in_domain:
            official_cores = [d.split(".")[0] for d in officials]
            if domain_core not in official_cores and domain not in officials:
                bump = 22.0
                score += bump
                factors.append(
                    _factor(
                        "Brand keyword on unrelated domain",
                        "high",
                        bump,
                        f"The registered domain contains a {brand['name']} keyword but does not match official domains ({', '.join(officials[:3])}).",
                        f"brand={brand['name']}; domain={domain}",
                        "brand_impersonation",
                    )
                )

        for official in officials:
            official_core = official.split(".")[0]
            target = domain_core
            if len(target) < 4:
                continue
            dist = levenshtein(target, official_core)
            nd = normalized_distance(target, official_core)
            folded = strip_confusables(target)
            folded_off = strip_confusables(official_core)
            if target == official_core:
                continue
            lookalike = (1 <= dist <= 2 and len(official_core) >= 5) or (
                nd <= 0.25 and len(official_core) >= 5
            ) or (folded == folded_off and target != official_core)
            if lookalike and domain not in officials:
                bump = 26.0
                score += bump
                factors.append(
                    _factor(
                        "Typosquatting / lookalike domain",
                        "high",
                        bump,
                        f"'{domain}' is visually or edit-distance similar to official {brand['name']} domain '{official}' (Levenshtein={dist}, normalized={nd:.2f}).",
                        f"compared_to={official}; distance={dist}",
                        "typosquatting",
                    )
                )
                break
    return factors, min(score, 40.0)


def run_heuristics(parsed: ParsedURL, features: dict[str, Any]) -> tuple[list[dict[str, Any]], float]:
    factors: list[dict[str, Any]] = []
    heuristic_score = 0.0

    brand_factors, brand_score = analyze_brand_and_typo(parsed)
    factors.extend(brand_factors)
    heuristic_score += brand_score

    if parsed.is_ip:
        factors.append(
            _factor(
                "IP address URL",
                "high",
                18,
                "The URL uses a raw IP address instead of a domain name, which is uncommon for legitimate consumer logins.",
                parsed.hostname,
                "ip_url",
            )
        )
        heuristic_score += 18

    if len(parsed.subdomains) >= 3:
        sev, pts = ("high", 14) if len(parsed.subdomains) >= 4 else ("medium", 9)
        factors.append(
            _factor(
                "Excessive subdomain complexity",
                sev,
                pts,
                f"The hostname has {len(parsed.subdomains)} subdomain labels ({'.'.join(parsed.subdomains)}), which can disguise the real registered domain.",
                ".".join(parsed.subdomains),
                "subdomains",
            )
        )
        heuristic_score += pts

    scripts = scripts_in(parsed.unicode_hostname)
    if parsed.punycode or len(scripts) > 1:
        factors.append(
            _factor(
                "Homograph / IDN risk",
                "high",
                16,
                "The hostname uses punycode or mixed writing scripts, which can hide visually confusable characters.",
                f"unicode={parsed.unicode_hostname}; ascii={parsed.ascii_hostname}; scripts={sorted(scripts)}",
                "homograph",
            )
        )
        heuristic_score += 16

    tld = (parsed.tld or "").split(".")[-1].lower()
    if tld in UNTRUSTED_TLDS:
        factors.append(
            _factor(
                "Untrusted TLD",
                "medium",
                8,
                f"The TLD '.{tld}' is frequently seen on disposable phishing domains. This is a weighted signal, not proof.",
                tld,
                "untrusted_tld",
            )
        )
        heuristic_score += 8

    if parsed.registrable_domain.lower() in SHORTENER_DOMAINS:
        factors.append(
            _factor(
                "URL shortener",
                "medium",
                7,
                "This hostname belongs to a URL shortening service, which hides the final destination.",
                parsed.registrable_domain,
                "shortener",
            )
        )
        heuristic_score += 7

    groups = features.get("keyword_groups") or {}
    sensitive = {"login", "verify", "account", "payment", "otp", "bank", "wallet", "urgency", "government"}
    hit = [g for g in groups if g in sensitive]
    if hit:
        pts = min(6 + 3 * len(hit), 16)
        factors.append(
            _factor(
                "Suspicious keywords",
                "medium" if pts < 12 else "high",
                pts,
                "The URL contains credential, payment, or urgency-related wording: " + ", ".join(hit) + ".",
                ",".join(hit),
                "keywords",
            )
        )
        heuristic_score += pts

    if features.get("url_length", 0) >= 90:
        factors.append(
            _factor(
                "Unusually long URL",
                "low",
                5,
                "Attackers may use long URLs to hide the destination or bury suspicious path segments.",
                str(features.get("url_length")),
                "long_url",
            )
        )
        heuristic_score += 5

    if features.get("has_userinfo"):
        factors.append(
            _factor(
                "Embedded user information",
                "medium",
                10,
                "The URL contains a username/password component (user@host), a classic phishing obfuscation trick.",
                parsed.username or "userinfo",
                "keywords",
            )
        )
        heuristic_score += 10

    if parsed.scheme == "https":
        factors.append(
            _factor(
                "HTTPS enabled",
                "positive",
                -4,
                "HTTPS is enabled. This only encrypts the connection; it does not prove the website is legitimate.",
                "https",
                "https",
            )
        )
        heuristic_score -= 4
    else:
        factors.append(
            _factor(
                "No HTTPS",
                "medium",
                8,
                "The URL uses HTTP without TLS. Credentials sent to this address could be intercepted.",
                "http",
                "https",
            )
        )
        heuristic_score += 8

    if features.get("contains_suspicious_port"):
        factors.append(
            _factor(
                "Unusual port",
                "medium",
                6,
                f"The URL specifies a non-standard port ({parsed.port}), which is uncommon for consumer websites.",
                str(parsed.port),
                "long_url",
            )
        )
        heuristic_score += 6

    heuristic_score = max(0.0, min(heuristic_score, 100.0))
    return factors, heuristic_score
