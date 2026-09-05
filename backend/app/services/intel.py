"""Optional DNS, TLS, and reputation intelligence. Failures never abort local analysis."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings
from app.security.ssrf import SSRFBlocked, assert_public_hostname
from app.utils.url_parser import ParsedURL


def _safe_dns(parsed: ParsedURL) -> dict[str, Any]:
    settings = get_settings()
    result: dict[str, Any] = {
        "available": False,
        "error": None,
        "a": [],
        "aaaa": [],
        "mx": False,
        "ns": False,
        "cname": False,
    }
    if parsed.is_ip:
        result["error"] = "Skipped DNS for raw IP URLs"
        return result
    try:
        assert_public_hostname(parsed.hostname, parsed.port)
    except SSRFBlocked as exc:
        result["error"] = str(exc)
        return result
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = settings.dns_timeout
        resolver.timeout = settings.dns_timeout

        def _records(rtype: str) -> list[str]:
            try:
                answers = resolver.resolve(parsed.hostname, rtype)
                return [str(r).rstrip(".") for r in answers]
            except Exception:
                return []

        result["a"] = _records("A")[:5]
        result["aaaa"] = _records("AAAA")[:5]
        result["mx"] = bool(_records("MX"))
        result["ns"] = bool(_records("NS"))
        result["cname"] = bool(_records("CNAME"))
        result["available"] = bool(result["a"] or result["aaaa"])
        if not result["available"]:
            result["error"] = "No A/AAAA records resolved"
    except Exception as exc:
        result["error"] = "DNS lookup unavailable"
        result["detail"] = type(exc).__name__
    return result


def _safe_tls(parsed: ParsedURL) -> dict[str, Any]:
    settings = get_settings()
    out: dict[str, Any] = {
        "checked": False,
        "https_available": parsed.scheme == "https",
        "valid": None,
        "issuer": None,
        "expires": None,
        "hostname_match": None,
        "error": None,
    }
    if parsed.scheme != "https":
        out["error"] = "Not an HTTPS URL"
        return out
    try:
        assert_public_hostname(parsed.hostname, parsed.port or 443)
    except SSRFBlocked as exc:
        out["error"] = str(exc)
        return out
    context = ssl.create_default_context()
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=settings.tls_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()
                out["checked"] = True
                out["valid"] = True
                out["hostname_match"] = True
                issuer = dict(x[0] for x in cert.get("issuer", []))
                out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                not_after = cert.get("notAfter")
                if not_after:
                    out["expires"] = not_after
    except ssl.SSLCertVerificationError as exc:
        out["checked"] = True
        out["valid"] = False
        out["hostname_match"] = False
        out["error"] = "Certificate verification failed"
        out["detail"] = str(exc)
    except Exception as exc:
        out["error"] = "TLS handshake skipped or failed"
        out["detail"] = type(exc).__name__
    return out


def _rdap(parsed: ParsedURL) -> dict[str, Any]:
    settings = get_settings()
    out: dict[str, Any] = {"available": False, "registrar": None, "created": None, "age_days": None, "error": None}
    if parsed.is_ip:
        out["error"] = "RDAP skipped for IP"
        return out
    domain = parsed.registrable_domain
    if not domain or "." not in domain:
        out["error"] = "No registrable domain"
        return out
    try:
        assert_public_hostname(parsed.hostname)
    except SSRFBlocked as exc:
        out["error"] = str(exc)
        return out
    try:
        import httpx

        url = f"https://rdap.org/domain/{domain}"
        with httpx.Client(timeout=settings.intel_timeout, follow_redirects=False) as client:
            resp = client.get(url, headers={"User-Agent": "PhishGuardAI/1.0"})
        if resp.status_code >= 400:
            out["error"] = f"RDAP unavailable ({resp.status_code})"
            return out
        data = resp.json()
        out["available"] = True
        entities = data.get("entities") or []
        for ent in entities:
            vcard = ent.get("vcardArray") or []
            roles = ent.get("roles") or []
            if "registrar" in roles:
                out["registrar"] = ent.get("handle")
                if isinstance(vcard, list) and len(vcard) > 1:
                    for item in vcard[1]:
                        if item and item[0] == "fn":
                            out["registrar"] = item[3]
        events = data.get("events") or []
        created = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)
        out["created"] = created
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                out["age_days"] = max((datetime.now(timezone.utc) - dt).days, 0)
            except Exception:
                pass
    except Exception as exc:
        out["error"] = "RDAP lookup failed"
        out["detail"] = type(exc).__name__
    return out


def gather_intelligence(parsed: ParsedURL) -> dict[str, Any]:
    dns = _safe_dns(parsed)
    tls = _safe_tls(parsed)
    rdap = _rdap(parsed)
    reputation = {
        "virustotal": {"configured": bool(get_settings().virustotal_api_key), "checked": False, "status": "not_configured"},
        "google_safe_browsing": {
            "configured": bool(get_settings().google_safe_browsing_key),
            "checked": False,
            "status": "not_configured",
        },
        "urlhaus": {"configured": get_settings().urlhaus_enabled, "checked": False, "status": "disabled"},
    }
    settings = get_settings()
    if settings.virustotal_api_key:
        reputation["virustotal"]["status"] = "skipped_until_key_used"
        reputation["virustotal"]["note"] = "Connector present. Local analysis continues if the API is unreachable."
        try:
            import httpx

            assert_public_hostname("www.virustotal.com")
            with httpx.Client(timeout=settings.intel_timeout) as client:
                resp = client.get(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": settings.virustotal_api_key},
                    params={"limit": 1},
                )
            # VT URL lookup requires URL-id; we do a lightweight authenticated ping only.
            reputation["virustotal"]["checked"] = resp.status_code < 500
            if resp.status_code >= 400:
                reputation["virustotal"]["status"] = "unavailable"
                reputation["virustotal"]["note"] = "External reputation service unavailable."
            else:
                reputation["virustotal"]["status"] = "reachable_not_authoritative"
                reputation["virustotal"]["note"] = "VirusTotal API reachable. Full URL report mapping can be enabled with a lookup id."
        except Exception:
            reputation["virustotal"]["status"] = "unavailable"
            reputation["virustotal"]["note"] = "External reputation service unavailable."

    if settings.google_safe_browsing_key:
        reputation["google_safe_browsing"]["status"] = "configured"
        reputation["google_safe_browsing"]["note"] = "Safe Browsing key present. Lookup uses Google API only when enabled."
        try:
            import httpx

            payload = {
                "client": {"clientId": "phishguard-ai", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": parsed.normalized}],
                },
            }
            with httpx.Client(timeout=settings.intel_timeout) as client:
                resp = client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.google_safe_browsing_key}",
                    json=payload,
                )
            reputation["google_safe_browsing"]["checked"] = True
            if resp.status_code >= 400:
                reputation["google_safe_browsing"]["status"] = "unavailable"
                reputation["google_safe_browsing"]["note"] = "External reputation service unavailable."
            else:
                matches = resp.json().get("matches") or []
                reputation["google_safe_browsing"]["status"] = "checked"
                reputation["google_safe_browsing"]["matches"] = len(matches)
        except Exception:
            reputation["google_safe_browsing"]["status"] = "unavailable"
            reputation["google_safe_browsing"]["note"] = "External reputation service unavailable."

    intel_score = 0.0
    notes: list[str] = []
    if dns.get("error") == "No A/AAAA records resolved":
        intel_score += 10
        notes.append("Domain did not resolve publicly.")
    if tls.get("valid") is False:
        intel_score += 12
        notes.append("TLS certificate could not be verified.")
    age = rdap.get("age_days")
    if isinstance(age, int) and age < 30:
        intel_score += 8
        notes.append(f"RDAP reports a young domain (~{age} days). New domains can be legitimate.")
    if reputation["google_safe_browsing"].get("matches"):
        intel_score += 25
        notes.append("Google Safe Browsing reported a threat match.")

    return {
        "dns": dns,
        "tls": tls,
        "rdap": rdap,
        "reputation": reputation,
        "intel_score": intel_score,
        "notes": notes,
        "redirects": {
            "enabled": settings.enable_redirect_analysis,
            "reason": "Disabled by default to prevent SSRF. Set ENABLE_REDIRECT_ANALYSIS=true only in a controlled environment.",
        },
    }
