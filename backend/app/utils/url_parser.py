"""Robust URL parsing and normalization. Never fetches the URL."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

import idna
import tldextract

from app.security.ssrf import hostname_is_ip

ALLOWED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 4096


class URLParseError(ValueError):
    pass


@dataclass
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    username: str | None
    password_present: bool
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    registrable_domain: str
    registered_domain: str
    subdomains: list[str]
    tld: str
    is_ip: bool
    is_ipv6: bool
    punycode: bool
    unicode_hostname: str
    ascii_hostname: str
    query_params: dict[str, list[str]] = field(default_factory=dict)


def _looks_like_url(value: str) -> bool:
    if "://" in value:
        return True
    if re.match(r"^[\w.-]+\.[a-zA-Z]{2,}(/|$|\?)", value):
        return True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?(/|$)", value):
        return True
    return False


def normalize_input(raw: str) -> str:
    text = raw.strip()
    if not text:
        raise URLParseError("URL is empty")
    if len(text) > MAX_URL_LENGTH:
        raise URLParseError("URL exceeds maximum length")
    if any(ch.isspace() for ch in text.split(" ", 1)[0]) and "://" not in text[:12]:
        raise URLParseError("URL contains whitespace")
    if not _looks_like_url(text) and "://" not in text:
        raise URLParseError("Value does not look like a URL")
    if "://" not in text:
        text = "http://" + text
    return text


def _ascii_host(host: str) -> tuple[str, str, bool]:
    host = host.strip(".").lower()
    puny = "xn--" in host
    try:
        unicode_host = idna.decode(host)
    except Exception:
        unicode_host = host
    try:
        ascii_host = idna.encode(unicode_host).decode("ascii")
    except Exception:
        ascii_host = host
    if ascii_host.startswith("xn--") or "xn--" in ascii_host:
        puny = True
    return unicode_host, ascii_host, puny


def parse_url(raw: str) -> ParsedURL:
    prepared = normalize_input(raw)
    parsed = urlparse(prepared)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLParseError(f"Unsupported protocol: {scheme or 'none'}. Only http and https are analyzed.")
    if not parsed.hostname:
        raise URLParseError("URL is missing a hostname")

    hostname = parsed.hostname
    is_ip = hostname_is_ip(hostname)
    is_ipv6 = False
    if is_ip:
        try:
            is_ipv6 = ipaddress.ip_address(hostname.strip("[]")).version == 6
        except ValueError:
            is_ipv6 = False
        unicode_host = hostname
        ascii_host = hostname
        puny = False
        registrable = hostname
        registered = hostname
        subdomains: list[str] = []
        tld = ""
    else:
        unicode_host, ascii_host, puny = _ascii_host(hostname)
        extracted = tldextract.extract(ascii_host)
        tld = extracted.suffix or ""
        registered = ".".join(p for p in [extracted.domain, extracted.suffix] if p)
        registrable = registered or ascii_host
        subdomains = [s for s in extracted.subdomain.split(".") if s]

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    username = parsed.username
    password_present = parsed.password is not None

    # Normalized form: lowercase host, decoded path (display-safe), drop userinfo
    netloc = ascii_host
    if parsed.port:
        netloc = f"{ascii_host}:{parsed.port}"
    normalized = f"{scheme}://{netloc}{path}"
    if query:
        normalized += f"?{query}"

    return ParsedURL(
        original=raw.strip(),
        normalized=normalized,
        scheme=scheme,
        username=unquote(username) if username else None,
        password_present=password_present,
        hostname=ascii_host,
        port=parsed.port,
        path=unquote(path),
        query=query,
        fragment=fragment,
        registrable_domain=registrable,
        registered_domain=registered,
        subdomains=subdomains,
        tld=tld,
        is_ip=is_ip,
        is_ipv6=is_ipv6,
        punycode=puny,
        unicode_hostname=unicode_host,
        ascii_hostname=ascii_host,
        query_params=parse_qs(query, keep_blank_values=True),
    )
