"""SSRF protections for any optional network look-ups."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
}

METADATA_HINTS = (
    "169.254.169.254",
    "metadata.google",
    "169.254.170.2",
)

BLOCKED_PORTS = {22, 23, 25, 135, 139, 445, 3306, 3389, 5432, 6379, 11211, 27017}


class SSRFBlocked(ValueError):
    pass


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def hostname_is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def assert_public_hostname(hostname: str | None, port: int | None = None) -> None:
    if not hostname:
        raise SSRFBlocked("Missing hostname")
    host = hostname.strip().lower().rstrip(".")
    if host in BLOCKED_HOSTS:
        raise SSRFBlocked("Blocked hostname")
    if any(h in host for h in METADATA_HINTS):
        raise SSRFBlocked("Blocked metadata endpoint")
    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".localhost"):
        raise SSRFBlocked("Blocked internal hostname")
    if port is not None and port in BLOCKED_PORTS:
        raise SSRFBlocked("Blocked port")
    if hostname_is_ip(host):
        if _is_private_ip(host.strip("[]")):
            raise SSRFBlocked("Private or reserved IP is not reachable by the scanner")
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"DNS resolution failed: {exc}") from exc
    if not infos:
        raise SSRFBlocked("DNS resolution returned no addresses")
    for info in infos:
        ip = info[4][0]
        if _is_private_ip(ip):
            raise SSRFBlocked("Hostname resolves to a private or reserved address")


def assert_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SSRFBlocked("Unsupported scheme")
    assert_public_hostname(parsed.hostname, parsed.port)
