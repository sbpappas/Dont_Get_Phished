"""Live network/host features: DNS, WHOIS, TLS certificate.

Every lookup here is wrapped so a single slow/broken service (a WHOIS server
that never replies, a DNS resolver that times out) degrades that one feature
to UNKNOWN (-1) instead of failing the whole analysis. That mirrors the
sentinel convention used in the training dataset.
"""
from __future__ import annotations

import concurrent.futures
import socket
import ssl
from datetime import datetime, timezone

import certifi
import dns.resolver

from .feature_schema import UNKNOWN

DNS_TIMEOUT = 4.0
TLS_TIMEOUT = 5.0
WHOIS_TIMEOUT = 6.0


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


def _dns_count(hostname: str, rtype: str) -> int:
    try:
        answer = _resolver().resolve(hostname, rtype)
        return len(answer)
    except Exception:
        return UNKNOWN


def _dns_ttl(hostname: str) -> int:
    try:
        answer = _resolver().resolve(hostname, "A")
        return int(answer.rrset.ttl)
    except Exception:
        return UNKNOWN


def _domain_spf(hostname: str) -> int:
    try:
        answer = _resolver().resolve(hostname, "TXT")
        for rdata in answer:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.lower().startswith("v=spf1"):
                return 1
        return 0
    except Exception:
        return UNKNOWN


def _tls_certificate_valid(hostname: str) -> int:
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return int(not_after.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc))
    except Exception:
        return 0


def _whois_dates(hostname: str) -> tuple[int, int]:
    try:
        import whois  # python-whois; imported lazily, it's a soft dependency
    except ImportError:
        return UNKNOWN, UNKNOWN

    def _lookup():
        return whois.whois(hostname)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(_lookup).result(timeout=WHOIS_TIMEOUT)
    except Exception:
        return UNKNOWN, UNKNOWN

    def _first(value):
        if isinstance(value, list):
            value = value[0] if value else None
        return value

    created = _first(getattr(result, "creation_date", None))
    expires = _first(getattr(result, "expiration_date", None))
    now = datetime.now()

    activation = UNKNOWN
    expiration = UNKNOWN
    if isinstance(created, datetime):
        activation = max((now - created.replace(tzinfo=None)).days, 0)
    if isinstance(expires, datetime):
        expiration = (expires.replace(tzinfo=None) - now).days

    return activation, expiration


def extract_network_features(hostname: str) -> dict:
    """Compute every live network feature in FEATURE_ORDER for `hostname`.

    Note: time_response and qty_redirects come from the HTTP fetch, not
    from here -- the analyzer merges them in.
    """
    activation, expiration = _whois_dates(hostname)
    return {
        "domain_spf": _domain_spf(hostname),
        "time_domain_activation": activation,
        "time_domain_expiration": expiration,
        "qty_ip_resolved": _dns_count(hostname, "A"),
        "qty_nameservers": _dns_count(hostname, "NS"),
        "qty_mx_servers": _dns_count(hostname, "MX"),
        "ttl_hostname": _dns_ttl(hostname),
        "tls_ssl_certificate": _tls_certificate_valid(hostname),
    }
