"""Safe, read-only HTTP fetching for live URL analysis.

Design constraints, all deliberate:
  * GET only, never submits forms or executes JavaScript.
  * Refuses to connect to loopback / private / link-local / reserved IPs so
    the tool can't be pointed at internal infrastructure (basic SSRF guard).
  * Hard timeout and a response-size cap so a malicious or huge page can't
    hang or exhaust memory.
  * Identifies itself with a descriptive User-Agent rather than pretending
    to be a browser.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests

USER_AGENT = "PhishGuard/0.1 (+educational-phishing-analyzer; read-only GET)"
TIMEOUT_SECONDS = 8
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5


class FetchBlocked(Exception):
    """Raised when a URL is refused before any network request is made."""


class FetchFailed(Exception):
    """Raised when the network request itself fails (DNS, timeout, refused)."""


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    html: str
    time_response: float
    qty_redirects: int
    headers: dict = field(default_factory=dict)


def _resolved_ips_are_safe(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True  # let the real request surface the DNS failure
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
    return True


def guard_url(url: str, allow_local: bool = False) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchBlocked(f"Unsupported scheme: {parts.scheme!r}")
    hostname = parts.hostname
    if not hostname:
        raise FetchBlocked("URL has no hostname")
    if allow_local:
        return
    if hostname in ("localhost",):
        raise FetchBlocked("Refusing to fetch localhost")
    if not _resolved_ips_are_safe(hostname):
        raise FetchBlocked(
            f"Refusing to fetch {hostname!r}: resolves to a private/internal address"
        )


def fetch(url: str, allow_local: bool = False) -> FetchResult:
    """Fetch `url` and return timing/redirect/HTML info, or raise.

    Raises FetchBlocked (refused before connecting) or FetchFailed (network
    error). Callers should catch both and fall back to offline analysis.
    """
    guard_url(url, allow_local=allow_local)
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT_SECONDS,
            allow_redirects=True,
            stream=True,
        )
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=8192):
            total += len(chunk)
            if total > MAX_BYTES:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        html = raw.decode(response.encoding or "utf-8", errors="replace")
    except requests.exceptions.RequestException as exc:
        raise FetchFailed(str(exc)) from exc

    if len(response.history) > MAX_REDIRECTS:
        raise FetchFailed(f"Too many redirects ({len(response.history)})")

    return FetchResult(
        final_url=response.url,
        status_code=response.status_code,
        html=html,
        time_response=response.elapsed.total_seconds(),
        qty_redirects=len(response.history),
        headers=dict(response.headers),
    )
