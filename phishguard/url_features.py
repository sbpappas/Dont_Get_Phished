"""Lexical feature extraction from a raw URL string.

Everything in this module is a pure function of the URL text itself -- no
network access, no filesystem access, fully deterministic. That makes it the
cheapest and most reliable feature tier: it always works, even for a URL
that never resolves, and it's what `phishguard analyze --offline` runs on.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qsl

VOWELS = set("aeiouAEIOU")

# A broad-but-not-exhaustive list of TLDs used to count "how many TLD-looking
# tokens appear in this URL" -- a classic phishing tell is a real TLD baked
# into a subdomain, e.g. "paypal.com.security-verify.xyz".
COMMON_TLDS = [
    "com", "net", "org", "info", "biz", "gov", "edu", "mil", "io", "co",
    "us", "uk", "ca", "de", "fr", "es", "it", "nl", "ru", "cn", "jp", "kr",
    "in", "br", "au", "eu", "me", "tv", "cc", "ai", "app", "dev", "xyz",
    "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "site",
    "online", "shop", "store", "live", "life", "world", "icu", "buzz",
    "monster", "cyou", "rest", "zip", "review", "loan", "men", "gdn",
    "kim", "science", "party", "download", "stream", "bid", "win", "cricket",
]

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorturl.at", "cutt.ly", "rebrand.ly", "tiny.cc", "soo.gd",
    "s.id", "rb.gy", "v.gd", "shorte.st", "bl.ink", "lnkd.in", "snip.ly",
    "rebrandly.com", "clck.ru", "chilp.it",
}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


@dataclass
class UrlParts:
    url: str
    scheme: str
    domain: str          # hostname, no port, no credentials
    port: int | None
    directory: str
    file: str
    query: str


def split_url(url: str) -> UrlParts:
    parts = urlsplit(url if "//" in url else f"//{url}", scheme="http")
    hostname = parts.hostname or ""
    path = parts.path or ""

    if path == "" or path.endswith("/"):
        directory, file = path, ""
    else:
        idx = path.rfind("/")
        if idx == -1:
            directory, file = "", path
        else:
            directory, file = path[: idx + 1], path[idx + 1 :]

    return UrlParts(
        url=url,
        scheme=parts.scheme or "http",
        domain=hostname,
        port=parts.port,
        directory=directory,
        file=file,
        query=parts.query or "",
    )


def _qty(text: str, ch: str) -> int:
    return text.count(ch)


def _count_tld_occurrences(text: str) -> int:
    lowered = text.lower()
    count = 0
    for tld in COMMON_TLDS:
        count += len(re.findall(rf"\.{tld}(?:[/.:?#&]|$)", lowered))
    return count


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_url_features(url: str) -> dict:
    """Compute every offline (lexical) feature in FEATURE_ORDER for `url`."""
    p = split_url(url)
    domain = p.domain
    directory = p.directory
    file_ = p.file
    query = p.query
    query_pairs = parse_qsl(query, keep_blank_values=True)

    features = {
        "qty_dot_url": _qty(url, "."),
        "qty_hyphen_url": _qty(url, "-"),
        "qty_underline_url": _qty(url, "_"),
        "qty_slash_url": _qty(url, "/"),
        "qty_questionmark_url": _qty(url, "?"),
        "qty_equal_url": _qty(url, "="),
        "qty_at_url": _qty(url, "@"),
        "qty_and_url": _qty(url, "&"),
        "qty_exclamation_url": _qty(url, "!"),
        "qty_tilde_url": _qty(url, "~"),
        "qty_tld_url": _count_tld_occurrences(url),
        "length_url": len(url),
        "qty_dot_domain": _qty(domain, "."),
        "qty_hyphen_domain": _qty(domain, "-"),
        "qty_underline_domain": _qty(domain, "_"),
        "qty_vowels_domain": sum(1 for c in domain if c in VOWELS),
        "domain_length": len(domain),
        "domain_in_ip": int(_is_ip(domain)),
        "server_client_domain": int(
            "server" in domain.lower() or "client" in domain.lower()
        ),
        "qty_dot_directory": _qty(directory, "."),
        "qty_hyphen_directory": _qty(directory, "-"),
        "qty_slash_directory": _qty(directory, "/"),
        "directory_length": len(directory),
        "file_length": len(file_),
        "qty_params": len(query_pairs),
        "tld_present_params": int(_count_tld_occurrences(query) > 0),
        "params_length": len(query),
        "email_in_url": int(bool(EMAIL_RE.search(url)) or "mailto:" in url.lower()),
        "url_shortened": int(_strip_www(domain.lower()) in KNOWN_SHORTENERS),
    }
    return features
