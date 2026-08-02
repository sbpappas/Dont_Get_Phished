"""Explainable rule-based scoring engine.

This is deliberately separate from the ML model (`ml_model.py`). The model
gives a statistical base rate learned from ~58k labeled examples; this
engine gives a human-readable "why" -- a list of concrete, named red flags a
non-technical user can act on even without trusting a black-box score.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from .url_features import UrlParts
from .feature_schema import UNKNOWN

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "country", "zip", "review", "loan", "men", "gdn", "kim", "science",
    "party", "download", "stream", "bid", "win", "faith", "accountant",
    "cricket", "icu", "buzz", "monster", "cyou", "rest",
}

SEVERITY_POINTS = {"low": 5, "medium": 10, "high": 20, "critical": 30}


@dataclass
class Finding:
    code: str
    message: str
    severity: str  # low | medium | high | critical
    points: int


@dataclass
class HeuristicResult:
    findings: list[Finding] = field(default_factory=list)
    score: int = 0  # 0-100, clipped

    def add(self, code: str, message: str, severity: str, points: int | None = None):
        pts = points if points is not None else SEVERITY_POINTS[severity]
        self.findings.append(Finding(code, message, severity, pts))


def _registered_domain(host: str) -> str:
    labels = host.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _brand_flags(domain: str, brands: dict[str, str], result: HeuristicResult) -> None:
    reg_domain = _registered_domain(domain)
    domain_lower = domain.lower()

    for brand, real_domain in brands.items():
        real_reg = _registered_domain(real_domain)
        if reg_domain == real_reg:
            continue  # this IS the real site (or a subdomain of it)

        if brand in domain_lower:
            result.add(
                "brand_in_domain_mismatch",
                f"Domain contains the brand name '{brand}' but is not "
                f"'{real_domain}' (registered domain is '{reg_domain}') -- "
                f"classic impersonation pattern.",
                "critical",
            )
            return

        similarity = difflib.SequenceMatcher(None, reg_domain, real_reg).ratio()
        if similarity >= 0.82:
            result.add(
                "typosquat_similarity",
                f"Domain '{reg_domain}' is suspiciously similar to "
                f"'{real_reg}' ({similarity:.0%} match) -- possible "
                f"typosquat of {brand}.",
                "critical",
            )
            return


def _keyword_flags(url_parts: UrlParts, keywords: list[str], result: HeuristicResult) -> None:
    haystack = f"{url_parts.domain}{url_parts.directory}{url_parts.file}".lower()
    hits = [kw for kw in keywords if kw in haystack]
    if len(hits) >= 2:
        result.add(
            "suspicious_keyword_cluster",
            f"URL contains multiple credential/urgency-themed keywords: "
            f"{', '.join(hits[:5])}.",
            "medium",
        )


def evaluate(
    url_parts: UrlParts,
    url_feats: dict,
    net_feats: dict | None,
    content: "object | None",
    brands: dict[str, str],
    keywords: list[str],
) -> HeuristicResult:
    result = HeuristicResult()
    domain = url_parts.domain

    if url_feats.get("domain_in_ip"):
        result.add(
            "ip_as_hostname",
            "URL uses a raw IP address instead of a domain name.",
            "high",
        )

    if any(label.startswith("xn--") for label in domain.lower().split(".")):
        result.add(
            "punycode_domain",
            "Domain uses punycode (internationalized) encoding, which can "
            "be used to visually spoof a trusted domain (homograph attack).",
            "medium",
        )

    if any(ord(c) > 127 for c in domain):
        result.add(
            "non_ascii_domain",
            "Domain contains non-ASCII characters, which can visually "
            "mimic a trusted domain.",
            "critical",
        )

    if url_feats.get("qty_at_url", 0) > 0:
        result.add(
            "at_symbol_in_url",
            "URL contains an '@' symbol, which browsers ignore everything "
            "before -- often used to disguise the real destination.",
            "high",
        )

    if url_feats.get("qty_dot_domain", 0) >= 3 and not url_feats.get("domain_in_ip"):
        result.add(
            "excessive_subdomains",
            "Domain has an unusually large number of subdomain levels.",
            "medium",
        )

    tld = domain.lower().rsplit(".", 1)[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS and not url_feats.get("domain_in_ip"):
        result.add(
            "suspicious_tld",
            f"Top-level domain '.{tld}' is frequently abused for "
            f"low-cost, throwaway phishing domains.",
            "medium",
        )

    if url_feats.get("url_shortened"):
        result.add(
            "url_shortener",
            "URL uses a link-shortening service, hiding the real "
            "destination until you click.",
            "medium",
        )

    if url_feats.get("length_url", 0) > 100:
        result.add(
            "long_url",
            "URL is unusually long, a common way to bury a fake domain or "
            "obscure the real destination.",
            "low",
        )

    if url_parts.scheme != "https":
        result.add(
            "no_https",
            "URL does not use HTTPS.",
            "medium",
        )

    _brand_flags(domain, brands, result)
    _keyword_flags(url_parts, keywords, result)

    if net_feats is not None:
        activation = net_feats.get("time_domain_activation", UNKNOWN)
        if activation != UNKNOWN:
            if activation < 30:
                result.add(
                    "very_new_domain",
                    f"Domain was registered only {activation} day(s) ago -- "
                    f"phishing domains are typically short-lived.",
                    "critical",
                )
            elif activation < 180:
                result.add(
                    "recent_domain",
                    f"Domain was registered {activation} days ago, "
                    f"relatively recent.",
                    "medium",
                )

        expiration = net_feats.get("time_domain_expiration", UNKNOWN)
        if expiration != UNKNOWN and expiration < 30:
            result.add(
                "expires_soon",
                f"Domain registration expires in {expiration} day(s), "
                f"consistent with a throwaway domain.",
                "medium",
            )

        if net_feats.get("tls_ssl_certificate") == 0:
            result.add(
                "no_valid_tls",
                "Site does not present a valid TLS certificate on port 443.",
                "high",
            )

        if net_feats.get("qty_ip_resolved", UNKNOWN) == 0:
            result.add(
                "dns_does_not_resolve",
                "Domain does not currently resolve to any IP address.",
                "high",
            )

        redirects = net_feats.get("qty_redirects", 0)
        if isinstance(redirects, int) and redirects > 2:
            result.add(
                "many_redirects",
                f"Request followed {redirects} redirects before landing on "
                f"the final page.",
                "medium",
            )

    if content is not None:
        if content.password_field_count > 0 and content.external_form_actions:
            result.add(
                "password_form_external_action",
                f"Page has a password field whose form submits to an "
                f"external domain ({content.external_form_actions[0]}) "
                f"instead of the page's own domain.",
                "critical",
            )
        elif content.password_field_count > 0 and url_feats.get("domain_in_ip"):
            result.add(
                "password_field_on_ip_host",
                "Page collects a password while hosted on a raw IP address.",
                "critical",
            )

        if content.javascript_form_actions:
            result.add(
                "javascript_form_action",
                "Form submission is handled via javascript:, which can "
                "hide where credentials actually go.",
                "medium",
            )

        if content.favicon_external_domain:
            result.add(
                "favicon_domain_mismatch",
                f"Favicon is loaded from a different domain "
                f"({content.favicon_external_domain}) than the page itself.",
                "medium",
            )

        if content.title_brand_hits:
            result.add(
                "title_brand_mismatch",
                f"Page title references '{content.title_brand_hits[0]}' but "
                f"the domain does not belong to that brand.",
                "high",
            )

        if content.meta_refresh:
            result.add(
                "meta_refresh_redirect",
                "Page uses a meta-refresh tag to auto-redirect visitors.",
                "low",
            )

        if content.iframe_count > 0:
            result.add(
                "iframe_present",
                f"Page embeds {content.iframe_count} iframe(s), which can "
                f"be used to overlay fake content on a real site.",
                "low",
            )

    result.score = min(sum(f.points for f in result.findings), 100)
    return result
