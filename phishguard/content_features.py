"""HTML content analysis for a fetched page.

These signals aren't part of the ML training data (the source dataset is
URL/host-only), so they feed exclusively into the explainable heuristics
engine rather than the model's feature vector. They tend to be the most
human-readable red flags: "this page has a password box that submits to a
different domain" is easy to justify to a non-technical reader.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from bs4 import BeautifulSoup


@dataclass
class ContentFindings:
    password_field_count: int = 0
    external_form_actions: list[str] = field(default_factory=list)
    javascript_form_actions: int = 0
    iframe_count: int = 0
    favicon_external_domain: str | None = None
    title: str | None = None
    title_brand_hits: list[str] = field(default_factory=list)
    meta_refresh: bool = False
    external_link_ratio: float = 0.0


def _same_site(host_a: str, host_b: str) -> bool:
    def _reg(h: str) -> str:
        parts = h.lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h.lower()

    return _reg(host_a) == _reg(host_b)


def analyze_content(html: str, page_domain: str, brands: dict[str, str]) -> ContentFindings:
    soup = BeautifulSoup(html, "html.parser")
    findings = ContentFindings()

    findings.password_field_count = len(soup.find_all("input", {"type": "password"}))
    findings.iframe_count = len(soup.find_all("iframe"))
    findings.meta_refresh = bool(
        soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
    )

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action.lower().startswith("javascript:"):
            findings.javascript_form_actions += 1
            continue
        if action.startswith("http://") or action.startswith("https://"):
            action_host = urlsplit(action).hostname or ""
            if action_host and not _same_site(action_host, page_domain):
                findings.external_form_actions.append(action_host)

    icon = soup.find("link", rel=lambda v: v and "icon" in v.lower())
    if icon and icon.get("href", "").startswith(("http://", "https://")):
        icon_host = urlsplit(icon["href"]).hostname or ""
        if icon_host and not _same_site(icon_host, page_domain):
            findings.favicon_external_domain = icon_host

    title_tag = soup.find("title")
    if title_tag and title_tag.text:
        findings.title = title_tag.text.strip()[:200]
        title_lower = findings.title.lower()
        for brand, real_domain in brands.items():
            if brand in title_lower and not _same_site(page_domain, real_domain):
                findings.title_brand_hits.append(brand)

    links = soup.find_all("a", href=True)
    if links:
        external = sum(
            1
            for a in links
            if a["href"].startswith(("http://", "https://"))
            and (urlsplit(a["href"]).hostname or "")
            and not _same_site(urlsplit(a["href"]).hostname, page_domain)
        )
        findings.external_link_ratio = round(external / len(links), 3)

    return findings
