"""Orchestrates feature extraction, network/content fetching, the heuristic
engine and the ML model into a single explainable Result.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from . import fetcher, ml_model
from .content_features import analyze_content
from .heuristics import evaluate, Finding
from .network_features import extract_network_features
from .url_features import extract_url_features, split_url

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_brands() -> dict[str, str]:
    return json.loads((DATA_DIR / "brands.json").read_text())


def _load_keywords() -> list[str]:
    return [
        line.strip()
        for line in (DATA_DIR / "suspicious_keywords.txt").read_text().splitlines()
        if line.strip()
    ]


BRANDS = _load_brands()
KEYWORDS = _load_keywords()


@dataclass
class Result:
    url: str
    domain: str
    checked_at: str
    verdict: str
    score: int
    ml_probability: float | None
    heuristic_score: int
    findings: list[Finding]
    fetched_live: bool
    fetch_error: str | None = field(default=None)
    final_url: str | None = field(default=None)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _verdict_for(score: int) -> str:
    if score >= 60:
        return "Likely Phishing"
    if score >= 30:
        return "Suspicious"
    return "Likely Safe"


def analyze(url: str, offline: bool = False, allow_local: bool = False) -> Result:
    url_parts = split_url(url)
    url_feats = extract_url_features(url)

    net_feats: dict | None = None
    content = None
    fetched_live = False
    fetch_error = None
    final_url = None

    if not offline:
        try:
            fetch_result = fetcher.fetch(url, allow_local=allow_local)
            fetched_live = True
            final_url = fetch_result.final_url
            net_feats = extract_network_features(url_parts.domain)
            net_feats["time_response"] = fetch_result.time_response
            net_feats["qty_redirects"] = fetch_result.qty_redirects
            content = analyze_content(fetch_result.html, url_parts.domain, BRANDS)
        except (fetcher.FetchBlocked, fetcher.FetchFailed) as exc:
            fetch_error = str(exc)
            # We can still get DNS/WHOIS/TLS signal even if the HTTP GET failed.
            try:
                net_feats = extract_network_features(url_parts.domain)
                net_feats["time_response"] = -1
                net_feats["qty_redirects"] = -1
            except Exception:
                net_feats = None

    heur = evaluate(url_parts, url_feats, net_feats, content, BRANDS, KEYWORDS)

    ml_proba = None
    if net_feats is not None:
        full_features = {**url_feats, **net_feats}
        ml_proba = ml_model.predict_proba(full_features)

    if ml_proba is not None:
        final_score = round(0.5 * heur.score + 0.5 * (ml_proba * 100))
    else:
        final_score = heur.score
    final_score = max(0, min(100, final_score))

    return Result(
        url=url,
        domain=url_parts.domain,
        checked_at=datetime.now(timezone.utc).isoformat(),
        verdict=_verdict_for(final_score),
        score=final_score,
        ml_probability=ml_proba,
        heuristic_score=heur.score,
        findings=heur.findings,
        fetched_live=fetched_live,
        fetch_error=fetch_error,
        final_url=final_url,
    )
