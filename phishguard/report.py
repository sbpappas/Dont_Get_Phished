"""Formats an analyzer Result for the CLI (plain text) or as JSON."""
from __future__ import annotations

import json

from .analyzer import Result

_COLORS = {
    "Likely Safe": "\033[32m",
    "Suspicious": "\033[33m",
    "Likely Phishing": "\033[31m",
}
_RESET = "\033[0m"
_SEVERITY_ICON = {"low": "-", "medium": "!", "high": "!!", "critical": "!!!"}


def to_json(result: Result, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def to_text(result: Result, color: bool = True) -> str:
    lines = []
    verdict_color = _COLORS.get(result.verdict, "") if color else ""
    reset = _RESET if color else ""

    lines.append(f"URL:     {result.url}")
    if result.final_url and result.final_url != result.url:
        lines.append(f"Landed:  {result.final_url}")
    lines.append(f"Domain:  {result.domain}")
    lines.append(f"Verdict: {verdict_color}{result.verdict}{reset}  (score {result.score}/100)")

    if result.ml_probability is not None:
        lines.append(
            f"  ML model probability of phishing: {result.ml_probability:.1%}  "
            f"| Heuristic score: {result.heuristic_score}/100"
        )
    else:
        lines.append(
            f"  Heuristic score only (ML unavailable this run): {result.heuristic_score}/100"
        )

    if not result.fetched_live:
        note = result.fetch_error or "offline mode"
        lines.append(f"  (Live page was not fetched: {note})")

    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in sorted(result.findings, key=lambda x: -x.points):
            icon = _SEVERITY_ICON.get(f.severity, "-")
            lines.append(f"  [{icon:<3}] ({f.severity:<8} +{f.points:>2}) {f.message}")
    else:
        lines.append("")
        lines.append("No red flags detected by the heuristic engine.")

    lines.append("")
    lines.append(
        "Note: this is an educational tool, not a substitute for a "
        "dedicated security product. Never enter credentials on a page "
        "flagged Suspicious or Likely Phishing."
    )
    return "\n".join(lines)
