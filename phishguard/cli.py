#!/usr/bin/env python3
"""PhishGuard CLI: analyze one URL or a batch from a file."""
from __future__ import annotations

import argparse
import json
import sys

from .analyzer import analyze
from . import report


def _analyze_one(url: str, offline: bool, allow_local: bool):
    try:
        return analyze(url, offline=offline, allow_local=allow_local)
    except Exception as exc:  # last-resort guard so batch runs don't die
        print(f"error analyzing {url}: {exc}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze a single URL")
    analyze_p.add_argument("url")
    analyze_p.add_argument("--offline", action="store_true", help="Skip live network/content checks")
    analyze_p.add_argument("--allow-local", action="store_true", help="Allow fetching localhost/private addresses (for testing)")
    analyze_p.add_argument("--json", action="store_true", help="Output JSON instead of text")
    analyze_p.add_argument("--no-color", action="store_true")

    batch_p = sub.add_parser("batch", help="Analyze one URL per line from a file")
    batch_p.add_argument("path")
    batch_p.add_argument("--offline", action="store_true")
    batch_p.add_argument("--allow-local", action="store_true")
    batch_p.add_argument("--json", action="store_true", help="Output a JSON array instead of a CSV summary")

    args = parser.parse_args(argv)

    if args.command == "analyze":
        result = _analyze_one(args.url, args.offline, args.allow_local)
        if result is None:
            return 1
        if args.json:
            print(report.to_json(result))
        else:
            print(report.to_text(result, color=not args.no_color))
        return 0

    if args.command == "batch":
        with open(args.path) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        results = []
        for url in urls:
            result = _analyze_one(url, args.offline, args.allow_local)
            if result is not None:
                results.append(result)

        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            print("url,verdict,score,ml_probability")
            for r in results:
                ml = f"{r.ml_probability:.3f}" if r.ml_probability is not None else ""
                print(f"{r.url},{r.verdict},{r.score},{ml}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
