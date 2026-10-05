"""headerscope command line."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

from . import report
from .scanner import scan


def main(argv: list[str] | None = None, client: httpx.Client | None = None) -> int:
    ap = argparse.ArgumentParser(prog="headerscope", description="Audit a website's security headers, cookies and TLS")
    ap.add_argument("urls", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--html", help="write an HTML report to this file")
    ap.add_argument("--no-tls", action="store_true", help="skip the certificate/protocol check")
    ap.add_argument("--min-grade", default="F", help="exit 1 if any site grades below this (A+,A,B,C,D,E,F)")
    a = ap.parse_args(argv)

    reports = []
    for url in a.urls:
        try:
            reports.append(scan(url, client=client, check_tls_cert=not a.no_tls))
        except httpx.HTTPError as exc:
            print(f"error: {url}: {exc}", file=sys.stderr)
    if a.json:
        print(json.dumps([r.as_dict() for r in reports], indent=2, default=str))
    else:
        print("\n\n".join(report.text(r) for r in reports))
    if a.html:
        Path(a.html).write_text(report.html_report(reports), encoding="utf-8")
        print(f"\nHTML report written to {a.html}")
    order = ["F", "E", "D", "C", "B", "A", "A+"]
    if not reports:
        return 2
    return 1 if any(order.index(r.grade) < order.index(a.min_grade) for r in reports) else 0


def entrypoint() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
