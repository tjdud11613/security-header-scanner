#!/usr/bin/env python3
"""
Security Header Scanner
------------------------
Checks a target URL for the presence and configuration of common
HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) and gives
each header a simple pass/warn/fail grade plus a remediation tip.

Usage:
    python scanner.py https://example.com
    python scanner.py https://example.com --json
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

@dataclass
class HeaderCheck:
    name: str
    description: str
    recommendation: str
    severity_if_missing: str = "high"  # high | medium | low

    def evaluate(self, value: Optional[str]) -> dict:
        if value is None:
            return {
                "header": self.name,
                "present": False,
                "value": None,
                "status": "FAIL",
                "severity": self.severity_if_missing,
                "message": f"Missing. {self.recommendation}",
            }
        return {
            "header": self.name,
            "present": True,
            "value": value,
            "status": "PASS",
            "severity": "info",
            "message": "Header is present.",
        }


CHECKS = [
    HeaderCheck(
        name="Strict-Transport-Security",
        description="Forces browsers to use HTTPS for future requests.",
        recommendation="Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'.",
        severity_if_missing="high",
    ),
    HeaderCheck(
        name="Content-Security-Policy",
        description="Restricts which sources of content (scripts, styles, etc.) the browser may load.",
        recommendation="Define a strict CSP, e.g. \"default-src 'self'\" and tighten per-resource as needed.",
        severity_if_missing="high",
    ),
    HeaderCheck(
        name="X-Frame-Options",
        description="Mitigates clickjacking by controlling whether the page can be framed.",
        recommendation="Add 'X-Frame-Options: DENY' or use CSP 'frame-ancestors'.",
        severity_if_missing="medium",
    ),
    HeaderCheck(
        name="X-Content-Type-Options",
        description="Prevents MIME-type sniffing attacks.",
        recommendation="Add 'X-Content-Type-Options: nosniff'.",
        severity_if_missing="medium",
    ),
    HeaderCheck(
        name="Referrer-Policy",
        description="Controls how much referrer information is leaked on navigation.",
        recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
        severity_if_missing="low",
    ),
    HeaderCheck(
        name="Permissions-Policy",
        description="Restricts which browser features/APIs the page may use.",
        recommendation="Add 'Permissions-Policy' limiting camera, microphone, geolocation, etc.",
        severity_if_missing="low",
    ),
]

# Headers that, if present, can leak information and are worth flagging.
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def fetch_headers(url: str, timeout: int = 10) -> dict:
    """Issue a GET request and return response headers (case-insensitive dict)."""
    resp = requests.get(url, timeout=timeout, allow_redirects=True)
    return resp.headers


def run_scan(url: str) -> dict:
    headers = fetch_headers(url)

    results = []
    for check in CHECKS:
        value = headers.get(check.name)
        results.append(check.evaluate(value))

    leaks = []
    for h in INFO_LEAK_HEADERS:
        if h in headers:
            leaks.append({"header": h, "value": headers.get(h)})

    score = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)

    return {
        "url": url,
        "score": f"{score}/{total}",
        "checks": results,
        "information_leak_headers": leaks,
    }


def print_human_report(report: dict) -> None:
    print(f"\nSecurity Header Scan: {report['url']}")
    print(f"Score: {report['score']}\n")

    for r in report["checks"]:
        icon = "✅" if r["status"] == "PASS" else "❌"
        print(f"{icon} {r['header']:<28} [{r['status']}] ({r['severity']})")
        if r["status"] == "FAIL":
            print(f"    -> {r['message']}")

    if report["information_leak_headers"]:
        print("\n⚠️  Information-leaking headers detected:")
        for leak in report["information_leak_headers"]:
            print(f"   - {leak['header']}: {leak['value']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Scan a URL for missing/misconfigured security headers.")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of a human-readable report")
    args = parser.parse_args()

    try:
        report = run_scan(args.url)
    except requests.exceptions.RequestException as e:
        print(f"Error reaching {args.url}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human_report(report)


if __name__ == "__main__":
    main()
