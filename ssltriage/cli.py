"""Command-line interface for SSLTRIAGE.

Usage:
    ssltriage grade <file|-> [--format table|json] [--target NAME]
    ssltriage --version

Reads openssl/sslyze-style output, prints a TLS report card. Exits non-zero
when actionable (medium+) findings are present or on failure.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import SEVERITY_ORDER, triage

_EXIT_OK = 0
_EXIT_FINDINGS = 1
_EXIT_ERROR = 2


def _read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _render_table(report) -> str:
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append(f"  {TOOL_NAME} TLS Report Card")
    lines.append("=" * 60)
    lines.append(f"  Target : {report.target}")
    lines.append(f"  Grade  : {report.grade}  (score {report.score}/100)")
    lines.append(f"  Worst  : {report.worst_severity.upper()}")
    if report.protocols:
        lines.append(f"  Protos : {', '.join(report.protocols)}")
    if report.cert_days_remaining is not None:
        lines.append(f"  Cert   : {report.cert_days_remaining} day(s) remaining"
                     f" (not_after {report.cert_not_after})")
    lines.append("-" * 60)
    if not report.findings:
        lines.append("  No findings.")
    else:
        lines.append(f"  Findings ({len(report.findings)}):")
        for f in report.findings:
            lines.append(f"   [{f.severity.upper():<8}] {f.code:<18} {f.message}")
            if f.evidence:
                lines.append(f"             evidence: {f.evidence}")
    lines.append("=" * 60)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Grade TLS config (protocols/ciphers/expiry) from openssl/sslyze output.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    g = sub.add_parser("grade", help="Grade TLS output from a file or stdin")
    g.add_argument("input", help="Path to openssl/sslyze output, or '-' for stdin")
    g.add_argument("--format", choices=("table", "json"), default="table",
                   help="Output format (default: table)")
    g.add_argument("--target", default=None,
                   help="Override/annotate the target hostname")
    g.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER),
                   default="medium",
                   help="Minimum severity that triggers non-zero exit (default: medium)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "grade":
        parser.print_help()
        return _EXIT_ERROR

    try:
        text = _read_source(args.input)
    except OSError as exc:
        print(f"{TOOL_NAME}: cannot read input: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    report = triage(text, target=args.target)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_table(report))

    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f.severity] >= threshold for f in report.findings):
        return _EXIT_FINDINGS
    return _EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
