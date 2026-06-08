"""SSLTRIAGE - TLS configuration report card.

Defensive/authorized-testing tool. Parses openssl/sslyze-style output and
grades TLS configuration (protocols, ciphers, certificate expiry). No network
access, no attack capability -- analysis and triage only.
"""
from .core import (
    Finding,
    TriageReport,
    grade_report,
    parse_input,
    triage,
    SEVERITY_ORDER,
)

TOOL_NAME = "ssltriage"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "TriageReport",
    "grade_report",
    "parse_input",
    "triage",
    "SEVERITY_ORDER",
]
