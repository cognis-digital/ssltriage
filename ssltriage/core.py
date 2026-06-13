"""Core triage engine for SSLTRIAGE.

Parses openssl/sslyze-style text output into a normalized TLS profile, then
applies a rule set to produce findings and a letter grade. Standard library
only. No network calls.
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Protocols considered insecure / deprecated. Maps token -> severity.
_INSECURE_PROTOCOLS = {
    "SSLv2": "critical",
    "SSLv3": "critical",
    "TLSv1.0": "high",
    "TLS1.0": "high",
    "TLSv1.1": "medium",
    "TLS1.1": "medium",
}

# Cipher substrings considered weak. Maps marker -> (severity, label).
_WEAK_CIPHER_MARKERS = [
    ("NULL", "critical", "NULL encryption cipher"),
    ("EXPORT", "critical", "EXPORT-grade cipher"),
    ("_RC4_", "high", "RC4 stream cipher"),
    ("-RC4-", "high", "RC4 stream cipher"),
    ("_DES_", "high", "single-DES cipher"),
    ("-DES-", "high", "single-DES cipher"),
    ("3DES", "medium", "3DES (Sweet32) cipher"),
    ("DES-CBC3", "medium", "3DES (Sweet32) cipher"),
    ("_MD5", "medium", "MD5 MAC cipher"),
    ("-MD5", "medium", "MD5 MAC cipher"),
    ("_CBC_", "low", "CBC-mode cipher (legacy)"),
    ("-CBC-", "low", "CBC-mode cipher (legacy)"),
]

_DATE_FORMATS = [
    "%b %d %H:%M:%S %Y %Z",   # openssl: Jun  8 12:00:00 2026 GMT
    "%b %d %H:%M:%S %Y",
    "%Y-%m-%dT%H:%M:%S",       # ISO / sslyze json-ish
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
]


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriageReport:
    target: str
    grade: str
    score: int
    protocols: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    cert_not_after: Optional[str] = None
    cert_days_remaining: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def has_actionable_findings(self) -> bool:
        return any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["medium"] for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "grade": self.grade,
            "score": self.score,
            "worst_severity": self.worst_severity,
            "protocols": self.protocols,
            "ciphers": self.ciphers,
            "cert_not_after": self.cert_not_after,
            "cert_days_remaining": self.cert_days_remaining,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_PROTO_LINE = re.compile(r"\b(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3|TLS1\.0|TLS1\.1|TLS1\.2|TLS1\.3|TLS\s+1\.0|TLS\s+1\.1|TLS\s+1\.2|TLS\s+1\.3)\b")
_CIPHER_LINE = re.compile(r"\b([A-Z0-9]+(?:[-_][A-Z0-9]+){2,})\b")
_NOT_AFTER = re.compile(r"not\s*after\s*[:=]\s*(.+)", re.IGNORECASE)
_TARGET_HINT = re.compile(r"(?:host|server|target|connecting to|CN\s*=)\s*[:=]?\s*([A-Za-z0-9._\-]+)", re.IGNORECASE)

# Lines that look like proto enablement: an "offered"/"enabled"/"yes" near a proto.
_ENABLED_HINT = re.compile(r"\b(offered|enabled|supported|accepted|yes)\b", re.IGNORECASE)
_DISABLED_HINT = re.compile(r"\b(not offered|disabled|rejected|no\b)", re.IGNORECASE)


def _parse_date(raw: str) -> Optional[_dt.datetime]:
    raw = raw.strip().rstrip(".")
    # Normalize multiple spaces (openssl pads day-of-month).
    norm = re.sub(r"\s+", " ", raw)
    for fmt in _DATE_FORMATS:
        for candidate in (norm, raw):
            try:
                return _dt.datetime.strptime(candidate, fmt)
            except ValueError:
                continue
    # Last resort: strip trailing timezone token and retry common forms.
    stripped = re.sub(r"\s+[A-Z]{2,4}$", "", norm)
    for fmt in ("%b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S"):
        try:
            return _dt.datetime.strptime(stripped, fmt)
        except ValueError:
            continue
    return None


def parse_input(text: str, target: Optional[str] = None) -> Dict[str, Any]:
    """Parse openssl/sslyze-style text into a normalized profile dict."""
    protocols: List[str] = []
    ciphers: List[str] = []
    cert_not_after_raw: Optional[str] = None
    detected_target: Optional[str] = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()

        # Certificate expiry
        m = _NOT_AFTER.search(stripped)
        if m and cert_not_after_raw is None:
            cert_not_after_raw = m.group(1).strip()

        # Target hint (first match wins)
        if detected_target is None:
            mt = _TARGET_HINT.search(stripped)
            if mt:
                cand = mt.group(1).strip()
                if "." in cand or cand.replace("_", "").isalnum():
                    detected_target = cand

        # Protocol detection: only count as enabled unless explicitly disabled.
        pm = _PROTO_LINE.search(stripped)
        if pm and not _DISABLED_HINT.search(low):
            tok = pm.group(1)
            # Normalize all variants to canonical TLSv1.x / SSLvX form.
            norm = tok.replace("TLS1.", "TLSv1.")
            norm = re.sub(r"^TLS\s+1\.", "TLSv1.", norm)
            if norm not in protocols:
                protocols.append(norm)

        # Cipher detection: look for cipher-suite-shaped tokens.
        if ("cipher" in low or "_" in stripped or "-" in stripped) and not _NOT_AFTER.search(stripped):
            for cm in _CIPHER_LINE.finditer(stripped):
                cand = cm.group(1)
                if _looks_like_cipher(cand) and cand not in ciphers:
                    ciphers.append(cand)

    return {
        "target": target or detected_target or "unknown",
        "protocols": protocols,
        "ciphers": ciphers,
        "cert_not_after_raw": cert_not_after_raw,
    }


def _looks_like_cipher(tok: str) -> bool:
    upper = tok.upper()
    if len(tok) < 8:
        return False
    # Cipher suites contain key-exchange / cipher / mac segments.
    keywords = ("AES", "RC4", "DES", "CHACHA", "NULL", "GCM", "CBC", "SHA", "MD5", "RSA", "ECDHE", "DHE", "POLY1305", "CCM")
    return sum(1 for k in keywords if k in upper) >= 2


# ---------------------------------------------------------------------------
# Rules / grading
# ---------------------------------------------------------------------------

# Score penalties by severity.
_PENALTY = {"info": 0, "low": 5, "medium": 12, "high": 25, "critical": 45}


def _evaluate(profile: Dict[str, Any], now: _dt.datetime) -> List[Finding]:
    findings: List[Finding] = []
    protocols = profile.get("protocols", [])
    ciphers = profile.get("ciphers", [])

    # Protocol rules
    for proto in protocols:
        sev = _INSECURE_PROTOCOLS.get(proto)
        if sev:
            findings.append(Finding(
                severity=sev,
                code="PROTO_INSECURE",
                message=f"Deprecated/insecure protocol enabled: {proto}",
                evidence=proto,
            ))
    if "TLSv1.2" not in protocols and "TLSv1.3" not in protocols and protocols:
        findings.append(Finding(
            severity="high",
            code="PROTO_NO_MODERN",
            message="No modern protocol (TLS 1.2 or 1.3) offered",
            evidence=",".join(protocols),
        ))
    if "TLSv1.3" not in protocols and ("TLSv1.2" in protocols):
        findings.append(Finding(
            severity="info",
            code="PROTO_NO_TLS13",
            message="TLS 1.3 not offered (recommended for forward secrecy/perf)",
            evidence=",".join(protocols),
        ))

    # Cipher rules
    for cipher in ciphers:
        up = cipher.upper()
        for marker, sev, label in _WEAK_CIPHER_MARKERS:
            if marker in up:
                findings.append(Finding(
                    severity=sev,
                    code="CIPHER_WEAK",
                    message=f"Weak cipher offered: {cipher} ({label})",
                    evidence=cipher,
                ))
                break  # one finding per cipher (worst marker wins by list order)

    # Certificate expiry rules
    raw = profile.get("cert_not_after_raw")
    if raw:
        parsed = _parse_date(raw)
        if parsed is None:
            findings.append(Finding(
                severity="low",
                code="CERT_UNPARSEABLE",
                message="Certificate 'not after' date could not be parsed",
                evidence=raw,
            ))
        else:
            days = (parsed - now).days
            profile["cert_days_remaining"] = days
            profile["cert_not_after"] = parsed.isoformat()
            if days < 0:
                findings.append(Finding(
                    severity="critical",
                    code="CERT_EXPIRED",
                    message=f"Certificate expired {abs(days)} day(s) ago",
                    evidence=raw,
                ))
            elif days <= 14:
                findings.append(Finding(
                    severity="high",
                    code="CERT_EXPIRING",
                    message=f"Certificate expires in {days} day(s)",
                    evidence=raw,
                ))
            elif days <= 30:
                findings.append(Finding(
                    severity="medium",
                    code="CERT_EXPIRING",
                    message=f"Certificate expires in {days} day(s)",
                    evidence=raw,
                ))
    else:
        findings.append(Finding(
            severity="info",
            code="CERT_MISSING",
            message="No certificate expiry information found in input",
        ))

    if not protocols and not ciphers:
        findings.append(Finding(
            severity="medium",
            code="PARSE_EMPTY",
            message="No protocols or ciphers detected; input may be unrecognized",
        ))

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return findings


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    if score >= 35:
        return "E"
    return "F"


def grade_report(findings: List[Finding]) -> tuple[int, str]:
    score = 100
    for f in findings:
        score -= _PENALTY[f.severity]
    # Any critical caps the grade at F regardless of arithmetic.
    if any(f.severity == "critical" for f in findings):
        score = min(score, 30)
    score = max(0, min(100, score))
    return score, _score_to_grade(score)


def triage(text: str, target: Optional[str] = None, now: Optional[_dt.datetime] = None) -> TriageReport:
    """Full pipeline: parse -> evaluate -> grade."""
    now = now or _dt.datetime.utcnow()
    profile = parse_input(text, target=target)
    findings = _evaluate(profile, now)
    score, grade = grade_report(findings)
    return TriageReport(
        target=profile["target"],
        grade=grade,
        score=score,
        protocols=profile.get("protocols", []),
        ciphers=profile.get("ciphers", []),
        cert_not_after=profile.get("cert_not_after"),
        cert_days_remaining=profile.get("cert_days_remaining"),
        findings=findings,
    )
