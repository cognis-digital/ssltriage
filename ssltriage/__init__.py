"""SSLTRIAGE — Grade TLS config (protocols/ciphers/expiry) from openssl/sslyze output."""
from ssltriage.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
