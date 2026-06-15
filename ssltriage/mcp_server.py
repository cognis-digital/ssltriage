"""SSLTRIAGE MCP server — exposes triage() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
from ssltriage.core import triage


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ssltriage[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-ssltriage[mcp]'")
        return 1
    app = FastMCP("ssltriage")

    @app.tool()
    def ssltriage_scan(target: str, ssl_output: str) -> str:
        """Grade TLS config (protocols/ciphers/expiry) from openssl/sslyze output.

        Args:
            target: Hostname being scanned.
            ssl_output: Raw openssl/sslyze text output to parse.

        Returns:
            JSON findings report.
        """
        try:
            report = triage(ssl_output, target=target)
        except (TypeError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(report.to_dict(), indent=2)

    app.run()
    return 0
