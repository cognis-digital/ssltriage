"""SSLTRIAGE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from ssltriage.core import scan, to_json

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
    def ssltriage_scan(target: str) -> str:
        """Grade TLS config (protocols/ciphers/expiry) from openssl/sslyze output. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
