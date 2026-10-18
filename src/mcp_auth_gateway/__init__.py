"""mcp-auth-gateway: an OAuth 2.1 reverse proxy for MCP servers."""

from importlib import metadata

try:
    __version__ = metadata.version("mcp-auth-gateway")
except metadata.PackageNotFoundError:  # source tree without an install
    __version__ = "0+unknown"
