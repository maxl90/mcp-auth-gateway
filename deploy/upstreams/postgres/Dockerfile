# crystaldba/postgres-mcp speaks stdio/SSE only. We wrap it with
# sparfenyuk/mcp-proxy to expose Streamable HTTP, which is what the gateway
# proxies to. mcp-proxy runs postgres-mcp as a stdio subprocess.
FROM python:3.12-slim

RUN pip install --no-cache-dir postgres-mcp mcp-proxy

EXPOSE 9000

# --transport streamablehttp: Streamable HTTP is not the default in mcp-proxy 0.12.
# --pass-environment: forwards DATABASE_URI through to the postgres-mcp child.
# `--` ends mcp-proxy's own option parsing so the child's flags pass through
#   untouched (otherwise mcp-proxy grabs --access-mode as its own).
CMD ["mcp-proxy", "--transport", "streamablehttp", "--host", "0.0.0.0", "--port", "9000", "--pass-environment", "--", "postgres-mcp", "--access-mode=unrestricted"]
