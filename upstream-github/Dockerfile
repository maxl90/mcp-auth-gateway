# The GitHub MCP server's own image is distroless (just the Go binary), and its
# `http` mode expects a per-request Authorization: Bearer <github-token> — which
# the gateway strips at the trust boundary. So we run the server in STDIO mode,
# where GITHUB_PERSONAL_ACCESS_TOKEN is the service identity, and wrap it with
# sparfenyuk/mcp-proxy to expose Streamable HTTP — exactly like the Postgres
# upstream. The gateway then forwards with no auth header; the PAT never leaves
# this container.
FROM ghcr.io/github/github-mcp-server AS gh

FROM python:3.12-slim
RUN pip install --no-cache-dir mcp-proxy
COPY --from=gh /server/github-mcp-server /usr/local/bin/github-mcp-server
EXPOSE 9001
# --pass-environment forwards GITHUB_PERSONAL_ACCESS_TOKEN / GITHUB_* to the child.
CMD ["mcp-proxy", "--transport", "streamablehttp", "--host", "0.0.0.0", "--port", "9001", "--pass-environment", "--", "github-mcp-server", "stdio"]
