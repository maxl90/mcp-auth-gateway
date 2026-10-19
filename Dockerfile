# The gateway image. The demo upstreams have their own Dockerfiles under deploy/upstreams/.
#
# The base image is pinned by digest (the manifest-list digest for
# python:3.12-slim), so the OS layer does not move under a rebuild. The Python
# dependencies are not pinned: pip resolves the ranges in pyproject.toml at build
# time and does not read uv.lock.
# To update the digest: docker buildx imagetools inspect python:3.12-slim
FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

WORKDIR /app

# Install just the package + its runtime deps. README/LICENSE are referenced by
# pyproject metadata, so copy them before the install.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Run as a dedicated non-root user. /app stays writable because the gateway
# writes its local sinks (audit.log, manifest-baseline.json) to the workdir by
# default; override with AUDIT_LOG_PATH / a volume in production if preferred.
RUN useradd --create-home --uid 10001 gateway \
    && chown -R gateway:gateway /app
USER gateway

EXPOSE 8080

# Config (UPSTREAM_MCP_URL, GATEWAY_ISSUER/_AUDIENCE/_JWKS_URL, POLICY_PATH) is
# injected by compose / the environment. With auth on, the gateway fails closed
# at boot if that config or the policy file is missing.
CMD ["uvicorn", "mcp_auth_gateway.main:app", "--host", "0.0.0.0", "--port", "8080"]
