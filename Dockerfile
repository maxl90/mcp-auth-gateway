# The gateway image. The demo upstreams have their own Dockerfiles under deploy/upstreams/.
#
# Both base images are pinned by digest (the manifest-list digest), so neither
# moves under a rebuild, and the runtime dependencies are the ones uv.lock pins,
# the versions CI tests. To update a digest: docker buildx imagetools inspect <image>

# The lock's runtime dependencies as a hashed requirements file.
FROM ghcr.io/astral-sh/uv:0.10.7@sha256:edd1fd89f3e5b005814cc8f777610445d7b7e3ed05361f9ddfae67bebfe8456a AS lock
COPY pyproject.toml uv.lock /src/
RUN ["/uv", "export", "--project", "/src", "--frozen", "--no-dev", "--no-emit-project", "--format", "requirements-txt", "--output-file", "/requirements.txt"]

FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

WORKDIR /app

# --require-hashes refuses anything the file does not pin, so pip cannot pull in a
# version the lock does not name; the package itself then adds no dependencies.
# README/LICENSE are referenced by pyproject metadata, so copy them before the install.
COPY --from=lock /requirements.txt ./
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
    && pip install --no-cache-dir --no-deps .

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
