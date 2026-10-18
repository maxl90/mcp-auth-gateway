"""Smoke-test the internet edge: the mTLS chain must admit a valid
client cert end-to-end and reject everything else.

Run against a live edge stack:

    bash infra/edge/gen-certs.sh
    docker compose -f docker-compose.quickstart.yml -f deploy/compose/docker-compose.edge.yml up -d --build
    uv run python scripts/smoke_edge.py

Probes (exit 0 only if ALL hold):
  1. valid client cert  -> full MCP handshake (initialize + tools/list), >=1 tool
  2. no client cert     -> rejected by the edge
  3. wrong-CA cert      -> rejected by the edge (proxy-client.pem is signed by
                           the INTERNAL CA, which the edge must not accept)
  4. (--revoked NAME)   -> that cert rejected — run after revoke-cert.sh +
                           `nginx -s reload` to drill the CRL kill switch

Windows note: system curl uses schannel and can't load PEM client certs; this
script uses Python's OpenSSL-backed ssl module instead.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from pathlib import Path

import httpx

HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}


def _ctx(certs: Path, cert_name: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(certs / "public-ca.pem"))
    if cert_name:
        ctx.load_cert_chain(str(certs / f"{cert_name}.pem"), str(certs / f"{cert_name}-key.pem"))
    return ctx


def _sse_or_json(body: str) -> dict:
    if body.lstrip().startswith("{"):
        return json.loads(body)
    data = "".join(ln[5:].strip() for ln in body.splitlines() if ln.startswith("data:"))
    return json.loads(data)


def probe_valid(url: str, certs: Path, cert_name: str) -> str | None:
    """Full MCP handshake through the edge; None = pass, else failure reason."""
    try:
        with httpx.Client(verify=_ctx(certs, cert_name), timeout=20) as c:
            init = c.post(
                url,
                headers=HEADERS,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "smoke-edge", "version": "0"},
                    },
                },
            )
            if init.status_code != 200:
                return f"initialize returned HTTP {init.status_code}: {init.text[:120]}"
            sid = init.headers.get("mcp-session-id")
            h = dict(HEADERS, **({"mcp-session-id": sid} if sid else {}))
            c.post(url, headers=h, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            tl = c.post(url, headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            if tl.status_code != 200:
                return f"tools/list returned HTTP {tl.status_code}: {tl.text[:120]}"
            tools = _sse_or_json(tl.text).get("result", {}).get("tools", [])
            if not tools:
                return "tools/list returned an empty catalog"
            return None
    except Exception as exc:  # noqa: BLE001 — any failure is the finding
        return f"{type(exc).__name__}: {exc}"


def probe_rejected(url: str, certs: Path, cert_name: str | None) -> str | None:
    """The edge must NOT serve MCP to this identity; None = pass (rejected).

    Asserted as "the FULL handshake fails" — not merely "some request got a
    4xx" — because an upstream error (e.g. missing-session 400) would otherwise
    masquerade as an edge rejection and hide a cert that was wrongly accepted.
    """
    failure = probe_valid(url, certs, cert_name)
    if failure is None:
        return "expected rejection but the full MCP handshake SUCCEEDED"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Smoke-test the mTLS edge")
    ap.add_argument("--url", default="https://localhost:8443/mcp")
    ap.add_argument("--certs", default="infra/edge/certs", type=Path)
    ap.add_argument(
        "--client-cert",
        default="customer-pilot",
        help="cert name (without .pem) for the valid-cert probe",
    )
    ap.add_argument(
        "--revoked",
        default=None,
        metavar="NAME",
        help="also assert this cert name is rejected (CRL drill)",
    )
    args = ap.parse_args()

    checks: list[tuple[str, str | None]] = [
        (
            "valid client cert -> full MCP handshake",
            probe_valid(args.url, args.certs, args.client_cert),
        ),
        ("no client cert -> rejected", probe_rejected(args.url, args.certs, None)),
        (
            "wrong-CA cert (proxy-client) -> rejected",
            probe_rejected(args.url, args.certs, "proxy-client"),
        ),
    ]
    if args.revoked:
        checks.append(
            (
                f"revoked cert ({args.revoked}) -> rejected",
                probe_rejected(args.url, args.certs, args.revoked),
            )
        )

    failed = 0
    for name, failure in checks:
        if failure is None:
            print(f"  PASS  {name}")
        else:
            failed += 1
            print(f"  FAIL  {name}\n        {failure}")
    print(f"\n{'ALL PASS' if not failed else f'{failed} FAILED'} ({len(checks)} checks)")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
