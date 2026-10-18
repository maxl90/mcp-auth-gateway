"""Step-up auth (RFC 9470).

Two layers: the pure ``step_up.evaluate`` decision over synthetic claims, and
the end-to-end enforcement through ``/mcp`` — a destructive tool without a
fresh strong auth gets the RFC 9470 challenge and is never forwarded; the same
tool with a satisfied, fresh ``acrs`` claim forwards.
"""

from __future__ import annotations

import json
import time

import httpx
import pytest
import respx

from mcp_auth_gateway.auth import step_up
from mcp_auth_gateway.auth.policy_resolver import Policy, StepUpRequirement, _parse_destructive

from .conftest import ANALYST_GROUP

REQ = StepUpRequirement(require_acr="c1", max_age=300)


# --- pure evaluator ---------------------------------------------------------


def test_satisfied_when_context_present_and_fresh():
    now = 1_000_000.0
    claims = {"acrs": ["c1"], "auth_time": now - 60}
    result = step_up.evaluate(claims, REQ, now=now)
    assert result.satisfied and result.reason == "satisfied"


def test_missing_context_fails_closed():
    claims = {"acrs": ["c2"], "auth_time": time.time()}
    assert not step_up.evaluate(claims, REQ).satisfied


def test_no_acrs_claim_fails_closed():
    assert step_up.evaluate({"auth_time": time.time()}, REQ).reason == "auth_context_missing"


def test_stale_auth_fails_closed():
    now = 1_000_000.0
    claims = {"acrs": ["c1"], "auth_time": now - 301}  # just past the 300s window
    result = step_up.evaluate(claims, REQ, now=now)
    assert not result.satisfied and result.reason == "auth_stale"


def test_context_without_auth_time_fails_closed():
    # Claims the context but can't prove freshness → re-challenge.
    result = step_up.evaluate({"acrs": ["c1"]}, REQ)
    assert not result.satisfied and result.reason == "auth_time_missing"


def test_scalar_acrs_tolerated():
    now = 1_000_000.0
    assert step_up.evaluate({"acrs": "c1", "auth_time": now}, REQ, now=now).satisfied


# --- policy parsing ---------------------------------------------------------


def test_destructive_list_form_inherits_defaults(monkeypatch):
    from mcp_auth_gateway.auth import policy_resolver as pr

    monkeypatch.setattr(pr.settings, "step_up_default_acr", "c1")
    monkeypatch.setattr(pr.settings, "step_up_max_age", 300)
    parsed = _parse_destructive(["execute_sql"])
    assert parsed["execute_sql"] == StepUpRequirement("c1", 300)


def test_destructive_mapping_form_overrides():
    parsed = _parse_destructive(
        {"execute_sql": {"require_acr": "c3", "max_age": 60}, "merge_pr": None}
    )
    assert parsed["execute_sql"] == StepUpRequirement("c3", 60)
    # null entry inherits defaults (whatever the config holds at parse time)
    assert parsed["merge_pr"].require_acr  # non-empty


@pytest.mark.parametrize(
    "bad",
    [
        {"t": {"max_age": 0}},  # non-positive
        {"t": {"max_age": -5}},
        {"t": {"require_acr": ""}},  # empty acr
        {"t": {"max_age": "soon"}},  # wrong type
        "execute_sql",  # bare string, not a list/mapping
    ],
)
def test_bad_destructive_shapes_raise(bad):
    with pytest.raises(ValueError):
        _parse_destructive(bad)


# --- end-to-end enforcement -------------------------------------------------

UPSTREAM = "http://localhost:9000/mcp"

_POLICY = Policy(
    groups={ANALYST_GROUP: ["list_schemas", "execute_sql"]},
    destructive={"execute_sql": StepUpRequirement("c1", 300)},
)


@pytest.fixture
def policy() -> Policy:
    return _POLICY


def _call(name: str) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": name}}
    ).encode()


def test_destructive_without_stepup_is_challenged_not_forwarded(
    legacy_client, make_token, tmp_path
):
    token = make_token(groups=[ANALYST_GROUP])  # no acrs claim
    with respx.mock:
        route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(
            "/mcp", content=_call("execute_sql"), headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 401
    assert route.call_count == 0  # NEVER forwarded

    # RFC 9470 challenge on the HTTP header...
    challenge = resp.headers["www-authenticate"]
    assert 'error="insufficient_user_authentication"' in challenge
    assert 'acr_values="c1"' in challenge
    assert "max_age=300" in challenge
    # ...and mirrored in the JSON-RPC error for JSON-RPC-only clients.
    body = resp.json()
    assert body["id"] == 5
    assert body["error"]["data"]["error"] == "insufficient_user_authentication"
    assert body["error"]["data"]["acr_values"] == "c1"

    record = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert record["outcome"] == "step_up_required"
    assert record["tool"] == "execute_sql"


def test_destructive_with_fresh_stepup_forwards(legacy_client, make_token):
    token = make_token(groups=[ANALYST_GROUP], acrs=["c1"], auth_time=int(time.time()))
    with respx.mock:
        route = respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 5, "result": {}})
        )
        resp = legacy_client.post(
            "/mcp", content=_call("execute_sql"), headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 200
    assert route.call_count == 1  # strong + fresh → forwarded
    # Trust boundary still holds on the stepped-up call.
    assert "authorization" not in {k.lower() for k in route.calls.last.request.headers}


def test_destructive_with_stale_stepup_is_challenged(legacy_client, make_token):
    token = make_token(groups=[ANALYST_GROUP], acrs=["c1"], auth_time=int(time.time()) - 3600)
    with respx.mock:
        route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
        resp = legacy_client.post(
            "/mcp", content=_call("execute_sql"), headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 401
    assert route.call_count == 0


def test_non_destructive_tool_needs_no_stepup(legacy_client, make_token):
    token = make_token(groups=[ANALYST_GROUP])  # no acrs
    with respx.mock:
        route = respx.post(UPSTREAM).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 5, "result": {}})
        )
        resp = legacy_client.post(
            "/mcp", content=_call("list_schemas"), headers={"Authorization": f"Bearer {token}"}
        )
    assert resp.status_code == 200
    assert route.call_count == 1
