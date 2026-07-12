"""Tool-level RBAC resolution — the AuthZ half."""

from __future__ import annotations

import pytest

from mcp_auth_gateway.auth.policy_resolver import Policy, load_policy

from .conftest import ANALYST_GROUP, DENIED_GROUP

_POLICY_YAML = f"""
groups:
  "{ANALYST_GROUP}":
    allow:
      - list_schemas
      - execute_sql
  "{DENIED_GROUP}":
    allow: []
destructive:
  - execute_sql
"""


@pytest.fixture
def policy(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(_POLICY_YAML, encoding="utf-8")
    return load_policy(p)


def test_allowed_tool_for_member(policy):
    assert policy.is_allowed([ANALYST_GROUP], "execute_sql")
    assert policy.is_allowed([ANALYST_GROUP], "list_schemas")


def test_tool_not_in_allowlist_denied(policy):
    assert not policy.is_allowed([ANALYST_GROUP], "drop_everything")


def test_denied_group_has_nothing(policy):
    assert not policy.is_allowed([DENIED_GROUP], "execute_sql")
    assert policy.allowed_tools([DENIED_GROUP]) == set()


def test_no_groups_means_denied(policy):
    assert not policy.is_allowed([], "execute_sql")


def test_allowed_set_is_union_of_groups(policy):
    assert policy.allowed_tools([ANALYST_GROUP, DENIED_GROUP]) == {
        "list_schemas",
        "execute_sql",
    }


def test_destructive_flagged_but_not_enforced(policy):
    assert policy.is_destructive("execute_sql")
    assert not policy.is_destructive("list_schemas")


def test_missing_policy_file_fails_closed(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "nope.yaml")


def test_groups_must_be_mapping(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("groups:\n  - not-a-mapping\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(p)


def test_empty_policy_is_valid_and_denies_all():
    pol = Policy(groups={}, destructive=[])
    assert not pol.is_allowed([ANALYST_GROUP], "execute_sql")
