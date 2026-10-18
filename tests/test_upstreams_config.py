"""Upstream config loading + namespacing.

Fail-closed loading (a misconfigured aggregator must not start) and the
namespace scheme that keeps one policy file unambiguous across upstreams.
"""

from __future__ import annotations

import pytest

from mcp_auth_gateway.naming import namespace_tool, split_namespaced
from mcp_auth_gateway.upstreams import load_upstreams


def _write(tmp_path, text: str):
    path = tmp_path / "upstreams.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_valid_config(tmp_path):
    path = _write(
        tmp_path,
        """
upstreams:
  - name: postgres
    url: http://mcp-upstream:9000/mcp
  - name: github
    url: http://github-upstream:9001/mcp
""",
    )
    upstreams = load_upstreams(path)
    assert [(u.name, u.url) for u in upstreams] == [
        ("postgres", "http://mcp-upstream:9000/mcp"),
        ("github", "http://github-upstream:9001/mcp"),
    ]


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_upstreams(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    "text",
    [
        "upstreams: []",
        "{}",
        "upstreams:\n  - name: ok\n",  # missing url
        "upstreams:\n  - url: http://x/mcp\n",  # missing name
        # '__' in a name would make split_namespaced ambiguous
        "upstreams:\n  - name: bad__name\n    url: http://x/mcp\n",
        "upstreams:\n  - name: UPPER\n    url: http://x/mcp\n",
        # duplicates would make routing ambiguous
        "upstreams:\n  - name: a\n    url: http://x/mcp\n  - name: a\n    url: http://y/mcp\n",
    ],
)
def test_invalid_configs_fail_closed(tmp_path, text):
    with pytest.raises((ValueError, TypeError)):
        load_upstreams(_write(tmp_path, text))


def test_namespace_roundtrip():
    assert namespace_tool("github", "merge_pull_request") == "github__merge_pull_request"
    assert split_namespaced("github__merge_pull_request") == ("github", "merge_pull_request")


def test_split_survives_dunder_in_tool_name():
    # Upstream names can't contain '__', so the FIRST separator always wins —
    # a tool whose own name contains '__' still routes home correctly.
    assert split_namespaced("pg__weird__tool") == ("pg", "weird__tool")


def test_split_rejects_unnamespaced():
    assert split_namespaced("execute_sql") is None
    assert split_namespaced("__leading") is None
    assert split_namespaced("trailing__") is None
