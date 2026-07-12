"""Phase 3: multi-upstream configuration + tool-name namespacing.

The gateway fronts N upstream MCP servers from one config file
(``upstreams.yaml``). Setting ``UPSTREAMS_CONFIG_PATH`` switches the gateway
into **aggregation mode**: ``/mcp`` becomes a stateful virtual MCP server over
all upstreams (stage 3b) and ``/mcp/<name>`` path-routes to a single one
(stage 3a). With it unset, the gateway is the legacy single-upstream proxy —
existing ``UPSTREAM_MCP_URL`` deploys are untouched.

Tool names are namespaced ``<upstream>__<tool>`` (ADR 005 gate 2) so two
servers exposing the same tool never collide, and so **one** RBAC policy file
spans every upstream. The upstream name may not itself contain ``__`` — that
keeps ``split_namespaced`` unambiguous.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import settings

NAMESPACE_SEP = "__"

# Lowercase alphanumerics and single hyphens: safe in URLs (path routing), in
# tool names, and can never contain the namespace separator.
_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


@dataclass(frozen=True)
class Upstream:
    """One configured upstream MCP server (Streamable HTTP endpoint)."""

    name: str
    url: str


def namespace_tool(upstream: str, tool: str) -> str:
    """The wire/policy name of ``tool`` served by ``upstream``."""
    return f"{upstream}{NAMESPACE_SEP}{tool}"


def split_namespaced(name: str) -> tuple[str, str] | None:
    """Split a namespaced tool name into ``(upstream, original_tool)``.

    Returns ``None`` if the name carries no namespace. The upstream name can't
    contain ``__`` (enforced at load), so splitting on the first occurrence is
    unambiguous even when the original tool name itself contains ``__``.
    """
    head, sep, tail = name.partition(NAMESPACE_SEP)
    if not sep or not head or not tail:
        return None
    return head, tail


def load_upstreams(path: str | Path | None = None) -> list[Upstream]:
    """Load and validate ``upstreams.yaml``. Fail closed on any problem —
    a misconfigured aggregator must refuse to start, not route ambiguously."""
    config_path = Path(path or settings.upstreams_config_path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"upstreams config not found: {config_path} (see upstreams.example.yaml)"
        )

    doc = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    entries = doc.get("upstreams")
    if not isinstance(entries, list) or not entries:
        raise ValueError("upstreams config must contain a non-empty 'upstreams' list")

    upstreams: list[Upstream] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"upstream entry must be a mapping: {entry!r}")
        name, url = entry.get("name"), entry.get("url")
        if not isinstance(name, str) or not isinstance(url, str) or not url:
            raise ValueError(f"upstream entry needs string 'name' and 'url': {entry!r}")
        if not _NAME_RE.match(name):
            raise ValueError(
                f"upstream name {name!r} invalid: lowercase alphanumerics and "
                "single hyphens only (it becomes a URL path segment and a tool-name "
                "namespace, and must never contain '__')"
            )
        if name in seen:
            raise ValueError(f"duplicate upstream name: {name!r}")
        seen.add(name)
        upstreams.append(Upstream(name=name, url=url))
    return upstreams


_upstreams: list[Upstream] | None = None


def aggregation_enabled() -> bool:
    """Aggregation mode is opt-in via ``UPSTREAMS_CONFIG_PATH`` (ADR 005)."""
    return bool(settings.upstreams_config_path)


def get_upstreams() -> list[Upstream]:
    """Process-wide upstream list, loaded once at first use (like the policy)."""
    global _upstreams
    if _upstreams is None:
        _upstreams = load_upstreams()
    return _upstreams


def get_upstream(name: str) -> Upstream | None:
    return next((u for u in get_upstreams() if u.name == name), None)
