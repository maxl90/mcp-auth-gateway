"""Upstream configuration for aggregation mode.

Setting ``UPSTREAMS_CONFIG_PATH`` to an ``upstreams.yaml`` switches the gateway
from the single-upstream proxy to aggregation mode: ``/mcp`` becomes one virtual
MCP server over every listed upstream and ``/mcp/<name>`` path-routes to one.
Upstream names may not contain ``__``: they prefix tool names on the wire and in
the policy (see ``naming``), so the separator must stay unambiguous.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import settings

# Lowercase alphanumerics and single hyphens: safe in URLs (path routing), in
# tool names, and can never contain the namespace separator.
_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


@dataclass(frozen=True)
class Upstream:
    """One configured upstream MCP server (Streamable HTTP endpoint)."""

    name: str
    url: str


def _parse_entry(entry: object, seen: set[str]) -> Upstream:
    """One validated upstream; ``seen`` catches duplicate names."""
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
    return Upstream(name=name, url=url)


def load_upstreams(path: str | Path | None = None) -> list[Upstream]:
    """Load and validate ``upstreams.yaml``. Fail closed on any problem —
    a misconfigured aggregator must refuse to start, not route ambiguously."""
    config_path = Path(path or settings.upstreams_config_path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"upstreams config not found: {config_path} (see examples/upstreams.example.yaml)"
        )

    doc = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    entries = doc.get("upstreams")
    if not isinstance(entries, list) or not entries:
        raise ValueError("upstreams config must contain a non-empty 'upstreams' list")

    seen: set[str] = set()
    return [_parse_entry(entry, seen) for entry in entries]


def aggregation_enabled() -> bool:
    """Aggregation mode is opt-in via ``UPSTREAMS_CONFIG_PATH``."""
    return bool(settings.upstreams_config_path)
