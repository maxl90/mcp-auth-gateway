"""Only the gateway and the edge proxy are published beyond loopback.

An upstream answers MCP with no authentication of its own, so publishing one on all
interfaces lets anyone on the network reach it without passing the gateway.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_COMPOSE_FILES = sorted(
    [*_ROOT.glob("docker-compose*.yml"), *(_ROOT / "deploy" / "compose").glob("*.yml")]
)
_FRONT_DOORS = {"gateway", "edge"}


class _ComposeLoader(yaml.SafeLoader):
    """Reads Compose's merge tags (``!reset``, ``!override``) as their plain value."""


for _tag in ("!reset", "!override"):
    _ComposeLoader.add_constructor(
        _tag,
        lambda loader, node: (
            loader.construct_sequence(node)
            if isinstance(node, yaml.SequenceNode)
            else loader.construct_mapping(node)
            if isinstance(node, yaml.MappingNode)
            else loader.construct_scalar(node)
        ),
    )


def _published(port: object) -> str:
    """The host address a ``ports`` entry binds to; ``""`` when it binds all interfaces."""
    if isinstance(port, dict):
        return str(port.get("host_ip", ""))
    parts = str(port).split(":")
    return parts[0] if len(parts) == 3 else ""


def test_compose_files_are_found():
    assert len(_COMPOSE_FILES) >= 5


@pytest.mark.parametrize("path", _COMPOSE_FILES, ids=lambda p: p.name)
def test_only_the_front_doors_are_published_beyond_loopback(path):
    services = (yaml.load(path.read_text(encoding="utf-8"), _ComposeLoader) or {}).get(
        "services", {}
    )
    exposed = [
        f"{name}: {port}"
        for name, service in services.items()
        if name not in _FRONT_DOORS
        for port in (service or {}).get("ports") or []
        if _published(port) != "127.0.0.1"
    ]
    assert exposed == []
