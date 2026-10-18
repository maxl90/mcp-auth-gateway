"""Tool-level RBAC: Entra group memberships to allowed tool names.

The policy file maps group object ids to the tools their members may call; a
caller's allowed set is the union over the groups in their token, and anything
else is denied. Granularity is the whole tool. The ``destructive`` section names
the tools that also need a step-up assertion, with optional per-tool
``require_acr`` / ``max_age`` overrides of the configured defaults.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..config import settings


@dataclass(frozen=True)
class StepUpRequirement:
    """What a destructive tool demands: the Entra authentication-context id expected in
    ``acrs`` and the freshness window in seconds."""

    require_acr: str
    max_age: int


class Policy:
    """An immutable view over the loaded policy document."""

    def __init__(
        self,
        groups: dict[str, list[str]],
        destructive: dict[str, StepUpRequirement] | list[str] | None = None,
    ) -> None:
        # group object id -> allowed tool names (as a set for O(1) lookup)
        self._groups: dict[str, set[str]] = {gid: set(tools or []) for gid, tools in groups.items()}
        # tool name -> step-up requirement; a bare list expands to the configured defaults.
        if isinstance(destructive, list):
            default = StepUpRequirement(settings.step_up_default_acr, settings.step_up_max_age)
            self._destructive = {tool: default for tool in destructive}
        else:
            self._destructive = dict(destructive or {})

    def allowed_tools(self, group_ids: Iterable[str]) -> set[str]:
        """Union of the allow-lists for every group the caller belongs to."""
        allowed: set[str] = set()
        for gid in group_ids:
            allowed |= self._groups.get(gid, set())
        return allowed

    def is_allowed(self, group_ids: Iterable[str], tool: str) -> bool:
        return tool in self.allowed_tools(group_ids)

    def step_up_for(self, tool: str) -> StepUpRequirement | None:
        """The step-up requirement for ``tool``, or ``None`` if it isn't
        destructive (no step-up needed)."""
        return self._destructive.get(tool)


def load_policy(path: str | Path | None = None) -> Policy:
    """Load and parse the policy YAML. Raises if the file is missing or malformed
    — a gateway with no policy must fail closed, not start permissive."""
    policy_path = Path(path or settings.policy_path)
    if not policy_path.exists():
        raise FileNotFoundError(
            f"policy file not found: {policy_path} "
            "(provisioning emits policy.generated.yaml; see examples/policy.example.yaml)"
        )

    doc = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    raw_groups = doc.get("groups") or {}
    if not isinstance(raw_groups, dict):
        raise ValueError("policy 'groups' must be a mapping of group-id -> {allow: [...]}")

    # Each group maps to an object with an `allow` list: {gid: {allow: [tool, ...]}}.
    groups: dict[str, list[str]] = {}
    for gid, entry in raw_groups.items():
        allow = (entry or {}).get("allow", []) if isinstance(entry, dict) else None
        if allow is None:
            raise ValueError(f"policy group '{gid}' must be a mapping with an 'allow' list")
        groups[gid] = list(allow)

    return Policy(groups=groups, destructive=_parse_destructive(doc.get("destructive")))


def _requirement_from(tool: str, spec: object, defaults: StepUpRequirement) -> StepUpRequirement:
    """One tool's step-up requirement from its mapping entry; null inherits both defaults."""
    spec = spec or {}
    if not isinstance(spec, dict):
        raise ValueError(
            f"destructive tool '{tool}' must map to null or {{require_acr?, max_age?}}"
        )
    acr = spec.get("require_acr", defaults.require_acr)
    max_age = spec.get("max_age", defaults.max_age)
    if not isinstance(acr, str) or not acr:
        raise ValueError(f"destructive tool '{tool}': require_acr must be a non-empty string")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
        raise ValueError(f"destructive tool '{tool}': max_age must be a positive integer")
    return StepUpRequirement(acr, max_age)


def _parse_destructive(raw: object) -> dict[str, StepUpRequirement]:
    """Per-tool step-up requirements from the ``destructive`` section.

    A list of tool names inherits the configured defaults; a mapping may override
    ``require_acr`` / ``max_age`` per tool (a null value inherits both).
    """
    defaults = StepUpRequirement(settings.step_up_default_acr, settings.step_up_max_age)
    if raw is None:
        return {}
    if isinstance(raw, list):
        return {tool: defaults for tool in raw}
    if isinstance(raw, dict):
        return {tool: _requirement_from(tool, spec, defaults) for tool, spec in raw.items()}
    raise ValueError("policy 'destructive' must be a list of tool names or a mapping")


_policy: Policy | None = None


def get_policy() -> Policy:
    """Process-wide policy, loaded once at first use."""
    global _policy
    if _policy is None:
        _policy = load_policy()
    return _policy
