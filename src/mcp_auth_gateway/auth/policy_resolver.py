"""Tool-level RBAC: Entra group memberships → allowed upstream tools.

The policy file maps Entra **group object IDs** to the set of tool names a
member may call. A caller's allowed set is the union of the allow-lists of every
group in their token's ``groups`` claim. Anything not in that set is denied.

This is intentionally coarse (tool-name granularity). Argument-level rules are
still deferred (ADR 006 — v1 classifies a whole tool as destructive). The
``destructive`` section names tools that additionally require a step-up auth
assertion; each entry may carry its own ``require_acr`` / ``max_age``, or be a
bare tool name that inherits the configured defaults.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..config import settings


@dataclass(frozen=True)
class StepUpRequirement:
    """The fresh-strong-auth a destructive tool demands (ADR 006). ``require_acr``
    is the Entra authentication-context id expected in the token's ``acrs``;
    ``max_age`` is the freshness window in seconds."""

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
        self._groups: dict[str, set[str]] = {
            gid: set(tools or []) for gid, tools in groups.items()
        }
        # tool name -> its step-up requirement. A bare list is accepted for
        # convenience (tests, back-compat) and expanded to the configured
        # defaults, mirroring the list form of the policy file.
        if isinstance(destructive, list):
            default = StepUpRequirement(
                settings.step_up_default_acr, settings.step_up_max_age
            )
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

    def is_destructive(self, tool: str) -> bool:
        return tool in self._destructive

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
            "(provisioning emits policy.generated.yaml; see policy.example.yaml)"
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


def _parse_destructive(raw: object) -> dict[str, StepUpRequirement]:
    """Parse the ``destructive`` section into per-tool step-up requirements.

    Two accepted shapes (ADR 006), so existing policies keep working:
    - **list** — ``[execute_sql, merge_pull_request]``: each tool inherits the
      configured default auth context + max age.
    - **mapping** — ``{execute_sql: {require_acr: c1, max_age: 300}}``: per-tool
      override; a null/empty value (``execute_sql:``) also inherits the defaults.
    A tool may name its own ``require_acr`` and/or ``max_age``; whichever it
    omits falls back to the ``step_up_*`` config defaults.
    """
    default_acr = settings.step_up_default_acr
    default_max_age = settings.step_up_max_age

    if raw is None:
        return {}

    if isinstance(raw, list):
        return {
            tool: StepUpRequirement(default_acr, default_max_age) for tool in raw
        }

    if isinstance(raw, dict):
        out: dict[str, StepUpRequirement] = {}
        for tool, spec in raw.items():
            spec = spec or {}
            if not isinstance(spec, dict):
                raise ValueError(
                    f"destructive tool '{tool}' must map to null or "
                    "{require_acr?, max_age?}"
                )
            acr = spec.get("require_acr", default_acr)
            max_age = spec.get("max_age", default_max_age)
            if not isinstance(acr, str) or not acr:
                raise ValueError(
                    f"destructive tool '{tool}': require_acr must be a non-empty string"
                )
            if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
                raise ValueError(f"destructive tool '{tool}': max_age must be a positive integer")
            out[tool] = StepUpRequirement(acr, max_age)
        return out

    raise ValueError("policy 'destructive' must be a list of tool names or a mapping")


_policy: Policy | None = None


def get_policy() -> Policy:
    """Process-wide policy, loaded once at first use."""
    global _policy
    if _policy is None:
        _policy = load_policy()
    return _policy
