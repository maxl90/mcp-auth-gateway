"""Tool-name namespacing: ``<upstream>__<tool>`` on the wire and in the policy.

Two upstreams exposing the same tool never collide, and one RBAC policy file
spans every upstream. An upstream name may not contain ``__`` (enforced when
the upstream config loads), which keeps :func:`split_namespaced` unambiguous.
"""

from __future__ import annotations

NAMESPACE_SEP = "__"


def namespace_tool(upstream: str, tool: str) -> str:
    """The wire/policy name of ``tool`` served by ``upstream``."""
    return f"{upstream}{NAMESPACE_SEP}{tool}"


def split_namespaced(name: str) -> tuple[str, str] | None:
    """``(upstream, original_tool)`` of a namespaced name, or ``None`` without a namespace.
    Upstream names never contain ``__``, so the first separator is unambiguous."""
    head, sep, tail = name.partition(NAMESPACE_SEP)
    if not sep or not head or not tail:
        return None
    return head, tail
