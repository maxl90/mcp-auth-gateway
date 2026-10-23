"""Schema-conformance telemetry on tool-call arguments: log, never reject.

Models invent schema fields, so as a call transits the gateway validates the
arguments against the tool's pinned ``inputSchema`` and records the verdict. A
non-conformant call is still forwarded unchanged (validation runs on a parsed
copy that ``jsonschema`` never mutates); the value is evidence about each
agent's behavior against the contracts it was shown.

**Invariant (same as ``audit.structure``):** nothing returned here may contain
an argument *value*. Violations are described only from the error's
*schema-side* facts — the JSON path, the failed keyword, and the schema's
expectation — never from ``err.instance`` or ``err.message``, both of which
embed the offending value. Property *names* (the JSON path, unexpected keys)
are shape, not data, matching the ``arg_keys`` precedent. Asserted
adversarially in the tests.

**No network.** The schema comes from the upstream, so a ``$ref`` is resolved
only inside the schema itself: one that points anywhere else (a network URI) is
never fetched and makes the verdict a ``schema_error``, as MCP 2026-07-28
requires. Schema size is capped for the same reason: the upstream controls it.
"""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft202012Validator, ValidationError, validators
from referencing import Registry

_MAX_VIOLATIONS = 10
_MAX_EXPECTED_LEN = 120
_MAX_UNEXPECTED_KEYS = 20
_MAX_SCHEMA_NODES = 2000
_MAX_SCHEMA_DEPTH = 32


def _within_limits(schema: dict[str, Any]) -> bool:
    """Whether the schema's object count and nesting depth are inside the caps."""
    nodes = 0
    stack: list[tuple[Any, int]] = [(schema, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            nodes += 1
            if nodes > _MAX_SCHEMA_NODES or depth > _MAX_SCHEMA_DEPTH:
                return False
            stack.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            stack.extend((value, depth) for value in node)
    return True


def _expected(validator_value: Any) -> str:
    """Compact, truncated rendering of the schema's expectation (schema-side text only)."""
    text = json.dumps(validator_value, sort_keys=True, default=str)
    if len(text) > _MAX_EXPECTED_LEN:
        text = text[:_MAX_EXPECTED_LEN] + "…"
    return text


def _describe(err: ValidationError) -> dict[str, Any]:
    """One value-free violation; never ``err.message``, which interpolates the instance value."""
    violation: dict[str, Any] = {
        "path": err.json_path,
        "keyword": err.validator,
        "expected": _expected(err.validator_value),
    }
    # "models invent schema fields" is THE signal this telemetry exists for —
    # name the invented keys. Keys are shape (arg_keys precedent), not values.
    if err.validator == "additionalProperties" and isinstance(err.instance, dict):
        declared = err.schema.get("properties") if isinstance(err.schema, dict) else None
        declared_keys = set(declared) if isinstance(declared, dict) else set()
        extras = sorted(str(k) for k in err.instance if k not in declared_keys)
        violation["unexpected_keys"] = extras[:_MAX_UNEXPECTED_KEYS]
    return violation


def check(schema: dict[str, Any] | None, arguments: Any) -> dict[str, Any] | None:
    """The ``conformance`` block for a tool-call record, or ``None`` with no pinned schema.

    An invalid, unsupported or oversize schema, or one with a ``$ref`` that does
    not resolve inside it, yields ``{"schema_error": true}``; otherwise
    ``schema_conformant`` plus value-free ``violations`` when false. Absent
    arguments validate as ``{}``: a tool that requires arguments got none.
    """
    if not isinstance(schema, dict):
        return None
    if not _within_limits(schema):
        return {"schema_conformant": None, "schema_error": True}
    try:
        validator_cls = validators.validator_for(schema, default=Draft202012Validator)
        validator_cls.check_schema(schema)
        # An empty registry has no retrieval: refs into the schema still resolve,
        # anything else raises instead of being fetched.
        validator = validator_cls(schema, registry=Registry())
        errors = sorted(
            validator.iter_errors(arguments if arguments is not None else {}),
            key=lambda e: str(e.json_path),
        )
    except Exception:  # telemetry must degrade, never fail the call
        return {"schema_conformant": None, "schema_error": True}

    if not errors:
        return {"schema_conformant": True}
    result: dict[str, Any] = {
        "schema_conformant": False,
        "violations": [_describe(e) for e in errors[:_MAX_VIOLATIONS]],
    }
    if len(errors) > _MAX_VIOLATIONS:
        result["violations_truncated"] = len(errors) - _MAX_VIOLATIONS
    return result
