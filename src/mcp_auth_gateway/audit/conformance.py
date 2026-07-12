"""Schema-conformance telemetry on tool-call arguments (backlog item 11).

Newer models invent schema fields — a tool call's contract can't be assumed
reliable at the model layer. As a call transits, the gateway validates the
arguments against the tool's pinned ``inputSchema`` and records the result in
the audit record. **Log, never reject**: a non-conformant call is forwarded
exactly as before (rejecting would be enforcement — ADR 007). The value is
evidence about *agent behavior quality* per identity: which agents send calls
that violate the contracts they were shown.

**Invariant (same as ``audit.structure``):** nothing returned here may contain
an argument *value*. Violations are described only from the error's
*schema-side* facts — the JSON path, the failed keyword, and the schema's
expectation — never from ``err.instance`` or ``err.message``, both of which
embed the offending value. Property *names* (the JSON path, unexpected keys)
are shape, not data, matching the ``arg_keys`` precedent. Asserted
adversarially in the tests.

Validation runs on the already-parsed request copy and ``jsonschema`` never
mutates the instance, so the forwarded body is untouched.
"""

from __future__ import annotations

import json
from typing import Any

from jsonschema import validators

_MAX_VIOLATIONS = 10
_MAX_EXPECTED_LEN = 120
_MAX_UNEXPECTED_KEYS = 20


def _expected(validator_value: Any) -> str:
    """Compact, truncated rendering of the schema's expectation (schema-side
    only — an ``enum``'s allowed values, a type name, a required-property list)."""
    try:
        text = json.dumps(validator_value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = str(type(validator_value).__name__)
    if len(text) > _MAX_EXPECTED_LEN:
        text = text[:_MAX_EXPECTED_LEN] + "…"
    return text


def _describe(err) -> dict:
    """One value-free violation. Never touches ``err.message`` (it interpolates
    the instance value)."""
    violation = {
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


def check(schema: dict | None, arguments: Any) -> dict | None:
    """The ``conformance`` block for a tool-call audit record, or ``None``.

    - No pinned schema for the tool → ``None`` (nothing to attest).
    - Schema itself invalid/unsupported → ``{"schema_error": true}`` — the
      telemetry degrades, the call is unaffected.
    - Otherwise → ``schema_conformant`` plus value-free ``violations`` when
      non-conformant. Absent arguments validate as ``{}`` — a tool that
      requires arguments and received none is a real contract violation.
    """
    if not isinstance(schema, dict):
        return None
    try:
        validator_cls = validators.validator_for(schema)
        validator_cls.check_schema(schema)
        validator = validator_cls(schema)
        errors = sorted(
            validator.iter_errors(arguments if arguments is not None else {}),
            key=lambda e: str(e.json_path),
        )
    except Exception:  # noqa: BLE001 — telemetry must degrade, never fail the call
        return {"schema_conformant": None, "schema_error": True}

    if not errors:
        return {"schema_conformant": True}
    result: dict = {
        "schema_conformant": False,
        "violations": [_describe(e) for e in errors[:_MAX_VIOLATIONS]],
    }
    if len(errors) > _MAX_VIOLATIONS:
        result["violations_truncated"] = len(errors) - _MAX_VIOLATIONS
    return result
