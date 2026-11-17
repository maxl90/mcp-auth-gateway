"""Value-free structural metadata about tool-call arguments.

Positive evidence that redaction happened: which tables and columns a SQL call
touched, whether a PII-shaped column was involved, or, for any other tool, which
argument keys were present. Never the values. A parse failure degrades to a
coarse descriptor, never to the raw input.

**Invariant:** nothing returned here may contain an argument *value*. Only
identifiers that come from the query/tool *shape* (table names, column names,
argument keys, statement type) are emitted. A SQL literal like ``'123-45-6789'``
is a value and must never appear. This is asserted adversarially in the tests.
"""

from __future__ import annotations

from typing import Any

import sqlglot
from sqlglot import expressions as exp

from ..naming import split_namespaced

# Column-name substrings that suggest regulated/PII data. Heuristic and
# deliberately conservative — this is an evidence signal ("a PII-shaped column
# was referenced"), not an enforcement decision. Matched case-insensitively
# against column identifiers only (never values).
_PII_HINTS = frozenset(
    {
        "ssn",
        "social_security",
        "mrn",
        "dob",
        "date_of_birth",
        "birth",
        "diagnosis",
        "patient",
        "first_name",
        "last_name",
        "email",
        "phone",
        "address",
        "salary",
        "account_number",
        "routing",
        "card",
        "passport",
        "national_id",
        "tax_id",
    }
)


# The caller chooses the tool name, the argument keys and the SQL, and a record is
# written for a call that is refused too. These caps bound what one request can add
# to the log and how long describing it can hold the event loop.
MAX_NAME_LEN = 256
_MAX_ARG_KEYS = 100
_MAX_SQL_LEN = 64 * 1024


def clip(text: str, limit: int = MAX_NAME_LEN) -> str:
    """``text``, cut to ``limit`` characters with a trailing ``…`` when it was longer."""
    return text if len(text) <= limit else text[:limit] + "…"


def _looks_pii(column: str) -> bool:
    c = column.lower()
    return any(hint in c for hint in _PII_HINTS)


def _describe_sql(sql: Any) -> dict[str, Any]:
    """Tables, columns, statement types and PII-shaped columns of a SQL string; never the SQL."""
    if not isinstance(sql, str):
        return {"kind": "sql", "sql_present": bool(sql)}
    if len(sql) > _MAX_SQL_LEN:
        # Parsing is synchronous and takes seconds per megabyte: not for a caller to spend.
        return {"kind": "sql", "too_large": True}
    try:
        statements = sqlglot.parse(sql)
    except Exception:  # any parser error degrades, never leaks
        return {"kind": "sql", "parse_error": True}

    tables: set[str] = set()
    columns: set[str] = set()
    statement_types: list[str] = []
    for stmt in statements:
        if stmt is None:
            continue
        statement_types.append(type(stmt).__name__.upper())
        for table in stmt.find_all(exp.Table):
            if table.name:
                tables.add(table.name)
        for column in stmt.find_all(exp.Column):
            if column.name:
                columns.add(column.name)

    pii_columns = sorted(c for c in columns if _looks_pii(c))
    return {
        "kind": "sql",
        "statement_types": statement_types,  # e.g. ["SELECT"], ["DELETE"]
        "tables": sorted(tables),
        "columns": sorted(columns),
        "pii_columns": pii_columns,
        "touches_pii": bool(pii_columns),
    }


def describe(tool: str, arguments: Any) -> dict[str, Any] | None:
    """Value-free structural metadata for a ``tools/call``, or ``None`` without arguments.

    A SQL-running tool (base name ``execute_sql``) yields table/column/PII shape, or
    ``too_large`` for SQL past the parse cap; any other tool yields its sorted
    top-level argument keys, each clipped, the first ``_MAX_ARG_KEYS`` of them.
    """
    if arguments is None:
        return None

    namespaced = split_namespaced(tool)
    base_tool = namespaced[1] if namespaced else tool
    if base_tool == "execute_sql":
        sql = arguments.get("sql") if isinstance(arguments, dict) else None
        return _describe_sql(sql)

    if isinstance(arguments, dict):
        keys = sorted(str(k) for k in arguments)
        described: dict[str, Any] = {
            "kind": "generic",
            "arg_keys": [clip(k) for k in keys[:_MAX_ARG_KEYS]],
        }
        if len(keys) > _MAX_ARG_KEYS:
            described["arg_keys_truncated"] = len(keys) - _MAX_ARG_KEYS
        return described

    # Non-dict arguments (a bare scalar/list): record only the type, never the value.
    return {"kind": "generic", "arg_type": type(arguments).__name__}
