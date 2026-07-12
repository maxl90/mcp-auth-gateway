"""Phase 3 stage 3b: the gateway as a stateful "single virtual MCP server".

One ``/mcp`` endpoint fronts every configured upstream: the gateway answers
``initialize`` itself, eagerly opens a session to each upstream, merges their
tool catalogs under namespaced names, and routes each ``tools/call`` to the
owning upstream — all behind the existing authN/RBAC/audit pass. See
``docs/architecture/multi-upstream-aggregation.md`` and ADR 005.
"""
