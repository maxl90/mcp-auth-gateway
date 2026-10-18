"""The gateway as one virtual MCP server over many upstreams.

One ``/mcp`` endpoint answers ``initialize`` itself, opens a session to every
configured upstream, merges their tool catalogs under namespaced names, and
routes each ``tools/call`` to the owning upstream, all behind the same
authentication, RBAC and audit pass as the single-upstream proxy.
"""
