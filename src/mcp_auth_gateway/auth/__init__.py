"""Who the caller is, and what they may call.

``token_validator`` turns an Entra ID token into claims; ``policy_resolver``
maps the groups claim to allowed tools; ``step_up`` and ``dpop`` add the
freshness and key-binding checks; ``enforce`` runs them in order for every
``/mcp`` request. The token is validated here and never forwarded.
"""
