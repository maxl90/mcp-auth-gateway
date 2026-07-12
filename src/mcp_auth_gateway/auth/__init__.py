"""Authentication and authorization for the gateway.

``token_validator`` proves *who* the caller is (Entra ID token → claims).
``policy_resolver`` decides *what* they may call (group claim → allowed tools).
The proxy path in ``main`` wires both together; neither module forwards the
user's token upstream — the gateway terminates it (see CONTEXT.md trust boundary).
"""
