"""``WWW-Authenticate`` values are quoted-string-escaped, so a crafted proof or token
header cannot inject auth-params into the challenge."""

from __future__ import annotations

from mcp_auth_gateway.auth import enforce


def test_www_authenticate_escapes_injected_quotes():
    # A crafted header field echoed into error_description must not be able to open a new
    # auth-param (e.g. a rogue resource_metadata pointer).
    malicious = 'zzz", resource_metadata="https://attacker.example/evil'
    header = enforce.www_authenticate(error="invalid_token", description=malicious)
    # The injected closing quote is backslash-escaped, so only OUR
    # resource_metadata (absent here) could ever appear — the attacker's doesn't.
    assert 'resource_metadata="https://attacker.example/evil"' not in header
    assert '\\"' in header  # the quote was escaped, not passed through


def test_www_authenticate_strips_control_chars():
    header = enforce.www_authenticate(description="a\r\nb")
    assert "\r" not in header and "\n" not in header
