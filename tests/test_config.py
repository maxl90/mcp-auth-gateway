"""Settings are validated when the gateway boots."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_auth_gateway.config import Settings


def test_unknown_dpop_mode_fails_at_boot(monkeypatch):
    monkeypatch.setenv("DPOP_MODE", "bogus")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize("mode", ["off", "if_present", "required"])
def test_dpop_modes_are_accepted(monkeypatch, mode):
    monkeypatch.setenv("DPOP_MODE", mode)
    assert Settings(_env_file=None).dpop_mode == mode
