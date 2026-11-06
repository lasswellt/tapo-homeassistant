# SPDX-License-Identifier: Apache-2.0
# Provenance: original (docs/plans/core-tplink-onboarding-helper/plan.md)
"""The manifest loads through Home Assistant's real loader."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_integration


async def test_manifest_loads(hass: HomeAssistant) -> None:
    """The integration resolves with the expected manifest metadata."""
    integration = await async_get_integration(hass, "tapo_onboard")

    assert integration.domain == "tapo_onboard"
    assert "dhcp" in integration.dependencies
    assert "tplink" in integration.after_dependencies
    assert integration.config_flow is True
    assert integration.requirements == ["tapolink-proto==0.1.1"]
