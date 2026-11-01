# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Stub of core's `tplink` config flow (real one would install GPL kasa)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo
from pytest_homeassistant_custom_component.common import (
    MockModule,
    mock_config_flow,
    mock_integration,
    mock_platform,
)

STUB_MAC = "aa:bb:cc:dd:ee:ff"


class StubTplinkFlow(ConfigFlow, domain="tplink"):
    """Mimics core tplink step ids and results."""

    VERSION = 1

    connect_result: str = "ok"  # ok | auth | cannot_connect | camera
    valid_password: str = "secret"
    dhcp_infos: list[DhcpServiceInfo] = []

    @classmethod
    def reset(cls) -> None:
        cls.connect_result = "ok"
        cls.valid_password = "secret"
        cls.dhcp_infos = []

    def _create(self, host: str) -> ConfigFlowResult:
        return self.async_create_entry(title=host, data={"host": host})

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is None:
            return self.async_show_form(step_id="user")
        self._host = user_input["host"]
        self._async_abort_entries_match({"host": self._host})
        mode = type(self).connect_result
        if mode == "cannot_connect":
            return self.async_show_form(
                step_id="user", errors={"base": "cannot_connect"}
            )
        await self.async_set_unique_id(STUB_MAC)
        if mode == "auth":
            return self.async_show_form(step_id="user_auth_confirm")
        if mode == "camera":
            return self.async_show_form(step_id="camera_auth_confirm")
        return self._create(self._host)

    async def async_step_user_auth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is None:
            return self.async_show_form(step_id="user_auth_confirm")
        if user_input["password"] != type(self).valid_password:
            return self.async_show_form(
                step_id="user_auth_confirm", errors={"password": "invalid_auth"}
            )
        return self._create(self._host)

    async def async_step_camera_auth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return self.async_show_form(step_id="camera_auth_confirm")

    async def async_step_discovery_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return self.async_show_form(step_id="discovery_confirm")

    async def async_step_dhcp(
        self, discovery_info: DhcpServiceInfo
    ) -> ConfigFlowResult:
        type(self).dhcp_infos.append(discovery_info)
        await self.async_set_unique_id(format_mac(discovery_info.macaddress))
        self._abort_if_unique_id_configured(updates={"host": discovery_info.ip})
        self._host = discovery_info.ip
        return self.async_show_form(step_id="discovery_confirm")


@contextmanager
def stub_tplink(hass: HomeAssistant) -> Iterator[type[StubTplinkFlow]]:
    """Register the stub `tplink` integration and flow."""
    StubTplinkFlow.reset()
    mock_integration(hass, MockModule("tplink"))
    mock_platform(hass, "tplink.config_flow", None)
    with mock_config_flow("tplink", StubTplinkFlow):
        yield StubTplinkFlow
