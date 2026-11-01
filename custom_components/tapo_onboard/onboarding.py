# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Bridge that hands Tapo devices to core's `tplink` config flow."""

from __future__ import annotations

from enum import StrEnum

from homeassistant.config_entries import SOURCE_DHCP, SOURCE_USER, ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResultType, UnknownHandler
from homeassistant.exceptions import DependencyError
from homeassistant.helpers import discovery_flow
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo

from .const import LOGGER, TPLINK_DOMAIN


class OnboardOutcome(StrEnum):
    """Result of trying to onboard one device into core `tplink`."""

    ADDED = "added"
    ALREADY_CONFIGURED = "already_configured"
    HANDED_TO_USER = "handed_to_user"
    AUTH_FAILED = "auth_failed"
    CANNOT_CONNECT = "cannot_connect"
    UNAVAILABLE = "unavailable"


@callback
def async_request_host_update(hass: HomeAssistant, *, host: str, mac: str) -> None:
    """Start a DHCP-sourced `tplink` flow (updates host or shows a card)."""
    discovery_flow.async_create_flow(
        hass,
        TPLINK_DOMAIN,
        {"source": SOURCE_DHCP},
        DhcpServiceInfo(
            ip=host,
            hostname="",
            macaddress=mac.replace(":", "").replace("-", "").lower(),
        ),
    )


@callback
def async_tplink_entry_for_mac(hass: HomeAssistant, mac: str) -> ConfigEntry | None:
    """Return the `tplink` entry whose unique_id is this MAC, if any."""
    unique_id = format_mac(mac)
    for entry in hass.config_entries.async_entries(TPLINK_DOMAIN):
        if entry.unique_id == unique_id:
            return entry
    return None


async def async_onboard_device(
    hass: HomeAssistant, *, host: str, mac: str, username: str, password: str
) -> OnboardOutcome:
    """Drive core's `tplink` user flow for `host`, falling back to a card."""
    flow = hass.config_entries.flow
    try:
        result = await flow.async_init(
            TPLINK_DOMAIN,
            context={"source": SOURCE_USER},
            data={CONF_HOST: host},
        )
    except (UnknownHandler, DependencyError):
        # No handler, or core tplink cannot load its dependencies.
        return OnboardOutcome.UNAVAILABLE

    if result["type"] == FlowResultType.FORM and (
        result["step_id"] == "user_auth_confirm"
    ):
        result = await flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: username, CONF_PASSWORD: password},
        )
        if result["type"] == FlowResultType.FORM and (
            result["step_id"] == "user_auth_confirm"
        ):
            flow.async_abort(result["flow_id"])
            async_request_host_update(hass, host=host, mac=mac)
            return OnboardOutcome.AUTH_FAILED

    if result["type"] == FlowResultType.CREATE_ENTRY:
        return OnboardOutcome.ADDED
    if result["type"] == FlowResultType.ABORT:
        if result["reason"] == "already_configured":
            return OnboardOutcome.ALREADY_CONFIGURED
        LOGGER.debug("tplink flow for %s aborted: %s", host, result["reason"])
        return OnboardOutcome.CANNOT_CONNECT

    flow.async_abort(result["flow_id"])
    if result["step_id"] == "user":
        return OnboardOutcome.CANNOT_CONNECT
    async_request_host_update(hass, host=host, mac=mac)
    return OnboardOutcome.HANDED_TO_USER
