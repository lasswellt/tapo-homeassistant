# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md,
#   docs/research/2026-11-08_concept-v4.md)
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
from tapolink_proto.discovery import async_probe, build_query

from .const import DOMAIN, LOGGER, TPLINK_DOMAIN

_TDP_QUERY_KEY = "tdp_query"


class OnboardOutcome(StrEnum):
    """Result of trying to onboard one device into core `tplink`."""

    ADDED = "added"
    ALREADY_CONFIGURED = "already_configured"
    HANDED_TO_USER = "handed_to_user"
    AUTH_FAILED = "auth_failed"
    CANNOT_CONNECT = "cannot_connect"
    UNAVAILABLE = "unavailable"
    IDENTITY_MISMATCH = "identity_mismatch"


class IdentityResult(StrEnum):
    """Outcome of the unicast TDP identity check."""

    VERIFIED = "verified"
    MISMATCH = "mismatch"
    NO_REPLY = "no_reply"


async def async_get_tdp_query(hass: HomeAssistant) -> bytes:
    """Return the TDP probe packet, building it once (RSA keygen) per hass."""
    store = hass.data.setdefault(DOMAIN, {})
    query: bytes | None = store.get(_TDP_QUERY_KEY)
    if query is None:
        query = await hass.async_add_executor_job(build_query)
        store[_TDP_QUERY_KEY] = query
    return query


def _require_one_claim(device_id: str | None, owner_email: str | None) -> None:
    """Reject calls that give neither or both identity claims."""
    if (device_id is None) == (owner_email is None):
        raise ValueError("exactly one of device_id and owner_email is required")


async def async_verify_identity(
    hass: HomeAssistant,
    *,
    host: str,
    mac: str,
    device_id: str | None = None,
    owner_email: str | None = None,
) -> IdentityResult:
    """Probe `host` and compare its TDP identity with one claim.

    The claim is either a cloud `device_id` (TDP device_id == MD5 of it) or the
    account `owner_email` (TDP owner == MD5 of it); the MAC must match in both
    cases. Exactly one claim is required, otherwise ValueError.

    Must pass before any credential or stored credential hash reaches `host`.
    A probe that fails unexpectedly counts as NO_REPLY: the host stays unverified.
    """
    _require_one_claim(device_id, owner_email)
    try:
        info = await async_probe(host, query=await async_get_tdp_query(hass))
    except Exception as exc:  # noqa: BLE001 - one host must not stop the caller
        LOGGER.debug("identity probe for %s failed: %s", mac, type(exc).__name__)
        return IdentityResult.NO_REPLY
    if info is None:
        return IdentityResult.NO_REPLY
    claim_ok = (device_id is not None and info.matches_cloud_device(device_id)) or (
        owner_email is not None and info.owned_by(owner_email)
    )
    if claim_ok and info.matches_mac(mac):
        return IdentityResult.VERIFIED
    LOGGER.debug("identity mismatch for device with MAC %s", mac)
    return IdentityResult.MISMATCH


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


async def async_hand_off_if_verified(
    hass: HomeAssistant,
    *,
    host: str,
    mac: str,
    device_id: str | None = None,
    owner_email: str | None = None,
) -> IdentityResult:
    """Start core's DHCP flow for `host` only once it proves the identity.

    Core's DHCP flow logs in with stored credentials, so nothing is started for
    a MISMATCH or NO_REPLY host.
    """
    identity = await async_verify_identity(
        hass, host=host, mac=mac, device_id=device_id, owner_email=owner_email
    )
    if identity is IdentityResult.VERIFIED:
        async_request_host_update(hass, host=host, mac=mac)
    return identity


@callback
def async_tplink_entry_for_mac(hass: HomeAssistant, mac: str) -> ConfigEntry | None:
    """Return the `tplink` entry whose unique_id is this MAC, if any."""
    unique_id = format_mac(mac)
    for entry in hass.config_entries.async_entries(TPLINK_DOMAIN):
        if entry.unique_id == unique_id:
            return entry
    return None


async def async_onboard_device(
    hass: HomeAssistant,
    *,
    host: str,
    mac: str,
    device_id: str | None = None,
    owner_email: str | None = None,
    username: str,
    password: str,
) -> OnboardOutcome:
    """Drive core's `tplink` user flow for a verified `host`.

    Credentials are only sent once the host proved the claimed identity.
    A silent host (TDP NO_REPLY) is CANNOT_CONNECT: retryable, no flow started.
    """
    identity = await async_verify_identity(
        hass, host=host, mac=mac, device_id=device_id, owner_email=owner_email
    )
    if identity is IdentityResult.MISMATCH:
        return OnboardOutcome.IDENTITY_MISMATCH
    if identity is IdentityResult.NO_REPLY:
        # Unverified host: a DHCP flow would test credentials against it.
        return OnboardOutcome.CANNOT_CONNECT
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
