# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md,
#   docs/research/2026-11-08_concept-v4.md)
"""Bridge that hands Tapo devices to core's `tplink` config flow."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from homeassistant.config_entries import (
    SOURCE_DHCP,
    SOURCE_INTEGRATION_DISCOVERY,
    SOURCE_USER,
    ConfigEntry,
    ConfigEntryState,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    STATE_UNAVAILABLE,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResultType, UnknownHandler
from homeassistant.exceptions import DependencyError
from homeassistant.helpers import discovery_flow
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo
from homeassistant.util import dt as dt_util
from tapolink_proto.discovery import TdpInfo, async_probe, build_query

from .const import DOMAIN, LOGGER, TPLINK_DOMAIN

_TDP_QUERY_KEY = "tdp_query"
_BROKEN_STATES = frozenset({ConfigEntryState.SETUP_RETRY, ConfigEntryState.SETUP_ERROR})


class OnboardOutcome(StrEnum):
    """Result of trying to onboard one device into core `tplink`."""

    ADDED = "added"
    ALREADY_CONFIGURED = "already_configured"
    HANDED_TO_USER = "handed_to_user"
    AUTH_FAILED = "auth_failed"
    CANNOT_CONNECT = "cannot_connect"
    UNAVAILABLE = "unavailable"
    IDENTITY_MISMATCH = "identity_mismatch"
    PENDING_CONFIRMATION = "pending_confirmation"


# Outcomes after which a device is not offered or tried again.
TERMINAL_OUTCOMES: Final = frozenset(
    {
        OnboardOutcome.ADDED,
        OnboardOutcome.ALREADY_CONFIGURED,
        OnboardOutcome.HANDED_TO_USER,
        OnboardOutcome.AUTH_FAILED,
        OnboardOutcome.IDENTITY_MISMATCH,
    }
)


def _model_base(model: str | None) -> str:
    """Strip a region suffix: "S310D(US)" -> "S310D"."""
    return (model or "").split("(", 1)[0].strip()


_MODEL_UNSAFE = re.compile(r"[^A-Za-z0-9 ._()/+-]")
MAX_MODEL_LENGTH = 40


def safe_model(model: str | None) -> str:
    """Return a model name that is safe to show in a card or repair.

    The TDP reply is unauthenticated, so anything outside a plain model
    charset (markdown, links) is dropped and the length is capped.
    """
    cleaned = _MODEL_UNSAFE.sub("", model or "")
    return cleaned[:MAX_MODEL_LENGTH].strip() or "Tapo device"


def is_lost(hass: HomeAssistant, tplink_entry: ConfigEntry) -> bool:
    """Return True when the `tplink` entry cannot reach its device.

    Failed setup counts as lost; a loaded entry is lost when it has enabled
    entities and every one is unavailable.
    """
    if tplink_entry.state in _BROKEN_STATES:
        return True
    if tplink_entry.state is not ConfigEntryState.LOADED:
        return False
    registry = er.async_get(hass)
    entity_ids = [
        ent.entity_id
        for ent in er.async_entries_for_config_entry(registry, tplink_entry.entry_id)
        if ent.disabled_by is None
    ]
    if not entity_ids:
        return False
    for entity_id in entity_ids:
        state = hass.states.get(entity_id)
        if state is None or state.state != STATE_UNAVAILABLE:
            return False
    return True


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


async def async_probe_info(hass: HomeAssistant, host: str) -> TdpInfo | None:
    """Unicast-probe `host`; None when it is silent or the probe fails."""
    try:
        return await async_probe(host, query=await async_get_tdp_query(hass))
    except Exception as exc:  # noqa: BLE001 - one host must not stop the caller
        LOGGER.debug("probe failed: %s", type(exc).__name__)
        return None


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
    info = await async_probe_info(hass, host)
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
    a MISMATCH or NO_REPLY host. When the MAC had a `tplink` entry and it is gone
    once the probe returns, nothing is started either (NO_REPLY: not handed off):
    core would otherwise log in to an unconfigured MAC with stored credentials.
    """
    had_entry = async_tplink_entry_for_mac(hass, mac) is not None
    identity = await async_verify_identity(
        hass, host=host, mac=mac, device_id=device_id, owner_email=owner_email
    )
    if identity is not IdentityResult.VERIFIED:
        return identity
    if had_entry and async_tplink_entry_for_mac(hass, mac) is None:
        return IdentityResult.NO_REPLY
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
    request_host_update: bool = True,
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
            if request_host_update:
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


class MovedCards:
    """Offers one "moved" card per lost device, re-offered once per interval."""

    def __init__(self, interval: timedelta) -> None:
        """Offer an unanswered card again after `interval`."""
        self._interval = interval
        # MAC -> (address, time) of the last card offered in the current lost episode.
        self._offered: dict[str, tuple[str, datetime]] = {}

    @callback
    def async_offer(
        self,
        hass: HomeAssistant,
        *,
        mac: str,
        ip: str,
        model: str | None,
        entry_id: str,
        device_id: str | None = None,
    ) -> None:
        """Start the card unless this address was offered and is still pending.

        A new address is offered at once; an unanswered card is offered again
        once per interval, never while one is open.
        """
        key = format_mac(mac)
        now = dt_util.utcnow()
        offered = self._offered.get(key)
        if (
            offered is not None
            and offered[0] == ip
            and (
                now - offered[1] < self._interval
                or hass.config_entries.flow.async_progress_by_handler(
                    DOMAIN, match_context={"unique_id": f"moved-{key}-{ip}"}
                )
            )
        ):
            return
        self._offered[key] = (ip, now)
        data: dict[str, str] = {
            "kind": "moved",
            "host": ip,
            "mac": mac,
            "model": safe_model(_model_base(model)),
            "entry_id": entry_id,
        }
        if device_id is not None:
            data["device_id"] = device_id
        discovery_flow.async_create_flow(
            hass, DOMAIN, {"source": SOURCE_INTEGRATION_DISCOVERY}, data
        )

    @callback
    def prune(self, hass: HomeAssistant) -> None:
        """Forget every MAC whose `tplink` entry is gone or no longer lost."""
        for mac in list(self._offered):
            entry = async_tplink_entry_for_mac(hass, mac)
            if entry is None or not is_lost(hass, entry):
                del self._offered[mac]
