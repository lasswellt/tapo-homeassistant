# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tapo Cloud Onboarding: hands cloud-discovered devices to core `tplink`."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from tapolink_proto.cloud import CloudClient, build_cloud_ssl_context

from .const import CONF_TERMINAL_UUID, DATA_PENDING_PASSWORD, DOMAIN
from .coordinator import InventoryCoordinator


@dataclass(slots=True)
class TapoOnboardRuntimeData:
    """Per-entry runtime state."""

    client: CloudClient
    coordinator: InventoryCoordinator
    password: str | None = None  # memory only


type TapoOnboardConfigEntry = ConfigEntry[TapoOnboardRuntimeData]


def _handoff(hass: HomeAssistant) -> dict[str, str]:
    handoff: dict[str, str] = hass.data.setdefault(DOMAIN, {}).setdefault(
        DATA_PENDING_PASSWORD, {}
    )
    return handoff


async def async_setup_entry(hass: HomeAssistant, entry: TapoOnboardConfigEntry) -> bool:
    """Set up the entry; the cloud is off the critical path."""
    ssl_ctx = await hass.async_add_executor_job(build_cloud_ssl_context)
    client = CloudClient(
        async_get_clientsession(hass),
        ssl_context=ssl_ctx,
        terminal_uuid=entry.data[CONF_TERMINAL_UUID],
    )
    handoff = _handoff(hass)
    runtime: TapoOnboardRuntimeData

    def password() -> str | None:
        fresh = handoff.pop(entry.unique_id or "", None)
        if fresh is not None:
            runtime.password = fresh
        return runtime.password

    coordinator = InventoryCoordinator(
        hass,
        entry,
        client,
        password=password,
        username=entry.data[CONF_USERNAME],
    )
    runtime = TapoOnboardRuntimeData(client, coordinator)
    entry.runtime_data = runtime

    def _drop_handoff() -> None:
        handoff.pop(entry.unique_id or "", None)

    entry.async_on_unload(_drop_handoff)

    # This integration has no entities, and `update_coordinator` only
    # reschedules a refresh while listeners exist. Register a no-op listener
    # before the first refresh so that refresh schedules the next one.
    @callback
    def _keep_polling() -> None:
        """No entities subscribe; HA only reschedules coordinators with listeners."""

    entry.async_on_unload(coordinator.async_add_listener(_keep_polling))

    # Not async_config_entry_first_refresh: it raises ConfigEntryNotReady.
    await coordinator.async_refresh()
    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: TapoOnboardConfigEntry
) -> bool:
    """Unload the entry; no platforms are forwarded."""
    entry.runtime_data.password = None
    return True
