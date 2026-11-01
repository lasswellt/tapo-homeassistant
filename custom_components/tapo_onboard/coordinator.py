# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Cloud inventory coordinator.

Fixed cadence: `timedelta(minutes=30)` (`INVENTORY_INTERVAL`), one
`list_devices` call per cycle. `device_details` is only called for `tplink`
entries that failed to set up (IP repair) and for devices not yet seen.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudClient,
    CloudDevice,
    CloudRateLimited,
    CloudResponseError,
    CloudSession,
    CloudUnavailable,
    DeviceDetails,
    TokenExpired,
)

from .const import (
    CONF_ACCOUNT_ID,
    CONF_IGNORED_MACS,
    CONF_REFRESH_TOKEN,
    CONF_TOKEN,
    DOMAIN,
    INVENTORY_INTERVAL,
    LOGGER,
    UNSUPPORTED_IN_CORE_MODELS,
)
from .onboarding import (
    OnboardOutcome,
    async_onboard_device,
    async_request_host_update,
    async_tplink_entry_for_mac,
)

_BROKEN_STATES = frozenset({ConfigEntryState.SETUP_RETRY, ConfigEntryState.SETUP_ERROR})


@dataclass(frozen=True, slots=True)
class InventoryState:
    """Result of one inventory cycle."""

    devices: Mapping[str, CloudDevice]
    outcomes: Mapping[str, OnboardOutcome]
    host_updates: tuple[str, ...]


class InventoryCoordinator(DataUpdateCoordinator[InventoryState]):
    """Polls the cloud device list and repairs / onboards `tplink` devices."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: CloudClient,
        *,
        password: Callable[[], str | None],
        username: str,
    ) -> None:
        super().__init__(
            hass,
            LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=INVENTORY_INTERVAL,
            always_update=False,
        )
        self._entry = entry
        self._client = client
        self._password = password
        self._username = username
        self._attempted: set[str] = set()
        self._reauth_started = False
        self._session = self._session_from_entry()

    def _session_from_entry(self) -> CloudSession:
        data = self._entry.data
        return CloudSession(
            token=data[CONF_TOKEN],
            refresh_token=data.get(CONF_REFRESH_TOKEN),
            account_id=data.get(CONF_ACCOUNT_ID),
        )

    def _start_reauth(self) -> UpdateFailed:
        if not self._reauth_started:
            self._reauth_started = True
            self._entry.async_start_reauth(self.hass)
        return UpdateFailed(translation_domain=DOMAIN, translation_key="cloud_auth")

    async def _call[T](self, call: Callable[[CloudSession], Awaitable[T]]) -> T:
        """Run a cloud call, refreshing the token once on expiry."""
        try:
            try:
                return await call(self._session)
            except TokenExpired:
                self._session = await self._client.refresh(self._session)
                self.hass.config_entries.async_update_entry(
                    self._entry,
                    data={
                        **self._entry.data,
                        CONF_TOKEN: self._session.token,
                        CONF_REFRESH_TOKEN: self._session.refresh_token,
                        CONF_ACCOUNT_ID: self._session.account_id,
                    },
                )
                return await call(self._session)
        except (TokenExpired, CloudAuthError) as exc:
            raise self._start_reauth() from exc

    async def _details(self, device: CloudDevice) -> DeviceDetails | None:
        """Fetch details; a per-device failure skips only that device."""
        try:
            return await self._call(lambda s: self._client.device_details(s, device))
        except (CloudUnavailable, CloudResponseError) as exc:
            LOGGER.debug("details for %s failed: %s", device.mac, type(exc).__name__)
            return None

    async def _async_update_data(self) -> InventoryState:
        # Tokens may have been rewritten by the reauth flow since last cycle.
        self._session = self._session_from_entry()
        try:
            listed = await self._call(self._client.list_devices)
            self._reauth_started = False
            return await self._process({d.mac: d for d in listed})
        except CloudRateLimited as exc:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="rate_limited",
                retry_after=exc.retry_after,
            ) from exc
        except (CloudUnavailable, CloudResponseError) as exc:
            raise UpdateFailed(
                translation_domain=DOMAIN, translation_key="cloud_unavailable"
            ) from exc

    async def _process(self, devices: dict[str, CloudDevice]) -> InventoryState:
        outcomes: dict[str, OnboardOutcome] = {}
        host_updates: list[str] = []
        ignored = set(self._entry.data.get(CONF_IGNORED_MACS, []))

        for mac, device in devices.items():
            tplink_entry = async_tplink_entry_for_mac(self.hass, mac)
            if tplink_entry is not None:
                # Case (a): IP repair for entries that failed to set up.
                if tplink_entry.state not in _BROKEN_STATES:
                    continue
                details = await self._details(device)
                if details is None or not details.ip:
                    continue
                if details.ip != tplink_entry.data.get("host"):
                    async_request_host_update(self.hass, host=details.ip, mac=mac)
                    host_updates.append(mac)
                continue

            # Case (b): new device.
            if (
                mac in ignored
                or mac in self._attempted
                or device.model_base in UNSUPPORTED_IN_CORE_MODELS
            ):
                continue
            details = await self._details(device)
            if details is None:
                continue
            self._attempted.add(mac)
            if not details.ip:
                LOGGER.debug("no IP for new device %s, skipping", mac)
                continue
            password = self._password()
            if password:
                outcomes[mac] = await async_onboard_device(
                    self.hass,
                    host=details.ip,
                    mac=mac,
                    username=self._username,
                    password=password,
                )
            else:
                async_request_host_update(self.hass, host=details.ip, mac=mac)
                outcomes[mac] = OnboardOutcome.HANDED_TO_USER

        return InventoryState(
            devices=devices, outcomes=outcomes, host_updates=tuple(host_updates)
        )
