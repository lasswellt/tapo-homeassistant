# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Cloud inventory coordinator.

Fixed cadence: `timedelta(minutes=30)` (`INVENTORY_INTERVAL`), one
`list_devices` call per cycle; the first cycle after the config flow reuses the
flow's list instead. `device_details` is only called for lost `tplink` entries
(failed to set up, or loaded with every enabled entity unavailable) and for
devices not yet seen, and at most once per device per 15 minutes
(`DETAILS_FLOOR`). Each failed lookup for the same device doubles that gap, up
to `DETAILS_BACKOFF_MAX`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudClient,
    CloudDevice,
    CloudError,
    CloudRateLimited,
    CloudSession,
    DeviceDetails,
    RefreshTokenUnusable,
    TokenExpired,
)

from .const import (
    CONF_ACCOUNT_ID,
    CONF_IGNORED_MACS,
    CONF_REFRESH_TOKEN,
    CONF_TOKEN,
    DETAILS_BACKOFF_MAX,
    DETAILS_FLOOR,
    DOMAIN,
    INVENTORY_INTERVAL,
    LOGGER,
    UNSUPPORTED_IN_CORE_MODELS,
)
from .onboarding import (
    IdentityResult,
    OnboardOutcome,
    async_hand_off_if_verified,
    async_onboard_device,
    async_tplink_entry_for_mac,
)

_BROKEN_STATES = frozenset({ConfigEntryState.SETUP_RETRY, ConfigEntryState.SETUP_ERROR})
_TERMINAL = frozenset(
    {
        OnboardOutcome.ADDED,
        OnboardOutcome.ALREADY_CONFIGURED,
        OnboardOutcome.HANDED_TO_USER,
        OnboardOutcome.AUTH_FAILED,
        OnboardOutcome.IDENTITY_MISMATCH,
    }
)


@dataclass(slots=True)
class FlowResult:
    """What the config flow already did, handed to setup in memory only."""

    outcomes: dict[str, OnboardOutcome] = field(default_factory=dict)
    details_at: dict[str, datetime] = field(default_factory=dict)
    # The flow's device list, reused by the first cycle instead of listing again.
    devices: tuple[CloudDevice, ...] = ()
    listed_at: datetime | None = None


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
        flow_result: FlowResult | None = None,
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
        self._details_not_before: dict[str, datetime] = {}
        self._details_called: dict[str, datetime] = {}
        self._failures: dict[str, int] = {}
        self._seed: dict[str, CloudDevice] | None = None
        if flow_result is not None:
            self._attempted.update(
                mac for mac, o in flow_result.outcomes.items() if o in _TERMINAL
            )
            self._details_not_before.update(
                (mac, at + DETAILS_FLOOR) for mac, at in flow_result.details_at.items()
            )
            listed_at = flow_result.listed_at
            if listed_at is not None and (
                dt_util.utcnow() - listed_at < INVENTORY_INTERVAL
            ):
                self._seed = {d.mac: d for d in flow_result.devices}
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
                try:
                    self._session = await self._client.refresh(self._session)
                except RefreshTokenUnusable as exc:
                    # Only an unusable refresh token means reauth; other
                    # refresh errors are transient (UpdateFailed upstream).
                    raise self._start_reauth() from exc
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

    def _is_lost(self, tplink_entry: ConfigEntry) -> bool:
        """Return True when the `tplink` entry cannot reach its device.

        Failed setup counts as lost. A loaded entry is lost when it has enabled
        entities and every one of them is unavailable (device moved or off).
        """
        if tplink_entry.state in _BROKEN_STATES:
            return True
        if tplink_entry.state is not ConfigEntryState.LOADED:
            return False
        registry = er.async_get(self.hass)
        entity_ids = [
            ent.entity_id
            for ent in er.async_entries_for_config_entry(
                registry, tplink_entry.entry_id
            )
            if ent.disabled_by is None
        ]
        if not entity_ids:
            return False
        for entity_id in entity_ids:
            state = self.hass.states.get(entity_id)
            if state is None or state.state != STATE_UNAVAILABLE:
                return False
        return True

    def _details_due(self, mac: str) -> bool:
        """True once the floor (or backoff) since this device's last call passed.

        The floor applies whether the flow or this coordinator made the call
        (rule 3).
        """
        not_before = self._details_not_before.get(mac)
        return not_before is None or dt_util.utcnow() >= not_before

    def _settle(self, mac: str, *, progressed: bool) -> None:
        """Reset the backoff after progress, else double the gap (capped)."""
        if progressed:
            self._failures.pop(mac, None)
            return
        failures = self._failures.get(mac, 0) + 1
        self._failures[mac] = failures
        delay: timedelta = min(DETAILS_FLOOR * 2 ** (failures - 1), DETAILS_BACKOFF_MAX)
        self._details_not_before[mac] = self._details_called[mac] + delay

    async def _details(self, device: CloudDevice) -> DeviceDetails | None:
        """Fetch details (caller checked `_details_due`).

        A per-device failure returns None and skips only that device.
        """
        now = dt_util.utcnow()
        self._details_called[device.mac] = now
        self._details_not_before[device.mac] = now + DETAILS_FLOOR
        try:
            return await self._call(lambda s: self._client.device_details(s, device))
        except CloudRateLimited:
            raise
        except CloudError as exc:
            LOGGER.debug("details for %s failed: %s", device.mac, type(exc).__name__)
            return None

    async def _async_update_data(self) -> InventoryState:
        # Tokens may have been rewritten by the reauth flow since last cycle.
        self._session = self._session_from_entry()
        try:
            if (seeded := self._seed) is not None:
                # The config flow listed seconds ago: no second call (rule 3).
                self._seed = None
                return await self._process(seeded)
            listed = await self._call(self._client.list_devices)
            self._reauth_started = False
            return await self._process({d.mac: d for d in listed})
        except CloudRateLimited as exc:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="rate_limited",
                retry_after=exc.retry_after,
            ) from exc
        except CloudError as exc:
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
                # Case (a): IP repair for lost entries. Core rewrites the host
                # and reloads for both loaded and setup-retry/error entries.
                if not self._is_lost(tplink_entry):
                    self._failures.pop(mac, None)
                    continue
                if not self._details_due(mac):
                    continue
                details = await self._details(device)
                ip = details.ip if details is not None else None
                if not ip or ip == tplink_entry.data.get("host"):
                    # Offline in the cloud, or still at the same address.
                    self._settle(mac, progressed=False)
                    continue
                identity = await async_hand_off_if_verified(
                    self.hass, host=ip, mac=mac, device_id=device.device_id
                )
                self._settle(mac, progressed=identity is IdentityResult.VERIFIED)
                if identity is IdentityResult.VERIFIED:
                    host_updates.append(mac)
                continue

            # Case (b): new device.
            if (
                mac in ignored
                or mac in self._attempted
                or device.model_base in UNSUPPORTED_IN_CORE_MODELS
            ):
                continue
            if not self._details_due(mac):
                continue
            details = await self._details(device)
            if details is None or not details.ip:
                LOGGER.debug("no IP for new device %s, skipping", mac)
                self._settle(mac, progressed=False)
                continue
            password = self._password()
            if password:
                try:
                    outcomes[mac] = await async_onboard_device(
                        self.hass,
                        host=details.ip,
                        mac=mac,
                        device_id=device.device_id,
                        username=self._username,
                        password=password,
                    )
                except Exception as exc:  # noqa: BLE001 - isolate one device
                    LOGGER.debug("onboarding %s failed: %s", mac, type(exc).__name__)
                    outcomes[mac] = OnboardOutcome.CANNOT_CONNECT
                if outcomes[mac] in _TERMINAL:
                    self._attempted.add(mac)
                self._settle(mac, progressed=outcomes[mac] in _TERMINAL)
            else:
                identity = await async_hand_off_if_verified(
                    self.hass, host=details.ip, mac=mac, device_id=device.device_id
                )
                if identity is IdentityResult.NO_REPLY:
                    # Unverified host: no hand-off, retried with backoff.
                    self._settle(mac, progressed=False)
                    continue
                outcomes[mac] = (
                    OnboardOutcome.HANDED_TO_USER
                    if identity is IdentityResult.VERIFIED
                    else OnboardOutcome.IDENTITY_MISMATCH
                )
                self._attempted.add(mac)
                self._settle(mac, progressed=True)

        return InventoryState(
            devices=devices, outcomes=outcomes, host_updates=tuple(host_updates)
        )
