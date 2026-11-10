# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-08_concept-v4.md)
"""Local sweep coordinator (no cloud).

Every `SWEEP_INTERVAL` it sends a TDP query to the configured subnets plus the
/24 of each core `tplink` entry, keeps replies owned by the account username,
repairs moved hosts of lost `tplink` entries and offers new devices as a
discovery card. The password is never sent to a new device unattended: the TDP
owner hash is public, so the user confirms each new device first.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Network
from typing import Final

from homeassistant.config_entries import (
    SOURCE_INTEGRATION_DISCOVERY,
    ConfigEntry,
    ConfigEntryState,
)
from homeassistant.const import STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import discovery_flow
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util
from tapolink_proto.discovery import (
    SweepRangeError,
    TdpInfo,
    async_sweep,
    network_of,
    parse_networks,
)

from .const import (
    CONF_IGNORED_MACS,
    CONF_SUBNETS,
    DOMAIN,
    LOGGER,
    LOST_CHECK_INTERVAL,
    SWEEP_INTERVAL,
    TPLINK_DOMAIN,
    UNSUPPORTED_IN_CORE_MODELS,
)
from .coordinator import _TERMINAL, FlowResult
from .onboarding import (
    IdentityResult,
    OnboardOutcome,
    async_get_tdp_query,
    async_hand_off_if_verified,
    async_tplink_entry_for_mac,
)

# Minimum gap between targeted sweeps of the same subnet.
TARGETED_SWEEP_FLOOR: Final = timedelta(seconds=60)

_BROKEN_STATES = frozenset({ConfigEntryState.SETUP_RETRY, ConfigEntryState.SETUP_ERROR})


@dataclass(frozen=True, slots=True)
class SweepState:
    """Result of one sweep."""

    devices: Mapping[str, TdpInfo]
    outcomes: Mapping[str, OnboardOutcome]
    host_updates: tuple[str, ...]
    # Replies owned by another account: diagnostics only.
    foreign: int
    # MACs of owned devices advertising TPAP: diagnostics only.
    tpap: tuple[str, ...] = ()


def advertises_tpap(info: TdpInfo) -> bool:
    """Return True when the TDP reply shows the TPAP login scheme."""
    return (info.encrypt_type or "").upper() == "TPAP" or bool(info.tpap)


def _model_base(model: str | None) -> str:
    """Strip a region suffix: "S310D(US)" -> "S310D"."""
    return (model or "").split("(", 1)[0].strip()


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


class SweepCoordinator(DataUpdateCoordinator[SweepState]):
    """Sweeps the LAN for devices owned by the account."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        username: str,
        flow_result: FlowResult | None = None,
    ) -> None:
        super().__init__(
            hass,
            LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=SWEEP_INTERVAL,
            always_update=False,
        )
        self._entry = entry
        self._username = username
        self._issue_id = f"tpap_firmware_detected_{entry.entry_id}"
        entry.async_on_unload(
            lambda: ir.async_delete_issue(hass, DOMAIN, self._issue_id)
        )
        self._attempted: set[str] = set()
        self._last_targeted: dict[IPv4Network, datetime] = {}
        # MAC -> login scheme the device showed while healthy at its known host.
        self._schemes: dict[str, str | None] = {}
        # MACs whose "moved" card was started in the current lost episode.
        self._moved_cards: set[str] = set()
        if flow_result is not None:
            self._attempted.update(
                mac for mac, o in flow_result.outcomes.items() if o in _TERMINAL
            )

    def sweep_networks(self) -> tuple[IPv4Network, ...]:
        """Stored subnets plus the /24 of every core `tplink` host, bounded."""
        stored: list[str] = list(self._entry.data.get(CONF_SUBNETS, []))
        extra: list[str] = []
        for tp in self.hass.config_entries.async_entries(TPLINK_DOMAIN):
            host = tp.data.get("host")
            if not isinstance(host, str):
                continue
            try:
                extra.append(str(network_of(host)))
            except SweepRangeError:
                continue
        try:
            return parse_networks([*stored, *extra])
        except SweepRangeError as exc:
            LOGGER.debug("sweep union rejected (%s), using stored subnets", exc.reason)
        try:
            return parse_networks(stored)
        except SweepRangeError as exc:
            LOGGER.debug("stored subnets rejected (%s)", exc.reason)
            return ()

    @callback
    def _record_scheme(self, info: TdpInfo) -> None:
        """Remember the scheme of a healthy device answering at its known host."""
        entry = async_tplink_entry_for_mac(self.hass, info.mac)
        if (
            entry is not None
            and info.ip == entry.data.get("host")
            and not is_lost(self.hass, entry)
        ):
            self._schemes[format_mac(info.mac)] = (
                info.encrypt_type or ""
            ).upper() or None

    @callback
    def _prune_moved_cards(self) -> None:
        """Forget the card marker of every entry that is no longer lost."""
        for mac in list(self._moved_cards):
            entry = async_tplink_entry_for_mac(self.hass, mac)
            if entry is None or not is_lost(self.hass, entry):
                self._moved_cards.discard(mac)

    async def _async_handle_moved(self, info: TdpInfo) -> bool:
        """Re-point a lost entry whose device answers elsewhere.

        Only KLAP is re-pointed unattended: the device must prove it knows the
        credentials before the client sends anything sensitive. Any other
        scheme (or an unknown one) sends the password at login, so the user
        confirms through a card. Returns True when core's flow was started.
        """
        assert info.ip is not None  # noqa: S101 - filtered by the callers
        mac = format_mac(info.mac)
        if (
            self._schemes.get(mac) == "KLAP"
            and (info.encrypt_type or "").upper() == "KLAP"
        ):
            identity = await async_hand_off_if_verified(
                self.hass, host=info.ip, mac=info.mac, owner_email=self._username
            )
            return identity is IdentityResult.VERIFIED
        if mac not in self._moved_cards:
            self._moved_cards.add(mac)
            discovery_flow.async_create_flow(
                self.hass,
                DOMAIN,
                {"source": SOURCE_INTEGRATION_DISCOVERY},
                {
                    "kind": "moved",
                    "host": info.ip,
                    "mac": info.mac,
                    "model": _model_base(info.device_model) or "Tapo device",
                    "entry_id": self._entry.entry_id,
                },
            )
        return False

    @callback
    def async_start_lost_check(self) -> None:
        """Check for lost `tplink` entries every `LOST_CHECK_INTERVAL`."""
        self._entry.async_on_unload(
            async_track_time_interval(
                self.hass, self._async_check_lost, LOST_CHECK_INTERVAL
            )
        )

    async def _async_check_lost(self, _now: datetime | None = None) -> None:
        """Sweep the subnet of each lost `tplink` entry, at most once per floor."""
        self._prune_moved_cards()
        by_subnet: dict[IPv4Network, list[tuple[str, str]]] = {}
        for tp in self.hass.config_entries.async_entries(TPLINK_DOMAIN):
            host = tp.data.get("host")
            if not tp.unique_id or not isinstance(host, str):
                continue
            if not is_lost(self.hass, tp):
                continue
            try:
                subnet = network_of(host)
            except SweepRangeError:
                continue
            by_subnet.setdefault(subnet, []).append((format_mac(tp.unique_id), host))
        if not by_subnet:
            return
        try:
            query = await async_get_tdp_query(self.hass)
        except Exception as exc:  # noqa: BLE001 - never raise out of the timer
            LOGGER.debug("lost-check query failed: %s", type(exc).__name__)
            return
        for subnet, lost in by_subnet.items():
            now = dt_util.utcnow()
            last = self._last_targeted.get(subnet)
            if last is not None and now - last < TARGETED_SWEEP_FLOOR:
                continue
            self._last_targeted[subnet] = now
            try:
                infos = await async_sweep([subnet], query=query)
                for info in infos:
                    if not info.ip or not info.owned_by(self._username):
                        continue
                    self._record_scheme(info)
                    mac = format_mac(info.mac)
                    if any(m == mac and h != info.ip for m, h in lost):
                        await self._async_handle_moved(info)
            except Exception as exc:  # noqa: BLE001 - isolate one subnet
                LOGGER.debug("targeted sweep failed: %s", type(exc).__name__)

    @callback
    def _update_tpap_issue(self, owned: Mapping[str, TdpInfo]) -> tuple[str, ...]:
        """Create or delete the TPAP repair; return the MACs advertising TPAP."""
        tpap = sorted(
            (i for i in owned.values() if advertises_tpap(i)),
            key=lambda i: [int(p) if p.isdigit() else 0 for p in str(i.ip).split(".")],
        )
        if not tpap:
            ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)
            return ()
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            self._issue_id,
            is_fixable=False,
            is_persistent=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="tpap_firmware_detected",
            translation_placeholders={
                "devices": ", ".join(
                    f"{_model_base(i.device_model) or 'Tapo'} ({i.ip})" for i in tpap
                )
            },
        )
        return tuple(i.mac for i in tpap)

    async def _async_update_data(self) -> SweepState:
        networks = self.sweep_networks()
        if not networks:
            return SweepState(devices={}, outcomes={}, host_updates=(), foreign=0)
        query = await async_get_tdp_query(self.hass)
        infos = await async_sweep(networks, query=query)
        owned: dict[str, TdpInfo] = {}
        foreign = 0
        for info in infos:
            if info.owned_by(self._username):
                if info.ip:
                    owned[info.mac] = info
            else:
                foreign += 1
        tpap_macs = self._update_tpap_issue(owned)
        outcomes: dict[str, OnboardOutcome] = {}
        host_updates: list[str] = []
        ignored = set(self._entry.data.get(CONF_IGNORED_MACS, []))

        self._prune_moved_cards()
        for mac, info in owned.items():
            assert info.ip is not None  # noqa: S101 - filtered above
            self._record_scheme(info)
            tplink_entry = async_tplink_entry_for_mac(self.hass, mac)
            if tplink_entry is not None:
                if not is_lost(self.hass, tplink_entry):
                    continue
                if info.ip == tplink_entry.data.get("host"):
                    continue
                if await self._async_handle_moved(info):
                    host_updates.append(mac)
                continue

            if (
                mac in ignored
                or mac in self._attempted
                or _model_base(info.device_model) in UNSUPPORTED_IN_CORE_MODELS
            ):
                continue
            discovery_flow.async_create_flow(
                self.hass,
                DOMAIN,
                {"source": SOURCE_INTEGRATION_DISCOVERY},
                {
                    "host": info.ip,
                    "mac": mac,
                    "model": _model_base(info.device_model) or "Tapo device",
                    "entry_id": self._entry.entry_id,
                },
            )
            outcomes[mac] = OnboardOutcome.PENDING_CONFIRMATION
            self._attempted.add(mac)

        return SweepState(
            devices=owned,
            outcomes=outcomes,
            host_updates=tuple(host_updates),
            foreign=foreign,
            tpap=tpap_macs,
        )
