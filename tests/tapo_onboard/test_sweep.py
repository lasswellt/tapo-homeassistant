# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-08_concept-v4.md)
"""Tests for the local sweep coordinator (UDP layer faked, stub tplink)."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.device_registry import format_mac
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockModule,
    async_fire_time_changed,
    mock_integration,
)
from stub_tplink import STUB_MAC, StubTplinkFlow, stub_tplink
from tapolink_proto.discovery import TdpInfo

if TYPE_CHECKING:
    from custom_components.tapo_onboard.sweep import SweepCoordinator

USER = "u@example.com"
MAC2 = "11:22:33:44:55:66"


def _md5(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest().upper()  # noqa: S324


def _info(
    mac: str = STUB_MAC,
    ip: str = "192.168.1.5",
    model: str = "P110(US)",
    owner: str = USER,
) -> TdpInfo:
    info = TdpInfo.from_result(
        {
            "device_id": _md5(f"id-{mac}"),
            "mac": mac,
            "owner": _md5(owner),
            "ip": ip,
            "device_model": model,
        }
    )
    assert info is not None
    return info


class FakeSweep:
    """Replaces `sweep.async_sweep` (the UDP layer)."""

    def __init__(self) -> None:
        self.replies: list[TdpInfo] = []
        self.calls: list[tuple[str, ...]] = []

    async def __call__(self, networks: Any, *, query: bytes, **_: object) -> Any:
        self.calls.append(tuple(str(n) for n in networks))
        return list(self.replies)


@pytest.fixture
def udp() -> Iterator[FakeSweep]:
    fake = FakeSweep()
    with patch("custom_components.tapo_onboard.sweep.async_sweep", fake):
        yield fake


@pytest.fixture(autouse=True)
def probe() -> Iterator[None]:
    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return _info(STUB_MAC, host)

    with patch("custom_components.tapo_onboard.onboarding.async_probe", _fake):
        yield


@pytest.fixture
def stub(hass: HomeAssistant) -> Iterator[type[StubTplinkFlow]]:
    # The manifest depends on core `dhcp`/`network`, whose extras are not installed.
    mock_integration(hass, MockModule("dhcp"))
    mock_integration(hass, MockModule("network"))
    with stub_tplink(hass) as flow:
        yield flow


def _entry(hass: HomeAssistant, **extra: object) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain="tapo_onboard", data={"subnets": ["192.168.1.0/24"], **extra}
    )
    entry.add_to_hass(hass)
    return entry


def _tplink(
    hass: HomeAssistant, state: ConfigEntryState, host: str = "192.168.1.1"
) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain="tplink",
        unique_id=format_mac(STUB_MAC),
        data={"host": host},
        state=state,
    )
    entry.add_to_hass(hass)
    return entry


def _coord(hass: HomeAssistant, entry: MockConfigEntry) -> SweepCoordinator:
    mod = importlib.import_module("custom_components.tapo_onboard.sweep")
    return cast(
        "SweepCoordinator",
        mod.SweepCoordinator(hass, entry, username=USER),
    )


async def test_new_device_starts_confirmation_card_only(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info()]
    entry = _entry(hass)
    coord = _coord(hass, entry)
    with patch(
        "custom_components.tapo_onboard.onboarding.async_onboard_device"
    ) as onboard:
        await coord.async_refresh()
        await hass.async_block_till_done(wait_background_tasks=True)
    onboard.assert_not_called()
    assert coord.data.outcomes[STUB_MAC].value == "pending_confirmation"
    assert hass.config_entries.flow.async_progress_by_handler("tplink") == []
    assert hass.config_entries.async_entries("tplink") == []
    assert stub.dhcp_infos == []
    flows = hass.config_entries.flow.async_progress_by_handler("tapo_onboard")
    assert [f["context"]["source"] for f in flows] == ["integration_discovery"]
    assert flows[0]["context"]["unique_id"] == STUB_MAC
    assert flows[0]["context"]["title_placeholders"] == {
        "model": "P110",
        "host": "192.168.1.5",
    }


async def test_same_mac_next_sweep_starts_no_second_flow(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info()]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done(wait_background_tasks=True)
    await coord.async_refresh()
    await hass.async_block_till_done(wait_background_tasks=True)
    assert coord.data.outcomes == {}
    assert len(hass.config_entries.flow.async_progress_by_handler("tapo_onboard")) == 1
    assert hass.config_entries.flow.async_progress_by_handler("tplink") == []


async def test_foreign_owner_ignored_and_counted(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info(owner="other@example.com")]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    assert coord.data.devices == {}
    assert coord.data.outcomes == {}
    assert coord.data.foreign == 1
    assert hass.config_entries.async_entries("tplink") == []


async def test_ignored_and_unsupported_skipped(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info(MAC2), _info(STUB_MAC, model="S310D(US)")]
    coord = _coord(hass, _entry(hass, ignored_macs=[MAC2]))
    await coord.async_refresh()
    assert coord.data.outcomes == {}
    assert hass.config_entries.async_entries("tplink") == []


async def test_lost_entry_at_new_ip_host_updated(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    udp.replies = [_info(ip="192.168.1.9")]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.host_updates == (STUB_MAC,)
    assert tp.data["host"] == "192.168.1.9"


async def test_lost_loaded_entry_foreign_owner_not_updated(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    ent = er.async_get(hass).async_get_or_create(
        "switch", "tplink", "a", config_entry=tp
    )
    hass.states.async_set(ent.entity_id, STATE_UNAVAILABLE)
    udp.replies = [_info(ip="192.168.1.9", owner="other@example.com")]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.host_updates == ()
    assert tp.data["host"] == "192.168.1.1"
    assert stub.dhcp_infos == []


async def test_healthy_entry_not_touched(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    udp.replies = [_info(ip="192.168.1.9")]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.host_updates == ()
    assert tp.data["host"] == "192.168.1.1"
    assert stub.dhcp_infos == []


async def test_networks_union_with_tplink_host(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    _tplink(hass, ConfigEntryState.LOADED, host="10.0.5.7")
    coord = _coord(hass, _entry(hass))
    assert {str(n) for n in coord.sweep_networks()} == {
        "192.168.1.0/24",
        "10.0.5.0/24",
    }


async def test_networks_fall_back_when_union_too_big(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    _tplink(hass, ConfigEntryState.LOADED, host="10.0.5.7")
    entry = _entry(hass, subnets=["172.16.0.0/20"])
    with patch(
        "custom_components.tapo_onboard.sweep.parse_networks",
        side_effect=_reject_unions,
    ):
        coord = _coord(hass, entry)
        assert [str(n) for n in coord.sweep_networks()] == ["172.16.0.0/20"]


def _reject_unions(values: list[str]) -> tuple[Any, ...]:
    from ipaddress import ip_network

    from tapolink_proto.discovery import SweepRangeError

    if len(values) > 1:
        raise SweepRangeError("too_many_hosts")
    return tuple(ip_network(v) for v in values)


async def test_no_networks_no_sweep(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    coord = _coord(hass, _entry(hass, subnets=[]))
    await coord.async_refresh()
    assert coord.last_update_success
    assert udp.calls == []
    assert coord.data.devices == {}


async def _tick(hass: HomeAssistant, seconds: int) -> None:
    onboarding = importlib.import_module("custom_components.tapo_onboard.onboarding")
    await onboarding.async_get_tdp_query(hass)  # warm cached RSA query (executor)
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=seconds))
    await hass.async_block_till_done()


@pytest.fixture
async def started(
    hass: HomeAssistant,
) -> AsyncIterator[Callable[[MockConfigEntry], None]]:
    entries: list[MockConfigEntry] = []

    def _start(entry: MockConfigEntry) -> None:
        _coord(hass, entry).async_start_lost_check()
        entries.append(entry)

    yield _start
    for entry in entries:
        await entry._async_process_on_unload(hass)


async def test_lost_check_updates_host(
    hass: HomeAssistant,
    stub: type[StubTplinkFlow],
    udp: FakeSweep,
    started: Callable[[MockConfigEntry], None],
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    udp.replies = [_info(ip="192.168.1.9")]
    entry = _entry(hass)
    started(entry)
    await _tick(hass, 61)
    assert udp.calls == [("192.168.1.0/24",)]
    assert tp.data["host"] == "192.168.1.9"


async def test_lost_check_same_ip_no_flow(
    hass: HomeAssistant,
    stub: type[StubTplinkFlow],
    udp: FakeSweep,
    started: Callable[[MockConfigEntry], None],
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    udp.replies = [_info(ip="192.168.1.1")]
    started(_entry(hass))
    await _tick(hass, 61)
    assert len(udp.calls) == 1
    assert tp.data["host"] == "192.168.1.1"
    assert stub.dhcp_infos == []


async def test_lost_check_nothing_lost_no_io(
    hass: HomeAssistant,
    stub: type[StubTplinkFlow],
    udp: FakeSweep,
    started: Callable[[MockConfigEntry], None],
) -> None:
    _tplink(hass, ConfigEntryState.LOADED)
    started(_entry(hass))
    await _tick(hass, 61)
    assert udp.calls == []


async def test_lost_check_floor_per_subnet(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    _tplink(hass, ConfigEntryState.SETUP_RETRY)
    coord = _coord(hass, _entry(hass))
    await coord._async_check_lost()
    await coord._async_check_lost()
    assert len(udp.calls) == 1


async def test_lost_check_query_failure_is_isolated(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    _tplink(hass, ConfigEntryState.SETUP_RETRY)
    coord = _coord(hass, _entry(hass))
    with patch(
        "custom_components.tapo_onboard.sweep.async_get_tdp_query",
        side_effect=OSError,
    ):
        await coord._async_check_lost()
    assert udp.calls == []


async def test_lost_check_foreign_owner_ignored(
    hass: HomeAssistant,
    stub: type[StubTplinkFlow],
    udp: FakeSweep,
    started: Callable[[MockConfigEntry], None],
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    udp.replies = [_info(ip="192.168.1.9", owner="other@example.com")]
    started(_entry(hass))
    await _tick(hass, 61)
    assert len(udp.calls) == 1
    assert tp.data["host"] == "192.168.1.1"
    assert stub.dhcp_infos == []


async def test_lost_check_stops_on_unload(
    hass: HomeAssistant,
    stub: type[StubTplinkFlow],
    udp: FakeSweep,
    started: Callable[[MockConfigEntry], None],
) -> None:
    _tplink(hass, ConfigEntryState.SETUP_RETRY)
    entry = _entry(hass)
    started(entry)
    await _tick(hass, 61)
    assert len(udp.calls) == 1
    await entry._async_process_on_unload(hass)
    await _tick(hass, 200)
    assert len(udp.calls) == 1


def _tpap_info(
    mac: str = STUB_MAC,
    ip: str = "192.168.1.5",
    owner: str = USER,
    scheme: dict[str, object] | None = None,
    tpap: dict[str, object] | None = None,
) -> TdpInfo:
    result: dict[str, object] = {
        "device_id": _md5(f"id-{mac}"),
        "mac": mac,
        "owner": _md5(owner),
        "ip": ip,
        "device_model": "P110(US)",
        "mgt_encrypt_schm": scheme or {"encrypt_type": "TPAP"},
    }
    if tpap is not None:
        result["tpap"] = tpap
    info = TdpInfo.from_result(result)
    assert info is not None
    return info


def _issue(hass: HomeAssistant, entry: MockConfigEntry) -> Any:
    return ir.async_get(hass).async_get_issue(
        "tapo_onboard", f"tpap_firmware_detected_{entry.entry_id}"
    )


async def test_tpap_issue_created_then_deleted(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_tpap_info()]
    entry = _entry(hass)
    coord = _coord(hass, entry)
    await coord.async_refresh()
    issue = _issue(hass, entry)
    assert issue is not None
    assert not issue.is_fixable
    devices = issue.translation_placeholders["devices"]
    assert "P110" in devices
    assert "192.168.1.5" in devices
    assert STUB_MAC not in devices
    assert coord.data.tpap == (STUB_MAC,)
    udp.replies = [_info()]
    await coord.async_refresh()
    assert _issue(hass, entry) is None
    assert coord.data.tpap == ()


async def test_tpap_block_with_klap_scheme_counts(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_tpap_info(scheme={"encrypt_type": "KLAP"}, tpap={"port": 443})]
    entry = _entry(hass)
    await _coord(hass, entry).async_refresh()
    assert _issue(hass, entry) is not None


async def test_tpap_foreign_device_no_issue(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_tpap_info(owner="other@example.com")]
    entry = _entry(hass)
    await _coord(hass, entry).async_refresh()
    assert _issue(hass, entry) is None


async def test_tpap_issue_deleted_on_unload(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_tpap_info()]
    entry = _entry(hass)
    await _coord(hass, entry).async_refresh()
    assert _issue(hass, entry) is not None
    await entry._async_process_on_unload(hass)
    assert _issue(hass, entry) is None


def _unavailable_entity(
    hass: HomeAssistant, tp: MockConfigEntry, uid: str, state: str | None
) -> None:
    ent = er.async_get(hass).async_get_or_create(
        "switch", "tplink", uid, config_entry=tp
    )
    if state is not None:
        hass.states.async_set(ent.entity_id, state)


async def test_not_loaded_entry_is_not_lost(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    tp = _tplink(hass, ConfigEntryState.NOT_LOADED)
    udp.replies = [_info(ip="192.168.1.9")]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.host_updates == ()
    assert tp.data["host"] == "192.168.1.1"


async def test_loaded_entry_all_entities_unavailable_is_lost(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    _unavailable_entity(hass, tp, "a", STATE_UNAVAILABLE)
    _unavailable_entity(hass, tp, "b", STATE_UNAVAILABLE)
    udp.replies = [_info(ip="192.168.1.9")]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.host_updates == (STUB_MAC,)
    assert tp.data["host"] == "192.168.1.9"


@pytest.mark.parametrize("other_state", ["on", None])
async def test_loaded_entry_with_a_live_or_stateless_entity_is_not_lost(
    hass: HomeAssistant,
    stub: type[StubTplinkFlow],
    udp: FakeSweep,
    other_state: str | None,
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    _unavailable_entity(hass, tp, "a", STATE_UNAVAILABLE)
    _unavailable_entity(hass, tp, "b", other_state)
    udp.replies = [_info(ip="192.168.1.9")]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.host_updates == ()
    assert tp.data["host"] == "192.168.1.1"


async def test_networks_skip_tplink_entries_without_usable_host(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    MockConfigEntry(
        domain="tplink", unique_id="aa:bb:cc:00:00:01", data={}
    ).add_to_hass(hass)
    MockConfigEntry(
        domain="tplink", unique_id="aa:bb:cc:00:00:02", data={"host": "not-an-ip"}
    ).add_to_hass(hass)
    coord = _coord(hass, _entry(hass))
    assert [str(n) for n in coord.sweep_networks()] == ["192.168.1.0/24"]


async def test_networks_union_too_big_uses_stored_subnets(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    _tplink(hass, ConfigEntryState.LOADED, host="10.0.5.7")
    coord = _coord(hass, _entry(hass, subnets=["172.16.0.0/16", "172.17.0.0/16"]))
    # Stored alone is already too big -> nothing to sweep.
    assert coord.sweep_networks() == ()
    coord = _coord(hass, _entry(hass, subnets=["172.16.0.0/20"]))
    assert [str(n) for n in coord.sweep_networks()] == ["172.16.0.0/20"]


async def test_invalid_stored_subnets_mean_no_sweep(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    coord = _coord(hass, _entry(hass, subnets=["8.8.8.0/24"]))
    assert coord.sweep_networks() == ()
    await coord.async_refresh()
    assert coord.last_update_success
    assert udp.calls == []


async def test_lost_check_skips_entries_without_id_host_or_valid_ip(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    MockConfigEntry(
        domain="tplink",
        data={"host": "192.168.1.1"},
        state=ConfigEntryState.SETUP_RETRY,
    ).add_to_hass(hass)
    MockConfigEntry(
        domain="tplink",
        unique_id="aa:bb:cc:00:00:01",
        data={},
        state=ConfigEntryState.SETUP_RETRY,
    ).add_to_hass(hass)
    MockConfigEntry(
        domain="tplink",
        unique_id="aa:bb:cc:00:00:02",
        data={"host": "not-an-ip"},
        state=ConfigEntryState.SETUP_RETRY,
    ).add_to_hass(hass)
    coord = _coord(hass, _entry(hass))
    await coord._async_check_lost()
    assert udp.calls == []


async def test_lost_check_sweep_failure_is_isolated_per_subnet(
    hass: HomeAssistant, stub: type[StubTplinkFlow]
) -> None:
    first = _tplink(hass, ConfigEntryState.SETUP_RETRY, host="192.168.1.1")
    second = MockConfigEntry(
        domain="tplink",
        unique_id=format_mac(MAC2),
        data={"host": "10.0.5.7"},
        state=ConfigEntryState.SETUP_RETRY,
    )
    second.add_to_hass(hass)
    seen: list[str] = []

    async def _sweep(networks: Any, *, query: bytes, **_: object) -> list[TdpInfo]:
        net = str(next(iter(networks)))
        seen.append(net)
        if net == "192.168.1.0/24":
            raise OSError("socket")
        return [_info(MAC2, ip="10.0.5.9")]

    async def _probe(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return _info(MAC2, host)

    with (
        patch("custom_components.tapo_onboard.sweep.async_sweep", _sweep),
        patch("custom_components.tapo_onboard.onboarding.async_probe", _probe),
    ):
        coord = _coord(hass, _entry(hass))
        await coord._async_check_lost()
        await hass.async_block_till_done()
    assert seen == ["192.168.1.0/24", "10.0.5.0/24"]
    assert first.data["host"] == "192.168.1.1"
    assert second.data["host"] == "10.0.5.9"
