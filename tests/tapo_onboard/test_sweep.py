# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-08_concept-v4.md)
"""Tests for the local sweep coordinator (UDP layer faked, stub tplink)."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_DHCP, ConfigEntryState
from homeassistant.const import STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import format_mac
from pytest_homeassistant_custom_component.common import MockConfigEntry
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


def _coord(
    hass: HomeAssistant, entry: MockConfigEntry, password: str | None = None
) -> SweepCoordinator:
    mod = importlib.import_module("custom_components.tapo_onboard.sweep")
    return cast(
        "SweepCoordinator",
        mod.SweepCoordinator(hass, entry, password=lambda: password, username=USER),
    )


async def test_new_device_with_password_added(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info()]
    coord = _coord(hass, _entry(hass), "secret")
    await coord.async_refresh()
    assert coord.data.outcomes[STUB_MAC].value == "added"
    assert len(hass.config_entries.async_entries("tplink")) == 1


async def test_new_device_without_password_dhcp_card(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info()]
    coord = _coord(hass, _entry(hass))
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.outcomes[STUB_MAC].value == "handed_to_user"
    flows = hass.config_entries.flow.async_progress_by_handler("tplink")
    assert [f["context"]["source"] for f in flows] == [SOURCE_DHCP]


async def test_foreign_owner_ignored_and_counted(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info(owner="other@example.com")]
    coord = _coord(hass, _entry(hass), "secret")
    await coord.async_refresh()
    assert coord.data.devices == {}
    assert coord.data.outcomes == {}
    assert coord.data.foreign == 1
    assert hass.config_entries.async_entries("tplink") == []


async def test_ignored_and_unsupported_skipped(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info(MAC2), _info(STUB_MAC, model="S310D(US)")]
    coord = _coord(hass, _entry(hass, ignored_macs=[MAC2]), "secret")
    await coord.async_refresh()
    assert coord.data.outcomes == {}
    assert hass.config_entries.async_entries("tplink") == []


async def test_attempted_not_retried(
    hass: HomeAssistant, stub: type[StubTplinkFlow], udp: FakeSweep
) -> None:
    udp.replies = [_info()]
    coord = _coord(hass, _entry(hass), "secret")
    await coord.async_refresh()
    assert coord.data.outcomes[STUB_MAC].value == "added"
    await coord.async_refresh()
    assert coord.data.outcomes == {}
    assert len(hass.config_entries.async_entries("tplink")) == 1


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
