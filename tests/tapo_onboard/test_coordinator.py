# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the inventory coordinator (fake cloud client, stub tplink)."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Iterator
from contextlib import AbstractContextManager
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_DHCP, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import format_mac
from pytest_homeassistant_custom_component.common import MockConfigEntry
from stub_tplink import STUB_MAC, StubTplinkFlow, stub_tplink
from tapolink_proto.cloud import (
    AppVersionTooOld,
    CloudAuthError,
    CloudDevice,
    CloudRateLimited,
    CloudResponseError,
    CloudSession,
    DeviceDetails,
    DeviceOffline,
    RefreshTokenUnusable,
    TokenExpired,
)
from tapolink_proto.discovery import TdpInfo

if TYPE_CHECKING:
    from custom_components.tapo_onboard.coordinator import InventoryCoordinator

MAC2 = "11:22:33:44:55:66"
MAC3 = "11:22:33:44:55:77"


def _device(mac: str, model_base: str = "P110") -> CloudDevice:
    return CloudDevice(
        device_id=f"id-{mac}",
        mac=mac,
        alias="x",
        model=model_base,
        model_base=model_base,
        device_type="SMART.TAPOPLUG",
        hw_ver="1",
        fw_ver="1",
        region=None,
        role=None,
    )


class FakeCloudClient:
    """Scripted CloudClient (public-method boundary only)."""

    def __init__(self, devices: list[CloudDevice], ips: dict[str, str | None]) -> None:
        self.devices = devices
        self.ips = ips
        self.list_errors: list[Exception] = []
        self.refreshed = CloudSession("new-token", "new-refresh", 7)
        self.list_calls = 0
        self.tokens_seen: list[str] = []
        self.details_calls: list[str] = []
        self.refresh_calls = 0
        self.details_errors: dict[str, Exception] = {}
        self.refresh_error: Exception | None = None

    async def list_devices(self, session: CloudSession) -> list[CloudDevice]:
        self.list_calls += 1
        self.tokens_seen.append(session.token)
        if self.list_errors:
            raise self.list_errors.pop(0)
        return self.devices

    async def device_details(
        self, session: CloudSession, device: CloudDevice
    ) -> DeviceDetails:
        self.details_calls.append(device.mac)
        if device.mac in self.details_errors:
            raise self.details_errors[device.mac]
        return DeviceDetails(ip=self.ips.get(device.mac), ssid=None, fw_ver=None)

    async def refresh(self, session: CloudSession) -> CloudSession:
        self.refresh_calls += 1
        if self.refresh_error is not None:
            raise self.refresh_error
        return self.refreshed


def _tdp(cloud_id: str, mac: str = STUB_MAC) -> TdpInfo:
    info = TdpInfo.from_result(
        {"device_id": hashlib.md5(cloud_id.encode()).hexdigest().upper(), "mac": mac}  # noqa: S324
    )
    assert info is not None
    return info


@pytest.fixture(autouse=True)
def probe() -> Iterator[None]:
    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return _tdp(f"id-{STUB_MAC}")

    with patch("custom_components.tapo_onboard.onboarding.async_probe", _fake):
        yield


@pytest.fixture
def stub(hass: HomeAssistant) -> Iterator[type[StubTplinkFlow]]:
    with stub_tplink(hass) as flow:
        yield flow


@pytest.fixture
def mod() -> ModuleType:
    return importlib.import_module("custom_components.tapo_onboard.coordinator")


def _entry(hass: HomeAssistant, **extra: object) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain="tapo_onboard",
        data={"token": "tok", "refresh_token": "ref", "account_id": 1, **extra},
    )
    entry.add_to_hass(hass)
    return entry


def _tplink(
    hass: HomeAssistant, state: ConfigEntryState, host: str = "10.0.0.1"
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
    mod: ModuleType,
    hass: HomeAssistant,
    entry: MockConfigEntry,
    client: FakeCloudClient,
    password: str | None = None,
) -> InventoryCoordinator:
    return cast(
        "InventoryCoordinator",
        mod.InventoryCoordinator(
            hass, entry, client, password=lambda: password, username="u@example.com"
        ),
    )


async def test_healthy_entry_no_details(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    _tplink(hass, ConfigEntryState.LOADED)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert coord.last_update_success
    assert client.list_calls == 1
    assert client.details_calls == []


async def test_setup_retry_ip_repair(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert client.details_calls == [STUB_MAC]
    assert coord.data.host_updates == (STUB_MAC,)
    assert tp.data["host"] == "10.0.0.9"


async def test_setup_error_same_ip_no_update(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    _tplink(hass, ConfigEntryState.SETUP_ERROR, host="10.0.0.9")
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert client.details_calls == [STUB_MAC]
    assert coord.data.host_updates == ()


async def test_new_device_with_password_added(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    await coord.async_refresh()
    assert coord.data.outcomes[STUB_MAC].value == "added"
    assert len(hass.config_entries.async_entries("tplink")) == 1


async def test_new_device_without_password_dhcp_card(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.data.outcomes[STUB_MAC].value == "handed_to_user"
    flows = hass.config_entries.flow.async_progress_by_handler("tplink")
    assert [f["context"]["source"] for f in flows] == [SOURCE_DHCP]


async def test_ignored_and_unsupported_no_details(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient(
        [_device(MAC2), _device(MAC3, "S310D")], {MAC2: "10.0.0.2", MAC3: "10.0.0.3"}
    )
    entry = _entry(hass, ignored_macs=[MAC2])
    coord = _coord(mod, hass, entry, client, password="secret")
    await coord.async_refresh()
    assert client.details_calls == []
    assert coord.data.outcomes == {}


async def test_attempted_not_retried(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(MAC2)], {MAC2: "192.168.1.60"})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    with _probe_returns(_tdp(f"id-{MAC2}", mac=MAC2)):
        await coord.async_refresh()
        await coord.async_refresh()
    assert client.list_calls == 2
    assert client.details_calls == [MAC2]


async def test_no_ip_device_retried(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(MAC2)], {MAC2: None})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    await coord.async_refresh()
    await coord.async_refresh()
    assert client.details_calls == [MAC2, MAC2]


async def test_token_refresh_persisted(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [TokenExpired(-20651)]
    entry = _entry(hass)
    coord = _coord(mod, hass, entry, client)
    await coord.async_refresh()
    assert coord.last_update_success
    assert client.refresh_calls == 1
    assert client.list_calls == 2
    assert entry.data["token"] == "new-token"
    assert entry.data["refresh_token"] == "new-refresh"


async def test_auth_error_starts_reauth_once(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [CloudAuthError(-20601), CloudAuthError(-20601)]
    entry = _entry(hass)
    coord = _coord(mod, hass, entry, client)
    with patch("homeassistant.config_entries.ConfigEntry.async_start_reauth") as reauth:
        await coord.async_refresh()
        await coord.async_refresh()
    assert not coord.last_update_success
    reauth.assert_called_once()


async def test_second_token_expired_starts_reauth(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [TokenExpired(-20651), TokenExpired(-20651)]
    coord = _coord(mod, hass, _entry(hass), client)
    with patch("homeassistant.config_entries.ConfigEntry.async_start_reauth") as reauth:
        await coord.async_refresh()
    assert not coord.last_update_success
    reauth.assert_called_once()


async def test_rate_limited_retry_after(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [CloudRateLimited(-20004, retry_after=1800)]
    coord: Any = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert not coord.last_update_success
    assert coord.last_exception.retry_after == 1800
    assert coord.last_exception.translation_key == "rate_limited"


async def test_reauth_result_picked_up_and_flag_reset(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [CloudAuthError(-20601)]
    entry = _entry(hass)
    coord = _coord(mod, hass, entry, client)
    with patch("homeassistant.config_entries.ConfigEntry.async_start_reauth") as reauth:
        await coord.async_refresh()
        assert reauth.call_count == 1
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, "token": "fresh"}
        )
        await coord.async_refresh()
        assert coord.last_update_success
        assert client.tokens_seen[-1] == "fresh"
        # Flag was reset: a later auth loss starts reauth again.
        client.list_errors = [CloudAuthError(-20601)]
        await coord.async_refresh()
        assert not coord.last_update_success
        assert reauth.call_count == 2


def _probe_returns(info: TdpInfo | None) -> AbstractContextManager[object]:
    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return info

    return patch("custom_components.tapo_onboard.onboarding.async_probe", _fake)


async def test_ip_repair_verified_updates_host(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    with _probe_returns(_tdp(f"id-{STUB_MAC}")):
        state = await _coord(mod, hass, _entry(hass), client)._async_update_data()
    await hass.async_block_till_done()
    assert state.host_updates == (STUB_MAC,)
    assert tp.data["host"] == "10.0.0.9"


@pytest.mark.parametrize("info", [_tdp("other-device"), None])
async def test_ip_repair_unverified_skipped(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    info: TdpInfo | None,
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    with _probe_returns(info):
        state = await _coord(mod, hass, _entry(hass), client)._async_update_data()
    await hass.async_block_till_done()
    assert state.host_updates == ()
    assert tp.data["host"] == "10.0.0.1"
    assert stub.dhcp_infos == []


async def test_new_device_no_password_mismatch_no_card(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    with _probe_returns(_tdp("other-device")):
        state = await _coord(mod, hass, _entry(hass), client)._async_update_data()
    await hass.async_block_till_done()
    assert state.outcomes[STUB_MAC] == "identity_mismatch"
    assert stub.dhcp_infos == []


async def test_new_device_no_password_no_reply_no_flow_retried(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client)
    with _probe_returns(None):
        state = await coord._async_update_data()
        await hass.async_block_till_done()
        assert STUB_MAC not in state.outcomes
        assert stub.dhcp_infos == []
        assert hass.config_entries.flow.async_progress_by_handler("tplink") == []
        await coord._async_update_data()
    assert client.details_calls == [STUB_MAC, STUB_MAC]
    assert stub.dhcp_infos == []
    state = await coord._async_update_data()
    await hass.async_block_till_done()
    assert state.outcomes[STUB_MAC] == "handed_to_user"
    assert len(stub.dhcp_infos) == 1


async def test_refresh_unusable_starts_reauth(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [TokenExpired(-20651)]
    client.refresh_error = RefreshTokenUnusable("no refresh token")
    coord: Any = _coord(mod, hass, _entry(hass), client)
    with patch("homeassistant.config_entries.ConfigEntry.async_start_reauth") as reauth:
        await coord.async_refresh()
    assert not coord.last_update_success
    assert coord.last_exception.translation_key == "cloud_auth"
    reauth.assert_called_once()


async def test_device_offline_isolated(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient(
        [_device(MAC2), _device(STUB_MAC)], {MAC2: "10.0.0.2", STUB_MAC: "10.0.0.5"}
    )
    client.details_errors = {MAC2: DeviceOffline(-20002)}
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    await coord.async_refresh()
    assert coord.last_update_success
    assert client.details_calls == [MAC2, STUB_MAC]
    assert coord.data.outcomes[STUB_MAC].value == "added"
    assert MAC2 not in coord.data.outcomes


async def test_list_app_version_too_old_no_raw_exception(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [AppVersionTooOld(-1)]
    coord: Any = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert not coord.last_update_success
    assert coord.last_exception.translation_key == "cloud_unavailable"


async def test_cannot_connect_retried_then_added_not(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    stub.connect_result = "cannot_connect"
    await coord.async_refresh()
    assert coord.data.outcomes[STUB_MAC].value == "cannot_connect"
    stub.connect_result = "ok"
    await coord.async_refresh()
    assert client.details_calls == [STUB_MAC, STUB_MAC]
    assert coord.data.outcomes[STUB_MAC].value == "added"
    await coord.async_refresh()
    assert STUB_MAC not in coord.data.outcomes
    assert len(hass.config_entries.async_entries("tplink")) == 1


async def test_details_rate_limited_stops_cycle(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([_device(MAC2)], {MAC2: "10.0.0.2"})
    client.details_errors = {MAC2: CloudRateLimited(-20004, retry_after=60)}
    coord: Any = _coord(mod, hass, _entry(hass), client, password="secret")
    await coord.async_refresh()
    assert not coord.last_update_success
    assert coord.last_exception.retry_after == 60
    assert coord.last_exception.translation_key == "rate_limited"


async def test_refresh_transient_failure_no_reauth(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [TokenExpired(-20651)]
    client.refresh_error = CloudResponseError("HTTP 503 from gateway")
    coord: Any = _coord(mod, hass, _entry(hass), client)
    with patch("homeassistant.config_entries.ConfigEntry.async_start_reauth") as reauth:
        await coord.async_refresh()
    assert not coord.last_update_success
    assert coord.last_exception.translation_key == "cloud_unavailable"
    reauth.assert_not_called()


async def test_onboard_exception_isolated(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient(
        [_device(MAC2), _device(STUB_MAC)], {MAC2: "10.0.0.2", STUB_MAC: "10.0.0.5"}
    )

    async def _probe(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        if host == "10.0.0.2":
            raise RuntimeError("boom")
        return _tdp(f"id-{STUB_MAC}")

    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    with patch("custom_components.tapo_onboard.onboarding.async_probe", _probe):
        await coord.async_refresh()
    assert coord.last_update_success
    assert coord.data.outcomes[MAC2].value == "cannot_connect"
    assert coord.data.outcomes[STUB_MAC].value == "added"
    assert len(hass.config_entries.async_entries("tplink")) == 1
