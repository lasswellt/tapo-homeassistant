# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the inventory coordinator (fake cloud client, stub tplink)."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from types import ModuleType
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_DHCP, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import format_mac
from pytest_homeassistant_custom_component.common import MockConfigEntry
from stub_tplink import STUB_MAC, StubTplinkFlow, stub_tplink
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudDevice,
    CloudRateLimited,
    CloudSession,
    DeviceDetails,
    TokenExpired,
)

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
        self.details_calls: list[str] = []
        self.refresh_calls = 0

    async def list_devices(self, session: CloudSession) -> list[CloudDevice]:
        self.list_calls += 1
        if self.list_errors:
            raise self.list_errors.pop(0)
        return self.devices

    async def device_details(
        self, session: CloudSession, device: CloudDevice
    ) -> DeviceDetails:
        self.details_calls.append(device.mac)
        return DeviceDetails(ip=self.ips.get(device.mac), ssid=None, fw_ver=None)

    async def refresh(self, session: CloudSession) -> CloudSession:
        self.refresh_calls += 1
        return self.refreshed


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
) -> object:
    return mod.InventoryCoordinator(
        hass, entry, client, password=lambda: password, username="u@example.com"
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
    client = FakeCloudClient([_device(MAC2)], {MAC2: None})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    await coord.async_refresh()
    await coord.async_refresh()
    assert client.list_calls == 2
    assert client.details_calls == [MAC2]


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
    with patch(
        "homeassistant.config_entries.ConfigEntry.async_start_reauth"
    ) as reauth:
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
    with patch(
        "homeassistant.config_entries.ConfigEntry.async_start_reauth"
    ) as reauth:
        await coord.async_refresh()
    assert not coord.last_update_success
    reauth.assert_called_once()


async def test_rate_limited_retry_after(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    client = FakeCloudClient([], {})
    client.list_errors = [CloudRateLimited(-20004, retry_after=1800)]
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert not coord.last_update_success
    assert coord.last_exception.retry_after == 1800
    assert coord.last_exception.translation_key == "rate_limited"
