# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the inventory coordinator (fake cloud client, stub tplink)."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Iterator
from contextlib import AbstractContextManager
from datetime import timedelta
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.config_entries import SOURCE_DHCP, ConfigEntryState
from homeassistant.const import STATE_ON, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import format_mac
from homeassistant.util import dt as dt_util
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


def _entity(
    hass: HomeAssistant,
    tp: MockConfigEntry,
    key: str,
    state: str | None,
    *,
    disabled: bool = False,
) -> None:
    ent = er.async_get(hass).async_get_or_create(
        "switch",
        "tplink",
        key,
        config_entry=tp,
        disabled_by=er.RegistryEntryDisabler.USER if disabled else None,
    )
    if state is not None:
        hass.states.async_set(ent.entity_id, state)


async def test_loaded_entry_all_unavailable_repaired(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    _entity(hass, tp, "a", STATE_UNAVAILABLE)
    _entity(hass, tp, "b", STATE_UNAVAILABLE)
    _entity(hass, tp, "c", None, disabled=True)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert client.details_calls == [STUB_MAC]
    assert coord.data.host_updates == (STUB_MAC,)
    assert [i.ip for i in stub.dhcp_infos] == ["10.0.0.9"]
    assert tp.data["host"] == "10.0.0.9"


@pytest.mark.parametrize(
    "states",
    [
        [STATE_UNAVAILABLE, STATE_ON],
        [STATE_UNAVAILABLE, None],
    ],
    ids=["one-available", "one-not-yet-added"],
)
async def test_loaded_entry_partly_available_not_lost(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    states: list[str | None],
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    for i, state in enumerate(states):
        _entity(hass, tp, str(i), state)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert client.details_calls == []
    assert tp.data["host"] == "10.0.0.1"


async def test_loaded_entry_only_disabled_entities_not_lost(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    _entity(hass, tp, "a", STATE_UNAVAILABLE, disabled=True)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert client.details_calls == []


@pytest.mark.parametrize(
    "state", [ConfigEntryState.NOT_LOADED, ConfigEntryState.SETUP_IN_PROGRESS]
)
async def test_other_states_not_lost(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    state: ConfigEntryState,
) -> None:
    tp = _tplink(hass, state)
    _entity(hass, tp, "a", STATE_UNAVAILABLE)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    await coord.async_refresh()
    assert client.details_calls == []


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
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    freezer: FrozenDateTimeFactory,
) -> None:
    client = FakeCloudClient([_device(MAC2)], {MAC2: None})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    await coord.async_refresh()
    freezer.tick(timedelta(minutes=31))
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


@pytest.mark.parametrize("info", [_tdp("other-device"), None])
async def test_loaded_lost_unverified_skipped(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    info: TdpInfo | None,
) -> None:
    tp = _tplink(hass, ConfigEntryState.LOADED)
    _entity(hass, tp, "a", STATE_UNAVAILABLE)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    with _probe_returns(info):
        state = await _coord(mod, hass, _entry(hass), client)._async_update_data()
    await hass.async_block_till_done()
    assert client.details_calls == [STUB_MAC]
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
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    freezer: FrozenDateTimeFactory,
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client)
    with _probe_returns(None):
        state = await coord._async_update_data()
        await hass.async_block_till_done()
        assert STUB_MAC not in state.outcomes
        assert stub.dhcp_infos == []
        assert hass.config_entries.flow.async_progress_by_handler("tplink") == []
        freezer.tick(timedelta(minutes=31))
        await coord._async_update_data()
    assert client.details_calls == [STUB_MAC, STUB_MAC]
    assert stub.dhcp_infos == []
    freezer.tick(timedelta(minutes=31))
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
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    freezer: FrozenDateTimeFactory,
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    stub.connect_result = "cannot_connect"
    await coord.async_refresh()
    assert coord.data.outcomes[STUB_MAC].value == "cannot_connect"
    stub.connect_result = "ok"
    freezer.tick(timedelta(minutes=31))
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


def _count_logins(
    stub: type[StubTplinkFlow], monkeypatch: pytest.MonkeyPatch
) -> list[str]:
    """Record the host of each credential submission reaching the stub flow.

    Installed with monkeypatch so the shared stub class is restored afterwards.
    """
    submitted: list[str] = []
    original = stub.async_step_user_auth_confirm

    async def _spy(
        self: StubTplinkFlow, user_input: dict[str, Any] | None = None
    ) -> Any:
        if user_input is not None:
            submitted.append(self._host)
        return await original(self, user_input)

    monkeypatch.setattr(stub, "async_step_user_auth_confirm", _spy)
    return submitted


async def test_terminal_outcomes_not_retried_after_floor(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    freezer: FrozenDateTimeFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminal outcomes stay attempted after the 15-min details floor lapses."""
    stub.connect_result = "auth"
    stub.valid_password = "other"
    logins = _count_logins(stub, monkeypatch)

    # Part 1: password path, AUTH_FAILED on refresh 1 is never retried.
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client, password="secret")
    await coord.async_refresh()
    assert coord.data.outcomes[STUB_MAC].value == "auth_failed"
    assert client.details_calls == [STUB_MAC]
    assert logins == ["10.0.0.5"]
    freezer.tick(timedelta(minutes=31))
    await coord.async_refresh()
    assert client.details_calls == [STUB_MAC]
    assert len(logins) == 1
    assert STUB_MAC not in coord.data.outcomes

    # Part 2: flow hand-off, terminal MAC skipped, CANNOT_CONNECT MAC retried.
    logins.clear()
    client2 = FakeCloudClient(
        [_device(STUB_MAC), _device(MAC2)],
        {STUB_MAC: "10.0.0.5", MAC2: "10.0.0.6"},
    )
    now = dt_util.utcnow()
    flow_result = mod.FlowResult(
        outcomes={
            STUB_MAC: mod.OnboardOutcome.AUTH_FAILED,
            MAC2: mod.OnboardOutcome.CANNOT_CONNECT,
        },
        details_at={STUB_MAC: now, MAC2: now},
    )
    coord2 = mod.InventoryCoordinator(
        hass,
        _entry(hass),
        client2,
        password=lambda: "secret",
        username="u@example.com",
        flow_result=flow_result,
    )
    freezer.tick(timedelta(minutes=31))
    await coord2.async_refresh()
    assert client2.details_calls == [MAC2]
    assert MAC2 in coord2.data.outcomes  # retried: an outcome was produced
    assert STUB_MAC not in coord2.data.outcomes
    assert "10.0.0.5" not in logins  # STUB_MAC's host: never logged in again


async def _cycles(
    coord: InventoryCoordinator,
    client: FakeCloudClient,
    freezer: FrozenDateTimeFactory,
    count: int,
) -> list[int]:
    """Run `count` 31-minute cycles; return the cycles that called details."""
    called: list[int] = []
    for cycle in range(count):
        before = len(client.details_calls)
        await coord._async_update_data()
        if len(client.details_calls) > before:
            called.append(cycle)
        freezer.tick(timedelta(minutes=31))
    return called


async def test_unreachable_new_device_backs_off(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    freezer: FrozenDateTimeFactory,
) -> None:
    """Gaps after failures: 15, 30, 60, 120 min, then capped at 120 min."""
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    coord = _coord(mod, hass, _entry(hass), client)
    with _probe_returns(None):
        called = await _cycles(coord, client, freezer, 13)
    # Calls at t=0, 31, 62, 124, 248, 372 min (cycle = t / 31).
    assert called == [0, 1, 2, 4, 8, 12]
    assert stub.dhcp_infos == []


async def test_offline_device_without_ip_backs_off(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    freezer: FrozenDateTimeFactory,
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: None})
    coord = _coord(mod, hass, _entry(hass), client)
    assert await _cycles(coord, client, freezer, 5) == [0, 1, 2, 4]


async def test_lost_entry_backoff_resets_when_entry_recovers(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    freezer: FrozenDateTimeFactory,
) -> None:
    """A lost entry still at the cloud's address backs off; recovery resets it."""
    tp = _tplink(hass, ConfigEntryState.LOADED, host="10.0.0.9")
    _entity(hass, tp, "a", STATE_UNAVAILABLE)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})
    coord = _coord(mod, hass, _entry(hass), client)
    assert await _cycles(coord, client, freezer, 3) == [0, 1, 2]
    entity_id = er.async_get(hass).async_get_entity_id("switch", "tplink", "a")
    assert entity_id is not None
    hass.states.async_set(entity_id, STATE_ON)  # recovered at cycle 3
    await coord._async_update_data()
    freezer.tick(timedelta(minutes=31))
    hass.states.async_set(entity_id, STATE_UNAVAILABLE)  # lost again
    # Without the reset, the 4th failure at cycle 4 would wait 120 min.
    assert await _cycles(coord, client, freezer, 2) == [0, 1]
    assert client.details_calls == [STUB_MAC] * 5


async def test_lost_entry_probe_error_does_not_fail_cycle(
    hass: HomeAssistant, mod: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    tp = _tplink(hass, ConfigEntryState.SETUP_RETRY)
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.9"})

    async def _boom(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        raise RuntimeError("socket exploded")

    coord = _coord(mod, hass, _entry(hass), client)
    with patch("custom_components.tapo_onboard.onboarding.async_probe", _boom):
        await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.last_update_success
    assert coord.data.host_updates == ()
    assert stub.dhcp_infos == []
    assert tp.data["host"] == "10.0.0.1"


@pytest.mark.parametrize(
    ("age", "lists"), [(timedelta(minutes=2), 0), (timedelta(minutes=31), 1)]
)
async def test_first_cycle_reuses_fresh_flow_list(
    hass: HomeAssistant,
    mod: ModuleType,
    stub: type[StubTplinkFlow],
    age: timedelta,
    lists: int,
) -> None:
    client = FakeCloudClient([_device(STUB_MAC)], {STUB_MAC: "10.0.0.5"})
    flow_result = mod.FlowResult(
        outcomes={STUB_MAC: mod.OnboardOutcome.ADDED},
        devices=(_device(STUB_MAC), _device(MAC2)),
        listed_at=dt_util.utcnow() - age,
    )
    coord = mod.InventoryCoordinator(
        hass,
        _entry(hass),
        client,
        password=lambda: None,
        username="u@example.com",
        flow_result=flow_result,
    )
    await coord.async_refresh()
    assert coord.last_update_success
    assert client.list_calls == lists
    expected = {STUB_MAC, MAC2} if lists == 0 else {STUB_MAC}
    assert set(coord.data.devices) == expected
    await coord.async_refresh()
    assert client.list_calls == lists + 1
