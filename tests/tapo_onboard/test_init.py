# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for integration setup, unload and diagnostics."""

from __future__ import annotations

import hashlib
import importlib
import json
import ssl
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import Mock, patch

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockModule,
    async_fire_time_changed,
    mock_integration,
)
from stub_tplink import STUB_MAC, StubTplinkFlow, stub_tplink
from tapolink_proto.cloud import (
    CloudDevice,
    CloudSession,
    CloudUnavailable,
    DeviceDetails,
)
from tapolink_proto.discovery import TdpInfo

DOMAIN = "tapo_onboard"
DATA_PENDING_PASSWORD = "pending_password"
EMAIL = "user@example.com"
TOKEN = "tok-secret"
REFRESH = "ref-secret"
TERMINAL = "term-uuid-secret"
IP = "10.9.8.7"
ALIAS = "Secret Lamp"
DEVICE_ID = "dev-id-secret"


class FakeCloudClient:
    """Scripted CloudClient (public-method boundary only)."""

    fail = False
    calls = 0

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def list_devices(self, session: CloudSession) -> list[CloudDevice]:
        type(self).calls += 1
        if type(self).fail:
            raise CloudUnavailable("down")
        return [
            CloudDevice(
                device_id=DEVICE_ID,
                mac="11:22:33:44:55:66",
                alias=ALIAS,
                model="P110(EU)",
                model_base="P110",
                device_type="SMART.TAPOPLUG",
                hw_ver="1",
                fw_ver="1",
                region=None,
                role=None,
            )
        ]

    async def device_details(
        self, session: CloudSession, device: CloudDevice
    ) -> DeviceDetails:
        return DeviceDetails(ip=IP, ssid=None, fw_ver=None)


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: MockConfigEntry
) -> dict[str, Any]:
    mod = importlib.import_module("custom_components.tapo_onboard.diagnostics")
    diag: dict[str, Any] = await mod.async_get_config_entry_diagnostics(hass, entry)
    return diag


@pytest.fixture(autouse=True)
def probe() -> Iterator[None]:
    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return TdpInfo.from_result(
            {
                "device_id": hashlib.md5(DEVICE_ID.encode()).hexdigest().upper(),
                "mac": STUB_MAC,
            }  # noqa: S324
        )

    with patch("custom_components.tapo_onboard.onboarding.async_probe", _fake):
        yield


@pytest.fixture(autouse=True)
def stub(hass: HomeAssistant) -> Iterator[type[StubTplinkFlow]]:
    FakeCloudClient.fail = False
    FakeCloudClient.calls = 0
    mock_integration(hass, MockModule("dhcp"))
    with (
        stub_tplink(hass) as flow,
        patch("custom_components.tapo_onboard.CloudClient", FakeCloudClient),
    ):
        yield flow


def _entry(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=EMAIL,
        data={
            "username": EMAIL,
            "token": TOKEN,
            "refresh_token": REFRESH,
            "account_id": 42,
            "terminal_uuid": TERMINAL,
        },
    )
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {}).setdefault(DATA_PENDING_PASSWORD, {})[EMAIL] = (
        "pw-secret"
    )
    return entry


async def test_setup_success(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data.coordinator.last_update_success
    assert entry.runtime_data.password == "pw-secret"
    assert EMAIL not in hass.data[DOMAIN][DATA_PENDING_PASSWORD]


async def test_cloud_down_leaves_tplink_untouched(hass: HomeAssistant) -> None:
    FakeCloudClient.fail = True
    tplink = MockConfigEntry(
        domain="tplink",
        unique_id=STUB_MAC,
        data={"host": "10.0.0.1"},
        state=ConfigEntryState.LOADED,
    )
    tplink.add_to_hass(hass)
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert not entry.runtime_data.coordinator.last_update_success
    assert tplink.state is ConfigEntryState.LOADED
    assert dict(tplink.data) == {"host": "10.0.0.1"}


async def test_unload(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    hass.data[DOMAIN][DATA_PENDING_PASSWORD][EMAIL] = "again"
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert entry.state is ConfigEntryState.NOT_LOADED
    assert EMAIL not in hass.data[DOMAIN][DATA_PENDING_PASSWORD]


async def test_diagnostics_redacted(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    diag = await async_get_config_entry_diagnostics(hass, entry)
    dumped = json.dumps(diag)
    for secret in (
        EMAIL,
        TOKEN,
        REFRESH,
        TERMINAL,
        IP,
        ALIAS,
        DEVICE_ID,
        "11:22:33:44:55:66",
        "pw-secret",
    ):
        assert secret not in dumped
    assert diag["inventory"]["count"] == 1
    assert diag["inventory"]["by_model_base"] == {"P110": 1}
    assert diag["coordinator"]["last_update_success"] is True


async def test_diagnostics_cloud_error_code(hass: HomeAssistant) -> None:
    FakeCloudClient.fail = True
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert diag["coordinator"]["last_exception"] == "UpdateFailed"
    assert diag["coordinator"]["last_cloud_error_code"] == -1


async def test_coordinator_repolls_without_entities(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert FakeCloudClient.calls == 1
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(minutes=31))
    await hass.async_block_till_done()
    assert FakeCloudClient.calls == 2
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(minutes=62))
    await hass.async_block_till_done()
    assert FakeCloudClient.calls == 3


async def test_coordinator_stops_polling_after_unload(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    calls = FakeCloudClient.calls
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(minutes=31))
    await hass.async_block_till_done()
    assert FakeCloudClient.calls == calls


MAC_ONE = "11:22:33:44:55:01"
MAC_TWO = "11:22:33:44:55:02"
FLOW_HOSTS = {MAC_ONE: "10.0.0.1", MAC_TWO: "10.0.0.2"}


class FlowCloudClient:
    """Two-device cloud fake that records every device_details call."""

    details_calls: list[str] = []
    list_calls = 0

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def login(self, username: str, password: str) -> CloudSession:
        return CloudSession("tok", "ref", 42)

    async def list_devices(self, session: CloudSession) -> list[CloudDevice]:
        type(self).list_calls += 1
        return [
            CloudDevice(
                device_id=DEVICE_ID,
                mac=mac,
                alias=mac,
                model="P110",
                model_base="P110",
                device_type="SMART.TAPOPLUG",
                hw_ver="1",
                fw_ver="1",
                region=None,
                role=None,
            )
            for mac in FLOW_HOSTS
        ]

    async def device_details(
        self, session: CloudSession, device: CloudDevice
    ) -> DeviceDetails:
        type(self).details_calls.append(device.mac)
        return DeviceDetails(ip=FLOW_HOSTS[device.mac], ssid=None, fw_ver=None)


@pytest.fixture
def flow_env(hass: HomeAssistant) -> Iterator[list[str]]:
    """Patch cloud client + probe for flow-then-setup; yields probed hosts."""
    FlowCloudClient.details_calls = []
    FlowCloudClient.list_calls = 0
    probed: list[str] = []
    host_macs = {host: mac for mac, host in FLOW_HOSTS.items()}

    async def _probe(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        probed.append(host)
        return TdpInfo.from_result(
            {
                "device_id": hashlib.md5(DEVICE_ID.encode()).hexdigest().upper(),
                "mac": host_macs[host],
            }  # noqa: S324
        )

    StubTplinkFlow.host_macs = host_macs
    with (
        patch("custom_components.tapo_onboard.onboarding.async_probe", _probe),
        patch(
            "custom_components.tapo_onboard.config_flow.CloudClient", FlowCloudClient
        ),
        patch("custom_components.tapo_onboard.CloudClient", FlowCloudClient),
        patch(
            "custom_components.tapo_onboard.config_flow.build_cloud_ssl_context",
            lambda: ssl.create_default_context(),
        ),
    ):
        yield probed


async def _run_flow(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "cloud"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"username": EMAIL, "password": "secret"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": list(FLOW_HOSTS)}
    )
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()


async def test_details_called_once_per_device_across_flow_and_setup(
    hass: HomeAssistant, flow_env: list[str]
) -> None:
    StubTplinkFlow.connect_result = "cannot_connect"
    await _run_flow(hass)
    assert sorted(FlowCloudClient.details_calls) == sorted(FLOW_HOSTS)


async def test_auth_failed_device_not_logged_in_again_on_setup(
    hass: HomeAssistant, flow_env: list[str]
) -> None:
    StubTplinkFlow.connect_result = "auth"
    StubTplinkFlow.valid_password = "other"
    await _run_flow(hass)
    assert sorted(FlowCloudClient.details_calls) == sorted(FLOW_HOSTS)
    assert sorted(flow_env) == sorted(FLOW_HOSTS.values())


async def test_cannot_connect_device_retried_after_floor(
    hass: HomeAssistant, flow_env: list[str], freezer: FrozenDateTimeFactory
) -> None:
    StubTplinkFlow.connect_result = "cannot_connect"
    await _run_flow(hass)
    assert len(FlowCloudClient.details_calls) == 2
    freezer.tick(timedelta(minutes=31))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert sorted(FlowCloudClient.details_calls) == sorted([*FLOW_HOSTS, *FLOW_HOSTS])


async def test_setup_lists_once_across_flow_and_first_cycle(
    hass: HomeAssistant, flow_env: list[str], freezer: FrozenDateTimeFactory
) -> None:
    """The flow's device list serves the setup refresh (rule 3: one per 30 min)."""
    StubTplinkFlow.connect_result = "cannot_connect"
    await _run_flow(hass)
    assert FlowCloudClient.list_calls == 1
    freezer.tick(timedelta(minutes=31))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert FlowCloudClient.list_calls == 2


async def test_failed_setup_drops_password_handoff(hass: HomeAssistant) -> None:
    entry = _entry(hass)

    def _broken() -> ssl.SSLContext:
        raise ssl.SSLError("anchor missing")

    with patch("custom_components.tapo_onboard.build_cloud_ssl_context", _broken):
        await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert EMAIL not in hass.data[DOMAIN][DATA_PENDING_PASSWORD]


LOCAL_MAC = "AA:BB:CC:DD:EE:01"
LOCAL_IP = "10.0.0.77"
LOST_HOST = "192.168.1.5"


def _local_entry(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=EMAIL,
        data={
            "username": EMAIL,
            "mode": "local",
            "subnets": ["10.0.0.0/24"],
            "ignored_macs": [],
        },
    )
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {}).setdefault(DATA_PENDING_PASSWORD, {})[EMAIL] = (
        "pw-secret"
    )
    return entry


def _local_info() -> TdpInfo:
    info = TdpInfo.from_result(
        {
            "device_id": "DEVHASH",
            "owner": hashlib.md5(EMAIL.encode()).hexdigest().upper(),  # noqa: S324
            "mac": LOCAL_MAC,
            "ip": LOCAL_IP,
            "device_model": "P110(EU)",
            "mgt_encrypt_schm": {"encrypt_type": "KLAP"},
        }
    )
    assert info is not None
    return info


class _Sweep:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail = False
        self.replies: list[TdpInfo] = []

    async def __call__(self, networks: Any, **_: object) -> list[TdpInfo]:
        self.calls.append(tuple(str(n) for n in networks))
        if self.fail:
            raise OSError("udp down")
        return self.replies


@pytest.fixture
def local_env() -> Iterator[tuple[_Sweep, Mock]]:
    sweep = _Sweep()
    cloud = Mock(side_effect=AssertionError("CloudClient must not be built"))
    ssl_job = Mock(side_effect=AssertionError("ssl context must not be built"))
    with (
        patch("custom_components.tapo_onboard.sweep.async_sweep", sweep),
        patch("custom_components.tapo_onboard.CloudClient", cloud),
        patch("custom_components.tapo_onboard.build_cloud_ssl_context", ssl_job),
    ):
        yield sweep, cloud


async def test_local_setup_has_no_cloud_client(
    hass: HomeAssistant, local_env: tuple[_Sweep, Mock]
) -> None:
    sweep, cloud = local_env
    sweep.replies = [_local_info()]
    entry = _local_entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data.client is None
    assert type(entry.runtime_data.coordinator).__name__ == "SweepCoordinator"
    cloud.assert_not_called()
    assert entry.runtime_data.password == "pw-secret"
    assert EMAIL not in hass.data[DOMAIN][DATA_PENDING_PASSWORD]
    assert sweep.calls == [("10.0.0.0/24",)]


async def test_local_sweep_failure_keeps_entry_loaded(
    hass: HomeAssistant, local_env: tuple[_Sweep, Mock]
) -> None:
    sweep, _ = local_env
    sweep.fail = True
    entry = _local_entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert not entry.runtime_data.coordinator.last_update_success


async def test_local_unload_drops_password(
    hass: HomeAssistant, local_env: tuple[_Sweep, Mock]
) -> None:
    entry = _local_entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    runtime = entry.runtime_data
    runtime.password = "pw-secret"
    hass.data[DOMAIN][DATA_PENDING_PASSWORD][EMAIL] = "again"
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert entry.state is ConfigEntryState.NOT_LOADED
    assert runtime.password is None
    assert EMAIL not in hass.data[DOMAIN][DATA_PENDING_PASSWORD]


async def test_local_lost_check_registered(
    hass: HomeAssistant, local_env: tuple[_Sweep, Mock]
) -> None:
    sweep, _ = local_env
    MockConfigEntry(
        domain="tplink",
        unique_id=STUB_MAC,
        data={"host": LOST_HOST},
        state=ConfigEntryState.SETUP_RETRY,
    ).add_to_hass(hass)
    entry = _local_entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    onboarding = importlib.import_module("custom_components.tapo_onboard.onboarding")
    await onboarding.async_get_tdp_query(hass)
    sweep.calls.clear()
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done()
    assert ("192.168.1.0/24",) in sweep.calls


async def test_local_diagnostics_redacted(
    hass: HomeAssistant, local_env: tuple[_Sweep, Mock]
) -> None:
    sweep, _ = local_env
    info = _local_info()
    sweep.replies = [info]
    entry = _local_entry(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    diag = await async_get_config_entry_diagnostics(hass, entry)
    dumped = json.dumps(diag)
    for secret in (EMAIL, LOCAL_IP, LOCAL_MAC, "pw-secret"):
        assert secret not in dumped
    assert diag["mode"] == "local"
    assert diag["entry"]["subnets"] == ["10.0.0.0/24"]
    assert diag["coordinator"]["last_update_success"] is True
    assert diag["sweep"]["count"] == 1
    assert diag["sweep"]["by_model"] == {"P110(EU)": 1}
    assert diag["sweep"]["by_encrypt_type"] == {"KLAP": 1}
    assert diag["sweep"]["tpap"] == 0
    assert diag["sweep"]["foreign"] == 0
    assert diag["sweep"]["devices"][0]["device_model"] == "P110(EU)"
