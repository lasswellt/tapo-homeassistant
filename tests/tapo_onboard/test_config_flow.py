# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the config flow (fake cloud client, stub tplink)."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest
import voluptuous as vol
from homeassistant.config_entries import (
    SOURCE_IGNORE,
    SOURCE_INTEGRATION_DISCOVERY,
    ConfigEntryState,
    ConfigFlowResult,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.device_registry import format_mac
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockModule,
    mock_integration,
)
from stub_tplink import STUB_MAC, StubTplinkFlow, stub_tplink
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudDevice,
    CloudRateLimited,
    CloudSession,
    CloudUnavailable,
    DeviceDetails,
    DeviceOffline,
    MfaRequired,
)
from tapolink_proto.discovery import TdpInfo

DOMAIN = "tapo_onboard"
DATA_PENDING_PASSWORD = "pending_password"
EMAIL = "User@Example.com"
PASSWORD = "secret"
MAC_PARTIAL = "11:22:33:44:55:66"
MAC_UNSUP = "11:22:33:44:55:77"
MAC_ALREADY = "11:22:33:44:55:88"


def _dev(mac: str, alias: str, model: str) -> CloudDevice:
    return CloudDevice(
        device_id=f"id-{mac}",
        mac=mac,
        alias=alias,
        model=model,
        model_base=model,
        device_type="SMART.TAPOPLUG",
        hw_ver="1",
        fw_ver="1",
        region=None,
        role=None,
    )


HOSTS = {
    STUB_MAC: "10.0.0.5",
    MAC_PARTIAL: "10.0.0.6",
    MAC_UNSUP: "10.0.0.7",
    MAC_ALREADY: "10.0.0.8",
}
MAC_BY_HOST = {host: mac for mac, host in HOSTS.items()}
# host -> MAC whose identity the fake probe reports instead of the owner's.
PROBE_AS: dict[str, str] = {}

DEVICES = [
    _dev(STUB_MAC, "Alpha", "P110"),
    _dev(MAC_PARTIAL, "Bravo", "L730"),
    _dev(MAC_UNSUP, "Charlie", "S310D"),
    _dev(MAC_ALREADY, "Delta", "P110"),
]


class _FatalError(BaseException):
    """Escapes the flow's per-device ``except Exception`` and fails the task."""


class FakeCloudClient:
    """Scripted CloudClient (public-method boundary only)."""

    devices: list[CloudDevice] = DEVICES
    login_error: Exception | None = None
    submit_error: Exception | None = None
    mfa: bool = False
    mfa_request_error: Exception | None = None
    list_error: Exception | None = None
    details_block: asyncio.Event | None = None
    details_fatal: bool = False
    details_error_on: str | None = None
    details_cancel_on: str | None = None
    no_ip_on: str | None = None
    details_calls: list[str] = []

    def __init__(self, session: object, *, ssl_context: object, terminal_uuid: str):
        self.terminal_uuid = terminal_uuid

    async def login(self, username: str, password: str) -> CloudSession:
        if self.login_error:
            raise self.login_error
        if self.mfa:
            raise MfaRequired("proc-1")
        return CloudSession("tok", "ref", 42)

    async def request_mfa_code(self, username: str, password: str) -> None:
        if self.mfa_request_error:
            raise self.mfa_request_error

    async def submit_mfa_code(
        self, username: str, process_id: str, code: str
    ) -> CloudSession:
        if self.submit_error:
            raise self.submit_error
        assert process_id == "proc-1"
        return CloudSession("tok", "ref", 42)

    async def list_devices(self, session: CloudSession) -> list[CloudDevice]:
        if self.list_error:
            raise self.list_error
        return self.devices

    async def device_details(
        self, session: CloudSession, device: CloudDevice
    ) -> DeviceDetails:
        self.details_calls.append(device.mac)
        if self.details_fatal:
            raise _FatalError
        if self.details_block is not None:
            await self.details_block.wait()
        if device.mac == self.no_ip_on:
            return DeviceDetails(ip=None, ssid=None, fw_ver=None)
        if device.mac == self.details_cancel_on:
            raise asyncio.CancelledError
        if device.mac == self.details_error_on:
            raise RuntimeError("boom")
        return DeviceDetails(ip=HOSTS[device.mac], ssid=None, fw_ver=None)


@pytest.fixture(autouse=True)
def probe() -> Iterator[None]:
    PROBE_AS.clear()

    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        owner = MAC_BY_HOST.get(host)
        if owner is None:
            return None
        mac = PROBE_AS.get(host, owner)
        return TdpInfo.from_result(
            {
                "device_id": hashlib.md5(f"id-{mac}".encode()).hexdigest().upper(),
                "owner": hashlib.md5(EMAIL.lower().encode()).hexdigest().upper(),
                "mac": mac,
            }  # noqa: S324
        )

    with patch("custom_components.tapo_onboard.onboarding.async_probe", _fake):
        yield


@pytest.fixture(autouse=True)
def fake_cloud(hass: HomeAssistant) -> Iterator[type[FakeCloudClient]]:
    FakeCloudClient.devices = DEVICES
    FakeCloudClient.login_error = None
    FakeCloudClient.submit_error = None
    FakeCloudClient.mfa = False
    FakeCloudClient.mfa_request_error = None
    FakeCloudClient.list_error = None
    FakeCloudClient.details_block = None
    FakeCloudClient.details_fatal = False
    FakeCloudClient.details_error_on = None
    FakeCloudClient.details_cancel_on = None
    FakeCloudClient.no_ip_on = None
    FakeCloudClient.details_calls = []
    base = "custom_components.tapo_onboard.config_flow"
    # Manifest depends on core `dhcp`, whose optional deps are not installed.
    mock_integration(hass, MockModule("dhcp"))
    mock_integration(hass, MockModule("network"))
    with (
        stub_tplink(hass) as stub,
        patch(f"{base}.CloudClient", FakeCloudClient),
        patch(
            f"{base}.build_cloud_ssl_context",
            lambda: ssl.create_default_context(),
        ),
    ):
        stub.host_macs = dict(MAC_BY_HOST)
        yield FakeCloudClient


async def _start(hass: HomeAssistant) -> ConfigFlowResult:
    return await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})


async def _login(hass: HomeAssistant) -> ConfigFlowResult:
    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "cloud"}
    )
    return await hass.config_entries.flow.async_configure(
        result["flow_id"], {"username": EMAIL, "password": PASSWORD}
    )


async def test_user_step_is_menu(hass: HomeAssistant) -> None:
    result = await _start(hass)
    assert result["type"] == FlowResultType.MENU
    assert result["step_id"] == "user"
    assert result["menu_options"] == ["local", "cloud"]


async def test_happy_path(hass: HomeAssistant) -> None:
    MockConfigEntry(
        domain="tplink", unique_id=format_mac(MAC_ALREADY), data={"host": "10.0.0.9"}
    ).add_to_hass(hass)
    result = await _login(hass)
    assert result["step_id"] == "pick_devices"
    schema = cast("vol.Schema", result["data_schema"]).schema
    key = next(k for k in schema if k == "devices")
    assert sorted(key.default()) == sorted([STUB_MAC, MAC_PARTIAL])
    labels = {o["value"]: o["label"] for o in schema[key].config["options"]}
    assert labels[STUB_MAC] == "Alpha (P110) – ready"
    assert labels[MAC_PARTIAL] == "Bravo (L730) – works partly in TP-Link Smart Home"
    assert labels[MAC_UNSUP] == "Charlie (S310D) – not supported by TP-Link Smart Home"
    assert labels[MAC_ALREADY] == "Delta (P110) – already in TP-Link Smart Home"
    assert list(labels) == [STUB_MAC, MAC_PARTIAL, MAC_UNSUP, MAC_ALREADY]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": [STUB_MAC, MAC_PARTIAL]}
    )
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    data = result["data"]
    assert "password" not in data
    assert PASSWORD not in str(data)
    assert data["username"] == EMAIL
    assert data["token"] == "tok"
    assert data["ignored_macs"] == sorted([MAC_UNSUP, MAC_ALREADY])
    assert result["title"] == EMAIL.lower()
    assert hass.data[DOMAIN][DATA_PENDING_PASSWORD][EMAIL.lower()] == PASSWORD
    tplink = hass.config_entries.async_entries("tplink")
    assert any(e.data == {"host": "10.0.0.5"} for e in tplink)
    # both ticked devices were really added, as distinct tplink entries.
    ours = [e for e in tplink if e.unique_id != format_mac(MAC_ALREADY)]
    assert sorted(e.unique_id or "" for e in ours) == sorted(
        [format_mac(STUB_MAC), format_mac(MAC_PARTIAL)]
    )
    ph = result["description_placeholders"]
    assert ph is not None
    assert ph["added"] == "2"


async def test_mfa_path(hass: HomeAssistant, fake_cloud: type[FakeCloudClient]) -> None:
    fake_cloud.mfa = True
    result = await _login(hass)
    assert result["step_id"] == "mfa"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"code": "12345"}
    )
    assert result["errors"] == {"base": "invalid_code"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"code": "abcdef"}
    )
    assert result["errors"] == {"base": "invalid_code"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"code": "123456"}
    )
    assert result["step_id"] == "pick_devices"


@pytest.mark.parametrize(
    ("error", "key"),
    [
        (CloudAuthError(-20601), "invalid_auth"),
        (CloudUnavailable("down"), "cannot_connect"),
        (CloudRateLimited(-20004, retry_after=1800), "rate_limited"),
        (DeviceOffline(-20571), "cannot_connect"),
        (RuntimeError("boom"), "unknown"),
    ],
)
async def test_login_errors(
    hass: HomeAssistant,
    fake_cloud: type[FakeCloudClient],
    error: Exception,
    key: str,
) -> None:
    fake_cloud.login_error = error
    result = await _login(hass)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "cloud"
    assert result["errors"] == {"base": key}


async def test_mfa_submit_error(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    fake_cloud.mfa = True
    fake_cloud.submit_error = CloudAuthError(-20601)
    result = await _login(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"code": "123456"}
    )
    assert result["errors"] == {"base": "invalid_auth"}


async def test_mfa_request_error(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    fake_cloud.mfa = True
    fake_cloud.mfa_request_error = CloudUnavailable("down")
    result = await _login(hass)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "cloud"
    assert result["errors"] == {"base": "cannot_connect"}


async def test_list_devices_error(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    fake_cloud.list_error = CloudAuthError(-20601)
    result = await _login(hass)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "cloud"
    assert result["errors"] == {"base": "invalid_auth"}


async def test_onboarding_task_cancelled_warns(
    hass: HomeAssistant,
    fake_cloud: type[FakeCloudClient],
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_cloud.details_block = asyncio.Event()
    result = await _login(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": [STUB_MAC]}
    )
    assert result["type"] == FlowResultType.SHOW_PROGRESS
    flow = hass.config_entries.flow._progress[result["flow_id"]]
    task = flow._task
    assert task is not None
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    result = await hass.config_entries.flow.async_configure(result["flow_id"])
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert "Onboarding was cancelled" in caplog.text
    assert result["type"] == FlowResultType.CREATE_ENTRY
    ph = result["description_placeholders"]
    assert ph is not None
    assert ph["added"] == "0"
    assert ph["failed"] == "1"


async def test_onboarding_task_failed_logs_error(
    hass: HomeAssistant,
    fake_cloud: type[FakeCloudClient],
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_cloud.details_fatal = True
    result = await _login(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": [STUB_MAC]}
    )
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert "Onboarding failed: _FatalError" in caplog.text
    assert result["type"] == FlowResultType.CREATE_ENTRY
    ph = result["description_placeholders"]
    assert ph is not None
    assert ph["added"] == "0"
    assert ph["failed"] == "1"


async def test_already_configured(hass: HomeAssistant) -> None:
    MockConfigEntry(domain=DOMAIN, unique_id=EMAIL.lower(), data={}).add_to_hass(hass)
    result = await _login(hass)
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_zero_devices(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    fake_cloud.devices = []
    result = await _login(hass)
    assert result["step_id"] == "pick_devices"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": []}
    )
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"]["ignored_macs"] == []


async def test_onboarding_device_failure_still_creates_entry(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    fake_cloud.details_error_on = MAC_PARTIAL
    result = await _login(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": [STUB_MAC, MAC_PARTIAL]}
    )
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    ph = result["description_placeholders"]
    assert ph is not None
    assert ph["added"] == "1"
    assert ph["failed"] == "1"
    assert ph["failed_devices"] == " (Bravo)"


async def test_onboarding_cancelled_marks_unreached_failed(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    fake_cloud.details_cancel_on = MAC_PARTIAL
    result = await _login(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": [STUB_MAC, MAC_PARTIAL, MAC_UNSUP]}
    )
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    ph = result["description_placeholders"]
    assert ph is not None
    assert ph["added"] == "1"
    assert ph["failed"] == "2"
    assert ph["failed_devices"] == " (Bravo, Charlie)"


async def _run(hass: HomeAssistant, macs: list[str]) -> ConfigFlowResult:
    result = await _login(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"devices": macs}
    )
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    return result


async def test_three_devices_added_card_and_no_ip(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    StubTplinkFlow.card_hosts = {HOSTS[MAC_PARTIAL]}
    fake_cloud.no_ip_on = MAC_UNSUP
    result = await _run(hass, [STUB_MAC, MAC_PARTIAL, MAC_UNSUP])
    assert result["description_placeholders"] == {
        "added": "1",
        "confirm": "1",
        "already": "0",
        "failed": "1",
        "failed_devices": " (Charlie)",
    }
    tplink = hass.config_entries.async_entries("tplink")
    assert [e.unique_id for e in tplink] == [format_mac(STUB_MAC)]
    assert dict(tplink[0].data) == {"host": HOSTS[STUB_MAC]}


async def test_untick_ignores_device(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    result = await _run(hass, [STUB_MAC])
    assert MAC_PARTIAL in result["data"]["ignored_macs"]
    assert [e.unique_id for e in hass.config_entries.async_entries("tplink")] == [
        format_mac(STUB_MAC)
    ]
    assert fake_cloud.details_calls == [STUB_MAC]


async def test_identity_mismatch_starts_no_flow(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    PROBE_AS[HOSTS[MAC_PARTIAL]] = STUB_MAC
    result = await _run(hass, [STUB_MAC, MAC_PARTIAL])
    ph = result["description_placeholders"]
    assert ph is not None
    assert (ph["added"], ph["failed"], ph["confirm"]) == ("1", "1", "0")
    assert ph["failed_devices"] == " (Bravo)"
    tplink = hass.config_entries.async_entries("tplink")
    assert [e.unique_id for e in tplink] == [format_mac(STUB_MAC)]
    assert not hass.config_entries.flow.async_progress_by_handler("tplink")


async def test_ticked_device_already_in_tplink_is_skipped(
    hass: HomeAssistant, fake_cloud: type[FakeCloudClient]
) -> None:
    MockConfigEntry(
        domain="tplink", unique_id=format_mac(MAC_ALREADY), data={"host": "10.0.0.9"}
    ).add_to_hass(hass)
    result = await _run(hass, [STUB_MAC, MAC_ALREADY])
    assert result["description_placeholders"] == {
        "added": "1",
        "confirm": "0",
        "already": "1",
        "failed": "0",
        "failed_devices": "",
    }
    assert fake_cloud.details_calls == [STUB_MAC]
    tplink = hass.config_entries.async_entries("tplink")
    assert sorted(e.unique_id or "" for e in tplink) == sorted(
        [format_mac(STUB_MAC), format_mac(MAC_ALREADY)]
    )


async def test_cannot_connect_counts_failed(hass: HomeAssistant) -> None:
    StubTplinkFlow.connect_result = "cannot_connect"
    result = await _run(hass, [STUB_MAC])
    assert result["description_placeholders"] == {
        "added": "0",
        "confirm": "0",
        "already": "0",
        "failed": "1",
        "failed_devices": " (Alpha)",
    }
    assert not hass.config_entries.async_entries("tplink")


async def test_auth_failed_counts_under_confirm(hass: HomeAssistant) -> None:
    StubTplinkFlow.connect_result = "auth"
    StubTplinkFlow.valid_password = "other"
    result = await _run(hass, [STUB_MAC])
    assert result["description_placeholders"] == {
        "added": "0",
        "confirm": "1",
        "already": "0",
        "failed": "0",
        "failed_devices": "",
    }


def _tdp(mac: str, ip: str, owner: str, model: str = "P110(US)") -> TdpInfo:
    info = TdpInfo.from_result(
        {
            "device_id": "X",
            "mac": mac,
            "ip": ip,
            "owner": hashlib.md5(owner.lower().encode()).hexdigest().upper(),  # noqa: S324
            "device_model": model,
        }
    )
    assert info is not None
    return info


ADAPTERS = [
    {"enabled": True, "ipv4": [{"address": "10.0.0.2", "network_prefix": 24}]},
    {"enabled": False, "ipv4": [{"address": "192.168.7.2", "network_prefix": 24}]},
    {"enabled": True, "ipv4": [{"address": "8.8.8.8", "network_prefix": 24}]},
]


async def _local_form(hass: HomeAssistant) -> ConfigFlowResult:
    result = await _start(hass)
    return await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "local"}
    )


async def test_local_path_adds_owned_device(hass: HomeAssistant) -> None:
    swept: list[list[str]] = []

    async def _sweep(networks: list[str], *, query: bytes) -> list[TdpInfo]:
        swept.append(list(networks))
        return [
            _tdp(STUB_MAC, HOSTS[STUB_MAC], EMAIL),
            _tdp(MAC_PARTIAL, HOSTS[MAC_PARTIAL], "other@example.com"),
        ]

    with (
        patch(
            "homeassistant.components.network.async_get_adapters",
            return_value=ADAPTERS,
        ),
        patch("custom_components.tapo_onboard.config_flow.async_sweep", _sweep),
        patch("custom_components.tapo_onboard.sweep.async_sweep", _sweep),
    ):
        result = await _local_form(hass)
        assert result["step_id"] == "local"
        schema = cast("vol.Schema", result["data_schema"]).schema
        key = next(k for k in schema if k == "subnets")
        assert key.default() == "10.0.0.0/24"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"username": EMAIL, "password": PASSWORD, "subnets": "10.0.0.0/24"},
        )
        while result["type"] == FlowResultType.SHOW_PROGRESS:
            await hass.async_block_till_done()
            result = await hass.config_entries.flow.async_configure(result["flow_id"])
        assert result["step_id"] == "pick_devices"
        schema = cast("vol.Schema", result["data_schema"]).schema
        key = next(k for k in schema if k == "devices")
        labels = {o["value"]: o["label"] for o in schema[key].config["options"]}
        assert labels == {STUB_MAC: "P110(US) at 10.0.0.5 – ready"}
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"devices": [STUB_MAC]}
        )
        while result["type"] == FlowResultType.SHOW_PROGRESS:
            await hass.async_block_till_done()
            result = await hass.config_entries.flow.async_configure(result["flow_id"])
        await hass.async_block_till_done()
    assert swept[0] == ["10.0.0.0/24"]
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        "username": EMAIL,
        "mode": "local",
        "subnets": ["10.0.0.0/24"],
        "ignored_macs": [],
    }
    assert result["title"] == EMAIL.lower()
    # Local setup moves the hand-off into the entry's memory-only runtime data.
    assert EMAIL.lower() not in hass.data[DOMAIN][DATA_PENDING_PASSWORD]
    (local_entry,) = hass.config_entries.async_entries(DOMAIN)
    assert local_entry.runtime_data.password == PASSWORD
    assert [e.unique_id for e in hass.config_entries.async_entries("tplink")] == [
        format_mac(STUB_MAC)
    ]
    ph = result["description_placeholders"]
    assert ph is not None
    assert ph["added"] == "1"


async def test_local_no_devices_creates_entry(hass: HomeAssistant) -> None:
    async def _sweep(networks: list[str], *, query: bytes) -> list[TdpInfo]:
        return []

    with (
        patch(
            "homeassistant.components.network.async_get_adapters",
            return_value=[],
        ),
        patch("custom_components.tapo_onboard.config_flow.async_sweep", _sweep),
        patch("custom_components.tapo_onboard.sweep.async_sweep", _sweep),
    ):
        result = await _local_form(hass)
        schema = cast("vol.Schema", result["data_schema"]).schema
        key = next(k for k in schema if k == "subnets")
        assert key.default is vol.UNDEFINED
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"username": EMAIL, "password": PASSWORD, "subnets": "10.1.0.0/24"},
        )
        while result["type"] == FlowResultType.SHOW_PROGRESS:
            await hass.async_block_till_done()
            result = await hass.config_entries.flow.async_configure(result["flow_id"])
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"]["subnets"] == ["10.1.0.0/24"]
    ph = result["description_placeholders"]
    assert ph is not None
    assert ph["added"] == "0"


@pytest.mark.parametrize(
    ("subnets", "key"),
    [
        ("not-a-cidr", "invalid_subnets"),
        (" , ", "invalid_subnets"),
        ("8.8.8.0/24", "not_private"),
        ("10.0.0.0/8", "too_many_hosts"),
        ("10.0.0.0/16 10.1.0.0/16", "too_many_hosts"),
    ],
)
async def test_local_subnet_errors(hass: HomeAssistant, subnets: str, key: str) -> None:
    with patch("homeassistant.components.network.async_get_adapters", return_value=[]):
        result = await _local_form(hass)
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"username": EMAIL, "password": PASSWORD, "subnets": subnets},
        )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "local"
    assert result["errors"] == {"subnets": key}


PREFILL_ADAPTERS = [
    {"enabled": True, "ipv4": [{"address": "10.0.0.2", "network_prefix": 24}]},
    {"enabled": True, "ipv4": [{"address": "10.0.0.9", "network_prefix": 24}]},
    {"enabled": False, "ipv4": [{"address": "192.168.7.2", "network_prefix": 24}]},
    {"enabled": True, "ipv4": [{"address": "127.0.0.1", "network_prefix": 8}]},
    {"enabled": True, "ipv4": [{"address": "169.254.1.5", "network_prefix": 16}]},
    {"enabled": True, "ipv4": [{"address": "8.8.8.8", "network_prefix": 24}]},
]


async def test_local_prefill_from_tplink_hosts_and_adapters(
    hass: HomeAssistant,
) -> None:
    MockConfigEntry(
        domain="tplink", unique_id="aa:bb:cc:00:00:01", data={"host": "not-an-ip"}
    ).add_to_hass(hass)
    MockConfigEntry(
        domain="tplink", unique_id="aa:bb:cc:00:00:02", data={"host": "192.168.9.4"}
    ).add_to_hass(hass)
    with patch(
        "homeassistant.components.network.async_get_adapters",
        return_value=PREFILL_ADAPTERS,
    ):
        result = await _local_form(hass)
    schema = cast("vol.Schema", result["data_schema"]).schema
    key = next(k for k in schema if k == "subnets")
    # tplink host first; invalid host, duplicate, disabled, loopback,
    # link-local and public adapter addresses are all left out.
    assert key.default() == "192.168.9.0/24, 10.0.0.0/24"


async def _drive(hass: HomeAssistant, result: ConfigFlowResult) -> ConfigFlowResult:
    while result["type"] == FlowResultType.SHOW_PROGRESS:
        await hass.async_block_till_done()
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    return result


async def _local_sweep(
    hass: HomeAssistant, subnets: str = "10.0.0.0/24"
) -> ConfigFlowResult:
    """Start a local flow and submit the form; patches stay for the caller."""
    result = await _local_form(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"username": EMAIL, "password": PASSWORD, "subnets": subnets},
    )
    return await _drive(hass, result)


def _patched(replies: list[TdpInfo] | type[BaseException]) -> tuple[object, ...]:
    async def _sweep(networks: list[str], *, query: bytes) -> list[TdpInfo]:
        if isinstance(replies, type):
            raise replies()
        return list(replies)

    return (
        patch("homeassistant.components.network.async_get_adapters", return_value=[]),
        patch("custom_components.tapo_onboard.config_flow.async_sweep", _sweep),
        patch("custom_components.tapo_onboard.sweep.async_sweep", _sweep),
    )


async def test_local_only_foreign_and_ipless_replies_create_entry_without_pick(
    hass: HomeAssistant,
) -> None:
    ipless = TdpInfo.from_result(
        {
            "device_id": "X",
            "mac": MAC_UNSUP,
            "owner": hashlib.md5(EMAIL.lower().encode()).hexdigest().upper(),  # noqa: S324
        }
    )
    assert ipless is not None and ipless.ip is None
    replies = [_tdp(MAC_PARTIAL, HOSTS[MAC_PARTIAL], "other@example.com"), ipless]
    p1, p2, p3 = _patched(replies)
    with p1, p2, p3:  # type: ignore[attr-defined]
        result = await _local_sweep(hass)
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    ph = result["description_placeholders"]
    assert ph is not None
    assert (ph["added"], ph["confirm"], ph["already"], ph["failed"]) == (
        "0",
        "0",
        "0",
        "0",
    )
    assert not hass.config_entries.async_entries("tplink")


async def test_local_sweep_cancelled_shows_form_error(
    hass: HomeAssistant,
) -> None:
    p1, p2, p3 = _patched(asyncio.CancelledError)
    with p1, p2, p3:  # type: ignore[attr-defined]
        result = await _local_sweep(hass)
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "local"
    assert result["errors"] == {"base": "sweep_failed"}


async def test_local_instant_sweep_failure_does_not_loop(
    hass: HomeAssistant,
) -> None:
    calls = 0

    async def _sweep(networks: list[str], *, query: bytes) -> list[TdpInfo]:
        nonlocal calls
        calls += 1
        raise OSError

    with (
        patch("homeassistant.components.network.async_get_adapters", return_value=[]),
        patch("custom_components.tapo_onboard.config_flow.async_sweep", _sweep),
    ):
        result = await _local_sweep(hass)
        await hass.async_block_till_done()
    assert calls == 1
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "sweep_failed"}


async def test_local_sweep_raises_shows_form_error_then_retry_proceeds(
    hass: HomeAssistant,
) -> None:
    p1, p2, p3 = _patched(OSError)
    with p1, p2, p3:  # type: ignore[attr-defined]
        result = await _local_sweep(hass, "10.0.0.0/24, 10.0.1.0/24")
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "local"
    assert result["errors"] == {"base": "sweep_failed"}
    schema = cast("vol.Schema", result["data_schema"]).schema
    defaults = {str(k): k.default() for k in schema if k.default is not vol.UNDEFINED}
    assert defaults == {
        "username": EMAIL,
        "subnets": "10.0.0.0/24, 10.0.1.0/24",
    }
    p1, p2, p3 = _patched([])
    with p1, p2, p3:  # type: ignore[attr-defined]
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"username": EMAIL, "password": PASSWORD, "subnets": "10.0.0.0/24"},
        )
        result = await _drive(hass, result)
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"]["subnets"] == ["10.0.0.0/24"]


async def test_local_pick_labels_defaults_outcomes_and_second_flow_aborts(
    hass: HomeAssistant,
) -> None:
    MockConfigEntry(
        domain="tplink", unique_id=format_mac(MAC_ALREADY), data={"host": "10.0.0.8"}
    ).add_to_hass(hass)
    replies = [
        _tdp(STUB_MAC, HOSTS[STUB_MAC], EMAIL, "P110(US)"),
        _tdp(MAC_PARTIAL, HOSTS[MAC_PARTIAL], EMAIL, "L730(US)"),
        _tdp(MAC_UNSUP, HOSTS[MAC_UNSUP], EMAIL, "S310D(US)"),
        _tdp(MAC_ALREADY, HOSTS[MAC_ALREADY], EMAIL, "P110(US)"),
        _tdp("11:22:33:44:55:99", "10.0.0.50", "other@example.com"),
    ]
    p1, p2, p3 = _patched(replies)
    with p1, p2, p3:  # type: ignore[attr-defined]
        result = await _local_sweep(hass)
        assert result["step_id"] == "pick_devices"
        schema = cast("vol.Schema", result["data_schema"]).schema
        key = next(k for k in schema if k == "devices")
        labels = {o["value"]: o["label"] for o in schema[key].config["options"]}
        assert labels == {
            STUB_MAC: "P110(US) at 10.0.0.5 – ready",
            MAC_PARTIAL: "L730(US) at 10.0.0.6 – works partly in TP-Link Smart Home",
            MAC_UNSUP: "S310D(US) at 10.0.0.7 – not supported by TP-Link Smart Home",
            MAC_ALREADY: "P110(US) at 10.0.0.8 – already in TP-Link Smart Home",
        }
        assert sorted(key.default()) == sorted([STUB_MAC, MAC_PARTIAL])
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"devices": [STUB_MAC, MAC_ALREADY]}
        )
        result = await _drive(hass, result)
        await hass.async_block_till_done()
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["description_placeholders"] == {
            "added": "1",
            "confirm": "0",
            "already": "1",
            "failed": "0",
            "failed_devices": "",
        }
        data = dict(result["data"])
        assert data["mode"] == "local"
        assert data["subnets"] == ["10.0.0.0/24"]
        assert data["ignored_macs"] == sorted([MAC_PARTIAL, MAC_UNSUP])
        assert not {"token", "refresh_token", "terminal_uuid", "password"} & set(data)
        # Second local flow for the same account is refused.
        again = await _local_form(hass)
        again = await hass.config_entries.flow.async_configure(
            again["flow_id"],
            {"username": EMAIL, "password": PASSWORD, "subnets": "10.0.0.0/24"},
        )
    assert again["type"] == FlowResultType.ABORT
    assert again["reason"] == "already_configured"


def _account(
    hass: HomeAssistant, *, loaded: bool = True, password: str | None = PASSWORD
) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=EMAIL.lower(),
        data={"username": EMAIL, "mode": "local", "subnets": ["10.0.0.0/24"]},
        state=ConfigEntryState.LOADED if loaded else ConfigEntryState.NOT_LOADED,
    )
    entry.add_to_hass(hass)
    entry.runtime_data = SimpleNamespace(password=password)
    return entry


async def _discover(
    hass: HomeAssistant,
    entry_id: str,
    mac: str = STUB_MAC,
    host: str = "10.0.0.5",
) -> ConfigFlowResult:
    return await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_INTEGRATION_DISCOVERY},
        data={"host": host, "mac": mac, "model": "P110", "entry_id": entry_id},
    )


async def test_discovery_shows_confirm_card(hass: HomeAssistant) -> None:
    entry = _account(hass)
    result = await _discover(hass, entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "discovery_confirm"
    assert result["description_placeholders"] == {"model": "P110", "host": "10.0.0.5"}
    flow = hass.config_entries.flow.async_get(result["flow_id"])
    assert flow is not None
    assert flow["context"]["unique_id"] == STUB_MAC
    assert flow["context"]["title_placeholders"] == {
        "model": "P110",
        "host": "10.0.0.5",
    }
    assert hass.config_entries.async_entries("tplink") == []


async def test_discovery_confirm_adds_device(hass: HomeAssistant) -> None:
    entry = _account(hass)
    result = await _discover(hass, entry.entry_id)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "device_added"
    assert [e.unique_id for e in hass.config_entries.async_entries("tplink")] == [
        format_mac(STUB_MAC)
    ]
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ("mismatch", "identity_mismatch"),
        ("cannot_connect", "cannot_connect"),
        ("silent", "cannot_connect"),
    ],
)
async def test_discovery_confirm_failure_reasons(
    hass: HomeAssistant, setup: str, reason: str
) -> None:
    entry = _account(hass)
    if setup == "mismatch":
        PROBE_AS["10.0.0.5"] = MAC_PARTIAL
    elif setup == "cannot_connect":
        StubTplinkFlow.connect_result = "cannot_connect"
    result = await _discover(
        hass, entry.entry_id, host="10.0.0.99" if setup == "silent" else "10.0.0.5"
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == reason
    assert hass.config_entries.async_entries("tplink") == []


async def test_discovery_confirm_already_configured_outcome(
    hass: HomeAssistant,
) -> None:
    entry = _account(hass)
    result = await _discover(hass, entry.entry_id)
    with patch(
        "custom_components.tapo_onboard.config_flow.async_onboard_device",
        return_value="already_configured",
    ) as onboard:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["reason"] == "already_configured"
    assert onboard.call_args.kwargs["password"] == PASSWORD
    assert onboard.call_args.kwargs["owner_email"] == EMAIL


@pytest.mark.parametrize("case", ["missing", "unloaded"])
async def test_discovery_account_not_running_aborts(
    hass: HomeAssistant, case: str
) -> None:
    entry = _account(hass, loaded=case != "unloaded")
    result = await _discover(hass, "missing" if case == "missing" else entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": PASSWORD}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "password_needed"
    assert hass.config_entries.async_entries("tplink") == []


async def test_discovery_card_after_restart_asks_password_and_remembers(
    hass: HomeAssistant,
) -> None:
    entry = _account(hass, password=None)
    result = await _discover(hass, entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    schema = cast("vol.Schema", result["data_schema"]).schema
    assert [str(k) for k in schema] == ["password"]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": PASSWORD}
    )
    assert result["reason"] == "device_added"
    assert entry.runtime_data.password == PASSWORD
    assert entry.data == {
        "username": EMAIL,
        "mode": "local",
        "subnets": ["10.0.0.0/24"],
    }
    second = await _discover(hass, entry.entry_id, mac=MAC_PARTIAL, host="10.0.0.6")
    assert second["type"] == FlowResultType.FORM
    assert second["data_schema"] is None


async def test_discovery_card_wrong_password_reshows_form_without_dhcp_flow(
    hass: HomeAssistant,
) -> None:
    entry = _account(hass, password=None)
    StubTplinkFlow.connect_result = "auth"
    StubTplinkFlow.valid_password = "right"
    result = await _discover(hass, entry.entry_id)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": "wrong"}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    assert entry.runtime_data.password is None
    await hass.async_block_till_done()
    assert StubTplinkFlow.dhcp_infos == []
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": "right"}
    )
    assert result["reason"] == "device_added"
    assert entry.runtime_data.password == "right"


async def test_discovery_card_remembered_password_rejected_asks_again(
    hass: HomeAssistant,
) -> None:
    entry = _account(hass)
    StubTplinkFlow.connect_result = "auth"
    StubTplinkFlow.valid_password = "right"
    result = await _discover(hass, entry.entry_id)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["errors"] == {"base": "invalid_auth"}
    schema = cast("vol.Schema", result["data_schema"]).schema
    assert [str(k) for k in schema] == ["password"]
    assert StubTplinkFlow.dhcp_infos == []
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": "right"}
    )
    assert result["reason"] == "device_added"
    assert entry.runtime_data.password == "right"


async def test_discovery_confirm_password_lost_before_submit_asks_again(
    hass: HomeAssistant,
) -> None:
    entry = _account(hass)
    result = await _discover(hass, entry.entry_id)
    entry.runtime_data.password = None
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {}
    schema = cast("vol.Schema", result["data_schema"]).schema
    assert [str(k) for k in schema] == ["password"]


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        ("added", "device_added"),
        ("already_configured", "already_configured"),
        ("identity_mismatch", "identity_mismatch"),
        ("handed_to_user", "handed_to_user"),
        ("cannot_connect", "cannot_connect"),
        ("unavailable", "tplink_unavailable"),
        ("pending_confirmation", "pending_confirmation"),
    ],
)
async def test_discovery_every_outcome_has_its_own_abort(
    hass: HomeAssistant, outcome: str, reason: str
) -> None:
    OnboardOutcome = importlib.import_module(  # noqa: N806
        "custom_components.tapo_onboard.onboarding"
    ).OnboardOutcome
    entry = _account(hass)
    result = await _discover(hass, entry.entry_id)
    with patch(
        "custom_components.tapo_onboard.config_flow.async_onboard_device",
        return_value=OnboardOutcome(outcome),
    ) as onboard:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == reason
    assert onboard.call_args.kwargs["request_host_update"] is False
    strings = json.loads(
        (
            Path(__file__).parents[2] / "custom_components/tapo_onboard/strings.json"
        ).read_text()
    )
    assert reason in strings["config"]["abort"]


async def test_discovery_model_is_sanitised(hass: HomeAssistant) -> None:
    entry = _account(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_INTEGRATION_DISCOVERY},
        data={
            "host": "10.0.0.5",
            "mac": STUB_MAC,
            "model": "[click](https://evil.example)\n**P110**" + "x" * 80,
            "entry_id": entry.entry_id,
        },
    )
    model = result["description_placeholders"]["model"]
    assert set(model) <= set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._()/+-"
    )
    assert len(model) == 40
    assert model.startswith("click(https//evil.example)P110")
    flow = hass.config_entries.flow.async_get(result["flow_id"])
    assert flow is not None
    assert flow["context"]["title_placeholders"]["model"] == model


async def test_discovery_empty_model_and_bad_host(hass: HomeAssistant) -> None:
    entry = _account(hass)
    info = {"host": "10.0.0.5", "mac": STUB_MAC, "entry_id": entry.entry_id}
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_INTEGRATION_DISCOVERY},
        data={**info, "model": "<>*"},
    )
    assert result["description_placeholders"]["model"] == "Tapo device"
    bad = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_INTEGRATION_DISCOVERY},
        data={**info, "mac": MAC_PARTIAL, "host": "[x](y)", "model": "P110"},
    )
    assert bad["type"] == FlowResultType.ABORT
    assert bad["reason"] == "cannot_connect"


async def test_discovery_ignored_mac_aborts(hass: HomeAssistant) -> None:
    entry = _account(hass)
    MockConfigEntry(
        domain=DOMAIN, unique_id=format_mac(STUB_MAC), source=SOURCE_IGNORE, data={}
    ).add_to_hass(hass)
    result = await _discover(hass, entry.entry_id)
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_discovery_mac_in_tplink_aborts(hass: HomeAssistant) -> None:
    entry = _account(hass)
    MockConfigEntry(
        domain="tplink", unique_id=format_mac(STUB_MAC), data={"host": "10.0.0.5"}
    ).add_to_hass(hass)
    result = await _discover(hass, entry.entry_id)
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def _moved(
    hass: HomeAssistant,
    entry_id: str,
    mac: str = STUB_MAC,
    host: str = "10.0.0.5",
) -> ConfigFlowResult:
    return await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_INTEGRATION_DISCOVERY},
        data={
            "kind": "moved",
            "host": host,
            "mac": mac,
            "model": "P110",
            "entry_id": entry_id,
        },
    )


def _lost_tplink(hass: HomeAssistant) -> MockConfigEntry:
    tp = MockConfigEntry(
        domain="tplink", unique_id=format_mac(STUB_MAC), data={"host": "10.0.0.4"}
    )
    tp.add_to_hass(hass)
    return tp


async def test_moved_card_asks_nothing_and_has_own_unique_id(
    hass: HomeAssistant,
) -> None:
    entry = _account(hass)
    _lost_tplink(hass)
    result = await _moved(hass, entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "moved_confirm"
    assert result["data_schema"] is None
    assert result["description_placeholders"] == {"model": "P110", "host": "10.0.0.5"}
    flow = hass.config_entries.flow.async_get(result["flow_id"])
    assert flow is not None
    assert flow["context"]["unique_id"] == f"moved-{format_mac(STUB_MAC)}"
    assert flow["context"]["title_placeholders"] == {
        "model": "P110",
        "host": "10.0.0.5",
    }
    again = await _moved(hass, entry.entry_id)
    assert again["type"] == FlowResultType.ABORT
    assert again["reason"] == "already_in_progress"


async def test_moved_card_not_blocked_by_ignored_new_device_card(
    hass: HomeAssistant,
) -> None:
    entry = _account(hass)
    _lost_tplink(hass)
    MockConfigEntry(
        domain=DOMAIN, unique_id=format_mac(STUB_MAC), source=SOURCE_IGNORE, data={}
    ).add_to_hass(hass)
    result = await _moved(hass, entry.entry_id)
    assert result["type"] == FlowResultType.FORM


async def test_moved_confirm_hands_off_to_tplink(hass: HomeAssistant) -> None:
    entry = _account(hass)
    tp = _lost_tplink(hass)
    result = await _moved(hass, entry.entry_id)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    await hass.async_block_till_done()
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "device_moved"
    assert tp.data["host"] == "10.0.0.5"
    assert [i.ip for i in StubTplinkFlow.dhcp_infos] == ["10.0.0.5"]


@pytest.mark.parametrize(
    ("host", "mismatch", "reason"),
    [
        ("10.0.0.5", True, "identity_mismatch"),
        ("10.0.0.99", False, "cannot_connect"),
    ],
)
async def test_moved_confirm_failure_reasons(
    hass: HomeAssistant, host: str, mismatch: bool, reason: str
) -> None:
    entry = _account(hass)
    _lost_tplink(hass)
    if mismatch:
        PROBE_AS[host] = MAC_PARTIAL
    result = await _moved(hass, entry.entry_id, host=host)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == reason
    assert StubTplinkFlow.dhcp_infos == []


async def test_moved_card_without_tplink_entry_aborts(hass: HomeAssistant) -> None:
    entry = _account(hass)
    result = await _moved(hass, entry.entry_id)
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.parametrize("case", ["missing", "unloaded"])
async def test_moved_confirm_account_not_running_aborts(
    hass: HomeAssistant, case: str
) -> None:
    entry = _account(hass, loaded=case != "unloaded")
    _lost_tplink(hass)
    result = await _moved(hass, "missing" if case == "missing" else entry.entry_id)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "password_needed"
    assert StubTplinkFlow.dhcp_infos == []


async def _local_pick_run(
    hass: HomeAssistant, macs: list[str]
) -> tuple[ConfigFlowResult, dict[str, str]]:
    """Sweep 3 owned devices, tick `macs`, return the final result and ids."""
    replies = [
        _tdp(STUB_MAC, HOSTS[STUB_MAC], EMAIL),
        _tdp(MAC_PARTIAL, HOSTS[MAC_PARTIAL], EMAIL),
        _tdp(MAC_UNSUP, HOSTS[MAC_UNSUP], EMAIL),
    ]
    p1, p2, p3 = _patched(replies)
    with p1, p2, p3:  # type: ignore[attr-defined]
        result = await _local_sweep(hass)
        assert result["step_id"] == "pick_devices"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"devices": macs}
        )
        result = await _drive(hass, result)
        await hass.async_block_till_done()
    return result, {}


@contextmanager
def _reject_hosts(hosts: set[str]) -> Iterator[None]:
    """Make the stub tplink flow reject the password only for `hosts`."""
    original = StubTplinkFlow.async_step_user_auth_confirm

    async def _step(
        self: StubTplinkFlow, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None and self._host in hosts:
            return self.async_show_form(
                step_id="user_auth_confirm", errors={"password": "invalid_auth"}
            )
        return await original(self, user_input)

    with patch.object(StubTplinkFlow, "async_step_user_auth_confirm", _step):
        yield


def _dhcp_hosts() -> list[str]:
    return sorted(i.ip for i in StubTplinkFlow.dhcp_infos)


async def test_local_two_rejections_stop_run_and_return_to_form(
    hass: HomeAssistant,
) -> None:
    StubTplinkFlow.connect_result = "auth"
    StubTplinkFlow.valid_password = "other"
    attempted: list[str] = []
    original = StubTplinkFlow.async_step_user

    async def _spy(
        self: StubTplinkFlow, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            attempted.append(user_input["host"])
        return await original(self, user_input)

    with patch.object(StubTplinkFlow, "async_step_user", _spy):
        result, _ = await _local_pick_run(hass, [STUB_MAC, MAC_PARTIAL, MAC_UNSUP])
    assert attempted == [HOSTS[STUB_MAC], HOSTS[MAC_PARTIAL]]
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "local"
    assert result["errors"] == {"base": "password_rejected"}
    schema = cast("vol.Schema", result["data_schema"]).schema
    defaults = {str(k): k.default() for k in schema if k.default is not vol.UNDEFINED}
    assert defaults == {"username": EMAIL, "subnets": "10.0.0.0/24"}
    assert not hass.config_entries.async_entries(DOMAIN)
    assert not hass.config_entries.async_entries("tplink")
    assert StubTplinkFlow.dhcp_infos == []
    assert not hass.data.get(DOMAIN, {}).get(DATA_PENDING_PASSWORD)
    # Retrying with the right password reaches the pick step again.
    StubTplinkFlow.valid_password = PASSWORD
    reply = _tdp(STUB_MAC, HOSTS[STUB_MAC], EMAIL)

    async def _slow_sweep(networks: list[str], *, query: bytes) -> list[TdpInfo]:
        await asyncio.sleep(0)  # not instant, as a real UDP sweep never is
        return [reply]

    with (
        patch("homeassistant.components.network.async_get_adapters", return_value=[]),
        patch("custom_components.tapo_onboard.config_flow.async_sweep", _slow_sweep),
        patch("custom_components.tapo_onboard.sweep.async_sweep", _slow_sweep),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"username": EMAIL, "password": PASSWORD, "subnets": "10.0.0.0/24"},
        )
        result = await _drive(hass, result)
        assert result["step_id"] == "pick_devices"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"devices": [STUB_MAC]}
        )
        result = await _drive(hass, result)
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["description_placeholders"]["added"] == "1"  # type: ignore[index]


async def test_local_added_then_two_rejections_runs_all_and_requests_updates(
    hass: HomeAssistant,
) -> None:
    StubTplinkFlow.connect_result = "auth"
    with _reject_hosts({HOSTS[MAC_PARTIAL], HOSTS[MAC_UNSUP]}):
        result, _ = await _local_pick_run(hass, [STUB_MAC, MAC_PARTIAL, MAC_UNSUP])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["description_placeholders"]["added"] == "1"  # type: ignore[index]
    assert result["description_placeholders"]["confirm"] == "2"  # type: ignore[index]
    assert _dhcp_hosts() == sorted([HOSTS[MAC_PARTIAL], HOSTS[MAC_UNSUP]])


async def test_local_single_rejection_continues_and_requests_update(
    hass: HomeAssistant,
) -> None:
    StubTplinkFlow.connect_result = "auth"
    with _reject_hosts({HOSTS[STUB_MAC]}):
        result, _ = await _local_pick_run(hass, [STUB_MAC, MAC_PARTIAL, MAC_UNSUP])
    assert result["type"] == FlowResultType.CREATE_ENTRY
    ph = result["description_placeholders"]
    assert ph is not None
    assert (ph["added"], ph["confirm"]) == ("2", "1")
    assert _dhcp_hosts() == [HOSTS[STUB_MAC]]


async def test_cloud_two_rejections_do_not_stop_run(hass: HomeAssistant) -> None:
    StubTplinkFlow.connect_result = "auth"
    with _reject_hosts({HOSTS[STUB_MAC], HOSTS[MAC_PARTIAL]}):
        result = await _run(hass, [STUB_MAC, MAC_PARTIAL, MAC_UNSUP])
    ph = result["description_placeholders"]
    assert ph is not None
    assert (ph["added"], ph["confirm"]) == ("1", "2")
    assert [e.unique_id for e in hass.config_entries.async_entries("tplink")] == [
        format_mac(MAC_UNSUP)
    ]
    # Cloud mode keeps the immediate host-update flow per rejected device.
    assert _dhcp_hosts() == sorted([HOSTS[STUB_MAC], HOSTS[MAC_PARTIAL]])
