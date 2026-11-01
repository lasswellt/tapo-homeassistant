# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the config flow (fake cloud client, stub tplink)."""

from __future__ import annotations

import hashlib
import ssl
from collections.abc import Iterator
from typing import cast
from unittest.mock import patch

import pytest
import voluptuous as vol
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.device_registry import format_mac
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockModule,
    mock_integration,
)
from stub_tplink import STUB_MAC, stub_tplink
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudDevice,
    CloudRateLimited,
    CloudSession,
    CloudUnavailable,
    DeviceDetails,
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


DEVICES = [
    _dev(STUB_MAC, "Alpha", "P110"),
    _dev(MAC_PARTIAL, "Bravo", "L730"),
    _dev(MAC_UNSUP, "Charlie", "S310D"),
    _dev(MAC_ALREADY, "Delta", "P110"),
]


class FakeCloudClient:
    """Scripted CloudClient (public-method boundary only)."""

    devices: list[CloudDevice] = DEVICES
    login_error: Exception | None = None
    submit_error: Exception | None = None
    mfa: bool = False

    def __init__(self, session: object, *, ssl_context: object, terminal_uuid: str):
        self.terminal_uuid = terminal_uuid

    async def login(self, username: str, password: str) -> CloudSession:
        if self.login_error:
            raise self.login_error
        if self.mfa:
            raise MfaRequired("proc-1")
        return CloudSession("tok", "ref", 42)

    async def request_mfa_code(self, username: str, password: str) -> None:
        return None

    async def submit_mfa_code(
        self, username: str, process_id: str, code: str
    ) -> CloudSession:
        if self.submit_error:
            raise self.submit_error
        assert process_id == "proc-1"
        return CloudSession("tok", "ref", 42)

    async def list_devices(self, session: CloudSession) -> list[CloudDevice]:
        return self.devices

    async def device_details(
        self, session: CloudSession, device: CloudDevice
    ) -> DeviceDetails:
        return DeviceDetails(ip="10.0.0.5", ssid=None, fw_ver=None)


@pytest.fixture(autouse=True)
def probe() -> Iterator[None]:
    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return TdpInfo.from_result(
            {
                "device_id": hashlib.md5(f"id-{STUB_MAC}".encode()).hexdigest().upper(),
                "mac": STUB_MAC,
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
    base = "custom_components.tapo_onboard.config_flow"
    # Manifest depends on core `dhcp`, whose optional deps are not installed.
    mock_integration(hass, MockModule("dhcp"))
    with (
        stub_tplink(hass),
        patch(f"{base}.CloudClient", FakeCloudClient),
        patch(
            f"{base}.build_cloud_ssl_context",
            lambda: ssl.create_default_context(),
        ),
    ):
        yield FakeCloudClient


async def _start(hass: HomeAssistant) -> ConfigFlowResult:
    return await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})


async def _login(hass: HomeAssistant) -> ConfigFlowResult:
    result = await _start(hass)
    return await hass.config_entries.flow.async_configure(
        result["flow_id"], {"username": EMAIL, "password": PASSWORD}
    )


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
    # stub tplink: first device added; the second hits the same host (aborts).
    tplink = hass.config_entries.async_entries("tplink")
    assert any(e.data == {"host": "10.0.0.5"} for e in tplink)


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
    assert result["step_id"] == "user"
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
