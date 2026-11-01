# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for integration setup, unload and diagnostics."""

from __future__ import annotations

import importlib
import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
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
