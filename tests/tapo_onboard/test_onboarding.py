# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the tplink onboarding bridge (against a stub tplink flow)."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from types import ModuleType

import pytest
from homeassistant.config_entries import SOURCE_DHCP
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry
from stub_tplink import STUB_MAC, StubTplinkFlow, stub_tplink

HOST = "192.168.1.50"


@pytest.fixture
def onb() -> ModuleType:
    # Importable only once the hass fixture has fixed up custom_components.
    return importlib.import_module("custom_components.tapo_onboard.onboarding")


@pytest.fixture
def stub(hass: HomeAssistant) -> Iterator[type[StubTplinkFlow]]:
    with stub_tplink(hass) as flow:
        yield flow


async def _onboard(
    onb: ModuleType, hass: HomeAssistant, password: str = "secret"
) -> object:
    return await onb.async_onboard_device(
        hass, host=HOST, mac=STUB_MAC, username="u@example.com", password=password
    )


async def test_added_without_credentials(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    assert await _onboard(onb, hass) is onb.OnboardOutcome.ADDED
    assert len(hass.config_entries.async_entries("tplink")) == 1


async def test_added_after_auth_confirm(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    stub.connect_result = "auth"
    assert await _onboard(onb, hass) is onb.OnboardOutcome.ADDED
    assert len(hass.config_entries.async_entries("tplink")) == 1


async def test_auth_failed_creates_dhcp_card(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    stub.connect_result = "auth"
    assert await _onboard(onb, hass, password="wrong") is onb.OnboardOutcome.AUTH_FAILED
    await hass.async_block_till_done()
    flows = hass.config_entries.flow.async_progress_by_handler("tplink")
    assert [f["context"]["source"] for f in flows] == [SOURCE_DHCP]
    assert len(hass.config_entries.async_entries("tplink")) == 0


async def test_cannot_connect(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    stub.connect_result = "cannot_connect"
    assert await _onboard(onb, hass) is onb.OnboardOutcome.CANNOT_CONNECT
    await hass.async_block_till_done()
    assert hass.config_entries.flow.async_progress_by_handler("tplink") == []


async def test_already_configured(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    MockConfigEntry(domain="tplink", data={"host": HOST}).add_to_hass(hass)
    assert await _onboard(onb, hass) is onb.OnboardOutcome.ALREADY_CONFIGURED


async def test_camera_handed_to_user(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    stub.connect_result = "camera"
    assert await _onboard(onb, hass) is onb.OnboardOutcome.HANDED_TO_USER
    await hass.async_block_till_done()
    flows = hass.config_entries.flow.async_progress_by_handler("tplink")
    assert [f["context"]["source"] for f in flows] == [SOURCE_DHCP]


async def test_unavailable_without_tplink(hass: HomeAssistant, onb: ModuleType) -> None:
    assert await _onboard(onb, hass) is onb.OnboardOutcome.UNAVAILABLE


async def test_request_host_update_changes_host(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    entry = MockConfigEntry(
        domain="tplink", unique_id=STUB_MAC, data={"host": "192.168.1.10"}
    )
    entry.add_to_hass(hass)
    onb.async_request_host_update(hass, host="192.168.1.99", mac="AA:BB:CC:DD:EE:FF")
    await hass.async_block_till_done()
    assert entry.data["host"] == "192.168.1.99"
    assert len(stub.dhcp_infos) == 1
    assert stub.dhcp_infos[0].macaddress == "aabbccddeeff"


async def test_entry_for_mac_either_format(
    hass: HomeAssistant, onb: ModuleType
) -> None:
    entry = MockConfigEntry(domain="tplink", unique_id=STUB_MAC, data={"host": HOST})
    entry.add_to_hass(hass)
    assert onb.async_tplink_entry_for_mac(hass, "AA-BB-CC-DD-EE-FF") is entry
    assert onb.async_tplink_entry_for_mac(hass, "aabbccddeeff") is entry
    assert onb.async_tplink_entry_for_mac(hass, "11:22:33:44:55:66") is None


async def test_camera_step_after_valid_auth_handed_to_user(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    stub.connect_result = "auth"
    stub.post_auth_camera = True
    assert await _onboard(onb, hass) is onb.OnboardOutcome.HANDED_TO_USER
    await hass.async_block_till_done()
    flows = hass.config_entries.flow.async_progress_by_handler("tplink")
    assert [f["context"]["source"] for f in flows] == [SOURCE_DHCP]
