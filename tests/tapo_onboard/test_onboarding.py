# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the tplink onboarding bridge (against a stub tplink flow)."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Iterator
from contextlib import AbstractContextManager
from types import ModuleType
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_DHCP
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry
from stub_tplink import STUB_MAC, StubTplinkFlow, stub_tplink
from tapolink_proto.discovery import TdpInfo

HOST = "192.168.1.50"
CLOUD_ID = "cloud-device-id"


def _tdp(cloud_id: str, mac: str = STUB_MAC) -> TdpInfo:
    info = TdpInfo.from_result(
        {"device_id": hashlib.md5(cloud_id.encode()).hexdigest().upper(), "mac": mac}  # noqa: S324
    )
    assert info is not None
    return info


@pytest.fixture(autouse=True)
def probe() -> Iterator[None]:
    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return _tdp(CLOUD_ID)

    with patch("custom_components.tapo_onboard.onboarding.async_probe", _fake):
        yield


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
        hass,
        host=HOST,
        mac=STUB_MAC,
        device_id=CLOUD_ID,
        username="u@example.com",
        password=password,
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


def _probe_returns(info: TdpInfo | None) -> AbstractContextManager[object]:
    async def _fake(host: str, *, query: bytes, **_: object) -> TdpInfo | None:
        return info

    return patch("custom_components.tapo_onboard.onboarding.async_probe", _fake)


async def test_identity_mismatch_device_id(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    with _probe_returns(_tdp("some-other-device")):
        assert await _onboard(onb, hass) is onb.OnboardOutcome.IDENTITY_MISMATCH
    await hass.async_block_till_done()
    assert hass.config_entries.flow.async_progress_by_handler("tplink") == []
    assert hass.config_entries.async_entries("tplink") == []
    assert stub.dhcp_infos == []


async def test_identity_mismatch_mac(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    with _probe_returns(_tdp(CLOUD_ID, mac="11:22:33:44:55:66")):
        assert await _onboard(onb, hass) is onb.OnboardOutcome.IDENTITY_MISMATCH
    await hass.async_block_till_done()
    assert hass.config_entries.flow.async_progress_by_handler("tplink") == []
    assert hass.config_entries.async_entries("tplink") == []


async def test_no_reply_handed_to_user_without_credentials(
    hass: HomeAssistant, onb: ModuleType, stub: type[StubTplinkFlow]
) -> None:
    stub.connect_result = "auth"
    with _probe_returns(None):
        assert await _onboard(onb, hass) is onb.OnboardOutcome.HANDED_TO_USER
    await hass.async_block_till_done()
    flows = hass.config_entries.flow.async_progress_by_handler("tplink")
    assert [f["context"]["source"] for f in flows] == [SOURCE_DHCP]
    assert [f["step_id"] for f in flows] != ["user_auth_confirm"]
    assert hass.config_entries.async_entries("tplink") == []


async def test_verify_identity_results(hass: HomeAssistant, onb: ModuleType) -> None:
    async def _verify() -> object:
        return await onb.async_verify_identity(
            hass, host=HOST, mac=STUB_MAC, device_id=CLOUD_ID
        )

    with _probe_returns(_tdp(CLOUD_ID)):
        assert await _verify() is onb.IdentityResult.VERIFIED
    with _probe_returns(_tdp("x")):
        assert await _verify() is onb.IdentityResult.MISMATCH
    with _probe_returns(None):
        assert await _verify() is onb.IdentityResult.NO_REPLY


async def test_tdp_query_built_once(hass: HomeAssistant, onb: ModuleType) -> None:
    calls: list[int] = []

    def _build() -> bytes:
        calls.append(1)
        return b"query"

    with patch("custom_components.tapo_onboard.onboarding.build_query", _build):
        assert await onb.async_get_tdp_query(hass) == b"query"
        assert await onb.async_get_tdp_query(hass) == b"query"
    assert len(calls) == 1
