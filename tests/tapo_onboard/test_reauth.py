# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Tests for the reauth flow (fake cloud client, no entry reload)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry
from tapolink_proto.cloud import CloudAuthError
from test_config_flow import (
    DATA_PENDING_PASSWORD,
    DOMAIN,
    EMAIL,
    PASSWORD,
    FakeCloudClient,
)
from test_config_flow import (
    fake_cloud as fake_cloud,
)

TERMINAL_UUID = "11111111-2222-3333-4444-555555555555"


def _entry(hass: HomeAssistant, unique_id: str = EMAIL.lower()) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=unique_id,
        data={
            "username": EMAIL,
            "terminal_uuid": TERMINAL_UUID,
            "token": "old",
            "refresh_token": "old-ref",
            "account_id": 1,
            "ignored_macs": [],
        },
    )
    entry.add_to_hass(hass)
    return entry


async def _start(hass: HomeAssistant, entry: MockConfigEntry) -> dict[str, Any]:
    result = await entry.start_reauth_flow(hass)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"
    assert result["description_placeholders"]["username"] == EMAIL
    return result


@pytest.mark.usefixtures("fake_cloud")
async def test_reauth_success(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    seen: list[str] = []
    orig_init = FakeCloudClient.__init__

    def spy(self: FakeCloudClient, session: object, **kw: Any) -> None:
        seen.append(kw["terminal_uuid"])
        orig_init(self, session, **kw)

    with (
        patch.object(FakeCloudClient, "__init__", spy),
        patch.object(hass.config_entries, "async_reload") as reload_mock,
    ):
        result = await _start(hass, entry)
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"password": PASSWORD}
        )
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["token"] == "tok"
    assert entry.data["refresh_token"] == "ref"
    assert entry.data["account_id"] == 42
    assert entry.data["terminal_uuid"] == TERMINAL_UUID
    assert PASSWORD not in str(entry.data)
    assert hass.data[DOMAIN][DATA_PENDING_PASSWORD][EMAIL.lower()] == PASSWORD
    assert seen == [TERMINAL_UUID]
    reload_mock.assert_not_called()


@pytest.mark.usefixtures("fake_cloud")
async def test_reauth_wrong_account(hass: HomeAssistant) -> None:
    entry = _entry(hass, unique_id="other@example.com")
    result = await _start(hass, entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": PASSWORD}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "wrong_account"
    assert entry.data["token"] == "old"


@pytest.mark.usefixtures("fake_cloud")
async def test_reauth_invalid_auth_then_retry(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    result = await _start(hass, entry)
    FakeCloudClient.login_error = CloudAuthError(-20601)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": "bad"}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    FakeCloudClient.login_error = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": PASSWORD}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"


@pytest.mark.usefixtures("fake_cloud")
async def test_reauth_mfa(hass: HomeAssistant) -> None:
    entry = _entry(hass)
    FakeCloudClient.mfa = True
    result = await _start(hass, entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": PASSWORD}
    )
    assert result["step_id"] == "mfa"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"code": "123456"}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["token"] == "tok"
