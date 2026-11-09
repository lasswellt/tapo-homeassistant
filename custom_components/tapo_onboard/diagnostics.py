# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Diagnostics with redaction of every secret and identifier."""

from __future__ import annotations

from collections import Counter
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from tapolink_proto.cloud import CloudError

from . import TapoOnboardConfigEntry
from .const import (
    CONF_ACCOUNT_ID,
    CONF_IGNORED_MACS,
    CONF_REFRESH_TOKEN,
    CONF_TERMINAL_UUID,
    CONF_TOKEN,
)
from .sweep import SweepCoordinator

TO_REDACT = {
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_TERMINAL_UUID,
    CONF_ACCOUNT_ID,
    CONF_IGNORED_MACS,
    "device_id",
    "mac",
    "alias",
    "ip",
    "owner",
}


def _local_diagnostics(
    entry: TapoOnboardConfigEntry, coordinator: SweepCoordinator
) -> dict[str, Any]:
    exc = coordinator.last_exception
    status: dict[str, Any] = {
        "last_update_success": coordinator.last_update_success,
        "last_exception": type(exc).__name__ if exc is not None else None,
    }
    sweep: dict[str, Any] = {}
    state = coordinator.data
    if state is not None:
        devices = list(state.devices.values())
        sweep = {
            "count": len(devices),
            "by_model": dict(Counter(d.device_model for d in devices)),
            "by_encrypt_type": dict(Counter(d.encrypt_type for d in devices)),
            "tpap": len(state.tpap),
            "foreign": state.foreign,
            "outcomes": dict(Counter(o.value for o in state.outcomes.values())),
            "host_updates": len(state.host_updates),
            "devices": [
                {
                    "mac": d.mac,
                    "ip": d.ip,
                    "device_model": d.device_model,
                    "encrypt_type": d.encrypt_type,
                }
                for d in devices
            ],
        }
    return async_redact_data(
        {
            "mode": "local",
            "entry": dict(entry.data),
            "coordinator": status,
            "sweep": sweep,
        },
        TO_REDACT,
    )


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: TapoOnboardConfigEntry
) -> dict[str, Any]:
    """Return redacted diagnostics for the entry."""
    coordinator = entry.runtime_data.coordinator
    if isinstance(coordinator, SweepCoordinator):
        return _local_diagnostics(entry, coordinator)
    exc = coordinator.last_exception
    cause = exc.__cause__ if exc is not None else None
    state = coordinator.data
    status: dict[str, Any] = {
        "last_update_success": coordinator.last_update_success,
        "last_exception": type(exc).__name__ if exc is not None else None,
        "last_cloud_error_code": (
            cause.code if isinstance(cause, CloudError) else None
        ),
    }
    inventory: dict[str, Any] = {}
    if state is not None:
        devices = list(state.devices.values())
        inventory = {
            "count": len(devices),
            "by_device_type": dict(Counter(d.device_type for d in devices)),
            "by_model_base": dict(Counter(d.model_base for d in devices)),
            "outcomes": dict(Counter(o.value for o in state.outcomes.values())),
            "host_updates": len(state.host_updates),
            "devices": [
                {
                    "device_id": d.device_id,
                    "mac": d.mac,
                    "alias": d.alias,
                    "model": d.model,
                    "model_base": d.model_base,
                    "device_type": d.device_type,
                }
                for d in devices
            ],
        }
    return async_redact_data(
        {
            "mode": "cloud",
            "entry": dict(entry.data),
            "coordinator": status,
            "inventory": inventory,
        },
        TO_REDACT,
    )
