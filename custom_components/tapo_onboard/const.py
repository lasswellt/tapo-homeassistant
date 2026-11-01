# SPDX-License-Identifier: Apache-2.0
# Provenance: original (docs/plans/core-tplink-onboarding-helper/plan.md)
"""Constants for the Tapo Cloud Onboarding integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Final

DOMAIN: Final = "tapo_onboard"
TPLINK_DOMAIN: Final = "tplink"

INVENTORY_INTERVAL: Final = timedelta(minutes=30)

CONF_TERMINAL_UUID: Final = "terminal_uuid"
CONF_TOKEN: Final = "token"
CONF_REFRESH_TOKEN: Final = "refresh_token"
CONF_ACCOUNT_ID: Final = "account_id"
CONF_IGNORED_MACS: Final = "ignored_macs"

# hass.data key for the in-memory password handoff from the flow to setup.
DATA_PENDING_PASSWORD: Final = "pending_password"

LOGGER: Final = logging.getLogger(__package__)

# The S310D is a BLE-mesh companion switch with no `on_off` component
# (RESEARCH section 11.6), so core's tplink cannot drive it.
UNSUPPORTED_IN_CORE_MODELS: Final[frozenset[str]] = frozenset({"S310D"})

# Core models the L730 as a plug with two child lights.
PARTIAL_IN_CORE_MODELS: Final[frozenset[str]] = frozenset({"L730"})
