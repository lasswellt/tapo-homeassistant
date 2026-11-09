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
# Local mode: fixed sweep cadence (matches core tplink's discovery interval) and
# the cadence of the cheap lost-entry check.
SWEEP_INTERVAL: Final = timedelta(minutes=15)
LOST_CHECK_INTERVAL: Final = timedelta(seconds=60)
# Minimum gap between two device_details calls for one device (rule 3).
DETAILS_FLOOR: Final = timedelta(minutes=15)
# Repeated failed lookups for one device double the gap from DETAILS_FLOOR up to
# this cap (a device that is off should not cost a cloud call every cycle).
DETAILS_BACKOFF_MAX: Final = timedelta(hours=2)

CONF_TERMINAL_UUID: Final = "terminal_uuid"
CONF_TOKEN: Final = "token"
CONF_REFRESH_TOKEN: Final = "refresh_token"
CONF_ACCOUNT_ID: Final = "account_id"
CONF_IGNORED_MACS: Final = "ignored_macs"
CONF_MODE: Final = "mode"
MODE_LOCAL: Final = "local"
MODE_CLOUD: Final = "cloud"
CONF_SUBNETS: Final = "subnets"  # list[str] of CIDRs

# hass.data key for the in-memory password handoff from the flow to setup.
DATA_PENDING_PASSWORD: Final = "pending_password"
# hass.data key for the in-memory flow outcomes handed to the coordinator.
DATA_FLOW_RESULT: Final = "flow_result"

LOGGER: Final = logging.getLogger(__package__)

# The S310D is a BLE-mesh companion switch with no `on_off` component
# (RESEARCH section 11.6), so core's tplink cannot drive it.
UNSUPPORTED_IN_CORE_MODELS: Final[frozenset[str]] = frozenset({"S310D"})

# Core models the L730 as a plug with two child lights.
PARTIAL_IN_CORE_MODELS: Final[frozenset[str]] = frozenset({"L730"})
