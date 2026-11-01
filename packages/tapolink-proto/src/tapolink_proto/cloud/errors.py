# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py
# (docs/RESEARCH.md §3.3, §11.2-11.3)
"""Typed error taxonomy for the TP-Link cloud API."""

from collections.abc import Mapping
from typing import Any


class CloudError(Exception):
    """Base cloud error carrying the API error code and message."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(f"[{code}] {message}" if message else f"[{code}]")
        self.code = code
        self.message = message


class CloudAuthError(CloudError):
    """Account not found (-20600) or invalid email/password (-20601)."""


class TokenExpired(CloudError):
    """Session token expired (-20651)."""


class CloudRateLimited(CloudError):
    """Rate limited (-20004); ``retry_after`` is seconds when known."""

    def __init__(
        self, code: int, message: str = "", retry_after: float | None = None
    ) -> None:
        super().__init__(code, message)
        self.retry_after = retry_after


class DeviceOffline(CloudError):
    """Device offline (-20571)."""


class AppVersionTooOld(CloudError):
    """App version rejected by the cloud (-23003)."""


class CloudResponseError(CloudError):
    """Malformed response or unexpected HTTP status."""

    def __init__(self, message: str = "", code: int = -2) -> None:
        super().__init__(code, message)


class CloudUnavailable(CloudError):
    """Transport or network failure."""

    def __init__(self, message: str = "") -> None:
        super().__init__(-1, message)


class MfaRequired(Exception):
    """Login needs a second factor; ``process_id`` identifies the challenge."""

    def __init__(self, process_id: str) -> None:
        super().__init__("MFA required")
        self.process_id = process_id


def _locked_minutes(payload: Mapping[str, Any] | None) -> float | None:
    if payload is None:
        return None
    value = payload.get("lockedMinutes")
    if value is None:
        nested = payload.get("result")
        if isinstance(nested, Mapping):
            value = nested.get("lockedMinutes")
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) * 60


def raise_for_error_code(
    code: int, message: str = "", payload: Mapping[str, Any] | None = None
) -> None:
    """Raise the mapped ``CloudError`` subclass; return None when ``code`` is 0."""
    if code == 0:
        return
    if code in (-20600, -20601):
        raise CloudAuthError(code, message)
    if code == -20651:
        raise TokenExpired(code, message)
    if code == -20004:
        raise CloudRateLimited(code, message, _locked_minutes(payload))
    if code == -20571:
        raise DeviceOffline(code, message)
    if code == -23003:
        raise AppVersionTooOld(code, message)
    raise CloudError(code, message)
