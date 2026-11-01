# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py
# (docs/RESEARCH.md §3.3, §11.2-11.3)
"""Value objects for cloud device listings and details.

The legacy ``status`` field is not online state and is deliberately ignored.
"""

import base64
import binascii
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tapolink_proto.cloud.errors import CloudResponseError

_MAC_RE = re.compile(r"[0-9a-f]{12}")


def _opt_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) and value else None


def _decode_alias(raw: str) -> str:
    try:
        text = base64.b64decode(raw, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return raw
    return text if text and text.isprintable() else raw


def _normalise_mac(raw: str) -> str:
    digits = re.sub(r"[:\-\s]", "", raw).lower()
    if not _MAC_RE.fullmatch(digits):
        raise CloudResponseError("device MAC is not 12 hex digits")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


@dataclass(frozen=True, slots=True)
class CloudDevice:
    """One entry of ``getDeviceListByPage``."""

    device_id: str
    mac: str
    alias: str
    model: str
    model_base: str
    device_type: str
    hw_ver: str
    fw_ver: str
    region: str | None
    role: int | None

    @property
    def region_code(self) -> str | None:
        """``us-east-1`` -> ``use1``; None when region is absent or malformed."""
        if self.region is None:
            return None
        parts = self.region.split("-")
        if len(parts) < 3:
            return None
        return parts[0] + parts[1][0] + parts[-1]

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> "CloudDevice":
        """Build from a raw API entry.

        Raises:
            CloudResponseError: deviceId or MAC missing, or MAC malformed.
        """
        device_id = _opt_str(data, "deviceId")
        if device_id is None:
            raise CloudResponseError("device entry has no deviceId")
        raw_mac = _opt_str(data, "deviceMac") or _opt_str(data, "mac")
        if raw_mac is None:
            raise CloudResponseError("device entry has no MAC")
        model = _opt_str(data, "deviceModel") or ""
        model_base = _opt_str(data, "deviceName") or re.split(r"[-(]", model)[0]
        role = data.get("role")
        return cls(
            device_id=device_id,
            mac=_normalise_mac(raw_mac),
            alias=_decode_alias(_opt_str(data, "alias") or ""),
            model=model,
            model_base=model_base,
            device_type=_opt_str(data, "deviceType") or "",
            hw_ver=_opt_str(data, "deviceHwVer") or "",
            fw_ver=_opt_str(data, "fwVer") or "",
            region=_opt_str(data, "deviceRegion"),
            role=role if isinstance(role, int) and not isinstance(role, bool) else None,
        )


@dataclass(frozen=True, slots=True)
class DeviceDetails:
    """Subset of ``things/<id>/details`` needed for onboarding."""

    ip: str | None
    ssid: str | None
    fw_ver: str | None

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> "DeviceDetails":
        """Build from raw details; ``ip`` kept only if a private IPv4."""
        ip: str | None = None
        raw_ip = data.get("ip")
        if isinstance(raw_ip, str):
            try:
                if ipaddress.IPv4Address(raw_ip).is_private:
                    ip = raw_ip
            except ipaddress.AddressValueError:
                ip = None
        return cls(ip=ip, ssid=_opt_str(data, "ssid"), fw_ver=_opt_str(data, "fwVer"))


@dataclass(frozen=True, slots=True)
class LoginResult:
    """Result of a successful login."""

    token: str
    refresh_token: str | None
    account_id: int | None

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> "LoginResult":
        """Build from the login ``result`` object.

        Raises:
            CloudResponseError: token missing.
        """
        token = _opt_str(data, "token")
        if token is None:
            raise CloudResponseError("login response has no token")
        account_id = data.get("accountId")
        return cls(
            token=token,
            refresh_token=_opt_str(data, "refreshToken"),
            account_id=account_id if isinstance(account_id, int) else None,
        )
