# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py
# (docs/RESEARCH.md §3.3, §11.2-11.3)
"""Tests for cloud models and the error taxonomy (synthetic fixtures)."""

import base64

import pytest
from tapolink_proto.cloud import (
    AppVersionTooOld,
    CloudAuthError,
    CloudDevice,
    CloudError,
    CloudRateLimited,
    CloudResponseError,
    DeviceDetails,
    DeviceOffline,
    LoginResult,
    TokenExpired,
    raise_for_error_code,
)


def _entry(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "deviceId": "AA" * 20,
        "alias": base64.b64encode(b"Desk Lamp").decode(),
        "deviceMac": "0A0B0C0D0E0F",
        "deviceModel": "L730-6(US)",
        "deviceName": "L730",
        "deviceType": "SMART.TAPOBULB",
        "deviceHwVer": "1.0",
        "fwVer": "1.2.3",
        "deviceRegion": "us-east-1",
        "role": 0,
        "status": 0,
    }
    base.update(over)
    return base


def test_mac_from_device_mac_and_mac() -> None:
    assert CloudDevice.from_api(_entry()).mac == "0a:0b:0c:0d:0e:0f"
    older = _entry(mac="0A0B0C0D0E0F")
    del older["deviceMac"]
    assert CloudDevice.from_api(older).mac == "0a:0b:0c:0d:0e:0f"


def test_alias_decoded_and_fallback() -> None:
    assert CloudDevice.from_api(_entry()).alias == "Desk Lamp"
    assert CloudDevice.from_api(_entry(alias="Lamp")).alias == "Lamp"
    assert CloudDevice.from_api(_entry(alias="not base64!")).alias == "not base64!"


def test_model_base() -> None:
    assert CloudDevice.from_api(_entry()).model_base == "L730"
    d = _entry()
    del d["deviceName"]
    assert CloudDevice.from_api(d).model_base == "L730"
    d["deviceModel"] = "P110(EU)"
    assert CloudDevice.from_api(d).model_base == "P110"


@pytest.mark.parametrize(
    ("region", "code"),
    [("us-east-1", "use1"), ("eu-west-1", "euw1"), ("ap-southeast-1", "aps1")],
)
def test_region_code(region: str, code: str) -> None:
    dev = CloudDevice.from_api(_entry(deviceRegion=region))
    assert dev.region == region
    assert dev.region_code == code


def test_region_absent() -> None:
    d = _entry()
    del d["deviceRegion"]
    assert CloudDevice.from_api(d).region_code is None


def test_from_api_errors() -> None:
    d = _entry()
    del d["deviceId"]
    with pytest.raises(CloudResponseError):
        CloudDevice.from_api(d)
    with pytest.raises(CloudResponseError):
        CloudDevice.from_api(_entry(deviceMac="ZZ0B0C0D0E0F"))
    with pytest.raises(CloudResponseError):
        CloudDevice.from_api(_entry(deviceMac="0A0B"))
    m = _entry()
    del m["deviceMac"]
    with pytest.raises(CloudResponseError):
        CloudDevice.from_api(m)


def test_details_ip_filtering() -> None:
    keep = DeviceDetails.from_api({"ip": "192.168.1.50", "ssid": "net", "fwVer": "1"})
    assert (keep.ip, keep.ssid, keep.fw_ver) == ("192.168.1.50", "net", "1")
    assert DeviceDetails.from_api({"ip": "8.8.8.8"}).ip is None
    assert DeviceDetails.from_api({"ip": "garbage"}).ip is None
    assert DeviceDetails.from_api({}).ip is None


def test_login_result() -> None:
    r = LoginResult.from_api({"token": "t", "refreshToken": "r", "accountId": 7})
    assert (r.token, r.refresh_token, r.account_id) == ("t", "r", 7)
    with pytest.raises(CloudResponseError):
        LoginResult.from_api({})


def test_ok_code_does_nothing() -> None:
    raise_for_error_code(0)


@pytest.mark.parametrize(
    ("code", "exc"),
    [
        (-20600, CloudAuthError),
        (-20601, CloudAuthError),
        (-20651, TokenExpired),
        (-20004, CloudRateLimited),
        (-20571, DeviceOffline),
        (-23003, AppVersionTooOld),
        (-20103, CloudError),
        (-99999, CloudError),
    ],
)
def test_error_mapping(code: int, exc: type[CloudError]) -> None:
    with pytest.raises(exc) as info:
        raise_for_error_code(code, "msg")
    assert type(info.value) is exc
    assert info.value.code == code
    assert info.value.message == "msg"


def test_retry_after() -> None:
    with pytest.raises(CloudRateLimited) as info:
        raise_for_error_code(-20004, "slow", {"lockedMinutes": 5})
    assert info.value.retry_after == 300.0
    with pytest.raises(CloudRateLimited) as nested:
        raise_for_error_code(-20004, "slow", {"result": {"lockedMinutes": 2}})
    assert nested.value.retry_after == 120.0
    with pytest.raises(CloudRateLimited) as none:
        raise_for_error_code(-20004)
    assert none.value.retry_after is None
