# SPDX-License-Identifier: Apache-2.0
# Provenance: original, tests for tapolink_proto.cloud.client
"""CloudClient tests; only the HTTP boundary is mocked (aioresponses)."""

import json
import re
import ssl
from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudClient,
    CloudDevice,
    CloudRateLimited,
    CloudResponseError,
    CloudSession,
    CloudUnavailable,
    MfaRequired,
    RefreshTokenUnusable,
)
from tapolink_proto.cloud.client import MAX_PAGES, PAGE_LIMIT

GW = "https://n-wap-gw.tplinkcloud.com"


def url(path: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(GW)}/{re.escape(path)}(\?.*)?$")


class _CompatResponse(aiohttp.ClientResponse):
    """aioresponses 0.7.9 predates aiohttp's required ``stream_writer`` kwarg."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("stream_writer", SimpleNamespace(output_size=0))
        super().__init__(*args, **kwargs)


@pytest.fixture
def mocked(monkeypatch: pytest.MonkeyPatch) -> Iterator[aioresponses]:
    monkeypatch.setattr("aioresponses.core.ClientResponse", _CompatResponse)
    with aioresponses() as m:
        yield m


@pytest.fixture
async def client() -> AsyncIterator[CloudClient]:
    async with aiohttp.ClientSession() as session:
        yield CloudClient(
            session, ssl_context=ssl.create_default_context(), terminal_uuid="T-UUID"
        )


def device(i: int, region: str = "us-east-1") -> dict[str, str]:
    return {
        "deviceId": f"{i:040X}",
        "deviceMac": f"AA-BB-CC-DD-{i // 256:02X}-{i % 256:02X}",
        "deviceModel": "P110(US)",
        "deviceName": "P110",
        "deviceType": "SMART.TAPOPLUG",
        "deviceRegion": region,
    }


SESSION = CloudSession("tok", "ref", 7)


async def test_login_success(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(
        url("api/v2/account/login"),
        payload={
            "error_code": 0,
            "result": {"token": "tok", "refreshToken": "ref", "accountId": 7},
        },
    )
    assert await client.login("Me@Example.COM", "pw") == SESSION
    call = next(iter(mocked.requests.values()))[0]
    body = json.loads(call.kwargs["data"])
    assert body["cloudUserName"] == "me@example.com"
    assert body["terminalName"] == "Home Assistant"
    assert "X-Authorization" in call.kwargs["headers"]


async def test_login_mfa_required(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(
        url("api/v2/account/login"),
        payload={"error_code": 0, "result": {"MFAProcessId": "proc1"}},
    )
    with pytest.raises(MfaRequired) as exc:
        await client.login("a@b.c", "pw")
    assert exc.value.process_id == "proc1"


async def test_login_bad_password(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(url("api/v2/account/login"), payload={"error_code": -20601, "msg": "x"})
    with pytest.raises(CloudAuthError):
        await client.login("a@b.c", "bad")


async def test_submit_mfa_code(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(
        url("api/v2/account/checkMFACodeAndLogin"),
        payload={"error_code": 0, "result": {"token": "t2", "refreshToken": "r2"}},
    )
    got = await client.submit_mfa_code("a@b.c", "proc1", "123456")
    assert got == CloudSession("t2", "r2", None)


async def test_request_mfa_code(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(url("api/v2/account/getEmailVC4TerminalMFA"), payload={"error_code": 0})
    await client.request_mfa_code("a@b.c", "pw")


async def test_refresh_keeps_refresh_token(
    mocked: aioresponses, client: CloudClient
) -> None:
    mocked.post(
        url("api/v2/account/refreshToken"),
        payload={"error_code": 0, "result": {"token": "new"}},
    )
    assert await client.refresh(SESSION) == CloudSession("new", "ref", 7)


async def test_list_devices_paginates(
    mocked: aioresponses, client: CloudClient
) -> None:
    path = "api/v2/common/getDeviceListByPage"
    mocked.post(
        url(path),
        payload={
            "error_code": 0,
            "result": {
                "deviceList": [device(i) for i in range(30)],
                "totalNum": 31,
            },
        },
    )
    mocked.post(
        url(path),
        payload={
            "error_code": 0,
            "result": {"deviceList": [device(30)], "totalNum": 31},
        },
    )
    devices = await client.list_devices(SESSION)
    assert len(devices) == 31
    calls = next(iter(mocked.requests.values()))
    assert [json.loads(c.kwargs["data"])["index"] for c in calls] == [0, 30]


async def test_list_devices_advances_by_entries_returned(
    mocked: aioresponses, client: CloudClient
) -> None:
    """`index` is an item offset (RESEARCH §11.7): a short page or a
    malformed entry still moves the offset by everything returned."""
    path = "api/v2/common/getDeviceListByPage"
    mocked.post(
        url(path),
        payload={
            "error_code": 0,
            "result": {
                "deviceList": [device(i) for i in range(24)] + ["junk"],
                "totalNum": 27,
            },
        },
    )
    mocked.post(
        url(path),
        payload={
            "error_code": 0,
            "result": {"deviceList": [device(25), device(26)], "totalNum": 27},
        },
    )
    devices = await client.list_devices(SESSION)
    assert len(devices) == 26
    calls = next(iter(mocked.requests.values()))
    assert [json.loads(c.kwargs["data"])["index"] for c in calls] == [0, 25]


async def test_list_devices_stops_at_page_cap(
    mocked: aioresponses, client: CloudClient, caplog: pytest.LogCaptureFixture
) -> None:
    """A cloud that never reaches its reported total cannot page forever.

    One malformed entry per page makes the devices returned differ from the
    entries seen, so the warning must report the former."""
    path = "api/v2/common/getDeviceListByPage"
    mocked.post(
        url(path),
        payload={
            "error_code": 0,
            "result": {
                "deviceList": [device(i) for i in range(PAGE_LIMIT - 1)] + ["junk"],
                "totalNum": 10**9,
            },
        },
        repeat=True,
    )
    devices = await client.list_devices(SESSION)
    calls = next(iter(mocked.requests.values()))
    assert len(calls) == MAX_PAGES
    assert len(devices) == MAX_PAGES * (PAGE_LIMIT - 1) == 2900
    assert "still incomplete after 100 pages" in caplog.text
    assert "using the 2900 devices listed" in caplog.text


async def test_rate_limited(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(
        url("api/v2/common/getDeviceListByPage"),
        payload={
            "error_code": -20004,
            "msg": "limit",
            "result": {"lockedMinutes": 30},
        },
    )
    with pytest.raises(CloudRateLimited) as exc:
        await client.list_devices(SESSION)
    assert exc.value.retry_after == 1800


async def test_device_details(mocked: aioresponses, client: CloudClient) -> None:
    dev = CloudDevice.from_api(device(1))
    mocked.get(
        "https://use1-app-server.iot.i.tplinknbu.com/v1/things/0000000000000000000000000000000000000001/details",
        payload={"ip": "192.168.1.20", "ssid": "home", "fwVer": "1.2"},
    )
    details = await client.device_details(SESSION, dev)
    assert details.ip == "192.168.1.20"
    call = next(iter(mocked.requests.values()))[0]
    assert call.kwargs["headers"]["Authorization"] == "ut|tok"


async def test_list_devices_skips_malformed(
    mocked: aioresponses, client: CloudClient
) -> None:
    bad = device(2)
    bad["deviceId"] = "not-hex"
    mocked.post(
        url("api/v2/common/getDeviceListByPage"),
        payload={
            "error_code": 0,
            "result": {"deviceList": [device(1), bad, device(3)], "totalNum": 3},
        },
    )
    devices = await client.list_devices(SESSION)
    assert [d.device_id for d in devices] == [f"{1:040X}", f"{3:040X}"]


async def test_malicious_region_uses_default_host(
    mocked: aioresponses, client: CloudClient
) -> None:
    dev = CloudDevice.from_api(device(1, region="evil.com/x-e-1"))
    mocked.get(
        f"https://use1-app-server.iot.i.tplinknbu.com/v1/things/{1:040X}/details",
        payload={"ip": "192.168.1.20"},
    )
    await client.device_details(SESSION, dev)
    call = next(iter(mocked.requests.values()))[0]
    assert call.kwargs["headers"]["Authorization"] == "ut|tok"
    assert all("evil.com" not in str(k[1]) for k in mocked.requests)


async def test_transport_failure(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(
        url("api/v2/account/login"), exception=aiohttp.ClientConnectionError("down")
    )
    with pytest.raises(CloudUnavailable):
        await client.login("a@b.c", "pw")


async def test_http_500(mocked: aioresponses, client: CloudClient) -> None:
    mocked.post(url("api/v2/account/login"), status=500, body="boom")
    with pytest.raises(CloudResponseError):
        await client.login("a@b.c", "pw")


async def test_non_numeric_error_code_post(
    mocked: aioresponses, client: CloudClient
) -> None:
    mocked.post(url("api/v2/account/login"), payload={"error_code": "abc", "msg": "x"})
    with pytest.raises(CloudResponseError):
        await client.login("a@b.c", "pw")


async def test_non_numeric_error_code_device_details(
    mocked: aioresponses, client: CloudClient
) -> None:
    dev = CloudDevice.from_api(device(1))
    mocked.get(
        "https://use1-app-server.iot.i.tplinknbu.com/v1/things/0000000000000000000000000000000000000001/details",
        payload={"error_code": "abc"},
    )
    with pytest.raises(CloudResponseError):
        await client.device_details(SESSION, dev)


async def test_refresh_without_token_is_unusable(client: CloudClient) -> None:
    with pytest.raises(RefreshTokenUnusable):
        await client.refresh(CloudSession("tok", None, 7))
