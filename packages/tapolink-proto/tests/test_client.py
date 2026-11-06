# SPDX-License-Identifier: Apache-2.0
# Provenance: original, tests for tapolink_proto.cloud.client
"""CloudClient tests against a local TLS aiohttp server.

The real cloud hostnames are routed to a loopback server by a custom resolver
that refuses every other host. The server presents a self-signed certificate
that the client context trusts, so TLS and hostname verification stay on, and
it records each request for the call-count and header assertions.
"""

from __future__ import annotations

import datetime
import json
import socket
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp import web
from aiohttp.abc import AbstractResolver, ResolveResult
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
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

pytestmark = pytest.mark.usefixtures("socket_enabled")

CLOUD_HOSTS = ("*.tplinkcloud.com", "*.iot.i.tplinknbu.com")
IOT_HOST = "use1-app-server.iot.i.tplinknbu.com"


def _is_cloud_host(host: str) -> bool:
    return host.endswith((".tplinkcloud.com", ".iot.i.tplinknbu.com"))


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Self-signed CA+server certificate whose SANs cover every cloud host."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tapolink-test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in CLOUD_HOSTS]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("cloud-tls")
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class FakeResolver(AbstractResolver):
    """Routes cloud hostnames to the local server; refuses everything else."""

    def __init__(self, port: int) -> None:
        self._port = port
        self.lookups: list[str] = []

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        self.lookups.append(host)
        if not _is_cloud_host(host):
            raise OSError(f"unexpected host {host}")
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": self._port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        return None


@dataclass(frozen=True, slots=True)
class Recorded:
    method: str
    host: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: str


@dataclass(slots=True)
class _Reply:
    payload: Any = None
    status: int = 200
    body: str | None = None
    drop: bool = False


@dataclass(slots=True)
class FakeCloud:
    """Scripted cloud endpoints; unscripted requests get 599 and are recorded."""

    requests: list[Recorded] = field(default_factory=list)
    routes: dict[tuple[str, str], list[_Reply]] = field(default_factory=dict)
    repeating: set[tuple[str, str]] = field(default_factory=set)
    port: int = 0

    def script(
        self,
        method: str,
        path: str,
        reply: _Reply,
        repeat: bool,
    ) -> None:
        key = (method, "/" + path.lstrip("/"))
        self.routes.setdefault(key, []).append(reply)
        if repeat:
            self.repeating.add(key)

    def post(
        self,
        path: str,
        payload: Any = None,
        *,
        status: int = 200,
        body: str | None = None,
        drop: bool = False,
        repeat: bool = False,
    ) -> None:
        self.script("POST", path, _Reply(payload, status, body, drop), repeat)

    def get(self, path: str, payload: Any = None, *, repeat: bool = False) -> None:
        self.script("GET", path, _Reply(payload), repeat)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        self.requests.append(
            Recorded(
                request.method,
                request.headers.get("Host", ""),
                request.path,
                dict(request.query),
                dict(request.headers),
                await request.text(),
            )
        )
        key = (request.method, request.path)
        queue = self.routes.get(key)
        if not queue:
            return web.Response(status=599, text="unscripted request")
        reply = queue[0] if key in self.repeating else queue.pop(0)
        if reply.drop:
            assert request.transport is not None
            request.transport.close()
            return web.Response(status=599)
        if reply.body is not None:
            return web.Response(status=reply.status, text=reply.body)
        return web.json_response(reply.payload, status=reply.status)


@pytest.fixture
async def cloud(cert_files: tuple[Path, Path]) -> AsyncIterator[FakeCloud]:
    fake = FakeCloud()
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", fake.handle)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(*cert_files)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_ctx)
    await site.start()
    fake.port = runner.addresses[0][1]
    try:
        yield fake
    finally:
        await runner.cleanup()


@pytest.fixture
async def resolver(cloud: FakeCloud) -> FakeResolver:
    return FakeResolver(cloud.port)


@pytest.fixture
async def client(
    cloud: FakeCloud, resolver: FakeResolver, cert_files: tuple[Path, Path]
) -> AsyncIterator[CloudClient]:
    ctx = ssl.create_default_context(cafile=str(cert_files[0]))
    connector = aiohttp.TCPConnector(resolver=resolver)
    async with aiohttp.ClientSession(connector=connector) as session:
        yield CloudClient(session, ssl_context=ctx, terminal_uuid="T-UUID")


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
LIST = "api/v2/common/getDeviceListByPage"
LOGIN = "api/v2/account/login"


async def test_login_success(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(
        LOGIN,
        {
            "error_code": 0,
            "result": {"token": "tok", "refreshToken": "ref", "accountId": 7},
        },
    )
    assert await client.login("Me@Example.COM", "pw") == SESSION
    call = cloud.requests[0]
    body = json.loads(call.body)
    assert body["cloudUserName"] == "me@example.com"
    assert body["terminalName"] == "Home Assistant"
    assert "X-Authorization" in call.headers


async def test_login_mfa_required(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(LOGIN, {"error_code": 0, "result": {"MFAProcessId": "proc1"}})
    with pytest.raises(MfaRequired) as exc:
        await client.login("a@b.c", "pw")
    assert exc.value.process_id == "proc1"


async def test_login_bad_password(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(LOGIN, {"error_code": -20601, "msg": "x"})
    with pytest.raises(CloudAuthError):
        await client.login("a@b.c", "bad")


async def test_submit_mfa_code(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(
        "api/v2/account/checkMFACodeAndLogin",
        {"error_code": 0, "result": {"token": "t2", "refreshToken": "r2"}},
    )
    got = await client.submit_mfa_code("a@b.c", "proc1", "123456")
    assert got == CloudSession("t2", "r2", None)


async def test_request_mfa_code(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post("api/v2/account/getEmailVC4TerminalMFA", {"error_code": 0})
    await client.request_mfa_code("a@b.c", "pw")


async def test_refresh_keeps_refresh_token(
    cloud: FakeCloud, client: CloudClient
) -> None:
    cloud.post(
        "api/v2/account/refreshToken",
        {"error_code": 0, "result": {"token": "new"}},
    )
    assert await client.refresh(SESSION) == CloudSession("new", "ref", 7)


async def test_list_devices_paginates(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(
        LIST,
        {
            "error_code": 0,
            "result": {
                "deviceList": [device(i) for i in range(30)],
                "totalNum": 31,
            },
        },
    )
    cloud.post(
        LIST,
        {
            "error_code": 0,
            "result": {"deviceList": [device(30)], "totalNum": 31},
        },
    )
    devices = await client.list_devices(SESSION)
    assert len(devices) == 31
    assert [json.loads(r.body)["index"] for r in cloud.requests] == [0, 30]


async def test_list_devices_advances_by_entries_returned(
    cloud: FakeCloud, client: CloudClient
) -> None:
    """`index` is an item offset (RESEARCH §11.7): a short page or a
    malformed entry still moves the offset by everything returned."""
    cloud.post(
        LIST,
        {
            "error_code": 0,
            "result": {
                "deviceList": [device(i) for i in range(24)] + ["junk"],
                "totalNum": 27,
            },
        },
    )
    cloud.post(
        LIST,
        {
            "error_code": 0,
            "result": {"deviceList": [device(25), device(26)], "totalNum": 27},
        },
    )
    devices = await client.list_devices(SESSION)
    assert len(devices) == 26
    assert [json.loads(r.body)["index"] for r in cloud.requests] == [0, 25]


async def test_list_devices_stops_at_page_cap(
    cloud: FakeCloud, client: CloudClient, caplog: pytest.LogCaptureFixture
) -> None:
    """A cloud that never reaches its reported total cannot page forever.

    One malformed entry per page makes the devices returned differ from the
    entries seen, so the warning must report the former."""
    cloud.post(
        LIST,
        {
            "error_code": 0,
            "result": {
                "deviceList": [device(i) for i in range(PAGE_LIMIT - 1)] + ["junk"],
                "totalNum": 10**9,
            },
        },
        repeat=True,
    )
    devices = await client.list_devices(SESSION)
    assert len(cloud.requests) == MAX_PAGES
    assert len(devices) == MAX_PAGES * (PAGE_LIMIT - 1) == 2900
    assert "still incomplete after 100 pages" in caplog.text
    assert "using the 2900 devices listed" in caplog.text


async def test_rate_limited(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(
        LIST,
        {"error_code": -20004, "msg": "limit", "result": {"lockedMinutes": 30}},
    )
    with pytest.raises(CloudRateLimited) as exc:
        await client.list_devices(SESSION)
    assert exc.value.retry_after == 1800


async def test_device_details(cloud: FakeCloud, client: CloudClient) -> None:
    dev = CloudDevice.from_api(device(1))
    cloud.get(
        "/v1/things/0000000000000000000000000000000000000001/details",
        {"ip": "192.168.1.20", "ssid": "home", "fwVer": "1.2"},
    )
    details = await client.device_details(SESSION, dev)
    assert details.ip == "192.168.1.20"
    assert cloud.requests[0].headers["Authorization"] == "ut|tok"


async def test_list_devices_skips_malformed(
    cloud: FakeCloud, client: CloudClient
) -> None:
    bad = device(2)
    bad["deviceId"] = "not-hex"
    cloud.post(
        LIST,
        {
            "error_code": 0,
            "result": {"deviceList": [device(1), bad, device(3)], "totalNum": 3},
        },
    )
    devices = await client.list_devices(SESSION)
    assert [d.device_id for d in devices] == [f"{1:040X}", f"{3:040X}"]


async def test_malicious_region_uses_default_host(
    cloud: FakeCloud, client: CloudClient, resolver: FakeResolver
) -> None:
    dev = CloudDevice.from_api(device(1, region="evil.com/x-e-1"))
    cloud.get(f"/v1/things/{1:040X}/details", {"ip": "192.168.1.20"})
    await client.device_details(SESSION, dev)
    assert cloud.requests[0].headers["Authorization"] == "ut|tok"
    assert cloud.requests[0].host.startswith(IOT_HOST)
    assert resolver.lookups == [IOT_HOST]
    assert all("evil.com" not in r.host for r in cloud.requests)


async def test_transport_failure(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(LOGIN, drop=True)
    with pytest.raises(CloudUnavailable):
        await client.login("a@b.c", "pw")


async def test_http_500(cloud: FakeCloud, client: CloudClient) -> None:
    cloud.post(LOGIN, status=500, body="boom")
    with pytest.raises(CloudResponseError):
        await client.login("a@b.c", "pw")


async def test_non_numeric_error_code_post(
    cloud: FakeCloud, client: CloudClient
) -> None:
    cloud.post(LOGIN, {"error_code": "abc", "msg": "x"})
    with pytest.raises(CloudResponseError):
        await client.login("a@b.c", "pw")


async def test_non_numeric_error_code_device_details(
    cloud: FakeCloud, client: CloudClient
) -> None:
    dev = CloudDevice.from_api(device(1))
    cloud.get(
        "/v1/things/0000000000000000000000000000000000000001/details",
        {"error_code": "abc"},
    )
    with pytest.raises(CloudResponseError):
        await client.device_details(SESSION, dev)


async def test_refresh_without_token_is_unusable(client: CloudClient) -> None:
    with pytest.raises(RefreshTokenUnusable):
        await client.refresh(CloudSession("tok", None, 7))
