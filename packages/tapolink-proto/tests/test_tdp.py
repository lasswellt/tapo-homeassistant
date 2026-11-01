# SPDX-License-Identifier: Apache-2.0
"""TDP unicast probe tests (synthetic data, real local UDP responder)."""

from __future__ import annotations

import asyncio
import binascii
import hashlib
import json
import struct
import time
from typing import Any

import pytest
from tapolink_proto.discovery import TdpInfo, async_probe, build_query
from tapolink_proto.discovery.tdp import _parse

pytestmark = pytest.mark.usefixtures("socket_enabled")

CLOUD_ID = "synthetic-cloud-device-id"
RESULT: dict[str, Any] = {
    "device_id": hashlib.md5(CLOUD_ID.encode()).hexdigest().upper(),
    "owner": "A" * 32,
    "device_type": "SMART.TAPOPLUG",
    "device_model": "P110",
    "ip": "192.0.2.10",
    "mac": "AA-BB-CC-DD-EE-FF",
    "mgt_encrypt_schm": {
        "encrypt_type": "AES",
        "http_port": 80,
        "is_support_https": False,
        "lv": 2,
    },
}


def _echo(reply: bytes, request: bytes) -> bytes:
    """Stamp the request's serial into a reply header, as devices do (§11.8)."""
    return reply[:8] + request[8:12] + reply[12:] if len(reply) >= 16 else reply


class _Responder(asyncio.DatagramProtocol):
    def __init__(self, reply: bytes | None, *, echo: bool = True) -> None:
        self.reply = reply
        self.echo = echo
        self.requests: list[bytes] = []
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.requests.append(data)
        if self.reply is not None and self.transport is not None:
            reply = _echo(self.reply, data) if self.echo else self.reply
            self.transport.sendto(reply, addr)


async def _serve(
    reply: bytes | None, *, echo: bool = True
) -> tuple[asyncio.BaseTransport, int]:
    transport, port, _ = await _serve_with(reply, echo=echo)
    return transport, port


async def _serve_with(
    reply: bytes | None, *, echo: bool = True
) -> tuple[asyncio.BaseTransport, int, _Responder]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _Responder(reply, echo=echo), local_addr=("127.0.0.1", 0)
    )
    return transport, int(transport.get_extra_info("sockname")[1]), protocol


def _frame(body: bytes) -> bytes:
    return b"\x00" * 16 + body


@pytest.fixture(scope="module")
def query() -> bytes:
    return build_query()


def test_query_header_and_crc(query: bytes) -> None:
    version, msg_type, op, size, flags, _pad, _serial, crc = struct.unpack(
        ">BBHHBBII", query[:16]
    )
    payload = query[16:]
    assert (version, msg_type, op, flags) == (2, 0, 1, 17)
    assert size == len(payload)
    zeroed = query[:12] + struct.pack(">I", 0x5A6B7C8D) + payload
    assert binascii.crc32(zeroed) == crc
    rsa_key = json.loads(payload)["params"]["rsa_key"]
    assert rsa_key.startswith("-----BEGIN PUBLIC KEY-----")


async def test_round_trip(query: bytes) -> None:
    reply = _frame(json.dumps({"error_code": 0, "result": RESULT}).encode())
    transport, port = await _serve(reply)
    try:
        info = await async_probe("127.0.0.1", query=query, port=port, timeout=2.0)
    finally:
        transport.close()
    assert info is not None
    assert info.mac == "aa:bb:cc:dd:ee:ff"
    assert info.device_model == "P110"
    assert info.encrypt_type == "AES"
    assert info.login_version == 2
    assert info.http_port == 80
    assert info.https is False
    assert info.tpap is None


def test_identity_helpers() -> None:
    info = TdpInfo.from_result(RESULT)
    assert info is not None
    assert info.matches_cloud_device(CLOUD_ID)
    assert not info.matches_cloud_device("other-id")
    for mac in ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", "aabbccddeeff"):
        assert info.matches_mac(mac)
    assert not info.matches_mac("11:22:33:44:55:66")
    assert not info.matches_mac("nonsense")


async def test_timeout_returns_none(query: bytes) -> None:
    transport, port = await _serve(None)
    transport.close()  # nothing listens on this port any more
    start = time.monotonic()
    info = await async_probe("127.0.0.1", query=query, port=port, timeout=0.6)
    assert info is None
    assert time.monotonic() - start < 2.0


async def test_malformed_json_returns_none(query: bytes) -> None:
    transport, port = await _serve(_frame(b"{not json"))
    try:
        assert (
            await async_probe("127.0.0.1", query=query, port=port, timeout=1.0) is None
        )
    finally:
        transport.close()


async def test_missing_device_id_returns_none(query: bytes) -> None:
    result = {k: v for k, v in RESULT.items() if k != "device_id"}
    transport, port = await _serve(_frame(json.dumps({"result": result}).encode()))
    try:
        assert (
            await async_probe("127.0.0.1", query=query, port=port, timeout=1.0) is None
        )
    finally:
        transport.close()


async def _serve_many(replies: list[bytes]) -> tuple[asyncio.BaseTransport, int]:
    class _Multi(_Responder):
        def datagram_received(self, data: bytes, addr: Any) -> None:
            assert self.transport is not None
            for reply in replies:
                self.transport.sendto(_echo(reply, data), addr)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Multi(None), local_addr=("127.0.0.1", 0)
    )
    return transport, int(transport.get_extra_info("sockname")[1])


async def test_junk_then_valid_reply(query: bytes) -> None:
    valid = _frame(json.dumps({"error_code": 0, "result": RESULT}).encode())
    transport, port = await _serve_many([b"junk", _frame(b"{not json"), valid])
    try:
        info = await async_probe("127.0.0.1", query=query, port=port, timeout=2.0)
    finally:
        transport.close()
    assert isinstance(info, TdpInfo)
    assert info.mac == "aa:bb:cc:dd:ee:ff"


async def test_deeply_nested_json_returns_none(query: bytes) -> None:
    transport, port = await _serve(_frame(b"[" * 6000))
    try:
        assert (
            await async_probe("127.0.0.1", query=query, port=port, timeout=0.8) is None
        )
    finally:
        transport.close()
    assert _parse(_frame(b"[" * 60000)) is None


async def test_oversize_reply_returns_none(query: bytes) -> None:
    body = json.dumps({"result": RESULT, "pad": "x" * 9000}).encode()
    assert _parse(_frame(body)) is None
    transport, port = await _serve(_frame(body))
    try:
        assert (
            await async_probe("127.0.0.1", query=query, port=port, timeout=0.8) is None
        )
    finally:
        transport.close()


async def test_reply_with_other_serial_ignored(query: bytes) -> None:
    """A well-formed reply that does not echo this probe's serial is dropped."""
    reply = _frame(json.dumps({"error_code": 0, "result": RESULT}).encode())
    transport, port = await _serve(reply, echo=False)
    try:
        info = await async_probe("127.0.0.1", query=query, port=port, timeout=0.8)
    finally:
        transport.close()
    assert info is None


async def test_each_probe_has_fresh_serial_and_valid_crc(query: bytes) -> None:
    reply = _frame(json.dumps({"error_code": 0, "result": RESULT}).encode())
    transport, port, responder = await _serve_with(reply)
    try:
        for _ in range(2):
            assert await async_probe("127.0.0.1", query=query, port=port, timeout=1.0)
    finally:
        transport.close()
    first, second = responder.requests[0], responder.requests[-1]
    assert first[8:12] != second[8:12]
    for packet in (first, second):
        assert packet[16:] == query[16:]
        zeroed = packet[:12] + struct.pack(">I", 0x5A6B7C8D) + packet[16:]
        assert binascii.crc32(zeroed) == struct.unpack(">I", packet[12:16])[0]
