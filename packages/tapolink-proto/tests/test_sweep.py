# SPDX-License-Identifier: Apache-2.0
"""Sweep tests (synthetic data, real local UDP responders on 127.0.0.x)."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterator
from ipaddress import IPv4Network
from typing import Any

import pytest
from pytest_socket import disable_socket, socket_allow_hosts
from tapolink_proto.discovery import (
    MAX_SWEEP_HOSTS,
    SweepRangeError,
    TdpInfo,
    async_sweep,
    build_query,
    network_of,
    parse_networks,
)

pytestmark = pytest.mark.usefixtures("socket_enabled")


@pytest.fixture(autouse=True)
def _allow_loopback_aliases(socket_enabled: None) -> Iterator[None]:
    """The HA harness only allows 127.0.0.1; the sweep needs 127.0.0.2-5 too."""
    socket_allow_hosts([f"127.0.0.{n}" for n in range(1, 6)])
    yield
    disable_socket(allow_unix_socket=True)


def _result(mac: str, ip: str, owner: str = "A" * 32) -> dict[str, Any]:
    return {
        "device_id": "D" * 32,
        "owner": owner,
        "device_type": "SMART.TAPOPLUG",
        "device_model": "P110",
        "ip": ip,
        "mac": mac,
        "mgt_encrypt_schm": {"encrypt_type": "AES", "http_port": 80, "lv": 2},
    }


class _Responder(asyncio.DatagramProtocol):
    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:
        assert self.transport is not None
        self.transport.sendto(self.reply[:8] + data[8:12] + self.reply[12:], addr)


def _frame(result: dict[str, Any]) -> bytes:
    return b"\x00" * 16 + json.dumps({"error_code": 0, "result": result}).encode()


async def _bind(
    host: str, port: int, reply: bytes | None
) -> asyncio.BaseTransport | None:
    """Bind a responder (or a silent socket when reply is None)."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Responder(reply) if reply is not None else asyncio.DatagramProtocol(),
        local_addr=(host, port),
    )
    return transport


async def _free_port() -> int:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
    )
    port = int(transport.get_extra_info("sockname")[1])
    transport.close()
    return port


@pytest.fixture(scope="module")
def query() -> bytes:
    return build_query()


def test_parse_normalises_and_dedups() -> None:
    nets = parse_networks(
        [" 192.168.1.7/24 ", "", "192.168.1.9", "192.168.1.0/24", "10.0.0.5"]
    )
    assert nets == (IPv4Network("10.0.0.5/32"), IPv4Network("192.168.1.0/24"))


def test_parse_accepts_widest_prefix() -> None:
    assert parse_networks(["10.0.0.0/20"]) == (IPv4Network("10.0.0.0/20"),)


@pytest.mark.parametrize(
    ("values", "reason"),
    [
        (["nonsense"], "invalid"),
        (["192.168.1.0/33"], "invalid"),
        (["fd00::/64"], "not_ipv4"),
        (["8.8.8.0/24"], "not_private"),
        (["10.0.0.0/19"], "too_wide"),
        (["10.0.0.0/8"], "too_wide"),
        (["10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20"], "too_many_hosts"),
    ],
)
def test_parse_rejects(values: list[str], reason: str) -> None:
    with pytest.raises(SweepRangeError) as err:
        parse_networks(values)
    assert err.value.reason == reason
    assert isinstance(err.value, ValueError)


def test_cap_constant() -> None:
    assert MAX_SWEEP_HOSTS == 4096
    assert parse_networks(["10.0.0.0/20"])  # 4094 hosts, under the cap


def test_network_of() -> None:
    assert network_of("192.168.5.77") == IPv4Network("192.168.5.0/24")
    assert network_of("192.168.5.77", 20) == IPv4Network("192.168.0.0/20")
    with pytest.raises(SweepRangeError):
        network_of("not-an-ip")


def test_owned_by() -> None:
    email = "Me@Example.com"
    typed = hashlib.md5(email.encode()).hexdigest()
    lowered = hashlib.md5(email.lower().encode()).hexdigest()
    base = TdpInfo.from_result(_result("aa:bb:cc:dd:ee:ff", "127.0.0.2"))
    assert base is not None
    for digest in (typed, lowered, typed.upper(), lowered.upper()):
        info = TdpInfo.from_result(_result("aa:bb:cc:dd:ee:ff", "x", owner=digest))
        assert info is not None
        assert info.owned_by(email)
    assert not base.owned_by(email)
    assert not base.owned_by("other@example.com")
    empty = TdpInfo.from_result(_result("aa:bb:cc:dd:ee:ff", "x", owner=""))
    assert empty is not None
    assert not empty.owned_by(email)


async def test_sweep_dedup_silent_and_order(query: bytes) -> None:
    port = await _free_port()
    plug = _frame(_result("AA-BB-CC-00-00-01", "127.0.0.2"))
    other = _frame(_result("AA-BB-CC-00-00-02", "127.0.0.4"))
    transports = [
        await _bind("127.0.0.2", port, plug),
        await _bind("127.0.0.3", port, None),  # silent host
        await _bind("127.0.0.4", port, other),
        await _bind("127.0.0.5", port, plug),  # same MAC as .2 -> dropped
    ]
    try:
        found = await async_sweep(
            ["127.0.0.2/31", "127.0.0.4/31"], query=query, port=port, timeout=0.3
        )
    finally:
        for transport in transports:
            assert transport is not None
            transport.close()
    assert [i.mac for i in found] == ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]
    assert [i.ip for i in found] == ["127.0.0.2", "127.0.0.4"]


async def test_sweep_all_silent(query: bytes) -> None:
    port = await _free_port()
    found = await async_sweep(
        [IPv4Network("127.0.0.2/32")], query=query, port=port, timeout=0.3
    )
    assert found == []


@pytest.mark.parametrize("bad", ["8.8.8.0/24", "10.0.0.0/8", "nonsense"])
async def test_sweep_rejects_before_sending(query: bytes, bad: str) -> None:
    loop = asyncio.get_running_loop()
    received: list[bytes] = []

    class _Spy(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: Any) -> None:
            received.append(data)

    transport, _ = await loop.create_datagram_endpoint(
        _Spy, local_addr=("127.0.0.1", 0)
    )
    port = int(transport.get_extra_info("sockname")[1])
    try:
        with pytest.raises(SweepRangeError):
            await async_sweep(["127.0.0.1", bad], query=query, port=port, timeout=0.3)
        await asyncio.sleep(0.05)
    finally:
        transport.close()
    assert received == []
