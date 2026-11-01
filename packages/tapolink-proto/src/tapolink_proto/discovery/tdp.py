# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py
# (docs/RESEARCH.md §2, §11.3, §11.8)
"""TDP (UDP 20002) unicast identity probe. Unicast only, never broadcast."""

from __future__ import annotations

import asyncio
import binascii
import hashlib
import json
import os
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

TDP_PORT: Final = 20002
TDP_HEADER_SIZE: Final = 16
_RESEND_INTERVAL: Final = 0.5
_MAX_REPLY_SIZE: Final = 8192
_SERIAL: Final = slice(8, 12)
_CRC: Final = slice(12, 16)
_CRC_PLACEHOLDER: Final = (0x5A6B7C8D).to_bytes(4, "big")
_HEX12 = re.compile(r"[0-9a-f]{12}")


def _norm_mac(value: str) -> str | None:
    raw = value.replace("-", "").replace(":", "").lower()
    if not _HEX12.fullmatch(raw):
        return None
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def build_query() -> bytes:
    """Build a TDP v2 probe packet (16-byte BE header + JSON with an RSA key).

    CPU-bound (RSA-2048 keygen, ~100 ms+): call once via
    ``loop.run_in_executor(None, build_query)`` and reuse the result.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = json.dumps(
        {"params": {"rsa_key": public_pem.decode()}}, separators=(",", ":")
    ).encode()
    header = struct.pack(
        ">BBHHBBII",
        2,  # version
        0,  # msg_type
        1,  # op_code: probe
        len(payload),
        17,  # flags 0x11
        0,
        int.from_bytes(os.urandom(4), "big"),  # device_serial
        0x5A6B7C8D,  # crc placeholder
    )
    query = bytearray(header + payload)
    query[12:16] = binascii.crc32(query).to_bytes(4, "big")
    return bytes(query)


def _with_serial(query: bytes, serial: bytes) -> bytes:
    """Return ``query`` with a new ``device_serial`` and a recomputed CRC."""
    packet = bytearray(query)
    packet[_SERIAL] = serial
    packet[_CRC] = _CRC_PLACEHOLDER
    packet[_CRC] = binascii.crc32(packet).to_bytes(4, "big")
    return bytes(packet)


@dataclass(frozen=True, slots=True)
class TdpInfo:
    """Identity advertised by a device in its TDP reply."""

    device_id: str
    owner: str
    mac: str
    ip: str | None
    device_type: str | None
    device_model: str | None
    encrypt_type: str | None
    login_version: int | None
    http_port: int | None
    https: bool
    tpap: Mapping[str, Any] | None

    @classmethod
    def from_result(cls, result: Mapping[str, Any]) -> TdpInfo | None:
        """Parse a TDP ``result`` object; None if device_id/mac missing or bad."""
        device_id = result.get("device_id")
        raw_mac = result.get("mac")
        if not isinstance(device_id, str) or not device_id:
            return None
        if not isinstance(raw_mac, str):
            return None
        mac = _norm_mac(raw_mac)
        if mac is None:
            return None
        scheme = result.get("mgt_encrypt_schm")
        if not isinstance(scheme, Mapping):
            scheme = {}
        tpap = result.get("tpap")
        login_version = scheme.get("lv")
        http_port = scheme.get("http_port")
        return cls(
            device_id=device_id,
            owner=_opt_str(result.get("owner")) or "",
            mac=mac,
            ip=_opt_str(result.get("ip")),
            device_type=_opt_str(result.get("device_type")),
            device_model=_opt_str(result.get("device_model")),
            encrypt_type=_opt_str(scheme.get("encrypt_type")),
            login_version=login_version if _is_int(login_version) else None,
            http_port=http_port if _is_int(http_port) else None,
            https=bool(scheme.get("is_support_https", False)),
            tpap=tpap if isinstance(tpap, Mapping) else None,
        )

    def matches_cloud_device(self, cloud_device_id: str) -> bool:
        """True if TDP device_id == MD5(cloud deviceId) (RESEARCH §11.3)."""
        digest = hashlib.md5(cloud_device_id.encode()).hexdigest()  # noqa: S324
        return self.device_id.lower() == digest

    def matches_mac(self, mac: str) -> bool:
        """Compare MACs ignoring case and ``-``/``:`` separators."""
        return _norm_mac(mac) == self.mac


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future[TdpInfo], serial: bytes) -> None:
        self._future = future
        self._serial = serial

    def datagram_received(self, data: bytes, addr: tuple[str | Any, ...]) -> None:
        """Complete the future only with a reply to this probe that parses.

        Devices echo the request's ``device_serial`` (RESEARCH §11.8); a reply
        carrying any other serial is stale or spoofed and is ignored.
        """
        if self._future.done() or data[_SERIAL] != self._serial:
            return
        info = _parse(data)
        if info is not None:
            self._future.set_result(info)

    def error_received(self, exc: Exception) -> None:
        """Ignore ICMP errors (e.g. refused); keep waiting until timeout."""


def _parse(data: bytes) -> TdpInfo | None:
    if not TDP_HEADER_SIZE < len(data) <= _MAX_REPLY_SIZE:
        return None
    try:
        body = json.loads(data[TDP_HEADER_SIZE:].decode())
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(body, dict):
        return None
    result = body.get("result")
    if not isinstance(result, Mapping):
        return None
    return TdpInfo.from_result(result)


async def async_probe(
    host: str,
    *,
    query: bytes,
    port: int = TDP_PORT,
    timeout: float = 3.0,  # noqa: ASYNC109
) -> TdpInfo | None:
    """Unicast a TDP probe to ``host``, resending every ~0.5 s until timeout.

    The socket is connected to ``host:port`` so the kernel drops datagrams from
    any other source, and each call stamps ``query`` with a fresh random serial
    that the reply must echo. Returns None on timeout, or OSError; junk
    datagrams and replies with another serial are ignored.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future[TdpInfo] = loop.create_future()
    serial = os.urandom(4)
    packet = _with_serial(query, serial)
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(future, serial), remote_addr=(host, port)
        )
    except OSError:
        return None
    try:
        deadline = loop.time() + timeout
        while (remaining := deadline - loop.time()) > 0:
            transport.sendto(packet)
            try:
                return await asyncio.wait_for(
                    asyncio.shield(future), min(_RESEND_INTERVAL, remaining)
                )
            except TimeoutError:
                continue
        return None
    except OSError:
        return None
    finally:
        transport.close()
