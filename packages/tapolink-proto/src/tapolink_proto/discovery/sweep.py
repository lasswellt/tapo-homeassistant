# SPDX-License-Identifier: Apache-2.0
# Provenance: original, from docs/RESEARCH.md §2, §11.8, §11.9
"""Bounded unicast TDP sweep of user-supplied private IPv4 ranges.

Never broadcasts. Ranges are validated before a single packet is sent.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network
from typing import Final, Literal

from .tdp import TDP_PORT, TdpInfo, async_probe

MAX_SWEEP_HOSTS: Final = 4096
MIN_PREFIX: Final = 20

SweepRangeReason = Literal[
    "invalid", "not_ipv4", "not_private", "too_wide", "too_many_hosts"
]


class SweepRangeError(ValueError):
    """A sweep range was rejected; ``reason`` is a closed, mappable set."""

    def __init__(self, reason: SweepRangeReason, value: str = "") -> None:
        super().__init__(f"{reason}: {value}" if value else reason)
        self.reason: SweepRangeReason = reason


def _host_count(network: IPv4Network) -> int:
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2


def _parse_one(value: str) -> IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as err:
        raise SweepRangeError("invalid", value) from err
    if not isinstance(network, IPv4Network):
        raise SweepRangeError("not_ipv4", value)
    if not network.network_address.is_private:
        raise SweepRangeError("not_private", value)
    if network.prefixlen < MIN_PREFIX:
        raise SweepRangeError("too_wide", value)
    return network


def parse_networks(values: Iterable[str]) -> tuple[IPv4Network, ...]:
    """Parse CIDR strings or bare IPv4 addresses into a bounded network set.

    Raises:
        SweepRangeError: on any invalid, non-IPv4, public, too-wide range, or
            when the de-duplicated total exceeds ``MAX_SWEEP_HOSTS`` hosts.
    """
    parsed = {_parse_one(v.strip()) for v in values if v.strip()}
    ordered = sorted(parsed, key=lambda n: (n.prefixlen, n.network_address))
    kept: list[IPv4Network] = []
    for network in ordered:
        if not any(network.subnet_of(other) for other in kept):
            kept.append(network)
    kept.sort(key=lambda n: n.network_address)
    if sum(_host_count(n) for n in kept) > MAX_SWEEP_HOSTS:
        raise SweepRangeError("too_many_hosts")
    return tuple(kept)


def network_of(host: str, prefix: int = 24) -> IPv4Network:
    """Return the ``prefix``-sized IPv4 network containing ``host``."""
    try:
        return IPv4Network(f"{IPv4Address(host)}/{prefix}", strict=False)
    except ValueError as err:
        raise SweepRangeError("invalid", host) from err


async def async_sweep(
    networks: Iterable[IPv4Network | str],
    *,
    query: bytes,
    concurrency: int = 64,
    timeout: float = 1.5,  # noqa: ASYNC109
    port: int = TDP_PORT,
) -> list[TdpInfo]:
    """Unicast-probe every host in ``networks``; return devices ordered by probed IP.

    Hosts are probed in ascending address order, so the result is ordered by
    probed IP. De-duplicated by MAC (first seen wins). Silent hosts dropped.

    Raises:
        SweepRangeError: before any packet is sent, if a range is rejected.
    """
    ranges = parse_networks(str(n) for n in networks)
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(host: str) -> TdpInfo | None:
        async with semaphore:
            return await async_probe(host, query=query, port=port, timeout=timeout)

    hosts = [str(h) for network in ranges for h in network.hosts()]
    found = await asyncio.gather(*(probe(h) for h in hosts))
    by_mac: dict[str, TdpInfo] = {}
    for info in found:
        if info is not None and info.mac not in by_mac:
            by_mac[info.mac] = info
    return list(by_mac.values())
