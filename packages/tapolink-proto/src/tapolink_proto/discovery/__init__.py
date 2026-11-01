# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py
# (docs/RESEARCH.md §2, §11.3)
"""Device discovery helpers."""

from .tdp import TDP_PORT, TdpInfo, async_probe, build_query

__all__ = ["TDP_PORT", "TdpInfo", "async_probe", "build_query"]
