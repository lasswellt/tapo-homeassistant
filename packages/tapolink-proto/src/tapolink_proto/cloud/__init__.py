# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py (docs/RESEARCH.md §3.1, §11.3)  # noqa: E501
"""TP-Link cloud helpers: request signing and pinned TLS."""

from tapolink_proto.cloud.signing import SignedRequest, query_params, sign_request
from tapolink_proto.cloud.tls import PinnedCertificateError, build_cloud_ssl_context

__all__ = [
    "PinnedCertificateError",
    "SignedRequest",
    "build_cloud_ssl_context",
    "query_params",
    "sign_request",
]
