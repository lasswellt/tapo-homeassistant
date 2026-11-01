# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py (docs/RESEARCH.md §3.1, §11.3)  # noqa: E501
import ssl

import pytest
from tapolink_proto.cloud.signing import query_params, sign_request
from tapolink_proto.cloud.tls import (
    TPLINK_ROOT_CA_PEM,
    TPLINK_ROOT_CA_SHA256,
    TPLINK_TAPO_CLOUD_CA_PEM,
    PinnedCertificateError,
    _verify_and_load,
    build_cloud_ssl_context,
)


def test_signature_vector() -> None:
    req = sign_request(
        '{"index":0,"limit":30}',
        "api/v2/common/getDeviceListByPage",
        timestamp="9999999999",
        nonce="00000000-0000-4000-8000-000000000000",
    )
    assert req.headers["Content-MD5"] == "kkqdzmdWTA05CfXIvthblw=="
    assert req.headers["X-Authorization"].endswith(
        "Signature=e1961127e479927e31a3afc778a0a0a010fb7a00"
    )
    assert req.headers["X-Authorization"].startswith(
        "Timestamp=9999999999, Nonce=00000000-0000-4000-8000-000000000000, AccessKey="
    )


def test_query_params_token_and_term_name() -> None:
    assert "token" not in query_params("tid")
    assert query_params("tid", "tok")["token"] == "tok"
    assert query_params("tid")["termName"] == "Home Assistant"


def test_ssl_context_flags() -> None:
    ctx = build_cloud_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


def test_tampered_pem_rejected() -> None:
    lines = TPLINK_ROOT_CA_PEM.splitlines()
    body = lines[3]
    lines[3] = body[:10] + ("B" if body[10] != "B" else "C") + body[11:]
    ctx = ssl.create_default_context()
    with pytest.raises(PinnedCertificateError):
        _verify_and_load(ctx, "\n".join(lines) + "\n", TPLINK_ROOT_CA_SHA256)


def test_other_valid_cert_rejected() -> None:
    ctx = ssl.create_default_context()
    with pytest.raises(PinnedCertificateError):
        _verify_and_load(ctx, TPLINK_TAPO_CLOUD_CA_PEM, TPLINK_ROOT_CA_SHA256)
