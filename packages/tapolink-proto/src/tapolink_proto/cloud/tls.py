# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py (docs/RESEARCH.md §3.1, §11.3)  # noqa: E501
"""Pinned TLS context for the TP-Link V2 cloud gateways."""

import hashlib
import ssl

# TP-Link's private root CA. The V2 gateways (n-*.tplinkcloud.com) chain to it
# instead of a public CA: leaf *.tplinkcloud.com -> "TP-LINK CA P1" -> "tp-link-CA"
# (self-signed, valid 2018-01-19 .. 2068-01-19). The V1 host wap.tplinkcloud.com uses a
# public DigiCert chain. Captured from the n-wap-gw.tplinkcloud.com TLS handshake on
# 2026-11-01. The same day, google.com, pypi.org and wap.tplinkcloud.com verified
# normally from the same machine, which rules out local TLS interception. This is a
# public certificate, not a secret. We trust it IN ADDITION to the system CAs, with
# full chain and hostname verification. Verification is never disabled.
TPLINK_ROOT_CA_SHA256 = (
    "8b54f0364e840fb010d517324725f0d30245d35b45f9be4b6e50b84f03fdec19"
)
TPLINK_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIQT5x0ma7QnINHCQvhnmzR9zANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDEwp0cC1saW5rLUNBMCAXDTE4MDExOTA4Mjc1MloYDzIwNjgwMTE5
MDgzNzUyWjAVMRMwEQYDVQQDEwp0cC1saW5rLUNBMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAuGG8n5zEUN1j5wuvUz4pAIMurhKHbpfUUu+b2acFHKS6
iU9hNJWvDyhXcihY5Wz6aq9m4D5SZcgW3k31YoNNtrztDjdg2qw7AaX85S99/G0B
VbIXktrhs34OW19WA/haDwut3dFhLem+gCRRKUXcmuqchZc84dY7JFVfhPcJci4m
sRjLCFNO0ho9OX+MZwfO4BLaeAqKVoAor6rf4BXVtO0xjYHDKO0fb3AWLLJ4EjGe
q6YieqPiYlPFEqRm5PrvBXTm0IuQogygyVpK4LHr/K207ZLyV33DxLLbsUgSEJVn
pZUv/WUujXjlIDgxIvyZZCYiXO3dle2/MEvpmZk6JQIDAQABo1EwTzALBgNVHQ8E
BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUxu2iBRTsef5iNnsADVhM
JDQWi6kwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggEBAB52Majd
+wo3cb5BsTo63z2Psbbyl4ACMUaw68NxUMy61Oihx3mcLzLJqiIZcKePiHskLqLJ
F7QfT9TqjvizMjFJVgsLuVubUBXKBzqyN+3KKlQci0PO3mH+ObhyaE7BzV+qrS3P
dVTgsCWFv8DkgLTRudSWxL7VwVoedc7lRz5EroGgJ33nRGCR0ngcW919tLTARDQO
pULmzulcdWeZgG+0PLX0xjJQIjFEvbOxR1Z+gxMupBz0rWFokmWYrcga8eWiWzjQ
Ia3/ASBVJ69srV77trWlfLumkChbXk9i64NXBKnce0Jmll0Y9OC1nMPqrbQKnzcn
dSAA4fejD/qMQn0=
-----END CERTIFICATE-----
"""

# Second private PKI, for the Tapo cloud (*.i.tplinkcloud.com, the device's
# `appServerUrlV2`): leaf -> "TP-Link Cloud Server CA" (TP-Link Systems Inc.,
# 2025-02-25 .. 2040-02-22, pathlen 0) -> "TP-Link Cloud Root CA". The server does not
# send that root, so the intermediate is pinned as the trust anchor (partial chain).
# Captured from n-use1-wap-gw.i.tplinkcloud.com on 2026-11-01.
TPLINK_TAPO_CLOUD_CA_SHA256 = (
    "28860572d5dc7e9d76702092e4164abae8ca73a900fc403d8941c22fb691b90e"
)
TPLINK_TAPO_CLOUD_CA_PEM = """-----BEGIN CERTIFICATE-----
MIICjjCCAjSgAwIBAgIUDvm17dXeo3BBXMzvuzzwOgi3Q40wCgYIKoZIzj0EAwMw
cjEeMBwGA1UEAwwVVFAtTGluayBDbG91ZCBSb290IENBMR0wGwYDVQQKDBRUUC1M
aW5rIFN5c3RlbXMgSW5jLjEPMA0GA1UEBwwGSXJ2aW5lMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMQswCQYDVQQGEwJVUzAeFw0yNTAyMjUwMzU3MDFaFw00MDAyMjIwMzU3
MDFaMHQxIDAeBgNVBAMMF1RQLUxpbmsgQ2xvdWQgU2VydmVyIENBMR0wGwYDVQQK
DBRUUC1MaW5rIFN5c3RlbXMgSW5jLjEPMA0GA1UEBwwGSXJ2aW5lMRMwEQYDVQQI
DApDYWxpZm9ybmlhMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABFfbER2ybkfy/g1y2r7eBKXT+f5d3y/TtX/Z4ydUFZOIb6VxbcTPAniMSI4B
/NNI0Tk/GCN0EFYlC/rGxoaA5mmjgaUwgaIwEgYDVR0TAQH/BAgwBgEB/wIBADAO
BgNVHQ8BAf8EBAMCAYYwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC50cGxp
bmtjbG91ZC5jb20vVFBMaW5rUm9vdENBLmNybDAdBgNVHQ4EFgQUiG82rMbvOSoF
Xc79B7Q2Co1VtJwwHwYDVR0jBBgwFoAUC1dD03ntY75yTHFAhLUICUoP6MkwCgYI
KoZIzj0EAwMDSAAwRQIhANMn7B+KXILe2IYiLipivo+Xm3mwuncrTThiV3HKM2aZ
AiBXBL/Z6Uyn1ySWkv+RKvW+Ig9onNIejl0dAV8z9ielHQ==
-----END CERTIFICATE-----
"""


class PinnedCertificateError(Exception):
    """An embedded TP-Link CA certificate does not match its pinned fingerprint."""


def _verify_and_load(ctx: ssl.SSLContext, pem: str, sha256: str) -> None:
    """Check the DER SHA-256 of `pem` against `sha256`, then add it as a trust anchor.

    Raises PinnedCertificateError on mismatch or an unparseable certificate.
    """
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except ValueError as exc:
        raise PinnedCertificateError("embedded TP-Link CA is not a valid PEM") from exc
    if hashlib.sha256(der).hexdigest() != sha256:
        raise PinnedCertificateError(
            "embedded TP-Link CA does not match its pinned fingerprint"
        )
    ctx.load_verify_locations(cadata=pem)


def build_cloud_ssl_context() -> ssl.SSLContext:
    """System CAs plus the two pinned TP-Link anchors; full chain + hostname checks.

    Synchronous: reads the system CA store from disk, so call it from an executor
    (``loop.run_in_executor``) when inside the event loop.

    Raises PinnedCertificateError if an embedded anchor fails its fingerprint check.
    """
    ctx = ssl.create_default_context()
    _verify_and_load(ctx, TPLINK_ROOT_CA_PEM, TPLINK_ROOT_CA_SHA256)
    _verify_and_load(ctx, TPLINK_TAPO_CLOUD_CA_PEM, TPLINK_TAPO_CLOUD_CA_SHA256)
    # Accept a pinned intermediate as trust anchor (default on 3.13+, explicit anyway).
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx
