#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "aiohttp",
#     "cryptography",
# ]
# ///
# python-kasa (GPL-3.0-or-later) is deliberately NOT a declared dependency.
# Stage 4 uses it only if the operator installed it separately; see stage_local.
# SPDX-License-Identifier: Apache-2.0
# Provenance: original, from docs/RESEARCH.md §2 (TDP) and §3 (cloud V1/V2).
"""Phase 0 validation spike for tapolink.

Answers the open questions in docs/RESEARCH.md section 9 against a live TP-Link
account and real hardware:

  1. Does getDeviceListByPage return `ip` for plugs and bulbs, or only cameras?
  2. How stale is the reported IP versus what the device actually answers on?
  3. Is getAccountStatusAndUrl required, or does the global gateway serve the
     device list directly?
  4. Does the TDP `owner` field equal md5(email.lower()) or md5(email_as_entered)?
  5. Which TPAP `pake` values do current-firmware devices advertise?
  6. Which endpoint, if any, refreshes a V2 cloud token without the password?
  7. Shared devices: what `role` does the cloud report, which owner hash do they
     carry, and does the TDP device_id equal the cloud deviceId?
  8. Does login accept a truthful terminal name (--term-name) instead of "iPhone"?

Runs four stages:

  CLOUD   - V2 signed login (with MFA), region resolution, paginated device list
  REFRESH - one token-refresh attempt per candidate endpoint (Q6)
  TDP     - unicast UDP:20002 probe of each cloud-reported IP (no broadcast)
  LOCAL   - OPTIONAL reference oracle: python-kasa Discover.try_connect_all against
            each cloud-reported IP (validates reachability/auth, not our stack).
            Runs only if python-kasa is already installed; skipped otherwise.
            tapolink never depends on, ships, or copies python-kasa (GPL).

Cloud budget per run: 1 optional region lookup, 1 login (+2 MFA calls), the
paginated device list (+1 retry on the global gateway if the regional one
fails), and at most 2 refresh attempts. Do not run it in a loop: TP-Link
answers excess calls with -20004 and can lock the account.

Nothing is written to disk except the optional --json report. No device state is
changed.

Usage:
    uv run tools/spike_cloud_discovery.py --username you@example.com
    uv run tools/spike_cloud_discovery.py -u you@example.com --json report.json
    uv run tools/spike_cloud_discovery.py -u you@example.com --no-local
    uv run tools/spike_cloud_discovery.py -u you@example.com --global-only
    uv run tools/spike_cloud_discovery.py -u you@example.com --v1

Without uv:
    pip install aiohttp cryptography
    python tools/spike_cloud_discovery.py --username you@example.com

Optional stage 4 oracle (installed by you, outside this project's dependencies):
    uv run --with python-kasa==0.12.0 tools/spike_cloud_discovery.py -u you@example.com
"""

import argparse
import asyncio
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

import aiohttp

# --------------------------------------------------------------------------- #
# App-level constants extracted from the TP-Link Tapo iOS client.
# These ship in every copy of the app and are published across multiple
# open-source projects. They are app identifiers, not user secrets.
# --------------------------------------------------------------------------- #

ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
APP_SECRET = b"6ed7d97f3e73467f8a5bab90b577ba4c"

APP_TYPE = "TP-Link_Tapo_iOS"
APP_VER = "2.8.21"
PLATFORM = "iOS 14.8"
USER_AGENT = "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)"

GLOBAL_GATEWAY = "https://n-wap-gw.tplinkcloud.com"
V1_ENDPOINT = "https://wap.tplinkcloud.com"

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


def load_env_file(path: str) -> None:
    """Minimal .env reader: KEY=value lines, optional quotes/`export`. Never prints values.

    Only sets keys that are not already in the environment.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[7:].lstrip()
        key, sep, value = s.partition("=")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


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


def build_cloud_ssl_context() -> ssl.SSLContext:
    """System CAs plus the two pinned TP-Link anchors; full chain + hostname checks."""
    ctx = ssl.create_default_context()
    for pem, fingerprint in (
        (TPLINK_ROOT_CA_PEM, TPLINK_ROOT_CA_SHA256),
        (TPLINK_TAPO_CLOUD_CA_PEM, TPLINK_TAPO_CLOUD_CA_SHA256),
    ):
        if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() != fingerprint:
            raise RuntimeError("embedded TP-Link CA does not match its pinned fingerprint")
        ctx.load_verify_locations(cadata=pem)
    # Accept a pinned intermediate as trust anchor (default on 3.13+, explicit for 3.11/3.12).
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


# Q6 candidate. No public source documents a V2 refresh path; this one follows
# the api/v2/account/* naming of the confirmed endpoints and is a guess. The
# spike reports the raw error code so the guess is confirmed or ruled out.
V2_REFRESH_PATH = "api/v2/account/refreshToken"

DEVICE_TYPES = [
    "SMART.TAPOBULB",
    "SMART.TAPOPLUG",
    "SMART.IPCAMERA",
    "SMART.TAPOHUB",
    "SMART.TAPOSENSOR",
    "SMART.TAPOSWITCH",
    "SMART.TAPODOORBELL",
    "SMART.TAPOCHIME",
    "SMART.TAPOLOCK",
    "SMART.TAPOROBOVAC",
    "SMART.TAPONVR",
]

CLOUD_ERRORS = {
    0: "success",
    -20004: "API rate limit exceeded (check terminalUUID uniqueness)",
    -20103: "missing method",
    -20104: "missing parameter",
    -20571: "device offline",
    -20573: "missing request data",
    -20600: "account not found",
    -20601: "invalid email or password",
    -20651: "token expired",
    -23003: "app version too old",
}

MATTER_MODELS = {
    "P100M", "P110M", "P125M", "P210M", "P304M",
    "L535E", "KP125M", "KS205", "KS225", "KS240", "EP25",
}

TDP_PORT = 20002
TDP_HEADER_SIZE = 16


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

C_OK, C_WARN, C_ERR, C_DIM, C_HDR, C_END = (
    ("\033[32m", "\033[33m", "\033[31m", "\033[90m", "\033[1;36m", "\033[0m")
    if sys.stdout.isatty()
    else ("", "", "", "", "", "")
)


def hdr(text: str) -> None:
    print(f"\n{C_HDR}{'=' * 74}\n{text}\n{'=' * 74}{C_END}")


def ok(text: str) -> None:
    print(f"  {C_OK}[ok]{C_END}   {text}")


def warn(text: str) -> None:
    print(f"  {C_WARN}[warn]{C_END} {text}")


def err(text: str) -> None:
    print(f"  {C_ERR}[fail]{C_END} {text}")


def dim(text: str) -> None:
    print(f"  {C_DIM}{text}{C_END}")


def redact(value: str | None, keep: int = 6) -> str:
    if not value:
        return "<none>"
    return value[:keep] + "…" if len(value) > keep else value


# --------------------------------------------------------------------------- #
# Cloud client
# --------------------------------------------------------------------------- #


class CloudError(Exception):
    def __init__(self, code: int, msg: str = "") -> None:
        self.code = code
        super().__init__(f"{code} ({CLOUD_ERRORS.get(code, 'unknown')}) {msg}".strip())


class MfaRequired(Exception):
    def __init__(self, process_id: str) -> None:
        self.process_id = process_id
        super().__init__("MFA required")


@dataclass(slots=True)
class CloudDevice:
    device_id: str
    alias: str
    model: str
    device_type: str
    mac: str
    ip: str | None
    hw_ver: str
    fw_ver: str
    online: bool
    role: int | None = None   # Q7: cloud `role`; meaning (owner vs shared) is what we measure
    lan_ip: str | None = None  # set from a local TDP broadcast reply, never from the cloud
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def matter_capable(self) -> bool:
        return self.model.split()[0].upper() in MATTER_MODELS

    @classmethod
    def from_api(cls, d: dict[str, Any]) -> "CloudDevice":
        alias = d.get("alias") or ""
        try:
            decoded = base64.b64decode(alias, validate=True).decode("utf-8")
            if decoded.isprintable():
                alias = decoded
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
        mac = (d.get("mac") or d.get("deviceMac") or "").replace("-", "").replace(":", "")
        mac = ":".join(mac[i : i + 2] for i in range(0, len(mac), 2)).lower()
        return cls(
            device_id=d.get("deviceId", ""),
            alias=alias,
            model=d.get("model") or d.get("deviceModel") or d.get("deviceName", ""),
            device_type=d.get("deviceType", ""),
            mac=mac,
            ip=d.get("ip"),
            hw_ver=d.get("hwVer") or d.get("deviceHwVer", ""),
            fw_ver=d.get("fwVer", ""),
            online=bool(d.get("status", 1)),
            role=d.get("role") if isinstance(d.get("role"), int) else None,
            raw=d,
        )


class TapoCloudClient:
    """Minimal V2 signed client. Read-only: login, region, device list."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        terminal_uuid: str,
        term_name: str | None = None,
    ) -> None:
        self._session = session
        self._term_id = terminal_uuid
        # Q8: None keeps the iOS app's values; a string tests a truthful name.
        self._term_name = term_name
        self._gateway = GLOBAL_GATEWAY
        self.token: str | None = None
        self.refresh_token: str | None = None
        self.account_id: int | None = None

    # -- signing ---------------------------------------------------------- #

    @staticmethod
    def _sign(body: str, path: str, timestamp: str, nonce: str) -> tuple[str, str]:
        content_md5 = base64.b64encode(
            hashlib.md5(body.encode()).digest()
        ).decode()
        content = f"{content_md5}\n{timestamp}\n{nonce}\n/{path}"
        sig = hmac.new(APP_SECRET, content.encode(), hashlib.sha1).hexdigest()
        return content_md5, sig

    def _query(self, with_token: bool) -> dict[str, str]:
        q = {
            "termID": self._term_id,
            "appVer": APP_VER,
            "locale": "en_US",
            "appName": APP_TYPE,
            "netType": "wifi",
            "model": "iPhone10,5",
            "termName": self._term_name or "iPhone",
            "termMeta": "3",
            "brand": "TPLINK",
            "ospf": "iOS 14.8",
        }
        if with_token and self.token:
            q["token"] = self.token
        return q

    async def _post(
        self, path: str, payload: dict[str, Any], *, with_token: bool = False
    ) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":"))
        timestamp = "9999999999"
        nonce = str(uuid.uuid4())
        content_md5, sig = self._sign(body, path, timestamp, nonce)
        headers = {
            "Content-Type": "application/json;UTF-8",
            "Content-MD5": content_md5,
            "Accept": "*/*",
            "User-Agent": USER_AGENT,
            "Accept-Language": "en-US;q=1",
            "X-Authorization": (
                f"Timestamp={timestamp}, Nonce={nonce}, "
                f"AccessKey={ACCESS_KEY}, Signature={sig}"
            ),
        }
        url = f"{self._gateway}/{path}"
        async with self._session.post(
            url, params=self._query(with_token), data=body, headers=headers
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise CloudError(-1, f"HTTP {resp.status} from {path}: {text[:200]}")
            data = json.loads(text)

        code = data.get("error_code", 0)
        result = data.get("result") or {}
        if code != 0:
            raise CloudError(code, data.get("msg", ""))
        return result

    # -- flows ------------------------------------------------------------ #

    async def resolve_region(self, username: str) -> str | None:
        """Q3: is this call required before login, and what does it return?"""
        try:
            result = await self._post(
                "api/v2/account/getAccountStatusAndUrl",
                {"cloudUserName": username, "appType": APP_TYPE},
            )
        except CloudError as exc:
            dim(f"getAccountStatusAndUrl unavailable pre-login: {exc}")
            return None

        urls = result.get("appServerUrlList") or result.get("urlList") or []
        idx = result.get("currentIndex", 0)
        if isinstance(urls, list) and urls:
            entry = urls[min(idx, len(urls) - 1)]
            url = entry.get("appServerUrl") if isinstance(entry, dict) else entry
            if url:
                return str(url)
        return None

    async def login(self, username: str, password: str) -> None:
        payload = {
            "appVersion": APP_VER,
            "refreshTokenNeeded": True,
            "platform": PLATFORM,
            "cloudPassword": password,
            "terminalUUID": self._term_id,
            "cloudUserName": username,
            "terminalName": self._term_name or "tapolink-spike",
            "terminalMeta": "3",
            "appType": APP_TYPE,
        }
        result = await self._post("api/v2/account/login", payload)
        if process_id := result.get("MFAProcessId"):
            raise MfaRequired(process_id)
        self._store(result)

    async def request_mfa_code(self, username: str, password: str) -> None:
        await self._post(
            "api/v2/account/getEmailVC4TerminalMFA",
            {
                "cloudPassword": password,
                "locale": "en_US",
                "terminalUUID": self._term_id,
                "cloudUserName": username,
                "appType": APP_TYPE,
            },
        )

    async def submit_mfa_code(
        self, username: str, process_id: str, code: str
    ) -> None:
        result = await self._post(
            "api/v2/account/checkMFACodeAndLogin",
            {
                "cloudUserName": username,
                "MFAProcessId": process_id,
                "appType": APP_TYPE,
                "MFAType": 2,
                "code": code,
                "terminalBindEnabled": True,
            },
        )
        self._store(result)

    def _store(self, result: dict[str, Any]) -> None:
        if not result.get("token"):
            raise CloudError(-1, f"login returned no token: {list(result)}")
        self.token = result["token"]
        self.refresh_token = result.get("refreshToken")
        self.account_id = result.get("accountId")

    async def refresh_v2(self) -> dict[str, Any]:
        """Q6: try the candidate V2 refresh path. Read-only on failure.

        On success the new token replaces the old one; on any error the current
        token is kept so the rest of the run is unaffected.
        """
        if not self.refresh_token:
            raise CloudError(-1, "login returned no refreshToken")
        result = await self._post(
            V2_REFRESH_PATH,
            {
                "appType": APP_TYPE,
                "refreshToken": self.refresh_token,
                "terminalUUID": self._term_id,
            },
        )
        if result.get("token"):
            self._store(result)
        return result

    async def passthrough(
        self, base_url: str, device_id: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        """Q9: read-only request relayed to a device by the cloud (Tapo flat format)."""
        previous = self._gateway
        self._gateway = base_url.rstrip("/")
        try:
            return await self._post(
                "api/v2/common/passthrough",
                {"deviceId": device_id, "requestData": request},
                with_token=True,
            )
        finally:
            self._gateway = previous

    async def things_details(self, region: str, device_id: str) -> dict[str, Any]:
        """Q10: TP-Link's newer IoT API — GET /v1/things/<deviceId>/details.

        Fact source (MIT): TA2k/ioBroker.tapo@5e67c5a43557 src/main.ts, which reads the
        device IP from this endpoint before falling back to passthrough. Read-only.
        Host: <region-code>-app-server.iot.i.tplinknbu.com, where the region code is
        derived from the device list's `deviceRegion` (us-east-1 -> use1).
        """
        parts = region.split("-")
        code = f"{parts[0]}{parts[1][:1]}{parts[2]}" if len(parts) == 3 else region
        url = f"https://{code}-app-server.iot.i.tplinknbu.com/v1/things/{device_id}/details"
        headers = {
            "Authorization": f"ut|{self.token}",
            "app-cid": f"app:{APP_TYPE}:{self._term_id}",
            "x-app-name": APP_TYPE,
            "x-app-version": APP_VER,
            "x-term-id": self._term_id,
            "x-ospf": PLATFORM,
            "x-net-type": "wifi",
            "x-locale": "en_US",
            "Accept": "*/*",
            "Content-Type": "application/json;UTF-8",
            "User-Agent": USER_AGENT,
        }
        async with self._session.get(url, headers=headers) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise CloudError(-1, f"HTTP {resp.status} from {url.split('/v1/')[0]}: {text[:200]}")
        data = json.loads(text)
        if isinstance(data, dict) and data.get("error_code"):
            raise CloudError(int(data["error_code"]), str(data.get("msg", "")))
        return data if isinstance(data, dict) else {"_value": data}

    @property
    def gateway(self) -> str:
        return self._gateway

    async def list_devices(self, gateway: str | None = None) -> list[CloudDevice]:
        """Paginate the device list on `gateway`, else on the current gateway.

        If a regional gateway fails, retry once on the global gateway before
        giving up, so a wrong region guess does not end the run.
        """
        if gateway and gateway.rstrip("/") != self._gateway:
            previous = self._gateway
            self._gateway = gateway.rstrip("/")
            try:
                return await self._list_devices_here()
            except CloudError as exc:
                if exc.code in (-20004, -20651):
                    raise
                warn(f"device list failed on {self._gateway}: {exc}; "
                     f"retrying once on {previous}")
                self._gateway = previous
        return await self._list_devices_here()

    async def _list_devices_here(self) -> list[CloudDevice]:
        devices: list[CloudDevice] = []
        index = 0
        while True:
            result = await self._post(
                "api/v2/common/getDeviceListByPage",
                {"index": index, "limit": 30, "deviceTypeList": DEVICE_TYPES},
                with_token=True,
            )
            page = result.get("deviceList") or []
            devices.extend(CloudDevice.from_api(d) for d in page)
            total = int(result.get("totalNum", len(devices)))
            index += len(page)
            if not page or index >= total:
                break
        return devices


async def v1_refresh(
    session: aiohttp.ClientSession, refresh_token: str, term_id: str
) -> dict[str, Any]:
    """Q6 fallback: the documented V1 refreshToken method (RESEARCH.md 3.2).

    Tests whether a refresh token issued by a V2 login is accepted by V1.
    """
    body = {
        "method": "refreshToken",
        "params": {
            "appType": "Tapo_Ios",
            "refreshToken": refresh_token,
            "terminalUUID": term_id,
        },
    }
    async with session.post(V1_ENDPOINT, json=body) as resp:
        data = await resp.json(content_type=None)
    if data.get("error_code"):
        raise CloudError(data["error_code"], data.get("msg", ""))
    return data.get("result") or {}


async def v1_device_list(
    session: aiohttp.ClientSession, username: str, password: str, term_id: str
) -> list[CloudDevice]:
    """Legacy unsigned endpoint. Confirms it still works and that `ip` is absent."""
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 6.0.1; A0001 Build/M4B30X)"
    }
    login = {
        "method": "login",
        "params": {
            "cloudUserName": username,
            "cloudPassword": password,
            "terminalUUID": term_id,
            "refreshTokenNeeded": "true",
            "appType": "Tapo_Ios",
        },
    }
    async with session.post(V1_ENDPOINT, json=login, headers=headers) as resp:
        data = await resp.json(content_type=None)
    if data.get("error_code"):
        raise CloudError(data["error_code"], data.get("msg", ""))
    token = data["result"]["token"]

    query = {"method": "getDeviceList", "params": {"appType": "Tapo_Ios"}}
    async with session.post(
        V1_ENDPOINT, params={"token": token}, json=query, headers=headers
    ) as resp:
        data = await resp.json(content_type=None)
    if data.get("error_code"):
        raise CloudError(data["error_code"], data.get("msg", ""))
    return [CloudDevice.from_api(d) for d in data["result"].get("deviceList", [])]


# --------------------------------------------------------------------------- #
# TDP unicast probe
# --------------------------------------------------------------------------- #


def build_tdp_query() -> bytes:
    """TDP v2 probe packet: 16-byte BE header + JSON payload carrying an RSA key.

    Self-contained: uses `cryptography` directly, not python-kasa. Raises
    ImportError if `cryptography` is missing. The caller builds the packet once,
    before probing, so a missing library is reported as such and never mistaken
    for an unreachable device.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = json.dumps(
        {"params": {"rsa_key": public_pem.decode()}},
        separators=(",", ":"),
    ).encode()

    header = struct.pack(
        ">BBHHBBII",
        2,                              # version
        0,                              # msg_type
        1,                              # op_code: probe
        len(payload),                   # msg_size
        17,                             # flags 0x11
        0,                              # padding
        int.from_bytes(os.urandom(4), "big"),  # device_serial
        0x5A6B7C8D,                     # initial crc placeholder
    )
    query = bytearray(header + payload)
    query[12:16] = binascii.crc32(query).to_bytes(4, "big")
    return bytes(query)


async def tdp_probe(
    host: str, query: bytes, timeout: float = 3.0
) -> dict[str, Any] | None:
    """Send a TDP probe to host:20002, resending until timeout. No broadcast."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            await loop.sock_sendto(sock, query, (host, TDP_PORT))
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096), timeout=0.5
                )
            except (asyncio.TimeoutError, ConnectionError):
                continue
            if len(data) <= TDP_HEADER_SIZE:
                continue
            try:
                return json.loads(data[TDP_HEADER_SIZE:].decode()).get("result")
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None
        return None
    finally:
        sock.close()


def _norm_mac(value: str) -> str:
    raw = value.replace("-", "").replace(":", "").lower()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


async def tdp_broadcast(
    query: bytes, seconds: float = 4.0, address: str = "255.255.255.255"
) -> dict[str, dict[str, Any]]:
    """Broadcast one TDP probe on the local subnet; collect replies by MAC.

    Same packet as the unicast probe; carries no credentials. Only devices on this
    machine's L2 segment can answer.
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(False)
    found: dict[str, dict[str, Any]] = {}
    try:
        deadline = loop.time() + seconds
        next_send = 0.0
        while (now := loop.time()) < deadline:
            if now >= next_send:  # resend a few times; UDP is lossy
                await loop.sock_sendto(sock, query, (address, TDP_PORT))
                next_send = now + 1.0
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096), timeout=0.3
                )
            except (asyncio.TimeoutError, ConnectionError):
                continue
            if len(data) <= TDP_HEADER_SIZE:
                continue
            try:
                result = json.loads(data[TDP_HEADER_SIZE:].decode()).get("result") or {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if mac := result.get("mac"):
                result.setdefault("ip", addr[0])
                found[_norm_mac(str(mac))] = result
        return found
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #


def regional_gateway(app_server_url: str | None) -> str | None:
    """Map an appServerUrl (n-<region>-wap) to its signed gateway (n-<region>-wap-gw).

    Heuristic from observed host names; list_devices falls back to the global
    gateway if the derived host rejects the call.
    """
    if not app_server_url:
        return None
    if "-wap-gw." in app_server_url:
        return app_server_url
    return app_server_url.replace("-wap.", "-wap-gw.")


async def stage_cloud(
    session: aiohttp.ClientSession,
    username: str,
    password: str,
    term_id: str,
    use_v1: bool,
    global_only: bool,
    term_name: str | None = None,
) -> tuple[list[CloudDevice], TapoCloudClient | None, dict[str, Any]]:
    hdr("STAGE 1 — CLOUD INVENTORY")
    dim(f"terminalUUID: {term_id}")
    q3: dict[str, Any] = {}

    if use_v1:
        dim("using legacy V1 endpoint (expect no `ip` field)")
        devices = await v1_device_list(session, username, password, term_id)
        ok(f"V1 login + getDeviceList succeeded, {len(devices)} devices")
        return devices, None, q3

    client = TapoCloudClient(session, term_id, term_name)

    # Q3, part 1: does region resolution work before login?
    region: str | None = None
    if global_only:
        dim("--global-only: skipping getAccountStatusAndUrl")
        q3["region_lookup"] = "skipped"
    else:
        region = await client.resolve_region(username.lower())
        q3["region_lookup"] = region or "failed"
        if region:
            ok(f"getAccountStatusAndUrl resolved region: {region}")
        else:
            warn("region not resolvable pre-login; using global gateway")

    try:
        await client.login(username.lower(), password)
    except MfaRequired as exc:
        q3["mfa_required"] = True
        if term_name:
            q3["q8_term_name_triggers_mfa"] = term_name
            warn(f"Q8: login with terminal name {term_name!r} triggered MFA "
                 f"(MFAProcessId returned)")
        if not sys.stdin.isatty():
            raise CloudError(-1, "MFA required but no interactive terminal; "
                                 "no code was requested") from None
        warn("account has MFA enabled; requesting email code")
        await client.request_mfa_code(username.lower(), password)
        code = input("  MFA code from email: ").strip()
        await client.submit_mfa_code(username.lower(), exc.process_id, code)

    ok(f"V2 login succeeded on {GLOBAL_GATEWAY} (token {redact(client.token)}, "
       f"refresh {redact(client.refresh_token)}, account {client.account_id})")
    if term_name:
        q3["q8_term_name_accepted"] = term_name
        hdr("Q8 — TRUTHFUL TERMINAL NAME")
        ok(f"login accepted terminalName/termName={term_name!r}; check the Tapo app's "
           f"trusted-devices list to see how it is displayed")

    # Q3, part 2: which gateway actually served the device list?
    gateway = regional_gateway(region)
    q3["regional_gateway_tried"] = gateway
    devices = await client.list_devices(gateway)
    q3["device_list_served_by"] = client.gateway
    ok(f"getDeviceListByPage returned {len(devices)} devices from {client.gateway}")

    hdr("Q3 — IS REGION RESOLUTION REQUIRED?")
    if client.gateway == GLOBAL_GATEWAY:
        ok("the global gateway served the device list; region lookup is optional"
           " for this account")
    else:
        warn(f"device list served by regional gateway {client.gateway}; re-run with"
             " --global-only to test whether the global gateway also serves it")
    return devices, client, q3


def _find_key(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            if (found := _find_key(v, key)) is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            if (found := _find_key(v, key)) is not None:
                return found
    return None


async def stage_passthrough(client: TapoCloudClient, devices: list[CloudDevice],
                            limit: int) -> dict[str, Any]:
    """Q9: does get_device_info via cloud passthrough reveal each device's LAN IP?"""
    hdr("STAGE 2b — CLOUD PASSTHROUGH get_device_info (Q9, read-only)")
    picked: list[CloudDevice] = []
    for dtype in sorted({d.device_type for d in devices}):   # one per type first
        picked.append(next(d for d in devices if d.device_type == dtype))
    picked += [d for d in devices if d not in picked]
    picked = picked[:limit]
    request = {"method": "get_device_info", "params": {}}
    results: dict[str, Any] = {}
    working_base: str | None = None
    for d in picked:
        raw = d.raw
        bases = [working_base] if working_base else [
            b for b in (raw.get("appServerUrlV2"), raw.get("appServerUrl"), GLOBAL_GATEWAY)
            if b
        ]
        outcome: dict[str, Any] = {"model": d.model, "attempts": []}
        for base in bases:
            try:
                resp = await client.passthrough(base, d.device_id, request)
            except CloudError as exc:
                outcome["attempts"].append({"host": base, "error": str(exc)})
                if exc.code in (-20004, -20601, -20651):
                    results[d.mac] = outcome
                    err(f"{d.alias[:20]:<20} stopping: {exc}")
                    return results
                continue
            except aiohttp.ClientError as exc:
                outcome["attempts"].append({"host": base, "error": f"{type(exc).__name__}: {exc}"})
                continue
            working_base = base
            ip = _find_key(resp, "ip")
            dev_err = _find_key(resp, "error_code")
            outcome.update(host=base, ok=True, device_error_code=dev_err,
                           ip_class=_classify_ip(ip) if isinstance(ip, str) else None,
                           response_keys=sorted(resp)[:20])
            if isinstance(ip, str) and _classify_ip(ip):
                d.lan_ip = ip
                ok(f"{d.alias[:20]:<20} {d.model:<12} LAN IP via passthrough: {ip} "
                   f"(host {base})")
            else:
                warn(f"{d.alias[:20]:<20} {d.model:<12} passthrough answered "
                     f"(device error_code={dev_err}) but no LAN `ip` in the response")
            break
        else:
            err(f"{d.alias[:20]:<20} {d.model:<12} passthrough failed on all hosts: "
                f"{outcome['attempts'][-1]['error'] if outcome['attempts'] else 'n/a'}")
        results[d.mac] = outcome
    got = sum(1 for r in results.values() if r.get("ip_class"))
    if got:
        ok(f"Q9: cloud passthrough revealed a LAN IP for {got}/{len(picked)} devices")
    else:
        err("Q9: cloud passthrough did not reveal any LAN IP")
    return results


def _key_paths(obj: Any, prefix: str = "") -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out.append(path)
            out += _key_paths(v, path)
    elif isinstance(obj, list) and obj:
        out += _key_paths(obj[0], f"{prefix}[]")
    return out


async def stage_things(client: TapoCloudClient, devices: list[CloudDevice],
                       limit: int) -> dict[str, Any]:
    """Q10: does the IoT `things/<id>/details` API return LAN IP and online state?"""
    hdr("STAGE 2c — IOT API things/<id>/details (Q10, read-only)")
    picked: list[CloudDevice] = []
    for dtype in sorted({d.device_type for d in devices}):
        picked.append(next(d for d in devices if d.device_type == dtype))
    picked += [d for d in devices if d not in picked]
    results: dict[str, Any] = {}
    for d in picked[:limit]:
        region = str(d.raw.get("deviceRegion") or "us-east-1")
        try:
            data = await client.things_details(region, d.device_id)
        except (CloudError, aiohttp.ClientError) as exc:
            err(f"{d.alias[:20]:<20} {d.model:<12} {type(exc).__name__}: {exc}")
            results[d.mac] = {"model": d.model, "error": str(exc)}
            if isinstance(exc, CloudError) and exc.code in (-20004, -20601, -20651):
                break
            continue
        paths = _key_paths(data)
        ip = None
        for key in ("ip", "ipaddr", "ipAddress", "lanIp", "localIp"):
            found = _find_key(data, key)
            if isinstance(found, str) and _classify_ip(found):
                ip = found
                break
        online = None
        for key in ("online", "isOnline", "status", "deviceStatus"):
            found = _find_key(data, key)
            if found is not None:
                online = f"{key}={found!r}"
                break
        results[d.mac] = {"model": d.model, "ip_class": _classify_ip(ip) if ip else None,
                          "online_field": online, "key_paths": paths[:80]}
        if ip:
            d.lan_ip = ip
            ok(f"{d.alias[:20]:<20} {d.model:<12} LAN IP {ip}  ({online or 'no online field'})")
        else:
            warn(f"{d.alias[:20]:<20} {d.model:<12} answered, no LAN IP "
                 f"({online or 'no online field'}); keys: {', '.join(paths[:25])}")
    got = sum(1 for r in results.values() if r.get("ip_class"))
    (ok if got else err)(f"Q10: IoT API returned a LAN IP for {got}/{min(limit, len(picked))} devices")
    return results


async def stage_refresh(
    session: aiohttp.ClientSession, client: TapoCloudClient, term_id: str
) -> dict[str, Any]:
    """Q6: can the cloud token be renewed without the password?"""
    hdr("STAGE 2 — TOKEN REFRESH (Q6)")
    results: dict[str, Any] = {"refresh_token_issued": bool(client.refresh_token)}
    if not client.refresh_token:
        err("login returned no refreshToken — persisting a refresh token is not "
            "possible; the design must re-collect the password on expiry")
        return results

    try:
        result = await client.refresh_v2()
        results["v2"] = {"ok": True, "keys": sorted(result)}
        ok(f"V2 {V2_REFRESH_PATH} accepted the refresh token "
           f"(response keys: {', '.join(sorted(result)) or 'none'})")
        return results
    except CloudError as exc:
        results["v2"] = {"ok": False, "code": exc.code, "error": str(exc)}
        warn(f"V2 {V2_REFRESH_PATH} rejected: {exc}")

    try:
        result = await v1_refresh(session, client.refresh_token, term_id)
        results["v1"] = {"ok": True, "keys": sorted(result)}
        ok("V1 refreshToken accepted the V2-issued refresh token "
           f"(response keys: {', '.join(sorted(result)) or 'none'})")
    except (CloudError, aiohttp.ClientError) as exc:
        results["v1"] = {"ok": False, "error": str(exc)}
        err(f"V1 refreshToken rejected: {exc} — no refresh path confirmed")
    return results


def report_ip_coverage(devices: list[CloudDevice]) -> dict[str, Any]:
    """Q1: does the cloud return `ip` for every device type, or only cameras?"""
    hdr("Q1 — IS `ip` PRESENT PER DEVICE TYPE?")
    by_type: dict[str, dict[str, int]] = {}
    for d in devices:
        stats = by_type.setdefault(d.device_type or "UNKNOWN", {"with_ip": 0, "total": 0})
        stats["total"] += 1
        if d.ip:
            stats["with_ip"] += 1

    print(f"  {'device_type':<24} {'with ip':>8} {'total':>7}")
    print(f"  {'-' * 24} {'-' * 8} {'-' * 7}")
    for dtype, stats in sorted(by_type.items()):
        print(f"  {dtype:<24} {stats['with_ip']:>8} {stats['total']:>7}")

    with_ip = [d for d in devices if d.ip]
    online = [d for d in devices if d.online]
    if not devices:
        warn("no devices on the account — cannot answer Q1")
    elif not with_ip:
        err(f"PREMISE NOT CONFIRMED: none of {len(devices)} devices carries an `ip` "
            f"field. See FIELD CENSUS below for where (if anywhere) an address appears.")
    elif len(with_ip) == len(devices):
        ok(f"PREMISE CONFIRMED: all {len(devices)} devices carry an `ip` field")
    else:
        warn(f"PREMISE PARTIAL: {len(with_ip)}/{len(devices)} devices carry an `ip` field")
    if devices and not online:
        warn("0 devices parsed as online — the `status` field may not mean online/offline "
             "on this endpoint; see FIELD CENSUS")
    return by_type


_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
# Keys whose distinct values are safe to print (no identifiers, no addresses).
_SAFE_VALUE_KEYS = {
    "status", "role", "category", "deviceType", "isSameRegion", "pcSameRegion",
    "deviceRegion", "deviceName", "model", "deviceModel", "hwVer", "fwVer",
    "isSubDevice", "online", "deviceStatus", "connectionStatus", "netType",
}


def _classify_ip(value: str) -> str | None:
    m = _IPV4_RE.match(value)
    if not m or any(int(g) > 255 for g in m.groups()):
        return None
    a, b = int(m.group(1)), int(m.group(2))
    private = a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    return "ipv4-private" if private else "ipv4-other"


def _walk(prefix: str, value: Any, out: dict[str, dict[str, Any]]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _walk(f"{prefix}.{k}" if prefix else str(k), v, out)
        return
    if isinstance(value, list):
        for v in value:
            _walk(f"{prefix}[]", v, out)
        return
    entry = out.setdefault(prefix, {"count": 0, "types": set(), "values": {}, "ip": set()})
    entry["count"] += 1
    entry["types"].add(type(value).__name__)
    leaf = prefix.rsplit(".", 1)[-1].rstrip("[]")
    if isinstance(value, str) and (cls := _classify_ip(value)):
        entry["ip"].add(cls)
    elif leaf in _SAFE_VALUE_KEYS and isinstance(value, (str, int, float, bool)):
        entry["values"][repr(value)] = entry["values"].get(repr(value), 0) + 1


def report_fields(devices: list[CloudDevice]) -> dict[str, Any]:
    """Which fields does getDeviceListByPage actually return? No identifiers printed.

    Prints every field path with its count and types. Distinct values are printed only
    for non-identifying keys (status, role, model, ...). Any value shaped like an IPv4
    address is reported as its class (private/other) and never printed.
    """
    hdr("FIELD CENSUS — getDeviceListByPage response fields (values redacted)")
    out: dict[str, dict[str, Any]] = {}
    for d in devices:
        _walk("", d.raw, out)
    ip_fields = []
    for path in sorted(out):
        e = out[path]
        line = f"  {path:<34} {e['count']:>3}x {'/'.join(sorted(e['types'])):<12}"
        if e["ip"]:
            line += f" ADDRESS: {', '.join(sorted(e['ip']))}"
            ip_fields.append(path)
        elif e["values"]:
            vals = ", ".join(f"{v}×{n}" for v, n in sorted(e["values"].items())[:8])
            line += f" {vals}"
        print(line)
    if ip_fields:
        ok(f"address-shaped values found in: {', '.join(ip_fields)}")
    else:
        err("no IPv4-shaped value anywhere in the device list response")
    return {
        path: {
            "count": e["count"],
            "types": sorted(e["types"]),
            "values": e["values"],
            "address_classes": sorted(e["ip"]),
        }
        for path, e in out.items()
    }


def print_inventory(devices: list[CloudDevice]) -> None:
    hdr("CLOUD INVENTORY")
    print(
        f"  {'alias':<22} {'model':<14} {'ip':<16} {'mac':<18} "
        f"{'fw':<26} {'on':<3}"
    )
    print(f"  {'-' * 22} {'-' * 14} {'-' * 16} {'-' * 18} {'-' * 26} {'-' * 3}")
    for d in sorted(devices, key=lambda x: x.alias.lower()):
        flag = "M" if d.matter_capable else ("y" if d.online else "-")
        print(
            f"  {d.alias[:22]:<22} {d.model[:14]:<14} {(d.ip or '—'):<16} "
            f"{d.mac:<18} {d.fw_ver[:26]:<26} {flag:<3}"
        )
    matter = [d for d in devices if d.matter_capable]
    if matter:
        dim(f"  'M' = Matter-capable ({len(matter)}); "
            f"prefer HA's Matter integration for these")


async def stage_tdp(devices: list[CloudDevice], username: str) -> dict[str, Any]:
    hdr("STAGE 3 — TDP PROBE (udp/20002)")
    try:
        query = build_tdp_query()
    except ImportError as exc:
        err(f"cannot build the TDP probe, cryptography import failed: {exc}. "
            f"Install cryptography. Q2, Q4 and Q5 are NOT answered.")
        return {"error": f"ImportError: {exc}"}

    expected_lower = hashlib.md5(username.lower().encode()).hexdigest()
    expected_raw = hashlib.md5(username.encode()).hexdigest()
    results: dict[str, Any] = {}
    owner_match = {"lower": 0, "raw": 0, "neither": 0}
    # Q7: owner-hash outcome and device_id agreement, grouped by cloud `role`.
    by_role: dict[str, dict[str, int]] = {}
    pake_seen: dict[str, int] = {}

    # The cloud `online` flag is not trusted here (see FIELD CENSUS); probe every
    # device the cloud gave an address for.
    targets = [d for d in devices if d.ip or d.lan_ip]
    probes: list[Any]
    if targets:
        dim(f"unicast probe of {len(targets)} address(es) "
            f"(cloud `ip` field or passthrough-reported LAN IP)")
        probes = list(await asyncio.gather(
            *(tdp_probe(d.ip or d.lan_ip or "", query) for d in targets),
            return_exceptions=True,
        ))
    else:
        warn("the cloud supplied no device addresses; falling back to ONE local TDP "
             "broadcast (no credentials) to see which devices are reachable on this "
             "machine's subnet")
        replies = await tdp_broadcast(query)
        by_mac = {d.mac: d for d in devices}
        targets, probes = [], []
        for mac, reply in replies.items():
            if mac in by_mac:
                by_mac[mac].lan_ip = str(reply.get("ip") or "") or None
                targets.append(by_mac[mac])
                probes.append(reply)
        unknown = len(replies) - len(targets)
        ok(f"broadcast: {len(replies)} TP-Link device(s) answered; {len(targets)} match "
           f"this account's inventory" + (f", {unknown} belong to other accounts or "
           f"are not in the list" if unknown else ""))
        missing = len(devices) - len(targets)
        if missing:
            warn(f"{missing} inventory device(s) did not answer the broadcast "
                 f"(other subnet/VLAN, asleep, or broadcast filtered)")
        results["_broadcast"] = {
            "replies": len(replies), "matched": len(targets), "unanswered": missing,
        }
        if not targets:
            return results

    for device, probe in zip(targets, probes):
        if isinstance(probe, BaseException):
            err(f"{device.alias} ({device.ip or device.lan_ip}) probe raised "
                f"{type(probe).__name__}: {probe}")
            results[device.mac] = {"reachable": False, "error": repr(probe)}
            continue
        if not probe:
            warn(f"{device.alias} ({device.ip or device.lan_ip}) no TDP response within 3s "
                 f"— udp/20002 likely filtered between subnets; resolver step 2 "
                 f"will fall through")
            results[device.mac] = {"reachable": False}
            continue

        schm = probe.get("mgt_encrypt_schm") or {}
        tpap = probe.get("tpap") or {}
        # Devices send uppercase hex (verified 2026-11-01); compare case-insensitively.
        owner = str(probe.get("owner") or "").lower()
        if owner == expected_lower:
            owner_form = "lower"
        elif owner == expected_raw:
            owner_form = "raw"
        else:
            owner_form = "neither"
        owner_match[owner_form] += 1

        # TDP device_id == MD5(cloud deviceId), uppercase hex (verified 2026-11-01).
        tdp_device_id = str(probe.get("device_id") or "")
        id_match = bool(tdp_device_id) and tdp_device_id.lower() == hashlib.md5(
            device.device_id.encode()
        ).hexdigest()
        role_stats = by_role.setdefault(
            str(device.role),
            {"devices": 0, "owner_lower": 0, "owner_raw": 0, "owner_neither": 0,
             "device_id_match": 0},
        )
        role_stats["devices"] += 1
        role_stats[f"owner_{owner_form}"] += 1
        role_stats["device_id_match"] += int(id_match)

        encrypt = schm.get("encrypt_type", "?")
        if tpap.get("pake") is not None:
            key = str(tpap["pake"])
            pake_seen[key] = pake_seen.get(key, 0) + 1

        cloud_ip = device.ip or device.lan_ip
        drift = "" if (not cloud_ip or probe.get("ip") == cloud_ip) else \
            f" {C_WARN}IP DRIFT cloud={cloud_ip} device={probe.get('ip')}{C_END}"
        ok(f"{device.alias[:20]:<20} {encrypt:<5} lv={schm.get('lv','?')} "
           f"port={schm.get('http_port','?')} https={bool(schm.get('is_support_https'))}"
           f"{(' tpap=' + str(tpap.get('pake'))) if tpap else ''}{drift}")

        results[device.mac] = {
            "reachable": True,
            "encrypt_type": encrypt,
            "login_version": schm.get("lv"),
            "http_port": schm.get("http_port"),
            "https": bool(schm.get("is_support_https")),
            "tpap": tpap or None,
            "reported_ip": probe.get("ip"),
            "ip_matches_cloud": (probe.get("ip") == cloud_ip) if cloud_ip else None,
            "cloud_role": device.role,
            "owner_form": owner_form,
            "device_id_matches_cloud": id_match,
        }

    hdr("Q4 — WHAT DOES TDP `owner` HASH?")
    print(f"  md5(email.lower()) matches : {owner_match['lower']}")
    print(f"  md5(email as entered)      : {owner_match['raw']}")
    print(f"  neither                    : {owner_match['neither']}")
    if owner_match["lower"] and not owner_match["raw"]:
        ok("owner == md5(email.lower()) — safe to use as a pre-auth ownership check")
    elif owner_match["neither"]:
        warn("some devices report an owner matching neither form")

    hdr("Q7 — SHARED DEVICES: OWNER HASH AND DEVICE ID BY CLOUD ROLE")
    print(f"  {'role':<6} {'devices':>7} {'own.lower':>9} {'own.raw':>7} "
          f"{'own.other':>9} {'id match':>8}")
    for role, s in sorted(by_role.items()):
        print(f"  {role:<6} {s['devices']:>7} {s['owner_lower']:>9} {s['owner_raw']:>7} "
              f"{s['owner_neither']:>9} {s['device_id_match']:>8}")
    if any(s["device_id_match"] < s["devices"] for s in by_role.values()):
        warn("TDP device_id differs from the cloud deviceId on some devices — the "
             "device-ID identity check (ARCHITECTURE §7.3) cannot rely on it alone")
    elif by_role:
        ok("TDP device_id equals the cloud deviceId on every reachable device")
    if len(by_role) < 2:
        dim("only one cloud role seen; share a device into this account (or sign in "
            "as a sharee) to answer whether shared devices pass the checks")
    dim("whether a sharee's credentials can log in locally is shown in stage 4 "
        "(optional oracle) — compare connected/failed by role in the JSON report")

    hdr("Q5 — TPAP `pake` VALUES IN THE FIELD")
    if pake_seen:
        for value, count in sorted(pake_seen.items()):
            warn(f"pake={value} on {count} device(s) — needs the TPAP transport")
    else:
        ok("no TPAP devices on this account yet")

    hdr("Q2 — CLOUD IP STALENESS")
    checked = [r for r in results.values()
               if isinstance(r, dict) and r.get("reachable")
               and r.get("ip_matches_cloud") is not None]
    drifted = [r for r in checked if not r.get("ip_matches_cloud")]
    if not any(d.ip or d.lan_ip for d in devices):
        warn("the cloud supplied no IPs — Q2 (staleness) does not apply")
    elif not checked:
        warn("no reachable devices — cannot measure staleness")
    elif not drifted:
        ok(f"cloud IP matched the device's own reported IP on all {len(checked)} devices")
    else:
        warn(f"{len(drifted)}/{len(checked)} devices report a different IP than the "
             f"cloud — resolver step 5 (MAC rematch) is load-bearing")
    return results


async def stage_local(devices: list[CloudDevice], username: str, password: str) -> dict[str, Any]:
    hdr("STAGE 4 — LOCAL CONNECT (cloud-supplied IP, else broadcast-found IP)")
    try:
        from kasa import Credentials, Discover
    except ImportError:
        warn("skipped: optional reference oracle (python-kasa) not installed. "
             "Stages 1-3 are unaffected. To run it: "
             "uv run --with python-kasa==0.12.0 tools/spike_cloud_discovery.py ...")
        return {"skipped": "python-kasa not installed (optional oracle)"}

    creds = Credentials(username, password)
    results: dict[str, Any] = {}
    targets = [d for d in devices if d.ip or d.lan_ip]

    for device in targets:
        host = device.ip or device.lan_ip or ""
        attempts: list[str] = []

        def on_attempt(attempt: Any, success: bool, _log=attempts) -> None:
            if success:
                _log.append(f"{attempt}")

        try:
            dev = await asyncio.wait_for(
                Discover.try_connect_all(
                    host, credentials=creds, timeout=5, on_attempt=on_attempt
                ),
                timeout=90,
            )
        except Exception as exc:  # noqa: BLE001 - spike wants every failure mode
            err(f"{device.alias[:20]:<20} {host:<16} {type(exc).__name__}: {exc}")
            results[device.mac] = {"connected": False, "error": str(exc),
                                   "cloud_role": device.role}
            continue

        if dev is None:
            err(f"{device.alias[:20]:<20} {host:<16} no protocol combination worked")
            results[device.mac] = {"connected": False, "error": "no working protocol",
                                   "cloud_role": device.role}
            continue

        try:
            await dev.update()
            mac_ok = dev.mac.replace("-", ":").lower() == device.mac
            ok(f"{device.alias[:20]:<20} {host:<16} "
               f"{type(dev.protocol._transport).__name__:<18} "
               f"mac_match={mac_ok} model={dev.model}")
            results[device.mac] = {
                "connected": True,
                "cloud_role": device.role,
                "transport": type(dev.protocol._transport).__name__,
                "protocol": type(dev.protocol).__name__,
                "mac_matches_cloud": mac_ok,
                "model": dev.model,
                "device_config": dev.config.to_dict(),
            }
        finally:
            await dev.protocol.close()

    connected = sum(1 for r in results.values() if r.get("connected"))
    hdr("STAGE 4 RESULT")
    if targets and connected == len(targets):
        ok(f"ALL {connected}/{len(targets)} devices connected locally using only the "
           f"cloud-supplied IP. Zero-IP setup is viable.")
    elif connected:
        warn(f"{connected}/{len(targets)} connected. Inspect failures above — "
             f"TPAP devices and camera-account-gated devices are expected misses.")
    else:
        err("no devices connected locally. Check credentials case, "
            "Tapo Lab > Third-Party Compatibility, and firewall between HA and the IoT VLAN.")
    return results


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


async def main() -> int:
    parser = argparse.ArgumentParser(description="tapolink phase 0 validation spike")
    parser.add_argument("--username", "-u", help="TP-Link cloud email")
    parser.add_argument("--password", "-p", help="prompted if omitted")
    parser.add_argument("--terminal-uuid", help="reuse a previously generated uuid4")
    parser.add_argument("--v1", action="store_true", help="use the legacy V1 endpoint")
    parser.add_argument("--term-name", metavar="NAME",
                        help="Q8: present this terminal name instead of 'iPhone' "
                             "(e.g. 'Home Assistant'). One login attempt; if it is "
                             "rejected, wait before re-running without it")
    parser.add_argument("--global-only", action="store_true",
                        help="skip region resolution; list devices on the global gateway (Q3)")
    parser.add_argument("--no-refresh", action="store_true",
                        help="skip the token refresh probe (Q6)")
    parser.add_argument("--no-tdp", action="store_true", help="skip the UDP probe stage")
    parser.add_argument("--no-local", action="store_true", help="skip the local connect stage")
    parser.add_argument("--json", metavar="PATH", help="write a full JSON report")
    parser.add_argument("--env-file", metavar="PATH", default=".env",
                        help="read TAPO_USERNAME / TAPO_PASSWORD from this file if not "
                             "already set in the environment (default: .env)")
    parser.add_argument("--things", metavar="N", type=int, default=0,
                        help="Q10: query the IoT API things/<id>/details for up to N "
                             "devices (one per type first). Read-only; N extra calls")
    parser.add_argument("--passthrough", metavar="N", type=int, default=0,
                        help="Q9: read get_device_info for up to N devices (one per type "
                             "first) through the cloud passthrough, to see whether it "
                             "reveals the LAN IP. Read-only; ~N+2 extra cloud calls")
    args = parser.parse_args()
    load_env_file(args.env_file)

    username = args.username or os.environ.get("TAPO_USERNAME")
    password = args.password or os.environ.get("TAPO_PASSWORD")
    if (not username or not password) and not sys.stdin.isatty():
        err("no interactive terminal: cannot prompt for the email/password (or an MFA "
            "code). Run this in a normal terminal window. Nothing was sent to the cloud.")
        return 2
    username = username or input("TP-Link email: ")
    password = password or getpass.getpass("Password: ")
    term_id = args.terminal_uuid or str(uuid.uuid4())

    started = time.time()
    report: dict[str, Any] = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "terminal_uuid": term_id,
        "endpoint": "v1" if args.v1 else "v2",
    }

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30),
        connector=aiohttp.TCPConnector(ssl=build_cloud_ssl_context()),
    ) as session:
        try:
            devices, client, report["q3_region"] = await stage_cloud(
                session, username, password, term_id, args.v1, args.global_only,
                args.term_name,
            )
        except aiohttp.ClientConnectorCertificateError as exc:
            err(f"TLS verification failed even with the pinned TP-Link root: {exc}")
            dim("Either TP-Link rotated its CA, or something on this network is "
                "intercepting TLS. Do NOT disable verification; compare the chain with "
                "`openssl s_client -connect n-wap-gw.tplinkcloud.com:443 -showcerts`.")
            return 1
        except aiohttp.ClientError as exc:
            err(f"cloud unreachable: {type(exc).__name__}: {exc}")
            return 1
        except CloudError as exc:
            err(f"cloud stage failed: {exc}")
            if args.term_name:
                warn(f"Q8: login was attempted with --term-name {args.term_name!r}; "
                     f"if the error is not a credential error, the server likely "
                     f"requires the iOS terminal values. Wait 30 min before re-running "
                     f"without --term-name.")
            if exc.code == -20004:
                dim("generate a fresh --terminal-uuid and wait before retrying")
            if exc.code in (-20600, -20601):
                dim("check the email case; the cloud wants lowercase")
            return 1

        print_inventory(devices)
        report["ip_coverage"] = report_ip_coverage(devices)
        report["field_census"] = report_fields(devices)
        report["devices"] = [
            {k: v for k, v in asdict(d).items() if k != "raw"} for d in devices
        ]

        if client and not args.no_refresh:
            report["q6_refresh"] = await stage_refresh(session, client, term_id)
        if client and args.things > 0:
            report["q10_things"] = await stage_things(client, devices, args.things)
        if client and args.passthrough > 0:
            report["q9_passthrough"] = await stage_passthrough(
                client, devices, args.passthrough
            )
        if not args.no_tdp:
            report["tdp"] = await stage_tdp(devices, username)
        if not args.no_local:
            report["local"] = await stage_local(devices, username, password)

    hdr("SUMMARY")
    online = [d for d in devices if d.online]
    with_ip = [d for d in online if d.ip]
    print(f"  devices on account        : {len(devices)}")
    print(f"  online                    : {len(online)}")
    print(f"  online with cloud IP      : {len(with_ip)}")
    print(f"  Matter-capable            : {sum(1 for d in devices if d.matter_capable)}")
    if not args.no_local:
        lc = report.get("local", {})
        if "skipped" in lc:
            print("  connected locally via IP  : skipped (optional oracle not installed)")
        else:
            connected = sum(
                1 for r in lc.values() if isinstance(r, dict) and r.get("connected")
            )
            print(f"  connected locally via IP  : {connected}")
    print(f"  elapsed                   : {time.time() - started:.1f}s")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        ok(f"report written to {args.json} "
           f"(contains device IDs and MACs — redact before sharing)")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
