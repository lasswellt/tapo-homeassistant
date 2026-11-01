# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py (docs/RESEARCH.md §3.1, §11.3)  # noqa: E501
"""V2 cloud request signing (HMAC-SHA1 X-Authorization + Content-MD5)."""

import base64
import hashlib
import hmac
import uuid
from dataclasses import dataclass

ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
APP_SECRET = b"6ed7d97f3e73467f8a5bab90b577ba4c"

APP_TYPE = "TP-Link_Tapo_iOS"
APP_VER = "2.8.21"
PLATFORM = "iOS 14.8"
USER_AGENT = "Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)"
TERMINAL_NAME = "Home Assistant"


@dataclass(frozen=True, slots=True)
class SignedRequest:
    body: str
    headers: dict[str, str]


def sign_request(
    body: str,
    path: str,
    *,
    timestamp: str = "9999999999",
    nonce: str | None = None,
) -> SignedRequest:
    """Sign `body` for POST to `/<path>`; returns the body and the headers to send."""
    nonce = nonce if nonce is not None else str(uuid.uuid4())
    content_md5 = base64.b64encode(hashlib.md5(body.encode()).digest()).decode()
    content = f"{content_md5}\n{timestamp}\n{nonce}\n/{path}"
    sig = hmac.new(APP_SECRET, content.encode(), hashlib.sha1).hexdigest()
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
    return SignedRequest(body=body, headers=headers)


def query_params(terminal_uuid: str, token: str | None = None) -> dict[str, str]:
    """Query-string parameters the iOS client sends; `token` only when given."""
    q = {
        "termID": terminal_uuid,
        "appVer": APP_VER,
        "locale": "en_US",
        "appName": APP_TYPE,
        "netType": "wifi",
        "model": "iPhone10,5",
        "termName": TERMINAL_NAME,
        "termMeta": "3",
        "brand": "TPLINK",
        "ospf": PLATFORM,
    }
    if token:
        q["token"] = token
    return q
