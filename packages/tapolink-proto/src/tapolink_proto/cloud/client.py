# SPDX-License-Identifier: Apache-2.0
# Provenance: original, ported from tools/spike_cloud_discovery.py
# (docs/RESEARCH.md §3.1, §11.1-11.4)
"""TP-Link cloud client: login, MFA, refresh, device list, device details."""

import json
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import aiohttp

from tapolink_proto.cloud.errors import (
    CloudResponseError,
    CloudUnavailable,
    MfaRequired,
    raise_for_error_code,
)
from tapolink_proto.cloud.models import CloudDevice, DeviceDetails, LoginResult
from tapolink_proto.cloud.signing import (
    APP_TYPE,
    APP_VER,
    PLATFORM,
    TERMINAL_NAME,
    USER_AGENT,
    query_params,
    sign_request,
)

GLOBAL_GATEWAY = "https://n-wap-gw.tplinkcloud.com"
DEFAULT_REGION_CODE = "use1"
PAGE_LIMIT = 30
DETAILS_URL = (
    "https://{region}-app-server.iot.i.tplinknbu.com/v1/things/{device_id}/details"
)

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


@dataclass(frozen=True, slots=True)
class CloudSession:
    """Credentials-free token bundle; callers hold it and pass it in."""

    token: str
    refresh_token: str | None
    account_id: int | None


class CloudClient:
    """Stateless V2 cloud client over an injected aiohttp session."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        ssl_context: ssl.SSLContext,
        terminal_uuid: str,
        gateway: str = GLOBAL_GATEWAY,
    ) -> None:
        self._session = session
        self._ssl = ssl_context
        self._terminal_uuid = terminal_uuid
        self._gateway = gateway.rstrip("/")

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None = None,
        data: str | None = None,
    ) -> Any:
        try:
            async with self._session.request(
                method, url, params=params, data=data, headers=headers, ssl=self._ssl
            ) as resp:
                text = await resp.text()
                if resp.status != 200:
                    raise CloudResponseError(f"HTTP {resp.status} from {url}")
        except (TimeoutError, aiohttp.ClientError) as exc:
            raise CloudUnavailable(f"{type(exc).__name__} calling {url}") from exc
        try:
            return json.loads(text)
        except ValueError as exc:
            raise CloudResponseError(f"non-JSON response from {url}") from exc

    async def _post(
        self, path: str, payload: dict[str, Any], *, token: str | None = None
    ) -> dict[str, Any]:
        signed = sign_request(json.dumps(payload, separators=(",", ":")), path)
        data = await self._request(
            "POST",
            f"{self._gateway}/{path}",
            headers=signed.headers,
            params=query_params(self._terminal_uuid, token),
            data=signed.body,
        )
        if not isinstance(data, dict):
            raise CloudResponseError(f"unexpected response shape from {path}")
        result = data.get("result")
        result = result if isinstance(result, dict) else {}
        raise_for_error_code(
            int(data.get("error_code", 0)), data.get("msg", ""), result
        )
        return result

    @staticmethod
    def _to_session(result: dict[str, Any]) -> CloudSession:
        login = LoginResult.from_api(result)
        return CloudSession(login.token, login.refresh_token, login.account_id)

    async def login(self, username: str, password: str) -> CloudSession:
        """Sign in once.

        Raises:
            MfaRequired: the account needs a second factor.
            CloudError: any cloud-side failure.
        """
        result = await self._post(
            "api/v2/account/login",
            {
                "appVersion": APP_VER,
                "refreshTokenNeeded": True,
                "platform": PLATFORM,
                "cloudPassword": password,
                "terminalUUID": self._terminal_uuid,
                "cloudUserName": username.lower(),
                "terminalName": TERMINAL_NAME,
                "terminalMeta": "3",
                "appType": APP_TYPE,
            },
        )
        if process_id := result.get("MFAProcessId"):
            raise MfaRequired(str(process_id))
        return self._to_session(result)

    async def request_mfa_code(self, username: str, password: str) -> None:
        """Ask the cloud to email an MFA code."""
        await self._post(
            "api/v2/account/getEmailVC4TerminalMFA",
            {
                "cloudPassword": password,
                "locale": "en_US",
                "terminalUUID": self._terminal_uuid,
                "cloudUserName": username.lower(),
                "appType": APP_TYPE,
            },
        )

    async def submit_mfa_code(
        self, username: str, process_id: str, code: str
    ) -> CloudSession:
        """Complete login with the emailed MFA code."""
        result = await self._post(
            "api/v2/account/checkMFACodeAndLogin",
            {
                "cloudUserName": username.lower(),
                "MFAProcessId": process_id,
                "appType": APP_TYPE,
                "MFAType": 2,
                "code": code,
                "terminalBindEnabled": True,
            },
        )
        return self._to_session(result)

    async def refresh(self, session: CloudSession) -> CloudSession:
        """Swap the token using the refresh token; the refresh token is kept.

        Raises:
            CloudResponseError: the session has no refresh token or none returned.
        """
        if session.refresh_token is None:
            raise CloudResponseError("session has no refresh token")
        result = await self._post(
            "api/v2/account/refreshToken",
            {
                "appType": APP_TYPE,
                "refreshToken": session.refresh_token,
                "terminalUUID": self._terminal_uuid,
            },
            token=session.token,
        )
        token = result.get("token")
        if not isinstance(token, str) or not token:
            raise CloudResponseError("refresh response has no token")
        return CloudSession(token, session.refresh_token, session.account_id)

    async def list_devices(self, session: CloudSession) -> list[CloudDevice]:
        """Fetch every page of the account's device list."""
        devices: list[CloudDevice] = []
        index = 0
        while True:
            result = await self._post(
                "api/v2/common/getDeviceListByPage",
                {"index": index, "limit": PAGE_LIMIT, "deviceTypeList": DEVICE_TYPES},
                token=session.token,
            )
            page = result.get("deviceList")
            entries = [d for d in page if isinstance(d, dict)] if page else []
            devices.extend(CloudDevice.from_api(d) for d in entries)
            index += len(entries)
            total = result.get("totalNum")
            if not entries or not isinstance(total, int) or index >= total:
                return devices

    async def device_details(
        self, session: CloudSession, device: CloudDevice
    ) -> DeviceDetails:
        """Read ``things/<id>/details`` from the device's regional IoT host."""
        region = device.region_code or DEFAULT_REGION_CODE
        url = DETAILS_URL.format(region=region, device_id=device.device_id)
        headers = {
            "Authorization": f"ut|{session.token}",
            "app-cid": f"app:{APP_TYPE}:{self._terminal_uuid}",
            "x-app-name": APP_TYPE,
            "x-app-version": APP_VER,
            "x-term-id": self._terminal_uuid,
            "x-ospf": PLATFORM,
            "x-net-type": "wifi",
            "x-locale": "en_US",
            "Accept": "*/*",
            "Content-Type": "application/json;UTF-8",
            "User-Agent": USER_AGENT,
        }
        data = await self._request("GET", url, headers=headers)
        if not isinstance(data, dict):
            raise CloudResponseError("unexpected details response shape")
        raise_for_error_code(
            int(data.get("error_code", 0)), str(data.get("msg", "")), data
        )
        return DeviceDetails.from_api(data)
