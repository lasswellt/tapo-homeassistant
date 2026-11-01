# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Config flow: sign in, pick devices, onboard them into core `tplink`."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any
from uuid import uuid4

import probatio as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudClient,
    CloudDevice,
    CloudRateLimited,
    CloudResponseError,
    CloudSession,
    CloudUnavailable,
    MfaRequired,
    build_cloud_ssl_context,
)

from .const import (
    CONF_ACCOUNT_ID,
    CONF_IGNORED_MACS,
    CONF_REFRESH_TOKEN,
    CONF_TERMINAL_UUID,
    CONF_TOKEN,
    DATA_PENDING_PASSWORD,
    DOMAIN,
    LOGGER,
    PARTIAL_IN_CORE_MODELS,
    UNSUPPORTED_IN_CORE_MODELS,
)
from .onboarding import OnboardOutcome, async_onboard_device, async_tplink_entry_for_mac

CONF_CODE = "code"
CONF_DEVICES = "devices"


class _Kind(StrEnum):
    READY = "ready"
    PARTIAL = "works partly in TP-Link Smart Home"
    UNSUPPORTED = "not supported by TP-Link Smart Home"
    ALREADY_IN_TPLINK = "already in TP-Link Smart Home"


class TapoOnboardConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the Tapo Cloud Onboarding config flow."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialise per-flow state (password stays in memory only)."""
        self._username = ""
        self._password = ""
        self._terminal_uuid = str(uuid4())
        self._client: CloudClient | None = None
        self._process_id = ""
        self._session: CloudSession | None = None
        self._devices: list[CloudDevice] = []
        self._ticked: list[str] = []
        self._selected: set[str] = set()
        self._ignored: list[str] = []
        self._outcomes: dict[str, OnboardOutcome] = {}
        self._task: asyncio.Task[None] | None = None
        self._reauth = False

    @staticmethod
    def _error(err: Exception) -> tuple[str, dict[str, str]]:
        placeholders = {"minutes": "a few"}
        if isinstance(err, CloudAuthError):
            return "invalid_auth", placeholders
        if isinstance(err, CloudRateLimited):
            if err.retry_after:
                placeholders["minutes"] = str(max(1, round(err.retry_after / 60)))
            return "rate_limited", placeholders
        if isinstance(err, CloudUnavailable | CloudResponseError):
            return "cannot_connect", placeholders
        LOGGER.exception("Unexpected error during Tapo cloud sign-in")
        return "unknown", placeholders

    def _user_form(
        self, errors: dict[str, str], ph: dict[str, str]
    ) -> ConfigFlowResult:
        schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME, default=self._username): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.EMAIL)
                ),
                vol.Required(CONF_PASSWORD): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders=ph,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the TP-Link cloud account and sign in."""
        if user_input is None:
            return self._user_form({}, {"minutes": ""})
        self._username = str(user_input[CONF_USERNAME]).strip()
        self._password = user_input[CONF_PASSWORD]
        await self.async_set_unique_id(self._username.lower())
        self._abort_if_unique_id_configured(reload_on_update=False)
        return await self._sign_in(self._user_form)

    async def _sign_in(
        self, show_form: Callable[[dict[str, str], dict[str, str]], ConfigFlowResult]
    ) -> ConfigFlowResult:
        ssl_ctx = await self.hass.async_add_executor_job(build_cloud_ssl_context)
        self._client = CloudClient(
            async_get_clientsession(self.hass),
            ssl_context=ssl_ctx,
            terminal_uuid=self._terminal_uuid,
        )
        try:
            self._session = await self._client.login(self._username, self._password)
        except MfaRequired as err:
            self._process_id = err.process_id
            try:
                await self._client.request_mfa_code(self._username, self._password)
            except Exception as mfa_err:  # noqa: BLE001 - mapped to a form error
                key, ph = self._error(mfa_err)
                return show_form({"base": key}, ph)
            return await self.async_step_mfa()
        except Exception as err:  # noqa: BLE001 - mapped to a form error
            key, ph = self._error(err)
            return show_form({"base": key}, ph)
        return await self._after_login()

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the emailed MFA code."""
        assert self._client is not None  # noqa: S101 - set by the user step
        errors: dict[str, str] = {}
        ph = {"minutes": "a few"}
        if user_input is not None:
            code = str(user_input[CONF_CODE]).strip()
            if len(code) != 6 or not code.isdigit():
                errors["base"] = "invalid_code"
            else:
                try:
                    self._session = await self._client.submit_mfa_code(
                        self._username, self._process_id, code
                    )
                except Exception as err:  # noqa: BLE001 - mapped to a form error
                    key, ph = self._error(err)
                    errors["base"] = key
                else:
                    return await self._after_login()
        return self.async_show_form(
            step_id="mfa",
            data_schema=vol.Schema({vol.Required(CONF_CODE): str}),
            errors=errors,
            description_placeholders={**ph, "email": self._username},
        )

    async def _after_login(self) -> ConfigFlowResult:
        if self._reauth:
            return await self._finish_reauth()
        assert self._client is not None and self._session is not None  # noqa: S101
        try:
            self._devices = await self._client.list_devices(self._session)
        except Exception as err:  # noqa: BLE001 - mapped to a form error
            key, ph = self._error(err)
            return self._user_form({"base": key}, ph)
        return await self.async_step_pick_devices()

    def _reauth_form(
        self, errors: dict[str, str], ph: dict[str, str]
    ) -> ConfigFlowResult:
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    )
                }
            ),
            errors=errors,
            description_placeholders={**ph, "username": self._username},
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start reauth after the coordinator lost the cloud sign-in."""
        entry = self._get_reauth_entry()
        self._reauth = True
        self._username = str(entry.data[CONF_USERNAME])
        self._terminal_uuid = str(entry.data[CONF_TERMINAL_UUID])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-collect the password and refresh the stored tokens."""
        if user_input is None:
            return self._reauth_form({}, {"minutes": ""})
        self._password = user_input[CONF_PASSWORD]
        return await self._sign_in(self._reauth_form)

    async def _finish_reauth(self) -> ConfigFlowResult:
        assert self._session is not None  # noqa: S101 - set by login
        unique_id = self._username.lower()
        await self.async_set_unique_id(unique_id)
        self._abort_if_unique_id_mismatch(reason="wrong_account")
        self.hass.data.setdefault(DOMAIN, {}).setdefault(DATA_PENDING_PASSWORD, {})[
            unique_id
        ] = self._password
        return self.async_update_and_abort(
            self._get_reauth_entry(),
            data_updates={
                CONF_TOKEN: self._session.token,
                CONF_REFRESH_TOKEN: self._session.refresh_token,
                CONF_ACCOUNT_ID: self._session.account_id,
            },
        )

    def _classify(self, device: CloudDevice) -> _Kind:
        if async_tplink_entry_for_mac(self.hass, device.mac) is not None:
            return _Kind.ALREADY_IN_TPLINK
        if device.model_base in UNSUPPORTED_IN_CORE_MODELS:
            return _Kind.UNSUPPORTED
        if device.model_base in PARTIAL_IN_CORE_MODELS:
            return _Kind.PARTIAL
        return _Kind.READY

    async def async_step_pick_devices(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let the user choose which devices to onboard."""
        if user_input is not None:
            self._selected = set(user_input[CONF_DEVICES])
            self._ignored = sorted(
                d.mac for d in self._devices if d.mac not in self._selected
            )
            return await self.async_step_onboarding()
        options: list[SelectOptionDict] = []
        ticked: list[str] = []
        for device in sorted(self._devices, key=lambda d: d.alias.lower()):
            kind = self._classify(device)
            options.append(
                SelectOptionDict(
                    value=device.mac,
                    label=f"{device.alias} ({device.model}) – {kind.value}",
                )
            )
            if kind in (_Kind.READY, _Kind.PARTIAL):
                ticked.append(device.mac)
        self._ticked = ticked
        schema = vol.Schema(
            {
                vol.Required(CONF_DEVICES, default=ticked): SelectSelector(
                    SelectSelectorConfig(
                        options=options,
                        multiple=True,
                        mode=SelectSelectorMode.LIST,
                    )
                )
            }
        )
        return self.async_show_form(step_id="pick_devices", data_schema=schema)

    async def _onboard_selected(self) -> None:
        assert self._client is not None and self._session is not None  # noqa: S101
        for device in self._devices:
            if device.mac not in self._selected:
                continue
            try:
                details = await self._client.device_details(self._session, device)
                ip = details.ip
            except Exception:  # noqa: BLE001 - one device must not stop the rest
                LOGGER.debug("device_details failed for %s", device.mac)
                ip = None
            if ip is None:
                self._outcomes[device.mac] = OnboardOutcome.CANNOT_CONNECT
                continue
            self._outcomes[device.mac] = await async_onboard_device(
                self.hass,
                host=ip,
                mac=device.mac,
                device_id=device.device_id,
                username=self._username,
                password=self._password,
            )

    async def async_step_onboarding(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Run onboarding as a progress step."""
        if self._task is None:
            self._task = self.hass.async_create_task(self._onboard_selected())
        if not self._task.done():
            return self.async_show_progress(
                step_id="onboarding",
                progress_action="onboarding",
                progress_task=self._task,
            )
        task, self._task = self._task, None
        if (err := task.exception()) is not None:
            LOGGER.error("Onboarding failed: %s", type(err).__name__)
        return self.async_show_progress_done(next_step_id="finish")

    async def async_step_finish(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Create the entry and hand the password to setup via memory."""
        assert self._session is not None  # noqa: S101
        unique_id = self._username.lower()
        self.hass.data.setdefault(DOMAIN, {}).setdefault(DATA_PENDING_PASSWORD, {})[
            unique_id
        ] = self._password
        outcomes = list(self._outcomes.values())
        added = outcomes.count(OnboardOutcome.ADDED)
        confirm = outcomes.count(OnboardOutcome.HANDED_TO_USER) + outcomes.count(
            OnboardOutcome.AUTH_FAILED
        )
        already = outcomes.count(OnboardOutcome.ALREADY_CONFIGURED)
        failed = len(outcomes) - added - confirm - already
        return self.async_create_entry(
            title=unique_id,
            data={
                CONF_USERNAME: self._username,
                CONF_TERMINAL_UUID: self._terminal_uuid,
                CONF_TOKEN: self._session.token,
                CONF_REFRESH_TOKEN: self._session.refresh_token,
                CONF_ACCOUNT_ID: self._session.account_id,
                CONF_IGNORED_MACS: self._ignored,
            },
            description_placeholders={
                "added": str(added),
                "confirm": str(confirm),
                "already": str(already),
                "failed": str(failed),
            },
        )
