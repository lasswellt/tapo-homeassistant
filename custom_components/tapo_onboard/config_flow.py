# SPDX-License-Identifier: Apache-2.0
# Provenance: original
#   (docs/research/2026-11-01_core-tplink-onboarding-helper.md)
"""Config flow: sign in, pick devices, onboard them into core `tplink`."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Network, ip_address
from typing import Any
from uuid import uuid4

import probatio as vol
from homeassistant.components import network
from homeassistant.config_entries import ConfigEntryState, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from homeassistant.util import dt as dt_util
from tapolink_proto.cloud import (
    CloudAuthError,
    CloudClient,
    CloudDevice,
    CloudError,
    CloudRateLimited,
    CloudResponseError,
    CloudSession,
    CloudUnavailable,
    MfaRequired,
    build_cloud_ssl_context,
)
from tapolink_proto.discovery import (
    SweepRangeError,
    TdpInfo,
    async_sweep,
    network_of,
    parse_networks,
)

from .const import (
    CONF_ACCOUNT_ID,
    CONF_IGNORED_MACS,
    CONF_MODE,
    CONF_REFRESH_TOKEN,
    CONF_SUBNETS,
    CONF_TERMINAL_UUID,
    CONF_TOKEN,
    DATA_FLOW_RESULT,
    DATA_PENDING_PASSWORD,
    DOMAIN,
    LOGGER,
    MODE_LOCAL,
    PARTIAL_IN_CORE_MODELS,
    TPLINK_DOMAIN,
    UNSUPPORTED_IN_CORE_MODELS,
)
from .coordinator import FlowResult
from .onboarding import (
    IdentityResult,
    OnboardOutcome,
    async_get_tdp_query,
    async_hand_off_if_verified,
    async_onboard_device,
    async_request_host_update,
    async_tplink_entry_for_mac,
)
from .sweep import _model_base, safe_model

_FAILED = frozenset(
    {
        OnboardOutcome.CANNOT_CONNECT,
        OnboardOutcome.UNAVAILABLE,
        OnboardOutcome.IDENTITY_MISMATCH,
    }
)

_DISCOVERY_ABORTS = {
    OnboardOutcome.ADDED: "device_added",
    OnboardOutcome.ALREADY_CONFIGURED: "already_configured",
    OnboardOutcome.AUTH_FAILED: "auth_failed",
    OnboardOutcome.IDENTITY_MISMATCH: "identity_mismatch",
    OnboardOutcome.HANDED_TO_USER: "handed_to_user",
    OnboardOutcome.CANNOT_CONNECT: "cannot_connect",
    OnboardOutcome.UNAVAILABLE: "tplink_unavailable",
    OnboardOutcome.PENDING_CONFIRMATION: "pending_confirmation",
}

_MOVED_ABORTS = {
    IdentityResult.VERIFIED: "device_moved",
    IdentityResult.MISMATCH: "identity_mismatch",
    IdentityResult.NO_REPLY: "moved_no_reply",
}

MAX_PASSWORD_REJECTIONS = 2

CONF_CODE = "code"
CONF_DEVICES = "devices"

_SUBNET_ERRORS = {
    "invalid": "invalid_subnets",
    "not_ipv4": "invalid_subnets",
    "not_private": "not_private",
    "too_wide": "too_many_hosts",
    "too_many_hosts": "too_many_hosts",
}


@dataclass(frozen=True, slots=True)
class _Candidate:
    """A device the user may onboard, from the cloud list or a local sweep."""

    mac: str
    label: str
    model: str | None
    model_base: str
    host: str | None
    device_id: str | None


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
        self._candidates: list[_Candidate] = []
        self._local = False
        self._networks: list[str] = []
        self._subnets_text = ""
        self._foreign = 0
        self._selected: set[str] = set()
        self._ignored: list[str] = []
        self._outcomes: dict[str, OnboardOutcome] = {}
        self._details_at: dict[str, datetime] = {}
        self._listed_at: datetime | None = None
        self._task: asyncio.Task[None] | None = None
        self._reauth = False
        self._discovered: dict[str, str] = {}
        self._ask_password = False
        self._sweep_failed = False
        self._password_rejected = False
        self._stopped = False

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
        if isinstance(err, CloudError):
            LOGGER.debug("Tapo cloud sign-in failed: %s", type(err).__name__)
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
            step_id="cloud",
            data_schema=schema,
            errors=errors,
            description_placeholders=ph,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Offer local discovery or the TP-Link cloud account."""
        return self.async_show_menu(step_id="user", menu_options=["local", "cloud"])

    async def _prefill_subnets(self) -> list[str]:
        """Return the private /24s of core `tplink` hosts and enabled adapters."""
        addresses = [
            str(entry.data[CONF_HOST])
            for entry in self.hass.config_entries.async_entries(TPLINK_DOMAIN)
            if entry.data.get(CONF_HOST)
        ]
        for adapter in await network.async_get_adapters(self.hass):
            if adapter["enabled"]:
                addresses.extend(ip4["address"] for ip4 in adapter["ipv4"])
        found: list[str] = []
        for address in addresses:
            try:
                net = network_of(address)
            except SweepRangeError:
                continue
            if net.is_private and not net.is_loopback and not net.is_link_local:
                if str(net) not in found:
                    found.append(str(net))
        return found

    def _local_form(self, errors: dict[str, str]) -> ConfigFlowResult:
        subnets_key = (
            vol.Required(CONF_SUBNETS, default=self._subnets_text)
            if self._subnets_text
            else vol.Required(CONF_SUBNETS)
        )
        schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME, default=self._username): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.EMAIL)
                ),
                vol.Required(CONF_PASSWORD): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
                subnets_key: TextSelector(TextSelectorConfig()),
            }
        )
        return self.async_show_form(step_id="local", data_schema=schema, errors=errors)

    async def async_step_local(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the account email, password and the subnets to look in."""
        # A progress step that finished at once hands its own input on here.
        if self._sweep_failed:
            self._sweep_failed = False
            return self._local_form({"base": "sweep_failed"})
        if user_input is None or CONF_USERNAME not in user_input:
            if self._password_rejected:
                self._password_rejected = False
                return self._local_form({"base": "password_rejected"})
            self._subnets_text = ", ".join(await self._prefill_subnets())
            return self._local_form({})
        self._username = str(user_input[CONF_USERNAME]).strip()
        self._password = user_input[CONF_PASSWORD]
        self._subnets_text = str(user_input[CONF_SUBNETS]).strip()
        values = [v for v in re.split(r"[,\s]+", self._subnets_text) if v]
        errors: dict[str, str] = {}
        networks: tuple[IPv4Network, ...] = ()
        try:
            networks = parse_networks(values)
        except SweepRangeError as err:
            errors[CONF_SUBNETS] = _SUBNET_ERRORS.get(err.reason, "invalid_subnets")
        if not networks and not errors:
            errors[CONF_SUBNETS] = "invalid_subnets"
        if errors:
            return self._local_form(errors)
        await self.async_set_unique_id(self._username.lower())
        self._abort_if_unique_id_configured(reload_on_update=False)
        self._local = True
        self._networks = [str(n) for n in networks]
        return await self.async_step_sweeping()

    async def _sweep(self) -> None:
        owned: list[TdpInfo] = []
        foreign = 0
        for info in await async_sweep(
            self._networks, query=await async_get_tdp_query(self.hass)
        ):
            if info.ip is None:
                continue
            if info.owned_by(self._username):
                owned.append(info)
            else:
                foreign += 1
        self._foreign = foreign
        self._candidates = [
            _Candidate(
                mac=info.mac,
                label=f"{info.device_model or 'Tapo device'} at {info.ip}",
                model=None,
                model_base=_model_base(info.device_model),
                host=info.ip,
                device_id=None,
            )
            for info in owned
        ]

    async def async_step_sweeping(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Sweep the subnets as a progress step."""
        if self._task is None:
            self._task = self.hass.async_create_task(self._sweep())
        if not self._task.done():
            return self.async_show_progress(
                step_id="sweeping",
                progress_action="sweeping",
                progress_task=self._task,
            )
        task, self._task = self._task, None
        if task.cancelled():
            LOGGER.debug("Sweep was cancelled")
            self._sweep_failed = True
        elif (err := task.exception()) is not None:
            LOGGER.debug("Sweep failed: %s", type(err).__name__)
            self._sweep_failed = True
        if self._sweep_failed:
            return self.async_show_progress_done(next_step_id="local")
        return self.async_show_progress_done(
            next_step_id="pick_devices" if self._candidates else "finish"
        )

    async def async_step_cloud(
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
            self._listed_at = dt_util.utcnow()
            self._candidates = [
                _Candidate(
                    mac=d.mac,
                    label=d.alias,
                    model=d.model,
                    model_base=d.model_base,
                    host=None,
                    device_id=d.device_id,
                )
                for d in self._devices
            ]
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
        entry = self._get_reauth_entry()
        result = self.async_update_and_abort(
            entry,
            data_updates={
                CONF_TOKEN: self._session.token,
                CONF_REFRESH_TOKEN: self._session.refresh_token,
                CONF_ACCOUNT_ID: self._session.account_id,
            },
        )
        if entry.state is ConfigEntryState.LOADED:
            self.hass.async_create_task(
                entry.runtime_data.coordinator.async_request_refresh()
            )
        return result

    async def async_step_integration_discovery(
        self, discovery_info: dict[str, Any]
    ) -> ConfigFlowResult:
        """Offer a new or moved device found by the background sweep as a card."""
        mac = str(discovery_info["mac"])
        moved = discovery_info.get("kind") == "moved"
        await self.async_set_unique_id(
            f"moved-{format_mac(mac)}-{discovery_info['host']}"
            if moved
            else format_mac(mac)
        )
        self._abort_if_unique_id_configured(reload_on_update=False)
        has_entry = async_tplink_entry_for_mac(self.hass, mac) is not None
        if moved and not has_entry:
            return self.async_abort(reason="moved_entry_gone")
        if has_entry and not moved:
            return self.async_abort(reason="already_configured")
        try:
            host = str(ip_address(str(discovery_info["host"])))
        except ValueError:
            return self.async_abort(reason="cannot_connect")
        model = safe_model(str(discovery_info["model"]))
        self._discovered = {
            "host": host,
            "mac": mac,
            "model": model,
            "entry_id": str(discovery_info["entry_id"]),
        }
        self.context["title_placeholders"] = {"model": model, "host": host}
        if moved:
            return await self.async_step_moved_confirm()
        return await self.async_step_discovery_confirm()

    async def async_step_moved_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask before core logs in at the new address of a device that moved."""
        if user_input is None:
            return self.async_show_form(
                step_id="moved_confirm",
                description_placeholders={
                    "model": self._discovered["model"],
                    "host": self._discovered["host"],
                },
            )
        account = self.hass.config_entries.async_get_entry(self._discovered["entry_id"])
        if account is None or account.state is not ConfigEntryState.LOADED:
            return self.async_abort(reason="password_needed")
        # The entry may have been removed while the card was open.
        if async_tplink_entry_for_mac(self.hass, self._discovered["mac"]) is None:
            return self.async_abort(reason="moved_entry_gone")
        identity = await async_hand_off_if_verified(
            self.hass,
            host=self._discovered["host"],
            mac=self._discovered["mac"],
            owner_email=str(account.data[CONF_USERNAME]),
        )
        return self.async_abort(reason=_MOVED_ABORTS[identity])

    def _confirm_form(
        self, *, ask_password: bool, errors: dict[str, str]
    ) -> ConfigFlowResult:
        schema = (
            vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    )
                }
            )
            if ask_password
            else None
        )
        return self.async_show_form(
            step_id="discovery_confirm",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "model": self._discovered["model"],
                "host": self._discovered["host"],
            },
        )

    async def async_step_discovery_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask before the password goes to a device the sweep just found.

        The password is asked here when the account entry has none in memory
        (after a restart); an accepted one is kept in memory only.
        """
        account = self.hass.config_entries.async_get_entry(self._discovered["entry_id"])
        loaded = (
            account if account and account.state is ConfigEntryState.LOADED else None
        )
        # A card can appear while the account entry is still setting up.
        remembered: str | None = loaded.runtime_data.password if loaded else None
        ask = self._ask_password or not remembered
        if user_input is None:
            return self._confirm_form(ask_password=ask, errors={})
        if loaded is None:
            return self.async_abort(reason="password_needed")
        typed = str(user_input.get(CONF_PASSWORD) or "") if ask else ""
        password: str | None
        if self._ask_password:
            # The remembered password was just rejected: only a typed one counts.
            if not typed:
                return self._confirm_form(
                    ask_password=True, errors={"base": "password_required"}
                )
            password = typed
        else:
            password = typed or remembered
        if not password:
            return self._confirm_form(ask_password=True, errors={})
        outcome = await async_onboard_device(
            self.hass,
            host=self._discovered["host"],
            mac=self._discovered["mac"],
            owner_email=str(loaded.data[CONF_USERNAME]),
            username=str(loaded.data[CONF_USERNAME]),
            password=password,
            request_host_update=False,
        )
        if outcome is OnboardOutcome.AUTH_FAILED:
            self._ask_password = True
            return self._confirm_form(
                ask_password=True, errors={"base": "invalid_auth"}
            )
        if outcome is OnboardOutcome.ADDED and typed:
            loaded.runtime_data.password = typed
        return self.async_abort(reason=_DISCOVERY_ABORTS[outcome])

    def _classify(self, device: _Candidate) -> _Kind:
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
        # A progress step that finished at once hands its own input on here.
        if user_input is not None and CONF_DEVICES in user_input:
            self._selected = set(user_input[CONF_DEVICES])
            self._ignored = sorted(
                d.mac for d in self._candidates if d.mac not in self._selected
            )
            return await self.async_step_onboarding()
        options: list[SelectOptionDict] = []
        ticked: list[str] = []
        for device in sorted(self._candidates, key=lambda d: d.label.lower()):
            kind = self._classify(device)
            name = (
                device.label
                if device.model is None
                else (f"{device.label} ({device.model})")
            )
            options.append(
                SelectOptionDict(value=device.mac, label=f"{name} – {kind.value}")
            )
            if kind in (_Kind.READY, _Kind.PARTIAL):
                ticked.append(device.mac)
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
        cloud = {d.mac: d for d in self._devices}
        rejected: list[tuple[str, str]] = []
        added = False
        for device in self._candidates:
            if device.mac not in self._selected:
                continue
            if async_tplink_entry_for_mac(self.hass, device.mac) is not None:
                self._outcomes[device.mac] = OnboardOutcome.ALREADY_CONFIGURED
                continue
            ip = device.host
            if ip is None:
                assert self._client is not None and self._session is not None  # noqa: S101
                self._details_at[device.mac] = dt_util.utcnow()
                try:
                    details = await self._client.device_details(
                        self._session, cloud[device.mac]
                    )
                    ip = details.ip
                except Exception:  # noqa: BLE001 - one device must not stop the rest
                    LOGGER.debug("device_details failed for %s", device.mac)
                    ip = None
            if ip is None:
                self._outcomes[device.mac] = OnboardOutcome.CANNOT_CONNECT
                continue
            outcome = await async_onboard_device(
                self.hass,
                host=ip,
                mac=device.mac,
                device_id=device.device_id,
                owner_email=self._username if device.device_id is None else None,
                username=self._username,
                password=self._password,
                request_host_update=not self._local,
            )
            self._outcomes[device.mac] = outcome
            if outcome is OnboardOutcome.ADDED:
                added = True
            elif outcome is OnboardOutcome.AUTH_FAILED and self._local:
                rejected.append((ip, device.mac))
                if len(rejected) >= MAX_PASSWORD_REJECTIONS and not added:
                    # Local mode never validated the password: stop rather
                    # than risk a lockout with one failed login per device.
                    self._stopped = True
                    return
        for host, mac in rejected:
            async_request_host_update(self.hass, host=host, mac=mac)

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
        if task.cancelled():
            LOGGER.warning("Onboarding was cancelled")
        elif (err := task.exception()) is not None:
            LOGGER.error("Onboarding failed: %s", type(err).__name__)
        if self._stopped:
            self._stopped = False
            self._password = ""
            self._password_rejected = True
            self._outcomes.clear()
            self._details_at.clear()
            self._selected = set()
            self._ignored = []
            self._candidates = []
            return self.async_show_progress_done(next_step_id="local")
        for mac in self._selected:
            self._outcomes.setdefault(mac, OnboardOutcome.CANNOT_CONNECT)
        return self.async_show_progress_done(next_step_id="finish")

    async def async_step_finish(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Create the entry and hand the password to setup via memory."""
        unique_id = self._username.lower()
        self.hass.data.setdefault(DOMAIN, {}).setdefault(DATA_PENDING_PASSWORD, {})[
            unique_id
        ] = self._password
        self.hass.data[DOMAIN].setdefault(DATA_FLOW_RESULT, {})[unique_id] = FlowResult(
            outcomes=dict(self._outcomes),
            details_at=dict(self._details_at),
            devices=tuple(self._devices),
            listed_at=self._listed_at,
        )
        outcomes = list(self._outcomes.values())
        added = outcomes.count(OnboardOutcome.ADDED)
        confirm = outcomes.count(OnboardOutcome.HANDED_TO_USER) + outcomes.count(
            OnboardOutcome.AUTH_FAILED
        )
        already = outcomes.count(OnboardOutcome.ALREADY_CONFIGURED)
        failed = sum(1 for o in outcomes if o in _FAILED)
        failed_names = sorted(
            (d.label for d in self._candidates if self._outcomes.get(d.mac) in _FAILED),
            key=str.lower,
        )
        failed_devices = f" ({', '.join(failed_names)})" if failed_names else ""
        placeholders = {
            "added": str(added),
            "confirm": str(confirm),
            "already": str(already),
            "failed": str(failed),
            "failed_devices": failed_devices,
        }
        if self._local:
            return self.async_create_entry(
                title=unique_id,
                data={
                    CONF_USERNAME: self._username,
                    CONF_MODE: MODE_LOCAL,
                    CONF_SUBNETS: list(self._networks),
                    CONF_IGNORED_MACS: self._ignored,
                },
                description_placeholders=placeholders,
            )
        assert self._session is not None  # noqa: S101
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
            description_placeholders=placeholders,
        )
