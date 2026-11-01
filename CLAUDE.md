# CLAUDE.md — tapolink

Home Assistant custom integration (HACS) for TP-Link **SMART-protocol** devices
(Tapo + current Kasa). **Cloud for discovery, LAN for control.** Domain: `tapolink`.

Two deliverables (`docs/ARCHITECTURE.md` §2):
- **`tapolink-proto`** — our own async protocol library on PyPI (cloud client, TDP,
  AES / KLAP / TPAP transports, SMART protocol, capability device model). No HA imports.
- **`tapolink`** — this repo: the HA integration. **No protocol code here.**

Read `docs/ARCHITECTURE.md` (revision 2) before changing anything, and
`docs/RESEARCH.md` for protocol facts.

---

## The one-line premise

The TP-Link cloud knows each device's **LAN IP address**. The IoT API
`GET https://<rc>-app-server.iot.i.tplinknbu.com/v1/things/<deviceId>/details` returns
it. `getDeviceListByPage` does **not** (verified, spike runs 2–5); it gives the
inventory (names, MACs, `deviceId`, `deviceRegion`). That eliminates manual IP entry
and works across subnets, unlike UDP broadcast discovery. Everything else in this repo
follows from that. Never use the legacy `status` field or passthrough for online
state: both said "offline" for working devices.

## Hard rules

1. **The cloud never controls a device.** Inventory only: deviceId, mac, ip, alias,
   model, fwVer. Control is always local via `tapolink_proto`. `iot_class` stays
   `local_polling`.
2. **No GPL code, ever (clean-room).** python-kasa (GPL-3.0-or-later) and plugp100
   (GPL-3.0-only) must not enter the integration or `tapolink-proto` in any form:
   no copied or translated functions, no mirrored class/module structure, no test
   fixtures or recorded responses from their repos, no dependency.
   - Protocol facts flow **only through `docs/RESEARCH.md`** (a written spec). When
     implementing a transport or device module, work from RESEARCH.md and MIT
     sources; do not open GPL source files for the module being written. If a fact
     is missing, add it to RESEARCH.md first (in your own words, citing the source),
     then implement from the spec.
   - Permissive sources may be adapted: MIT (`TA2k/ioBroker.tapo`,
     `mihai-dinculescu/tapo`, `pytapo`) and Apache-2.0 HA core (**HA-side idioms
     only**, e.g. flow structure or DHCP matcher lists; never core `tplink`'s
     python-kasa calls). Before adapting, confirm the licence at the pinned commit.
     Every file containing adapted code carries a header:
     `# Provenance: adapted from <repo>@<commit> <path> (<SPDX>, © <holder>)`, and the
     licence text goes in `THIRD_PARTY_NOTICES`.
   - Files written from the spec carry `# Provenance: original, from docs/RESEARCH.md §<n>`.
   - Every review/check of `transport/`, `detect.py`, `discovery/`, `cloud/`,
     `protocol/` and `device/` verifies provenance headers. A missing header is a
     blocking finding.
   - Our own licence is **Apache-2.0** (library and integration).
3. **Cloud call budget per account entry:** one login per setup/reauth, one refresh per
   `-20651`, one `list_devices` every 30 min (fixed, not a user option), plus at most
   one early `list_devices` after a working device is lost, plus one `device_details`
   (IoT API) per device only when it needs an address (setup, new MAC, lost device
   with details older than 15 min) — never sooner than 15 min
   after the previous call. Anything more is a bug — TP-Link returns `-20004` and locks
   accounts. Never retry a failed login immediately.
4. **Never persist the cloud password.** Persist `refresh_token`, `terminal_uuid`, and
   the per-scheme auth material in ARCHITECTURE §6.2. The password lives in
   `entry.runtime_data` only. Treat the stored KLAP hash as **offline-guessable**
   (fast, unsalted, known username): persist only the hash variants actually in use,
   and never let `auth_material` / `tpap_verifier` reach diagnostics, logs, repair
   text or exceptions.
5. **`terminal_uuid` is generated once per install and never regenerated.**
6. **MAC is identity.** Subentry `unique_id` = MAC. If `get_device_info` returns a
   different MAC, keep that device unavailable, raise the `wrong_device_at_host`
   repair, and drop to resolver step 2. Do not "fix it up".
7. **Cloud IP is a hint, never authoritative.** Always verify with a local connect.
8. **One device never takes the account down.** Subentries share the account entry's
   setup state, so per-device problems are `UpdateFailed` in that device's coordinator
   (+ a repair if the user can act) — never `ConfigEntryNotReady` /
   `ConfigEntryAuthFailed`. Losing the cloud session calls
   `entry.async_start_reauth(hass)` and pauses inventory; devices keep running.
   Local password needs after restart → the `password_needed_for_devices` repair, not
   reauth.
9. **No brute-force protocol guessing.** Transport comes from the TDP scheme or the
   signal-driven cascade (ARCHITECTURE §7.2). Every real login attempt is a lockout risk.
10. **No placeholder code.** No `TODO`, no `pass  # implement later`, no stubbed
    returns. If a phase isn't being built yet, the module doesn't exist yet.

## Scope

In: SMART-protocol devices. MVP = plugs, power strips, bulbs, light strips, wall
switches and dimmers (dimmer → `light`, on/off wall switch → `switch`, from
capabilities). Test hardware on hand: L730-6 bulbs, S310D dimmers, P306 strip.
Deferred: hubs + hub sensors, cameras/doorbells, vacuums.
Out: legacy Kasa IOT protocol (XOR on 9999, IOT.KLAP).

## Layout

```
custom_components/tapolink/          # this repo
  __init__.py        # setup/unload, account update listener, TapolinkConfigEntry
  config_flow.py     # account: user -> mfa -> probing -> pick_devices; reauth; dhcp
                     # device subentry flow: user (add/un-ignore), reconfigure
  coordinator.py     # InventoryCoordinator (30 min fixed), DeviceCoordinator (5 s)
  resolver.py        # ladder: profile -> TDP -> cascade -> broadcast -> DHCP
  repairs.py         # ARCHITECTURE §11.1
  entity.py switch.py light.py sensor.py binary_sensor.py button.py diagnostics.py
  quality_scale.yaml icons.json strings.json brand/

tapolink_proto/                      # library (separate package)
  cloud/ discovery/ transport/{aes,klap,tpap/} protocol/ device/ detect.py profile.py
```

## Home Assistant conventions (target: Platinum, min HA 2026.11)

Dev docs live at `contributors.home-assistant.io` (moved 2026-10-16).
`docs/research/2026-11-01_ha-platinum-review.md` has the rule-by-rule status.

- **Entry model:** one **account** config entry; each device is a **config subentry**
  (`subentry_type: "device"`). `type TapolinkConfigEntry = ConfigEntry[TapolinkRuntimeData]`
  everywhere. `async_setup_entry` / `async_unload_entry` return `None`; unload with
  `async_unload_platforms_or_raise`.
- **One update listener** on the account entry diffs subentries (add → start device,
  change → swap in place, remove → stop). **No reloading flow methods**: use
  `async_update_and_abort`, `_abort_if_unique_id_configured(reload_on_update=False)`
  (listener + reload methods error from 2026.12).
- **New devices** from inventory → `async_add_subentry` automatically unless in
  `ignored_macs` (Gold `dynamic-devices`). Not a repair.
- **Devices:** `DeviceInfo` is a dataclass (2026.11), registered with
  `async_get_or_create_from_info(..., config_subentry_id=...)`. Strip sockets are
  **child devices** (`ChildDeviceInfo`, `parent_device_id`, explicit
  `config_subentry_id`) — not `via_device_id`. Never use `via_device`, unscoped
  `async_get_device()`, or `DeviceEntry.config_entries`.
- **Entities:** `_attr_has_entity_name = True`; primary entity `_attr_name = None`;
  others `translation_key`; never set `entity_id`; `PARALLEL_UPDATES = 0` in every
  platform; diagnostic category + disabled-by-default per ARCHITECTURE §10; Kelvin
  only for lights.
- **Errors:** every `HomeAssistantError` / `UpdateFailed` / `ConfigEntry*` uses
  `translation_domain=DOMAIN, translation_key=...` and no message. `UpdateFailed(retry_after=...)`
  for `-20004`. `ConfigEntryNotReady`/`ConfigEntryAuthFailed` only when the account
  as a whole cannot work (no subentries and cloud login fails).
- **Repairs:** actionable or informative issues only (ARCHITECTURE §11.1), always with
  `config_entry_id`, re-evaluated in `ir.async_refresh_issues`.
- **Flows:** every `async_show_form` passes `step_id`; every field has
  `data_description`; secrets via `probatio.Secret`; no options flow.
- **Overlap with core `tplink`:** compare MACs against
  `hass.config_entries.async_entries("tplink")` unique IDs (devices are no longer
  merged, so the registry won't show it).
- **Library session:** pass `async_get_clientsession(hass)` to the cloud client and a
  dedicated `async_create_clientsession(hass, verify_ssl=False,
  cookie_jar=aiohttp.CookieJar(unsafe=True))` to devices. The library never creates
  sessions.

## Cloud API cheat sheet

```
TLS:      V2 hosts chain to TP-Link's PRIVATE root "tp-link-CA"; pin it
          (SHA-256 8b54f036…fdec19, RESEARCH.md §3.1). Never verify_ssl=False.
          Tapo cloud *.i.tplinkcloud.com chains to "TP-Link Cloud Server CA"
          (pin as partial-chain anchor, SHA-256 28860572…91b90e, RESEARCH §11.3).
IoT API:  GET https://<rc>-app-server.iot.i.tplinknbu.com/v1/things/<deviceId>/details
          Authorization: ut|<token>; app-cid: app:TP-Link_Tapo_iOS:<terminal_uuid>
          rc from deviceRegion (us-east-1 -> use1). Returns the LAN `ip`. No HMAC.
Gateway:  https://n-wap-gw.tplinkcloud.com          (auth)
          https://n-<region>-wap-gw.tplinkcloud.com (device list, from
                                                     getAccountStatusAndUrl)

Query string on every call:
  ?termID=<terminal_uuid>&appVer=2.8.21&locale=en_US&appName=TP-Link_Tapo_iOS
  &netType=wifi&model=iPhone10%2C5&termName=iPhone&termMeta=3
  &brand=TPLINK&ospf=iOS%2014.8   [&token=<token>]

Headers:
  Content-Type:    application/json;UTF-8
  Content-MD5:     base64(md5(body))
  User-Agent:      Tapo/2.8.21 (iPhone; iOS 14.8; Scale/3.00)
  X-Authorization: Timestamp=<ts>, Nonce=<nonce>, AccessKey=<AK>, Signature=<sig>

Signature:
  content = base64(md5(body)) + "\n" + ts + "\n" + nonce + "\n/" + path
  sig     = hexdigest(HMAC-SHA1(APP_SECRET, content))

App constants (public, shipped in every copy of the Tapo iOS app):
  ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
  APP_SECRET = "6ed7d97f3e73467f8a5bab90b577ba4c"

Endpoints:
  api/v2/account/getAccountStatusAndUrl
  api/v2/account/login
  api/v2/account/getEmailVC4TerminalMFA
  api/v2/account/checkMFACodeAndLogin      (MFAType=2, terminalBindEnabled=true)
  api/v2/common/getDeviceListByPage        <- returns `ip`

Login body keys:
  appVersion refreshTokenNeeded platform cloudPassword terminalUUID
  cloudUserName terminalName terminalMeta appType

Device list body:
  {"index":0,"limit":30,"deviceTypeList":[
    "SMART.TAPOBULB","SMART.TAPOPLUG","SMART.IPCAMERA","SMART.TAPOHUB",
    "SMART.TAPOSENSOR","SMART.TAPOSWITCH","SMART.TAPODOORBELL",
    "SMART.TAPOCHIME","SMART.TAPOLOCK","SMART.TAPOROBOVAC","SMART.TAPONVR"]}

Never include SMART.NVRCHANNEL or SMART.TAPOREMOTE — they arrive as children.

Cloud username is lowercased. Local auth username is CASE-SENSITIVE.
`alias` is base64 UTF-8 — decode it.

Error codes: 0 ok | -20004 rate limit | -20571 device offline |
-20600 no account | -20601 bad creds | -20651 token expired | -23003 appVer too old
```

## TDP probe (unicast, no broadcast)

```python
struct.pack(">BBHHBBII", 2, 0, 1, len(payload), 17, 0, rand32, 0x5A6B7C8D)
payload = b'{"params":{"rsa_key":"<PEM 2048 public>"}}'
packet[12:16] = crc32(packet).to_bytes(4, "big")
# UDP -> host:20002, strip 16-byte header from response, parse JSON
```

Response `result` gives: `device_id owner device_type device_model ip mac
mgt_encrypt_schm{encrypt_type http_port is_support_https lv} tpap{pake port tls
user_hash_type}`.

Identity check before sending credentials (ARCHITECTURE §7.3, verified RESEARCH
§11.3): TDP `device_id` = **MD5(cloud `deviceId`)** and `owner` = **MD5(owning account
email)**. Both are uppercase hex, so compare case-insensitively. The device-ID check
works for shared devices too. A shared device's `owner` is the sharer's hash, so
record it and reject only when the device ID also mismatches.

## Local connect (summary of ARCHITECTURE §7)

```
1. persisted ConnectionProfile @ (host_override or host) -> connect, verify MAC
2. cloud-hint host -> TDP unicast probe  -> identity check -> scheme from mgt_encrypt_schm
3. TDP filtered -> cascade on tcp:       KLAP handshake1 -> TPAP pake_register -> AES
4. TDP broadcast on HA's own subnets     -> match MAC             # same-L2 only
5. IP moved -> async_step_dhcp / early inventory (15-min floor) -> retry from 2
-> UpdateFailed("device_unreachable") for that device only
```

A step-1 failure goes straight to step 2: devices can flip scheme (TPAP↔KLAP), so
never retry a stale cached scheme.

## Testing without hardware

`tools/spike_cloud_discovery.py` exercises the cloud path, the TDP probe, and a local
reference connect against a real account:

```bash
uv run tools/spike_cloud_discovery.py -u you@example.com                    # prompts for pw
uv run tools/spike_cloud_discovery.py -u you@example.com --json r.json --no-local  # inventory only
uv run tools/spike_cloud_discovery.py -u you@example.com --global-only      # Q3: skip region lookup
uv run tools/spike_cloud_discovery.py -u you@example.com --v1               # legacy endpoint
uv run tools/spike_cloud_discovery.py -u you@example.com --term-name "Home Assistant"  # Q8
```

Dependencies are declared inline (PEP 723), so `uv run` installs them. The TDP probe
uses `cryptography` directly. Stage 4 is an **optional** oracle that runs python-kasa
only if you install it separately (`uv run --with python-kasa==0.12.0 ...`); it is not
a declared dependency and nothing from it is kept in this repo.

It answers `docs/RESEARCH.md` §9 Q1–Q8. Run it before writing `tapolink_proto.cloud`.
One run costs a handful of cloud calls; never loop it (`-20004`).

Library tests use a device simulator (aiohttp server implementing the device side of
KLAP/AES/TPAP) plus recorded `component_nego` / `get_device_info` fixtures captured
from our own devices — not fixture files copied from GPL projects.

## Style

- Python 3.13+ (HA runs 3.14 since 2026.3). Full type hints; `mypy --strict` clean;
  library ships `py.typed`. Test coverage >95% (config flow 100%).
- `async` throughout. No blocking I/O in the event loop.
- Dataclasses with `slots=True, frozen=True` for value objects.
- `_LOGGER.debug` for protocol traffic, with secrets redacted.

## Do not

- Add cloud passthrough control.
- Poll the cloud more than rule 3 allows, or make the inventory interval a user option.
- Add python-kasa as a runtime dependency of the integration or the library.
- Add Matter-capable models (`*M` suffix, `L535E`) without the `matter_available`
  notice (owner decision: add them, and tell the user Matter is an option).
- Use `via_device`, `via_device_id` for strip sockets (they are child devices),
  unscoped `async_get_device()`, or reloading flow methods.
- Raise `ConfigEntryNotReady` / `ConfigEntryAuthFailed` for a single device.
- Surface new devices as repairs (they are added automatically).
- Persist the plaintext password, or any AES-scheme credential (it is the password).
