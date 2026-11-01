# tapolink — Tapo for Home Assistant, without the IP addresses

A Home Assistant custom integration for TP-Link Tapo (and current Kasa) devices that
uses the TP-Link cloud **for discovery only** and controls every device **locally
over the LAN**.

Sign in once with your Tapo account. Tick the devices you want. Done. No IP
addresses, no DHCP reservations, and it works when your IoT devices are on a
different VLAN from Home Assistant.

You sign in once. After that, new devices on your Tapo account are added
automatically. Any device you untick stays out until you add it back.

## Why this exists

The official `tplink` integration and the existing Tapo custom components discover
devices by UDP broadcast to `255.255.255.255:20002`. Broadcast does not cross
subnets. So once your smart plugs live on an IoT VLAN, you have to enter IP addresses
by hand and pin DHCP leases forever.

The TP-Link cloud already knows every device on your account **and its LAN IP**.
This integration reads that inventory, then connects to each device directly.
Control never goes through the cloud.

| | Official `tplink` (TP-Link Smart Home) | tapolink |
|---|---|---|
| Setup | IP address per device (or same-subnet broadcast) | Account login, tick a list |
| Cross-subnet discovery | No | Yes |
| New devices | Discovered on the same subnet only | Added automatically from your account |
| Control path | Local | Local |
| Cloud usage | None | Device list only, every 30 min |
| Plugs on firmware 1.4.x (TPAP login) | Upstream support pending | Required before the first public release |
| Device scope | Tapo, Kasa (incl. legacy) | Tapo + current Kasa; first release: plugs, power strips, bulbs, light strips, wall switches and dimmers |
| Moving between the two | — | Guided; see "Moving from TP-Link Smart Home" below |

## How it is built

- **`tapolink-proto`**: a standalone async Python library with its own
  implementation of the TP-Link cloud inventory API, the Tapo Discovery Protocol, and
  the local AES / KLAP / TPAP protocols. Published separately on PyPI.
- **`tapolink`**: this repository, the Home Assistant integration on top of it,
  designed to Home Assistant's Platinum quality scale.

Both are Apache-2.0 licensed and contain no GPL code.

## tapo_onboard: use it today with TP-Link Smart Home

`custom_components/tapo_onboard` ("Tapo Cloud Onboarding for TP-Link Smart Home",
domain `tapo_onboard`) is a small helper, not a replacement. The cloud finds the IPs;
Home Assistant's core `tplink` integration controls the devices.

- Logs in to the TP-Link cloud (with MFA if enabled) and lists your devices with
  their LAN IPs.
- Drives core `tplink`'s add-device flow for the ones you pick, passing the IP and
  your credentials, so you never type an IP. The hand-off, and any "Discovered" card,
  happen only after the device answers an identity probe.
- Every 30 minutes it re-reads the list. It repairs the IP of `tplink` entries stuck
  in setup retry/error, and onboards newly added devices.

**Install.** Copy `custom_components/tapo_onboard` into your `custom_components/`
directory, or add this repository as a HACS custom repository. The integration needs
`tapolink-proto` (`packages/tapolink-proto/`) from PyPI, which is **not yet
published**. Until it is, installation is development-only, via the uv workspace in
this repository.

**Setup.**

1. Settings > Devices & services > Add integration > "Tapo Cloud Onboarding for
   TP-Link Smart Home".
2. Enter your TP-Link account email and password; enter the MFA code if asked.
3. Tick the devices to onboard. Each is labelled: ready / works partly in TP-Link
   Smart Home / not supported by TP-Link Smart Home / already in TP-Link Smart Home.
   Only "ready" devices start ticked.
4. Wait for the progress step; the devices appear under TP-Link Smart Home.

**Support in core `tplink`** (tested on the maintainer's devices, 2026-11-01):

| Model | Result in TP-Link Smart Home |
|---|---|
| P306 power strip | Full: one switch per socket |
| L730-6 bulb | Partial: a switch plus two child lights ("Down Light", "Ring Light"); also Matter-capable |
| S310D | Not supported by core (BLE-mesh companion switch with no on/off); labelled and left unticked |

**Stored:** the refresh token and terminal UUID only. The password is never stored;
it is held in memory during setup.

**IP upkeep:** the 30-minute poll calls `device_details` only for `tplink` entries in
setup retry/error and for new devices, and requests a host update through core's DHCP
flow.

**Limitations.**

- After a Home Assistant restart the password is gone from memory. New devices then
  get a "Discovered" card, only if they pass the identity probe, and you re-enter
  credentials there.
- A device that does not answer the identity probe (for example UDP 20002 blocked
  between Home Assistant and the IoT network) is not onboarded and is retried every
  30 minutes.
- Core `tplink`'s own login issues still apply (for example plugs on firmware 1.4.x
  needing TPAP, which core does not provide).
- Matches are only as good as the cloud's IP data; it does not control devices.

Contract drift against core is checked by `tools/check_core_tplink_contract.sh`.

## Status

Phase 1a (`tapo_onboard` and `packages/tapolink-proto/`, a cloud-only library) is
built (2026-11-01). Still pending: manual verification on a real Home Assistant
instance with real devices. The full `tapolink` integration is still a design.
There is **no public release before TPAP support**: without it, most current Tapo
plugs would not connect.

Before writing integration code, run the validation spike against your own account:

```bash
uv run tools/spike_cloud_discovery.py --username you@example.com
# or: pip install aiohttp cryptography
#     python tools/spike_cloud_discovery.py --username you@example.com
```

The spike checks:

- that the cloud returns LAN IPs for your device types, and whether those IPs are
  current;
- each device's protocol, by probing it over unicast UDP;
- whether a cloud token can be refreshed without the password;
- how shared devices identify themselves;
- optionally, whether the login can say "Home Assistant" instead of "iPhone"
  (`--term-name`).

Add `--json report.json` for a full dump. Redact it before sharing: it contains
device IDs and MAC addresses. The local-connect stage can optionally use
python-kasa as an independent cross-check if you install it yourself. tapolink
neither depends on nor includes it.

## Moving from TP-Link Smart Home

Since Home Assistant 2026.8, devices are no longer merged across integrations. A
device set up in both places appears twice, and the second copy's entities get `_2`
IDs. During setup, devices that TP-Link Smart Home already manages start unticked.

To move one:

1. Note any automations that use the device.
2. Delete the device in **TP-Link Smart Home**. This frees its entity IDs.
3. Add it in tapolink, either by ticking it in setup or with **Add device** on the
   account.
4. Check the automations. They work again if the entity IDs match.

Running both integrations against the same device causes intermittent login
failures, so pick one per device.

## Known limitations

- Cameras, doorbells, hubs, hub sensors and vacuums are not supported yet. Legacy
  Kasa devices (port 9999 protocol) are out of scope.
- Devices using the old AES login (pre-2023 firmware) need your password again after
  each Home Assistant restart. A single repair notice asks for it.
- On another VLAN, an IP change can take up to 15–30 minutes to notice, because
  DHCP traffic does not cross VLANs. You can pin an IP per device under
  **Reconfigure** if you prefer.
- Matter-capable models (P110M, P125M, P210M, P304M, L535E, …) are added like any
  device. A notice explains that Home Assistant's Matter integration can also
  control them, with no TP-Link login.

## Security posture

- **Your Tapo password is never written to disk.** It is exchanged for a cloud refresh
  token and kept in memory only until Home Assistant restarts.
- **What is stored** in Home Assistant's config entry storage, like every
  integration's credentials:
  - the cloud refresh token and a per-install terminal ID;
  - for KLAP devices, a login hash derived from your email and password, so plugs
    reconnect after a restart without asking you. The devices require this exact hash,
    so tapolink cannot strengthen it;
  - for TPAP devices, per-device login material derived the same way, but through a
    slower key-derivation step.
- **What a stolen hash means.** Anyone who copies these values (from a backup, a
  `.storage` copy or the disk) can:
  - **control your KLAP devices on your local network** directly;
  - **guess your password offline.** The KLAP hash uses fast, unsalted hashing
    (SHA-1/SHA-256, or MD5 on older devices), and your email is already known, so
    ordinary hardware can test billions of guesses per second. **This can expose a
    weak or reused password, and with it your whole TP-Link account (cameras
    included), not just the plugs.** The TPAP material slows guessing but does not
    prevent it for a weak password.
- **What to do:**
  - use a **strong, unique** password for your TP-Link account, and don't reuse it
    anywhere else;
  - turn on **encrypted Home Assistant backups**, and keep unencrypted copies of
    `.storage` off shared or cloud drives;
  - consider a **dedicated TP-Link account** that owns only your Home Assistant
    devices, once spike Q7 confirms that works (see below).
- **Diagnostics downloads** contain no tokens, hashes, MAC addresses or device names.
- **Cloud usage** is at most one sign-in, one token refresh per expiry, and one
  device-list check per 30 minutes. TP-Link rate-limits and locks accounts that
  exceed this. If the cloud is unreachable or your sign-in expires, **your devices
  keep working**; only finding new devices pauses.
- **Before any credentials are sent**, each device's identity is checked against
  your account's device list.
- **Your Tapo account's list of signed-in devices** shows this integration under the
  name "Home Assistant". The login accepts that name (verified 2026-11-01). Otherwise
  it talks to the TP-Link cloud the way the Tapo iOS app does, so other fields may
  still say iOS/iPhone.
- **Shared devices.** Whether a device shared into your account from another
  TP-Link account can be controlled locally is still being verified (spike Q7). Until
  then, use the account that owns the devices.

## Documentation

- The design notes, protocol reference and research behind this project are kept
  outside the repository. Source files name the section they were written from in
  their `Provenance:` header.
- `CLAUDE.md`: working context for Claude Code.
- `custom_components/tapo_onboard/quality_scale.yaml`: Home Assistant quality-scale
  self-audit.

## Credits

Protocol knowledge in this repo was assembled by reading the work of the
`python-kasa` maintainers, `petretiandrea/plugp100`, `JurajNyiri/pytapo`,
`mihai-dinculescu/tapo`, `TA2k/ioBroker.tapo`, `iluvdata/PyKasaCloud`, K4CZP3R,
Quentin Kaiser, and Spaceraccoon. No code from GPL-licensed projects is included.
Not affiliated with or endorsed by TP-Link.
