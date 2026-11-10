# tapolink — Tapo for Home Assistant, without the IP addresses

A Home Assistant custom integration for TP-Link Tapo (and current Kasa) devices that
finds your devices **by probing your IoT subnets directly** (the TP-Link cloud is an
optional fallback) and controls every device **locally over the LAN**.

Enter your Tapo account email and the subnet your devices are on. Tick the devices
you want. Done. No IP addresses, no DHCP reservations, and it works when your IoT
devices are on a different VLAN from Home Assistant.

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
| Cloud usage | None | None in local mode; device list every 30 min in cloud mode |
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
domain `tapo_onboard`) is a small helper, not a replacement. It finds the IPs; Home
Assistant's core `tplink` integration controls the devices. It has two modes, picked
from a menu when you add it.

### Local mode (recommended, no cloud)

Local mode finds your devices by probing your IoT subnets directly (one unicast TDP
packet per address on UDP 20002) and never contacts TP-Link's cloud.

- **You enter:** your TP-Link account email, its password, and the subnets your
  devices live on. The subnets are pre-filled from the `/24` of every existing TP-Link
  Smart Home device and Home Assistant's own networks. Only private IPv4 ranges, `/20`
  or narrower, at most 4096 addresses in total.
- **Your devices only:** each device's reply carries an owner hash (MD5 of the account
  email). Devices owned by another account are never offered and never receive your
  credentials.
- **Upkeep:** a full sweep every 15 minutes (the same interval as core's own discovery)
  offers each new device as a card you confirm (after a restart the card asks for
  your password, which is then kept in memory only). When a TP-Link Smart Home entry goes unavailable, its `/24` is
  re-probed within about a minute and, if the device answers at a new IP, core's DHCP
  flow updates the host.
- **TPAP warning:** if one of your devices starts advertising TP-Link's newer TPAP
  login, a repair tells you which ones and how to turn on Third-Party Compatibility.
- **Stored:** email, subnets and ignored devices. No cloud token. The password is held
  in memory only.
- **Firewall:** Home Assistant must reach UDP 20002 on the IoT subnets. On the
  maintainer's network one sweep of a `/24` takes about 1.5 s. If UDP is blocked
  between the VLANs, local mode finds nothing; use cloud mode instead.
- **Shared devices** (shared to you from another account) carry the sharer's owner
  hash, so local mode skips them; use cloud mode for those.

### Cloud mode

- Logs in to the TP-Link cloud (with MFA if enabled) and lists your devices with
  their LAN IPs.
- Drives core `tplink`'s add-device flow for the ones you pick, passing the IP and
  your credentials, so you never type an IP. The hand-off, and any "Discovered" card,
  happen only after the device at that IP answers a unicast probe with the device ID
  and MAC address the cloud listed for it.
- Every 30 minutes it re-reads the list. It repairs the IP of lost `tplink` entries
  (stuck in setup retry/error, or loaded with every entity unavailable), and onboards
  newly added devices.

**Install** (Home Assistant 2026.10 or later). In HACS, open the menu > Custom
repositories, add `https://github.com/lasswellt/tapo-homeassistant` with type
"Integration", install "Tapo Cloud Onboarding for TP-Link Smart Home", and restart
Home Assistant. Without HACS, copy `custom_components/tapo_onboard` from the latest
release into your `custom_components/` directory. Home Assistant installs the
`tapolink-proto` library from PyPI on first load.

**Setup.**

1. Settings > Devices & services > Add integration > "Tapo Cloud Onboarding for
   TP-Link Smart Home".
2. Pick **Find devices on my network** (local mode: email, password, subnets) or
   **Use my TP-Link cloud account** (cloud mode: email and password, then the MFA code
   if asked).
3. Tick the devices to onboard. Each is labelled: ready / works partly in TP-Link
   Smart Home / not supported by TP-Link Smart Home / already in TP-Link Smart Home.
   Only "ready" devices start ticked.
4. Wait for the progress step; the devices appear under TP-Link Smart Home. The
   summary names any device that failed (for example, one that is offline).

**Support in core `tplink`** (tested on the maintainer's devices, 2026-11-01):

| Model | Result in TP-Link Smart Home |
|---|---|
| P306 power strip | Full: one switch per socket |
| L730-6 bulb | Partial: a switch plus two child lights ("Down Light", "Ring Light"); also Matter-capable |
| S310D | Not supported by core (BLE-mesh companion switch with no on/off); labelled and left unticked |

**Stored (cloud mode):** the refresh token and terminal UUID only. The password is
never stored; it is held in memory during setup.

**IP upkeep (cloud mode):** the 30-minute poll calls `device_details` only for lost `tplink`
entries and for new devices, at most once per device per 15 minutes. An entry is lost
when it is in setup retry/error, or when it is loaded and every enabled entity is
unavailable (the device moved or is off). If the cloud reports a different IP and the
device there answers with a matching identity, it requests a host update through
core's DHCP flow; core rewrites the host and reloads the entry. Each failed lookup for
the same device (no IP in the cloud, same IP as before, or no matching answer) doubles
the gap before the next one: 15, 30, 60, then at most 120 minutes. The gap resets once
the entry works again. The first poll after setup reuses the device list the setup
dialog just fetched.

**Limitations.**

- After a Home Assistant restart the password is gone from memory. New devices then
  get a "Discovered" card, only if they answer with a matching identity, and you
  re-enter credentials there.
- A device that does not answer the probe (for example UDP 20002 blocked between Home
  Assistant and the IoT network) is not onboarded. It is retried with the backoff
  above.
- A device that answers with a **different** identity (another device now holds that
  IP) gets no card and is not retried until Home Assistant restarts or the
  integration is reloaded.
- Core `tplink`'s own login issues still apply (for example plugs on firmware 1.4.x
  needing TPAP, which core does not provide).
- Matches are only as good as the cloud's IP data; it does not control devices.

Contract drift against core is checked by `tools/check_core_tplink_contract.sh`.

## Status

Phase 1a is released (latest v0.1.2): `tapo_onboard` and `tapolink-proto` (a cloud-only
library). It was verified on Home Assistant 2026.10.4 with real devices on
2026-11-01: 19 of 20 selected devices were onboarded without typing an IP, and the
one failure was a bulb that was offline. Recovering a device that moved IP is covered
by tests but has not been observed on hardware. The full `tapolink` integration is
still a design, with **no public release before TPAP support**: without it, most
current Tapo plugs would not connect.

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
- **New devices in local mode need your confirmation.** The owner hash a device
  reports (MD5 of your account email) is public, so local mode cannot prove a newly
  found device is genuine. After setup, Tapo Onboard shows a "Discovered" card and
  only sends your password to the device once you confirm it. Ignoring the card
  keeps it from coming back.
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
- **Before any credentials are sent**, the device at the cloud's IP must answer a
  unicast probe with the device ID and MAC address your account lists for it, and
  the reply must echo the probe's random serial. The probe is unauthenticated UDP: it
  stops credentials going to a stale or reused IP, not to an attacker on your LAN who
  can see the probe.
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
