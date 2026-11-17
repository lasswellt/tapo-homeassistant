# Changelog

All notable changes to `tapo_onboard` and `tapolink-proto` (they share one version).
Earlier releases: see the GitHub releases page.

## [0.2.0] - 2026-11-17

### Added
- **Local mode.** Setup now offers *local* or *cloud*. Local mode sweeps your IoT subnets (pre-filled with the subnets of your existing `tplink` devices) with a unicast TDP probe, about 1.5 s per /24, across VLANs, with no cloud calls. You pick the devices to hand to core `tplink`.
- **Upkeep in local mode.** A sweep every 15 minutes, plus a targeted re-probe of a lost device's subnet within a minute. New devices appear as a *Discovered* card that sends your password only after you confirm (it asks for the password again after a restart).
- **`tpap_firmware_detected` repair** when a device advertises the newer TPAP login, which core `tplink` cannot use yet.
- **`tapolink-proto` 0.2.0:** `async_sweep`, `parse_networks` (private IPv4 only, /20 or narrower, 4096 hosts at most, never broadcasts) and `TdpInfo.owned_by`.

### Security
- **Moved devices (both modes).** A device that changed address is updated without asking only when it used KLAP while healthy and still answers KLAP; KLAP makes the device prove it knows your credentials first. Every other case shows a *moved* card. Cloud-mode moved cards check the cloud device ID, so devices shared from another account work.
- Sweep replies whose claimed IP is not the probed address are dropped.
- Local setup stops after two devices reject the password and none accept it.
- README → *Security posture* documents the remaining trade-offs, including that cloud mode still adds new devices automatically.

### Fixed
- A failed sweep shows a form error instead of an empty list.
- A typed password on a *Discovered* card wins over one remembered meanwhile.
- After a restart, concurrent probes share one RSA key build.

### Not yet verified on hardware
Local mode and the moved-device rule are covered by tests (312 tests; config flow at 100% coverage) but have not been run against real devices yet.
