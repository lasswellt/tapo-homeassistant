#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Provenance: original (docs/plans/core-tplink-onboarding-helper/plan.md, Risks)
#
# Contract check: the identifiers the tapo_onboard bridge relies on exist in
# Home Assistant core's tplink config_flow.py (Apache-2.0) at the pinned tag,
# and the test stub declares the same step ids. Reads HA core only, never
# python-kasa.
#
# Exit: 0 ok, 1 contract drift (core or stub), 2 fetch failure.
# HA_REF_DEV=<ref> additionally checks that ref, warn-only.
set -euo pipefail

HA_REF="${HA_REF:-2026.10.4}"
HA_REF_DEV="${HA_REF_DEV:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STUB="$ROOT/tests/tapo_onboard/stub_tplink.py"
URL_BASE="https://raw.githubusercontent.com/home-assistant/core"
URL_PATH="homeassistant/components/tplink/config_flow.py"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Fixed-string patterns required in core.
CORE_FIXED=(
  'async def async_step_user('
  'async def async_step_user_auth_confirm('
  'step_id="user_auth_confirm"'
  'async def async_step_dhcp('
  '_abort_if_unique_id_configured(updates={CONF_HOST: host})'
  'errors["base"] = "cannot_connect"'
  'STEP_AUTH_DATA_SCHEMA'
)
# Regex: CONF_HOST in the user schema (vol.Optional or default="" forms).
CORE_HOST_RE='(vol|probatio)\.(Optional|Required)\(CONF_HOST|CONF_HOST, default=""'

# Prints DRIFT lines for the core file at $1 (a ref); returns 2 on fetch error.
# Echoes nothing to stdout on success; DRIFT lines go to stdout, count via rc 1.
check_core() {
  local ref="$1" fail=0 p
  if ! curl -fsSL --max-time 30 "$URL_BASE/$ref/$URL_PATH" -o "$tmp"; then
    echo "FETCH FAILED: $URL_BASE/$ref/$URL_PATH (network or ref problem, not contract drift)" >&2
    return 2
  fi
  for p in "${CORE_FIXED[@]}"; do
    grep -qF -- "$p" "$tmp" || { echo "DRIFT: $p"; fail=1; }
  done
  grep -qE -- "$CORE_HOST_RE" "$tmp" || { echo "DRIFT: CONF_HOST user schema"; fail=1; }
  # CONF_USERNAME / CONF_PASSWORD must be present for the credentials form.
  for p in CONF_USERNAME CONF_PASSWORD; do
    grep -qF -- "$p" "$tmp" || { echo "DRIFT: $p"; fail=1; }
  done
  return "$fail"
}

rc=0
core_rc=0
check_core "$HA_REF" || core_rc=$?
if [ "$core_rc" -eq 2 ]; then exit 2; fi
[ "$core_rc" -eq 0 ] || rc=1

# Stub must declare the step ids/handlers the bridge maps.
STUB_PATTERNS=(
  'step_id="user"'
  'step_id="user_auth_confirm"'
  'async_step_dhcp'
)
for p in "${STUB_PATTERNS[@]}"; do
  grep -qF -- "$p" "$STUB" || { echo "STUB: $p"; rc=1; }
done

if [ -n "$HA_REF_DEV" ]; then
  dev_rc=0
  dev_out="$(check_core "$HA_REF_DEV")" || dev_rc=$?
  if [ "$dev_rc" -eq 0 ]; then
    echo "OK: core tplink @ ${HA_REF_DEV} also matches (dev check)"
  else
    echo "WARN: dev drift: ${HA_REF_DEV} (rc=${dev_rc}) $(printf '%s' "$dev_out" | tr '\n' ';')"
  fi
fi

if [ "$rc" -eq 0 ]; then
  echo "OK: core tplink @ ${HA_REF} matches the tapo_onboard bridge contract"
fi
exit "$rc"
