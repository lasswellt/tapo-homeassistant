# SPDX-License-Identifier: Apache-2.0
# Provenance: original (docs/plans/core-tplink-onboarding-helper/plan.md)
"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest_plugins = "pytest_homeassistant_custom_component"

_REPO_COMPONENTS = str(Path(__file__).resolve().parents[1] / "custom_components")


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Enable custom integrations and make this repo's ones importable.

    The harness ships its own regular `custom_components` package (put on
    sys.path when `hass` starts), which shadows this repo's directory, so
    extend its search path rather than adding `custom_components/__init__.py`.
    """
    import custom_components  # noqa: PLC0415 - only importable once hass is up

    if _REPO_COMPONENTS not in custom_components.__path__:
        custom_components.__path__.append(_REPO_COMPONENTS)
