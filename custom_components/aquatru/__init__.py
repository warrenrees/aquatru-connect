"""The AquaTru integration."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .api import AquaTruAuthError, AquaTruConnectionError
from .const import DOMAIN
from .coordinator import AquaTruDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]


@dataclass
class AquaTruRuntimeData:
    """Runtime data for AquaTru integration."""

    coordinator: AquaTruDataUpdateCoordinator


type AquaTruConfigEntry = ConfigEntry[AquaTruRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: AquaTruConfigEntry) -> bool:
    """Set up AquaTru from a config entry."""
    coordinator = AquaTruDataUpdateCoordinator(hass, entry)

    try:
        await coordinator.async_config_entry_first_refresh()
    except AquaTruAuthError as err:
        _LOGGER.error("Authentication failed: %s", err)
        raise ConfigEntryNotReady(f"Authentication failed: {err}") from err
    except AquaTruConnectionError as err:
        _LOGGER.error("Connection failed: %s", err)
        raise ConfigEntryNotReady(f"Connection failed: {err}") from err

    entry.runtime_data = AquaTruRuntimeData(coordinator=coordinator)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: AquaTruConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        await entry.runtime_data.coordinator.async_shutdown()

    return unload_ok
