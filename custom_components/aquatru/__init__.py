"""The AquaTru integration."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .coordinator import AquaTruDataUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]


@dataclass
class AquaTruRuntimeData:
    """Runtime data for AquaTru integration."""

    coordinator: AquaTruDataUpdateCoordinator


type AquaTruConfigEntry = ConfigEntry[AquaTruRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: AquaTruConfigEntry) -> bool:
    """Set up AquaTru from a config entry."""
    coordinator = AquaTruDataUpdateCoordinator(hass, entry)

    # The coordinator raises ConfigEntryAuthFailed (-> reauth) on auth errors and
    # UpdateFailed (-> ConfigEntryNotReady) on connection errors; first_refresh
    # surfaces both correctly, so no extra handling is needed here.
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = AquaTruRuntimeData(coordinator=coordinator)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: AquaTruConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        await entry.runtime_data.coordinator.async_shutdown()

    return unload_ok
