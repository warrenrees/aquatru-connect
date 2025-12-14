"""Data update coordinator for AquaTru."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    AquaTruApiClient,
    AquaTruAuthError,
    AquaTruConnectionError,
    AquaTruDeviceData,
)
from .const import CONF_COUNTRY_CODE, CONF_DEVICE_ID, CONF_PHONE, DEFAULT_COUNTRY_CODE, DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


class AquaTruDataUpdateCoordinator(DataUpdateCoordinator[AquaTruDeviceData]):
    """Class to manage fetching AquaTru data from the API."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the coordinator."""
        self.client = AquaTruApiClient(
            phone=entry.data[CONF_PHONE],
            password=entry.data[CONF_PASSWORD],
            country_code=entry.data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
            session=async_get_clientsession(hass),
        )
        self.device_id = entry.data[CONF_DEVICE_ID]
        self.device_name = entry.data.get("device_name", f"AquaTru {self.device_id[:8]}")

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{self.device_id}",
            update_interval=DEFAULT_SCAN_INTERVAL,
            config_entry=entry,
        )

    async def _async_update_data(self) -> AquaTruDeviceData:
        """Fetch data from API."""
        try:
            return await self.client.async_get_device_data(self.device_id)
        except AquaTruAuthError as err:
            raise ConfigEntryAuthFailed(f"Authentication failed: {err}") from err
        except AquaTruConnectionError as err:
            raise UpdateFailed(f"Connection error: {err}") from err
        except Exception as err:
            _LOGGER.exception("Unexpected error fetching data")
            raise UpdateFailed(f"Unexpected error: {err}") from err

    async def async_shutdown(self) -> None:
        """Shutdown the coordinator."""
        await super().async_shutdown()
        # Note: We don't close the client session as it's shared
