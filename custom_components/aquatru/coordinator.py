"""Data update coordinator for AquaTru."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.issue_registry import IssueSeverity, async_create_issue, async_delete_issue
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    AquaTruApiClient,
    AquaTruAuthError,
    AquaTruConnectionError,
    AquaTruDeviceData,
)
from .const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAC,
    CONF_PHONE,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MQTT_TOPIC_DEVICE_STATUS,
    MQTT_TOPIC_SENSOR_DATA,
)
from .mqtt import (
    AquaTruMqttClient,
    AwsIotSettings,
    parse_device_status,
    parse_sensor_data,
)

_LOGGER = logging.getLogger(__name__)

# Longer polling interval when MQTT is connected (fallback only)
MQTT_FALLBACK_SCAN_INTERVAL = timedelta(minutes=5)

# Issue IDs
ISSUE_CONNECTION_FAILED = "connection_failed"

# Number of consecutive failures before creating an issue
CONNECTION_FAILURE_THRESHOLD = 3


class AquaTruDataUpdateCoordinator(DataUpdateCoordinator[AquaTruDeviceData]):
    """Class to manage fetching AquaTru data from the API."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the coordinator."""
        # Don't use HA's shared session - it uses aiodns which has DNS timeout issues
        # on some devices (e.g., Home Assistant Yellow). Let API client create its own
        # session with ThreadedResolver for reliable DNS resolution.
        self.client = AquaTruApiClient(
            phone=entry.data[CONF_PHONE],
            password=entry.data[CONF_PASSWORD],
            country_code=entry.data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
        )
        self.device_id = entry.data[CONF_DEVICE_ID]
        self.device_name = entry.data.get("device_name", f"AquaTru {self.device_id[:8]}")
        self.device_mac = entry.data.get(CONF_DEVICE_MAC)

        # MQTT client for real-time updates
        self._mqtt_client: AquaTruMqttClient | None = None
        self._mqtt_connected = False

        # Track consecutive connection failures for repair issues
        self._consecutive_failures = 0

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{self.device_id}",
            update_interval=DEFAULT_SCAN_INTERVAL,
            config_entry=entry,
        )

    @property
    def mqtt_connected(self) -> bool:
        """Return True if MQTT is connected."""
        return self._mqtt_connected and self._mqtt_client is not None

    async def async_start_mqtt(self) -> bool:
        """Start MQTT connection for real-time updates."""
        # Get MAC address - either from config or from device data
        mac_address = self.device_mac
        if not mac_address and self.data:
            mac_address = self.data.mac_address

        if not mac_address:
            _LOGGER.warning("No MAC address available for MQTT connection")
            return False

        # Get access token from API client
        access_token = self.client.access_token
        if not access_token:
            _LOGGER.warning("No access token available for MQTT connection")
            return False

        try:
            # Fetch AWS settings from API
            aws_settings = None
            api_settings = await self.client.async_get_settings()
            if api_settings:
                aws_settings = AwsIotSettings(
                    identity_pool_id=api_settings.identity_pool_id,
                    region=api_settings.region,
                )
                _LOGGER.debug(
                    "Using AWS settings from API: region=%s, identity_pool=%s",
                    aws_settings.region,
                    aws_settings.identity_pool_id,
                )
            else:
                _LOGGER.warning("Could not fetch AWS settings, using defaults")

            # Don't use HA's shared session - let MQTT client create its own
            # session with ThreadedResolver for reliable DNS resolution
            self._mqtt_client = AquaTruMqttClient(
                device_mac=mac_address,
                access_token=access_token,
                aws_settings=aws_settings,
                on_message=self._on_mqtt_message,
            )

            success = await self._mqtt_client.async_connect()
            if success:
                self._mqtt_connected = True
                # Reduce polling interval since we have real-time updates
                self.update_interval = MQTT_FALLBACK_SCAN_INTERVAL
                _LOGGER.info("MQTT connected, reduced polling to %s", MQTT_FALLBACK_SCAN_INTERVAL)
                return True
            else:
                _LOGGER.warning("Failed to connect to MQTT")
                return False

        except Exception as err:
            _LOGGER.error("Error starting MQTT: %s", err)
            return False

    def _on_mqtt_message(self, topic: str, payload: dict[str, Any]) -> None:
        """Handle incoming MQTT message."""
        if self.data is None:
            _LOGGER.debug("Ignoring MQTT message - no data yet")
            return

        try:
            # Get device MAC from topic (format: aws/{mac}/event/...)
            topic_parts = topic.split("/")
            if len(topic_parts) < 4:
                return

            topic_mac = topic_parts[1]
            event_type = topic_parts[3]

            # Verify this is for our device
            expected_mac = self.device_mac or (self.data.mac_address if self.data else None)
            if expected_mac:
                clean_mac = expected_mac.replace(":", "").replace("-", "").lower()
                if topic_mac.lower() != clean_mac:
                    _LOGGER.debug("Ignoring MQTT message for different device: %s", topic_mac)
                    return

            _LOGGER.debug("Processing MQTT event: %s", event_type)

            # Parse and update data based on event type
            if event_type == "SENSOR-DATA":
                updates = parse_sensor_data(payload)
                self._apply_updates(updates)
            elif event_type == "DEVICE-STATUS":
                updates = parse_device_status(payload)
                self._apply_updates(updates)
            elif event_type == "MCU-VERSION":
                if "version" in payload:
                    self.data.mcu_version = payload["version"]
                    self.async_set_updated_data(self.data)
            elif event_type == "WELCOME":
                _LOGGER.info("Device welcomed on MQTT")

        except Exception as err:
            _LOGGER.error("Error processing MQTT message: %s", err)

    def _apply_updates(self, updates: dict[str, Any]) -> None:
        """Apply updates to the device data and notify listeners."""
        if not updates or self.data is None:
            return

        # Update data fields
        for key, value in updates.items():
            if hasattr(self.data, key):
                setattr(self.data, key, value)
                _LOGGER.debug("Updated %s = %s via MQTT", key, value)

        # Notify listeners of the update
        self.async_set_updated_data(self.data)

    async def _async_update_data(self) -> AquaTruDeviceData:
        """Fetch data from API."""
        try:
            _LOGGER.debug("Fetching data for device_id: %s", self.device_id)
            data = await self.client.async_get_device_data(self.device_id)
            _LOGGER.debug("Got data: tds_tap=%s, tds_clean=%s, is_connected=%s",
                          data.tds_tap, data.tds_clean, data.is_connected)

            # Store MAC address if we got it from API
            if data.mac_address and not self.device_mac:
                self.device_mac = data.mac_address
                _LOGGER.debug("Got MAC address from API: %s", self.device_mac)

            # Try to start MQTT if not connected
            if not self._mqtt_connected and self.device_mac:
                _LOGGER.info("Attempting to start MQTT connection...")
                await self.async_start_mqtt()

            # Success - reset failure counter and clear any connection issues
            if self._consecutive_failures > 0:
                self._consecutive_failures = 0
                async_delete_issue(
                    self.hass,
                    DOMAIN,
                    f"{ISSUE_CONNECTION_FAILED}_{self.config_entry.entry_id}",
                )

            return data
        except AquaTruAuthError as err:
            raise ConfigEntryAuthFailed(f"Authentication failed: {err}") from err
        except AquaTruConnectionError as err:
            self._consecutive_failures += 1
            if self._consecutive_failures >= CONNECTION_FAILURE_THRESHOLD:
                async_create_issue(
                    self.hass,
                    DOMAIN,
                    f"{ISSUE_CONNECTION_FAILED}_{self.config_entry.entry_id}",
                    is_fixable=False,
                    severity=IssueSeverity.WARNING,
                    translation_key="connection_failed",
                    translation_placeholders={
                        "device_name": self.device_name,
                        "failures": str(self._consecutive_failures),
                    },
                )
            raise UpdateFailed(f"Connection error: {err}") from err
        except Exception as err:
            _LOGGER.exception("Unexpected error fetching data")
            raise UpdateFailed(f"Unexpected error: {err}") from err

    async def async_shutdown(self) -> None:
        """Shutdown the coordinator."""
        # Disconnect MQTT
        if self._mqtt_client:
            _LOGGER.info("Disconnecting MQTT...")
            await self._mqtt_client.async_disconnect()
            self._mqtt_client = None
            self._mqtt_connected = False

        await super().async_shutdown()
        # Close the API client session since we created it
        await self.client.close()
