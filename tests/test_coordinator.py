"""Test the AquaTru data update coordinator."""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.aquatru.api import (
    AquaTruAuthError,
    AquaTruConnectionError,
    AquaTruDeviceData,
)
from custom_components.aquatru.const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_PHONE,
    DOMAIN,
)


async def test_coordinator_setup(
    hass: HomeAssistant, mock_coordinator_api, mock_mqtt_client
) -> None:
    """Test coordinator setup."""
    from homeassistant import config_entries

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "testpassword",
            CONF_COUNTRY_CODE: "US",
            CONF_DEVICE_ID: "test-device-id-123",
            CONF_DEVICE_NAME: "Test AquaTru",
            CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
        },
        source=config_entries.SOURCE_USER,
        options={},
        unique_id="5551234567",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.aquatru.coordinator.AquaTruMqttClient"
    ) as mock_mqtt_class:
        mock_mqtt = AsyncMock()
        mock_mqtt.async_connect = AsyncMock(return_value=False)
        mock_mqtt.async_disconnect = AsyncMock()
        mock_mqtt_class.return_value = mock_mqtt

        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        assert entry.state == ConfigEntryState.LOADED


async def test_coordinator_auth_failure(
    hass: HomeAssistant, mock_mqtt_client
) -> None:
    """Test coordinator handles auth failure."""
    from homeassistant import config_entries

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "wrongpassword",
            CONF_COUNTRY_CODE: "US",
            CONF_DEVICE_ID: "test-device-id-123",
            CONF_DEVICE_NAME: "Test AquaTru",
            CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
        },
        source=config_entries.SOURCE_USER,
        options={},
        unique_id="5551234567",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.aquatru.coordinator.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_get_device_data = AsyncMock(
            side_effect=AquaTruAuthError("Auth failed")
        )
        mock_client.close = AsyncMock()
        mock_client_class.return_value = mock_client

        with patch(
            "custom_components.aquatru.coordinator.AquaTruMqttClient"
        ) as mock_mqtt_class:
            mock_mqtt = AsyncMock()
            mock_mqtt.async_connect = AsyncMock(return_value=False)
            mock_mqtt.async_disconnect = AsyncMock()
            mock_mqtt_class.return_value = mock_mqtt

            # Should fail to set up due to auth error
            result = await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()

            # Entry should be in setup retry state
            assert entry.state == ConfigEntryState.SETUP_RETRY


async def test_coordinator_connection_failure(
    hass: HomeAssistant, mock_mqtt_client
) -> None:
    """Test coordinator handles connection failure."""
    from homeassistant import config_entries

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "testpassword",
            CONF_COUNTRY_CODE: "US",
            CONF_DEVICE_ID: "test-device-id-123",
            CONF_DEVICE_NAME: "Test AquaTru",
            CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
        },
        source=config_entries.SOURCE_USER,
        options={},
        unique_id="5551234567",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.aquatru.coordinator.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_get_device_data = AsyncMock(
            side_effect=AquaTruConnectionError("Connection failed")
        )
        mock_client.close = AsyncMock()
        mock_client_class.return_value = mock_client

        with patch(
            "custom_components.aquatru.coordinator.AquaTruMqttClient"
        ) as mock_mqtt_class:
            mock_mqtt = AsyncMock()
            mock_mqtt.async_connect = AsyncMock(return_value=False)
            mock_mqtt.async_disconnect = AsyncMock()
            mock_mqtt_class.return_value = mock_mqtt

            # Should fail to set up due to connection error
            result = await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()

            # Entry should be in setup retry state
            assert entry.state == ConfigEntryState.SETUP_RETRY


async def test_coordinator_mqtt_connection(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test coordinator starts MQTT connection."""
    from homeassistant import config_entries

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "testpassword",
            CONF_COUNTRY_CODE: "US",
            CONF_DEVICE_ID: "test-device-id-123",
            CONF_DEVICE_NAME: "Test AquaTru",
            CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
        },
        source=config_entries.SOURCE_USER,
        options={},
        unique_id="5551234567",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.aquatru.coordinator.AquaTruMqttClient"
    ) as mock_mqtt_class:
        mock_mqtt = AsyncMock()
        mock_mqtt.async_connect = AsyncMock(return_value=True)
        mock_mqtt.async_disconnect = AsyncMock()
        mock_mqtt.is_connected = True
        mock_mqtt_class.return_value = mock_mqtt

        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        assert entry.state == ConfigEntryState.LOADED

        # Verify MQTT was attempted
        mock_mqtt.async_connect.assert_called()


async def test_coordinator_data_update(
    hass: HomeAssistant, mock_coordinator_api, mock_device_data
) -> None:
    """Test coordinator data updates."""
    from homeassistant import config_entries

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "testpassword",
            CONF_COUNTRY_CODE: "US",
            CONF_DEVICE_ID: "test-device-id-123",
            CONF_DEVICE_NAME: "Test AquaTru",
            CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
        },
        source=config_entries.SOURCE_USER,
        options={},
        unique_id="5551234567",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.aquatru.coordinator.AquaTruMqttClient"
    ) as mock_mqtt_class:
        mock_mqtt = AsyncMock()
        mock_mqtt.async_connect = AsyncMock(return_value=False)
        mock_mqtt.async_disconnect = AsyncMock()
        mock_mqtt_class.return_value = mock_mqtt

        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        # Verify data was fetched
        coordinator = entry.runtime_data.coordinator
        assert coordinator.data is not None
        assert coordinator.data.tds_tap == 200
        assert coordinator.data.tds_clean == 10


async def test_coordinator_shutdown(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test coordinator shutdown disconnects MQTT."""
    from homeassistant import config_entries

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "testpassword",
            CONF_COUNTRY_CODE: "US",
            CONF_DEVICE_ID: "test-device-id-123",
            CONF_DEVICE_NAME: "Test AquaTru",
            CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
        },
        source=config_entries.SOURCE_USER,
        options={},
        unique_id="5551234567",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.aquatru.coordinator.AquaTruMqttClient"
    ) as mock_mqtt_class:
        mock_mqtt = AsyncMock()
        mock_mqtt.async_connect = AsyncMock(return_value=True)
        mock_mqtt.async_disconnect = AsyncMock()
        mock_mqtt.is_connected = True
        mock_mqtt_class.return_value = mock_mqtt

        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        # Now unload
        await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()

        # MQTT should be disconnected
        mock_mqtt.async_disconnect.assert_called()


async def test_coordinator_mqtt_message_handling(
    hass: HomeAssistant, mock_coordinator_api, mock_device_data
) -> None:
    """Test coordinator handles MQTT messages."""
    from homeassistant import config_entries
    from custom_components.aquatru.coordinator import AquaTruDataUpdateCoordinator

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "testpassword",
            CONF_COUNTRY_CODE: "US",
            CONF_DEVICE_ID: "test-device-id-123",
            CONF_DEVICE_NAME: "Test AquaTru",
            CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
        },
        source=config_entries.SOURCE_USER,
        options={},
        unique_id="5551234567",
    )
    entry.add_to_hass(hass)

    captured_callback = None

    with patch(
        "custom_components.aquatru.coordinator.AquaTruMqttClient"
    ) as mock_mqtt_class:
        def capture_callback(*args, **kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("on_message")
            mock_mqtt = AsyncMock()
            mock_mqtt.async_connect = AsyncMock(return_value=True)
            mock_mqtt.async_disconnect = AsyncMock()
            mock_mqtt.is_connected = True
            return mock_mqtt

        mock_mqtt_class.side_effect = capture_callback

        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

        coordinator = entry.runtime_data.coordinator

        # Verify callback was captured
        assert captured_callback is not None

        # Test SENSOR-DATA message
        mac = "483fdaa38c99"
        topic = f"aws/{mac}/event/SENSOR-DATA"
        payload = {"tdsClean": 5, "tdsTap": 250}

        # Call the callback
        captured_callback(topic, payload)

        # Data should be updated
        assert coordinator.data.tds_clean == 5
        assert coordinator.data.tds_tap == 250
