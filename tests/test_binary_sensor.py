"""Test the AquaTru binary sensor platform."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.core import HomeAssistant

from custom_components.aquatru.const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_PHONE,
    DOMAIN,
)


async def test_binary_sensors_created(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test that binary sensors are created correctly."""
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

        # Check filtering binary sensor
        state = hass.states.get("binary_sensor.test_aquatru_filtering")
        assert state is not None
        assert state.state == "off"

        # Check clean tank full binary sensor
        state = hass.states.get("binary_sensor.test_aquatru_clean_tank_full")
        assert state is not None
        assert state.state == "off"

        # Check tap removed binary sensor
        state = hass.states.get("binary_sensor.test_aquatru_tap_tank_removed")
        assert state is not None
        assert state.state == "off"

        # Check tap near end binary sensor
        state = hass.states.get("binary_sensor.test_aquatru_tap_tank_low")
        assert state is not None
        assert state.state == "off"

        # Check clean removed binary sensor
        state = hass.states.get("binary_sensor.test_aquatru_clean_tank_removed")
        assert state is not None
        assert state.state == "off"

        # Check cover up binary sensor
        state = hass.states.get("binary_sensor.test_aquatru_cover_open")
        assert state is not None
        assert state.state == "off"


async def test_binary_sensor_filtering_on(
    hass: HomeAssistant, mock_device_data
) -> None:
    """Test filtering binary sensor when on."""
    from homeassistant import config_entries

    # Modify device data to have filtering on
    mock_device_data.is_filtering = True

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
        mock_client.async_get_device_data = AsyncMock(return_value=mock_device_data)
        mock_client.async_get_settings = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        mock_client.access_token = "test-access-token"
        mock_client_class.return_value = mock_client

        with patch(
            "custom_components.aquatru.coordinator.AquaTruMqttClient"
        ) as mock_mqtt_class:
            mock_mqtt = AsyncMock()
            mock_mqtt.async_connect = AsyncMock(return_value=False)
            mock_mqtt.async_disconnect = AsyncMock()
            mock_mqtt_class.return_value = mock_mqtt

            await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()

            state = hass.states.get("binary_sensor.test_aquatru_filtering")
            assert state is not None
            assert state.state == "on"


async def test_binary_sensor_clean_tank_full(
    hass: HomeAssistant, mock_device_data
) -> None:
    """Test clean tank full binary sensor."""
    from homeassistant import config_entries

    # Modify device data
    mock_device_data.is_clean_tank_full = True

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
        mock_client.async_get_device_data = AsyncMock(return_value=mock_device_data)
        mock_client.async_get_settings = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        mock_client.access_token = "test-access-token"
        mock_client_class.return_value = mock_client

        with patch(
            "custom_components.aquatru.coordinator.AquaTruMqttClient"
        ) as mock_mqtt_class:
            mock_mqtt = AsyncMock()
            mock_mqtt.async_connect = AsyncMock(return_value=False)
            mock_mqtt.async_disconnect = AsyncMock()
            mock_mqtt_class.return_value = mock_mqtt

            await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()

            state = hass.states.get("binary_sensor.test_aquatru_clean_tank_full")
            assert state is not None
            assert state.state == "on"


async def test_binary_sensor_problem_states(
    hass: HomeAssistant, mock_device_data
) -> None:
    """Test problem binary sensors."""
    from homeassistant import config_entries

    # Set problem states
    mock_device_data.is_tap_removed = True
    mock_device_data.is_tap_near_end = True
    mock_device_data.is_clean_removed = True

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
        mock_client.async_get_device_data = AsyncMock(return_value=mock_device_data)
        mock_client.async_get_settings = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        mock_client.access_token = "test-access-token"
        mock_client_class.return_value = mock_client

        with patch(
            "custom_components.aquatru.coordinator.AquaTruMqttClient"
        ) as mock_mqtt_class:
            mock_mqtt = AsyncMock()
            mock_mqtt.async_connect = AsyncMock(return_value=False)
            mock_mqtt.async_disconnect = AsyncMock()
            mock_mqtt_class.return_value = mock_mqtt

            await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()

            # All problem sensors should be on
            state = hass.states.get("binary_sensor.test_aquatru_tap_tank_removed")
            assert state is not None
            assert state.state == "on"

            state = hass.states.get("binary_sensor.test_aquatru_tap_tank_low")
            assert state is not None
            assert state.state == "on"

            state = hass.states.get("binary_sensor.test_aquatru_clean_tank_removed")
            assert state is not None
            assert state.state == "on"


async def test_binary_sensor_cover_open(
    hass: HomeAssistant, mock_device_data
) -> None:
    """Test cover open binary sensor."""
    from homeassistant import config_entries

    mock_device_data.is_cover_up = True

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
        mock_client.async_get_device_data = AsyncMock(return_value=mock_device_data)
        mock_client.async_get_settings = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        mock_client.access_token = "test-access-token"
        mock_client_class.return_value = mock_client

        with patch(
            "custom_components.aquatru.coordinator.AquaTruMqttClient"
        ) as mock_mqtt_class:
            mock_mqtt = AsyncMock()
            mock_mqtt.async_connect = AsyncMock(return_value=False)
            mock_mqtt.async_disconnect = AsyncMock()
            mock_mqtt_class.return_value = mock_mqtt

            await hass.config_entries.async_setup(entry.entry_id)
            await hass.async_block_till_done()

            state = hass.states.get("binary_sensor.test_aquatru_cover_open")
            assert state is not None
            assert state.state == "on"
