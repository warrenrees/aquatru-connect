"""Test the AquaTru sensor platform."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.const import PERCENTAGE, UnitOfVolume
from homeassistant.core import HomeAssistant

from custom_components.aquatru.const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_PHONE,
    DOMAIN,
)


async def test_sensors_created(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test that sensors are created correctly."""
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

        # Check that key sensors exist
        state = hass.states.get("sensor.test_aquatru_tap_water_tds")
        assert state is not None
        assert state.state == "200"

        state = hass.states.get("sensor.test_aquatru_clean_water_tds")
        assert state is not None
        assert state.state == "10"

        state = hass.states.get("sensor.test_aquatru_pre_filter_life")
        assert state is not None
        assert state.state == "80"

        state = hass.states.get("sensor.test_aquatru_total_water_filtered")
        assert state is not None
        assert state.state == "500.0"


async def test_tds_reduction_calculation(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test that TDS reduction is calculated correctly."""
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

        # TDS reduction should be (200 - 10) / 200 * 100 = 95%
        state = hass.states.get("sensor.test_aquatru_tds_reduction")
        assert state is not None
        assert state.state == "95.0"
