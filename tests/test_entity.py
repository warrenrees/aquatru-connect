"""Test the AquaTru base entity."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

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
from custom_components.aquatru.entity import AquaTruEntity


async def test_entity_unique_id(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test entity unique_id generation."""
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

        # Get a sensor entity and check its unique_id
        state = hass.states.get("sensor.test_aquatru_tap_water_tds")
        assert state is not None

        # Get the entity registry to check unique_id
        entity_registry = hass.helpers.entity_registry.async_get(hass)
        entity_entry = entity_registry.async_get("sensor.test_aquatru_tap_water_tds")
        assert entity_entry is not None
        assert entity_entry.unique_id == "test-device-id-123_tds_tap"


async def test_entity_device_info(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test entity device_info."""
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

        # Get device registry
        device_registry = hass.helpers.device_registry.async_get(hass)

        # Find the device
        device = device_registry.async_get_device(
            identifiers={(DOMAIN, "test-device-id-123")}
        )
        assert device is not None
        assert device.name == "Test AquaTru"
        assert device.manufacturer == "AquaTru"
        assert device.model == "Classic Smart"


async def test_entity_availability(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test entity availability."""
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

        # Entity should be available when coordinator has data
        state = hass.states.get("sensor.test_aquatru_tap_water_tds")
        assert state is not None
        assert state.state != "unavailable"


async def test_entity_firmware_versions(
    hass: HomeAssistant, mock_coordinator_api
) -> None:
    """Test entity device info includes firmware versions."""
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

        # Get device registry
        device_registry = hass.helpers.device_registry.async_get(hass)

        # Find the device
        device = device_registry.async_get_device(
            identifiers={(DOMAIN, "test-device-id-123")}
        )
        assert device is not None

        # Firmware versions from mock_device_data fixture
        assert device.sw_version == "2.0.0"  # MCU version
        assert device.hw_version == "1.0.0"  # WiFi version
