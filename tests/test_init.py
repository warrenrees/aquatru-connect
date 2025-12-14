"""Test the AquaTru integration initialization."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant

from custom_components.aquatru.const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_PHONE,
    DOMAIN,
)


async def test_setup_entry(
    hass: HomeAssistant, mock_coordinator_api, mock_mqtt_client
) -> None:
    """Test successful setup of config entry."""
    entry = hass.config_entries.async_entries(DOMAIN)[0] if hass.config_entries.async_entries(DOMAIN) else None

    if entry is None:
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


async def test_unload_entry(
    hass: HomeAssistant, mock_coordinator_api, mock_mqtt_client
) -> None:
    """Test successful unload of config entry."""
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

        await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()

        assert entry.state == ConfigEntryState.NOT_LOADED
