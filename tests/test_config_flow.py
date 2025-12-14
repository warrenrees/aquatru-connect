"""Test the AquaTru config flow."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.aquatru.api import (
    AquaTruAuthError,
    AquaTruConnectionError,
    AquaTruDevice,
)
from custom_components.aquatru.const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_PHONE,
    DOMAIN,
)

from .conftest import mock_device


async def test_form(hass: HomeAssistant, mock_api_client, mock_setup_entry) -> None:
    """Test the config flow with a single device."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_PHONE: "5551234567",
            "password": "testpassword",
            CONF_COUNTRY_CODE: "US",
        },
    )
    await hass.async_block_till_done()

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["title"] == "Test AquaTru"
    assert result["data"] == {
        CONF_PHONE: "5551234567",
        "password": "testpassword",
        CONF_COUNTRY_CODE: "US",
        CONF_DEVICE_ID: "test-device-id-123",
        CONF_DEVICE_NAME: "Test AquaTru",
        CONF_DEVICE_MAC: "48:3f:da:a3:8c:99",
    }
    assert len(mock_setup_entry.mock_calls) == 1


async def test_form_multiple_devices(
    hass: HomeAssistant, mock_setup_entry
) -> None:
    """Test the config flow with multiple devices."""
    devices = [
        AquaTruDevice(
            device_id="device-1",
            name="Kitchen AquaTru",
            model="Classic Smart",
            mac_address="11:22:33:44:55:66",
        ),
        AquaTruDevice(
            device_id="device-2",
            name="Office AquaTru",
            model="Classic Smart",
            mac_address="aa:bb:cc:dd:ee:ff",
        ),
    ]

    with patch(
        "custom_components.aquatru.config_flow.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_login = AsyncMock(return_value=True)
        mock_client.async_get_devices = AsyncMock(return_value=devices)
        mock_client.close = AsyncMock()
        mock_client_class.return_value = mock_client

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_PHONE: "5551234567",
                "password": "testpassword",
                CONF_COUNTRY_CODE: "US",
            },
        )

        # Should show device selection step
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "device"

        # Select a device
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_DEVICE_ID: "device-1"},
        )
        await hass.async_block_till_done()

        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["title"] == "Kitchen AquaTru"
        assert result["data"][CONF_DEVICE_ID] == "device-1"


async def test_form_invalid_auth(hass: HomeAssistant) -> None:
    """Test handling invalid auth."""
    with patch(
        "custom_components.aquatru.config_flow.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_login = AsyncMock(side_effect=AquaTruAuthError("Invalid"))
        mock_client.close = AsyncMock()
        mock_client_class.return_value = mock_client

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_PHONE: "5551234567",
                "password": "wrongpassword",
                CONF_COUNTRY_CODE: "US",
            },
        )

        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "invalid_credentials"}


async def test_form_cannot_connect(hass: HomeAssistant) -> None:
    """Test handling connection error."""
    with patch(
        "custom_components.aquatru.config_flow.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_login = AsyncMock(
            side_effect=AquaTruConnectionError("Connection failed")
        )
        mock_client.close = AsyncMock()
        mock_client_class.return_value = mock_client

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_PHONE: "5551234567",
                "password": "testpassword",
                CONF_COUNTRY_CODE: "US",
            },
        )

        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "cannot_connect"}


async def test_form_no_devices(hass: HomeAssistant) -> None:
    """Test handling no devices found."""
    with patch(
        "custom_components.aquatru.config_flow.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_login = AsyncMock(return_value=True)
        mock_client.async_get_devices = AsyncMock(return_value=[])
        mock_client.close = AsyncMock()
        mock_client_class.return_value = mock_client

        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_PHONE: "5551234567",
                "password": "testpassword",
                CONF_COUNTRY_CODE: "US",
            },
        )

        assert result["type"] == FlowResultType.FORM
        assert result["errors"] == {"base": "no_devices"}


async def test_reauth_flow(
    hass: HomeAssistant, mock_api_client, mock_setup_entry
) -> None:
    """Test the reauth flow."""
    # Create a config entry
    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Test AquaTru",
        data={
            CONF_PHONE: "5551234567",
            "password": "oldpassword",
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

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={
            "source": config_entries.SOURCE_REAUTH,
            "entry_id": entry.entry_id,
        },
        data=entry.data,
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"password": "newpassword"},
    )

    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
