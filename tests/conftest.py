"""Fixtures for AquaTru tests."""
from __future__ import annotations

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.aquatru.api import AquaTruDevice, AquaTruDeviceData
from custom_components.aquatru.const import DOMAIN

# Import pytest-homeassistant-custom-component fixtures
pytest_plugins = "pytest_homeassistant_custom_component"


@pytest.fixture
def mock_device() -> AquaTruDevice:
    """Create a mock AquaTru device."""
    return AquaTruDevice(
        device_id="test-device-id-123",
        name="Test AquaTru",
        model="Classic Smart",
        serial_number="SN123456",
        mac_address="48:3f:da:a3:8c:99",
        location="Kitchen",
        is_connected=True,
    )


@pytest.fixture
def mock_device_data() -> AquaTruDeviceData:
    """Create mock device data."""
    return AquaTruDeviceData(
        device_id="test-device-id-123",
        mac_address="48:3f:da:a3:8c:99",
        tds_tap=200,
        tds_clean=10,
        filter_pre_life=80,
        filter_ro_life=70,
        filter_voc_life=60,
        is_connected=True,
        is_filtering=False,
        is_clean_tank_full=False,
        is_tap_removed=False,
        is_tap_near_end=False,
        is_clean_removed=False,
        is_purifier_synced=True,
        is_cover_up=False,
        daily_usage=1.5,
        weekly_usage=10.0,
        monthly_usage=40.0,
        total_usage=500.0,
        filtration_time=3600,
        money_saved=150.0,
        bottles_saved=1000,
        wifi_version="1.0.0",
        mcu_version="2.0.0",
        connection_name="home-wifi",
    )


@pytest.fixture
def mock_api_client(mock_device: AquaTruDevice, mock_device_data: AquaTruDeviceData):
    """Create a mock API client."""
    with patch(
        "custom_components.aquatru.config_flow.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_login = AsyncMock(return_value=True)
        mock_client.async_get_devices = AsyncMock(return_value=[mock_device])
        mock_client.async_get_device_data = AsyncMock(return_value=mock_device_data)
        mock_client.async_get_settings = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        mock_client.access_token = "test-access-token"
        mock_client_class.return_value = mock_client
        yield mock_client


@pytest.fixture
def mock_coordinator_api(mock_device_data: AquaTruDeviceData):
    """Create a mock API client for coordinator."""
    with patch(
        "custom_components.aquatru.coordinator.AquaTruApiClient"
    ) as mock_client_class:
        mock_client = AsyncMock()
        mock_client.async_login = AsyncMock(return_value=True)
        mock_client.async_get_device_data = AsyncMock(return_value=mock_device_data)
        mock_client.async_get_settings = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        mock_client.access_token = "test-access-token"
        mock_client_class.return_value = mock_client
        yield mock_client


@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock, None, None]:
    """Override async_setup_entry."""
    with patch(
        "custom_components.aquatru.async_setup_entry", return_value=True
    ) as mock_setup:
        yield mock_setup


@pytest.fixture
def mock_mqtt_client():
    """Create a mock MQTT client."""
    with patch(
        "custom_components.aquatru.coordinator.AquaTruMqttClient"
    ) as mock_mqtt_class:
        mock_mqtt = AsyncMock()
        mock_mqtt.async_connect = AsyncMock(return_value=True)
        mock_mqtt.async_disconnect = AsyncMock()
        mock_mqtt.is_connected = True
        mock_mqtt.credentials_expiration = None
        mock_mqtt_class.return_value = mock_mqtt
        yield mock_mqtt
