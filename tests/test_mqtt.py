"""Test the AquaTru MQTT client."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from custom_components.aquatru.mqtt import (
    AquaTruMqttClient,
    AwsIotSettings,
    CognitoCredentials,
    parse_device_status,
    parse_sensor_data,
    CREDENTIAL_REFRESH_BUFFER,
    CREDENTIAL_CHECK_INTERVAL,
)


@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    session.closed = False
    return session


@pytest.fixture
def aws_settings():
    """Create AWS IoT settings."""
    return AwsIotSettings(
        identity_pool_id="us-east-1:test-pool-id",
        region="us-east-1",
    )


@pytest.fixture
def mqtt_client(aws_settings, mock_session):
    """Create an MQTT client with mocks."""
    return AquaTruMqttClient(
        device_mac="48:3f:da:a3:8c:99",
        access_token="test-access-token",
        aws_settings=aws_settings,
        session=mock_session,
    )


class TestAwsIotSettings:
    """Test AwsIotSettings dataclass."""

    def test_cognito_endpoint(self, aws_settings):
        """Test cognito endpoint property."""
        assert aws_settings.cognito_endpoint == "https://cognito-identity.us-east-1.amazonaws.com"

    def test_different_region(self):
        """Test cognito endpoint with different region."""
        settings = AwsIotSettings(
            identity_pool_id="eu-west-1:test-pool",
            region="eu-west-1",
        )
        assert settings.cognito_endpoint == "https://cognito-identity.eu-west-1.amazonaws.com"


class TestCognitoCredentials:
    """Test CognitoCredentials dataclass."""

    def test_credentials_creation(self):
        """Test creating credentials."""
        expiration = datetime.now(timezone.utc) + timedelta(hours=6)
        creds = CognitoCredentials(
            identity_id="us-east-1:identity-id",
            access_key_id="AKIATEST",
            secret_key="secretkey",
            session_token="sessiontoken",
            expiration=expiration,
        )

        assert creds.identity_id == "us-east-1:identity-id"
        assert creds.access_key_id == "AKIATEST"
        assert creds.expiration == expiration


class TestAquaTruMqttClient:
    """Test AquaTruMqttClient."""

    def test_init_with_session(self, mqtt_client, mock_session):
        """Test initialization with injected session."""
        assert mqtt_client._session == mock_session
        assert mqtt_client._owns_session is False

    def test_init_without_session(self, aws_settings):
        """Test initialization without session."""
        client = AquaTruMqttClient(
            device_mac="48:3f:da:a3:8c:99",
            access_token="test-token",
            aws_settings=aws_settings,
        )
        assert client._session is None
        assert client._owns_session is True

    def test_mac_address_normalization(self, aws_settings):
        """Test MAC address is normalized."""
        client = AquaTruMqttClient(
            device_mac="48:3F:DA:A3:8C:99",
            access_token="test-token",
            aws_settings=aws_settings,
        )
        assert client._device_mac == "483fdaa38c99"

        client = AquaTruMqttClient(
            device_mac="48-3f-da-a3-8c-99",
            access_token="test-token",
            aws_settings=aws_settings,
        )
        assert client._device_mac == "483fdaa38c99"

    def test_is_connected_property(self, mqtt_client):
        """Test is_connected property."""
        assert mqtt_client.is_connected is False

        mqtt_client._connected = True
        assert mqtt_client.is_connected is True

    def test_credentials_expiration_property(self, mqtt_client):
        """Test credentials_expiration property."""
        assert mqtt_client.credentials_expiration is None

        expiration = datetime.now(timezone.utc) + timedelta(hours=6)
        mqtt_client._credentials = CognitoCredentials(
            identity_id="test",
            access_key_id="test",
            secret_key="test",
            session_token="test",
            expiration=expiration,
        )
        assert mqtt_client.credentials_expiration == expiration

    def test_credentials_need_refresh_no_credentials(self, mqtt_client):
        """Test credentials_need_refresh when no credentials."""
        assert mqtt_client._credentials_need_refresh() is True

    def test_credentials_need_refresh_valid(self, mqtt_client):
        """Test credentials_need_refresh with valid credentials."""
        expiration = datetime.now(timezone.utc) + timedelta(hours=6)
        mqtt_client._credentials = CognitoCredentials(
            identity_id="test",
            access_key_id="test",
            secret_key="test",
            session_token="test",
            expiration=expiration,
        )
        assert mqtt_client._credentials_need_refresh() is False

    def test_credentials_need_refresh_expired(self, mqtt_client):
        """Test credentials_need_refresh with expired credentials."""
        expiration = datetime.now(timezone.utc) - timedelta(hours=1)
        mqtt_client._credentials = CognitoCredentials(
            identity_id="test",
            access_key_id="test",
            secret_key="test",
            session_token="test",
            expiration=expiration,
        )
        assert mqtt_client._credentials_need_refresh() is True

    def test_credentials_need_refresh_within_buffer(self, mqtt_client):
        """Test credentials_need_refresh within buffer period."""
        # Credentials expire in 4 minutes (within 5 minute buffer)
        expiration = datetime.now(timezone.utc) + timedelta(minutes=4)
        mqtt_client._credentials = CognitoCredentials(
            identity_id="test",
            access_key_id="test",
            secret_key="test",
            session_token="test",
            expiration=expiration,
        )
        assert mqtt_client._credentials_need_refresh() is True

    def test_update_access_token(self, mqtt_client):
        """Test update_access_token method."""
        mqtt_client.update_access_token("new-token")
        assert mqtt_client._access_token == "new-token"

    async def test_ensure_session_creates_when_none(self, aws_settings):
        """Test _ensure_session creates session when none exists."""
        client = AquaTruMqttClient(
            device_mac="48:3f:da:a3:8c:99",
            access_token="test-token",
            aws_settings=aws_settings,
        )

        with patch("custom_components.aquatru.mqtt.aiohttp.ClientSession") as mock_cls:
            mock_session = AsyncMock()
            mock_cls.return_value = mock_session

            session = await client._ensure_session()

            assert session == mock_session
            assert client._owns_session is True

    async def test_disconnect_closes_owned_session(self, aws_settings, mock_session):
        """Test disconnect closes session when client owns it."""
        client = AquaTruMqttClient(
            device_mac="48:3f:da:a3:8c:99",
            access_token="test-token",
            aws_settings=aws_settings,
            session=None,
        )
        client._session = mock_session
        client._owns_session = True

        await client.async_disconnect()

        mock_session.close.assert_called_once()

    async def test_disconnect_does_not_close_injected_session(self, mqtt_client, mock_session):
        """Test disconnect does not close injected session."""
        await mqtt_client.async_disconnect()

        mock_session.close.assert_not_called()


class TestParseSensorData:
    """Test parse_sensor_data function."""

    def test_parse_sensor_data_full(self):
        """Test parsing full sensor data payload."""
        payload = {
            "tdsClean": 10,
            "tdsTap": 200,
        }

        result = parse_sensor_data(payload)

        assert result["tds_clean"] == 10
        assert result["tds_tap"] == 200

    def test_parse_sensor_data_partial(self):
        """Test parsing partial sensor data payload."""
        payload = {
            "tdsClean": 15,
        }

        result = parse_sensor_data(payload)

        assert result["tds_clean"] == 15
        assert "tds_tap" not in result

    def test_parse_sensor_data_empty(self):
        """Test parsing empty payload."""
        result = parse_sensor_data({})
        assert result == {}


class TestParseDeviceStatus:
    """Test parse_device_status function."""

    def test_parse_device_status_full(self):
        """Test parsing full device status payload."""
        payload = {
            "isFiltering": True,
            "tapNearEnd": True,
            "tapRemoved": False,
            "cleanRemoved": False,
            "cleanTankFull": True,
            "coverUp": False,
            "isSynced": True,
        }

        result = parse_device_status(payload)

        assert result["is_filtering"] is True
        assert result["is_tap_near_end"] is True
        assert result["is_tap_removed"] is False
        assert result["is_clean_removed"] is False
        assert result["is_clean_tank_full"] is True
        assert result["is_cover_up"] is False
        assert result["is_purifier_synced"] is True

    def test_parse_device_status_partial(self):
        """Test parsing partial device status payload."""
        payload = {
            "isFiltering": True,
        }

        result = parse_device_status(payload)

        assert result["is_filtering"] is True
        assert "is_tap_near_end" not in result

    def test_parse_device_status_empty(self):
        """Test parsing empty payload."""
        result = parse_device_status({})
        assert result == {}

    def test_parse_device_status_all_false(self):
        """Test parsing all false values."""
        payload = {
            "isFiltering": False,
            "tapNearEnd": False,
            "tapRemoved": False,
            "cleanRemoved": False,
            "cleanTankFull": False,
            "coverUp": False,
            "isSynced": False,
        }

        result = parse_device_status(payload)

        assert all(value is False for value in result.values())


class TestCredentialConstants:
    """Test credential-related constants."""

    def test_credential_refresh_buffer(self):
        """Test credential refresh buffer is 5 minutes."""
        assert CREDENTIAL_REFRESH_BUFFER == timedelta(minutes=5)

    def test_credential_check_interval(self):
        """Test credential check interval is 10 minutes."""
        assert CREDENTIAL_CHECK_INTERVAL == timedelta(minutes=10)
