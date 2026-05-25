"""Test the AquaTru API client."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from custom_components.aquatru.api import (
    AquaTruApiClient,
    AquaTruApiError,
    AquaTruAuthError,
    AquaTruConnectionError,
    AquaTruDevice,
    AquaTruDeviceData,
    AquaTruAwsSettings,
)


@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    session.closed = False
    return session


@pytest.fixture
def api_client(mock_session):
    """Create an API client with a mock session."""
    return AquaTruApiClient(
        phone="5551234567",
        password="testpassword",
        country_code="US",
        session=mock_session,
    )


class TestAquaTruApiClient:
    """Test cases for AquaTruApiClient."""

    async def test_init_with_session(self, mock_session):
        """Test initialization with provided session."""
        client = AquaTruApiClient(
            phone="5551234567",
            password="testpass",
            session=mock_session,
        )
        assert client._session == mock_session
        assert client._close_session is False

    async def test_init_without_session(self):
        """Test initialization without session."""
        client = AquaTruApiClient(
            phone="5551234567",
            password="testpass",
        )
        assert client._session is None

    async def test_login_success(self, api_client, mock_session):
        """Test successful login."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "credentials": {
                "accessToken": "test-access-token",
                "refreshToken": "test-refresh-token",
                "firmwareToken": "test-firmware-token",
            },
            "dashboard": {
                "userId": "user-123",
            },
        })
        mock_session.request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response), __aexit__=AsyncMock()))

        result = await api_client.async_login()

        assert result is True
        assert api_client._access_token == "test-access-token"
        assert api_client._refresh_token == "test-refresh-token"

    async def test_login_failure(self, api_client, mock_session):
        """Test login with invalid credentials."""
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.json = AsyncMock(return_value={"message": "Invalid credentials"})
        mock_session.request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response), __aexit__=AsyncMock()))

        with pytest.raises(AquaTruAuthError):
            await api_client.async_login()

    async def test_login_connection_error(self, api_client, mock_session):
        """Test login with connection error."""
        mock_session.request = MagicMock(side_effect=aiohttp.ClientError("Connection failed"))

        with pytest.raises(AquaTruConnectionError):
            await api_client.async_login()

    async def test_get_devices_success(self, api_client, mock_session):
        """Test getting devices list."""
        api_client._access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "purifiers": [
                {
                    "purifierId": "device-1",
                    "name": "Kitchen AquaTru",
                    "model": "Classic Smart",
                    "serialNumber": "SN123",
                    "macAddress": "aa:bb:cc:dd:ee:ff",
                }
            ]
        })
        mock_session.request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response), __aexit__=AsyncMock()))

        devices = await api_client.async_get_devices()

        assert len(devices) == 1
        assert devices[0].device_id == "device-1"
        assert devices[0].name == "Kitchen AquaTru"

    async def test_get_device_data_success(self, api_client, mock_session):
        """Test getting device data."""
        api_client._access_token = "test-token"

        # The /user/purifiers endpoint returns a list of purifier objects,
        # each keyed by "id" with camelCase sensor fields (per traffic captures).
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=[
            {
                "id": "device-1",
                "macAddress": "aa:bb:cc:dd:ee:ff",
                "tdsClean": 10,
                "tdsTap": 200,
                "preFilter": {"health": 80},
                "revFilter": {"health": 70},
                "vocFilter": {"health": 60},
                "connectionStatus": "connected",
                "purifiedAmount": 500.0,
            }
        ])
        mock_session.request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response), __aexit__=AsyncMock()))

        data = await api_client.async_get_device_data("device-1")

        assert data.device_id == "device-1"
        assert data.tds_clean == 10
        assert data.tds_tap == 200

    async def test_token_refresh(self, api_client, mock_session):
        """Test token refresh on 401 response."""
        api_client._access_token = "old-token"
        api_client._refresh_token = "refresh-token"

        # First call returns 401, then refresh succeeds, then retry succeeds
        call_count = 0

        def mock_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = AsyncMock()

            if call_count == 1:
                # First call - 401
                mock_resp.status = 401
                mock_resp.json = AsyncMock(return_value={})
            elif call_count == 2:
                # Refresh token call
                mock_resp.status = 200
                mock_resp.json = AsyncMock(return_value={
                    "accessToken": "new-token",
                    "refreshToken": "new-refresh-token",
                })
            else:
                # Retry succeeds
                mock_resp.status = 200
                mock_resp.json = AsyncMock(return_value={"data": "success"})

            return AsyncMock(__aenter__=AsyncMock(return_value=mock_resp), __aexit__=AsyncMock())

        mock_session.request = mock_request

        # This should trigger token refresh and retry
        result = await api_client._request("GET", "test/endpoint")
        assert result == {"data": "success"}

    async def test_get_headers_with_auth(self, api_client):
        """Test headers with authentication."""
        api_client._access_token = "test-token"

        headers = api_client._get_headers(include_auth=True, use_bearer=True)

        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test-token"

    async def test_get_headers_without_auth(self, api_client):
        """Test headers without authentication."""
        headers = api_client._get_headers(include_auth=False)

        assert "Authorization" not in headers
        assert "Content-Type" in headers

    async def test_close_session_when_owned(self):
        """Test closing session when client created it."""
        client = AquaTruApiClient(
            phone="5551234567",
            password="testpass",
        )

        # Simulate session creation
        mock_session = AsyncMock()
        mock_session.closed = False
        client._session = mock_session
        client._close_session = True

        await client.close()

        mock_session.close.assert_called_once()

    async def test_close_session_when_not_owned(self, api_client, mock_session):
        """Test not closing session when client didn't create it."""
        await api_client.close()

        # Should not close the injected session
        mock_session.close.assert_not_called()


class TestAquaTruDevice:
    """Test cases for AquaTruDevice dataclass."""

    def test_device_creation(self):
        """Test creating a device instance."""
        device = AquaTruDevice(
            device_id="test-id",
            name="Test Device",
            model="Classic Smart",
        )

        assert device.device_id == "test-id"
        assert device.name == "Test Device"
        assert device.model == "Classic Smart"
        assert device.is_connected is False  # Default

    def test_device_with_all_fields(self):
        """Test creating device with all fields."""
        device = AquaTruDevice(
            device_id="test-id",
            name="Test Device",
            model="Classic Smart",
            serial_number="SN123",
            mac_address="aa:bb:cc:dd:ee:ff",
            location="Kitchen",
            location_id="loc-1",
            is_connected=True,
        )

        assert device.serial_number == "SN123"
        assert device.mac_address == "aa:bb:cc:dd:ee:ff"
        assert device.is_connected is True


class TestAquaTruDeviceData:
    """Test cases for AquaTruDeviceData dataclass."""

    def test_device_data_defaults(self):
        """Test device data default values."""
        data = AquaTruDeviceData(device_id="test-id")

        assert data.device_id == "test-id"
        assert data.tds_tap is None
        assert data.tds_clean is None
        assert data.is_connected is False
        assert data.is_filtering is False

    def test_device_data_with_values(self):
        """Test device data with all values."""
        data = AquaTruDeviceData(
            device_id="test-id",
            tds_tap=200,
            tds_clean=10,
            filter_pre_life=80,
            filter_ro_life=70,
            filter_voc_life=60,
            is_connected=True,
            is_filtering=True,
            daily_usage=1.5,
            weekly_usage=10.0,
            monthly_usage=40.0,
            total_usage=500.0,
        )

        assert data.tds_tap == 200
        assert data.tds_clean == 10
        assert data.filter_pre_life == 80
        assert data.is_filtering is True
        assert data.total_usage == 500.0


class TestUsageStatisticsSelection:
    """Test cases for _select_period_usage."""

    def test_exact_period_match(self):
        """Exact current-period match is preferred."""
        stats = [
            {"period": "2026-05-24", "amount": 1.0},
            {"period": "2026-05-25", "amount": 2.5},
        ]
        assert AquaTruApiClient._select_period_usage(stats, "2026-05-25") == 2.5

    def test_falls_back_to_latest_when_current_missing(self):
        """When the current period is absent, the latest period is used."""
        stats = [
            {"period": "2026-05-22", "amount": 1.0},
            {"period": "2026-05-24", "amount": 3.0},
        ]
        # Current day not present (e.g. no usage logged yet) -> latest period.
        assert AquaTruApiClient._select_period_usage(stats, "2026-05-25") == 3.0

    def test_empty_returns_none(self):
        """An empty stats list returns None."""
        assert AquaTruApiClient._select_period_usage([], "2026-05-25") is None


class TestMoneyAndBottleStatistics:
    """Test cases for computed money/bottle savings."""

    def test_computed_from_volume(self, api_client):
        """Bottles and money are derived from purifiedAmount and bottleSize.

        Mirrors the AquaTru app, which ignores the (null) dollarsSaved and the
        mismatched bottleSaved fields and computes from the raw inputs.
        """
        data = {
            "purifiedAmount": 193,
            "moneyStatistic": {
                "quantityInPack": 24,
                "dollarsSaved": None,
                "bottleSize": 0.132086,
                "waterCost": 3,
                "bottleSaved": 476.9619793165059,
            },
        }
        device_data = AquaTruDeviceData(device_id="x")
        api_client._parse_dashboard_purifier(data, device_data)

        # ceil(193 / 0.132086) == 1462 (matches the app's displayed count)
        assert device_data.bottles_saved == 1462
        # (193 / 0.132086 / 24) * 3 ≈ 182.65
        assert device_data.money_saved == pytest.approx(182.65, abs=0.05)

    def test_falls_back_when_no_bottle_size(self, api_client):
        """Without bottleSize, fall back to the cloud-provided values."""
        data = {
            "purifiedAmount": 193,
            "moneyStatistic": {"bottleSaved": 477, "dollarsSaved": 12.5},
        }
        device_data = AquaTruDeviceData(device_id="x")
        api_client._parse_dashboard_purifier(data, device_data)

        assert device_data.bottles_saved == 477
        assert device_data.money_saved == 12.5


class TestAquaTruAwsSettings:
    """Test cases for AquaTruAwsSettings dataclass."""

    def test_aws_settings_creation(self):
        """Test creating AWS settings."""
        settings = AquaTruAwsSettings(
            identity_pool_id="us-east-1:pool-id",
            user_pool_id="us-east-1_poolid",
            client_id="client123",
            region="us-east-1",
            policy_name="test-policy",
        )

        assert settings.identity_pool_id == "us-east-1:pool-id"
        assert settings.region == "us-east-1"
