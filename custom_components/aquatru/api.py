"""API client for AquaTru water purifiers."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp
from aiohttp.resolver import ThreadedResolver

from .const import (
    API_BASE_URL,
    DEFAULT_COUNTRY_CODE,
    ENDPOINT_CONNECTION_STATUS,
    ENDPOINT_GRAPH,
    ENDPOINT_LOGIN,
    ENDPOINT_PURIFIERS,
    ENDPOINT_PURIFIERS_LIST,
    ENDPOINT_REFRESH_TOKEN,
    ENDPOINT_SAVINGS,
    ENDPOINT_SETTINGS,
    FILTER_PRE,
    FILTER_RO,
    FILTER_VOC,
)

_LOGGER = logging.getLogger(__name__)


class AquaTruAuthError(Exception):
    """Authentication error."""


class AquaTruConnectionError(Exception):
    """Connection error."""


class AquaTruApiError(Exception):
    """General API error."""


@dataclass
class AquaTruDevice:
    """Representation of an AquaTru device."""

    device_id: str
    name: str
    model: str
    serial_number: str | None = None
    mac_address: str | None = None
    location: str | None = None
    location_id: str | None = None
    is_connected: bool = False


@dataclass
class AquaTruAwsSettings:
    """AWS IoT settings from the API."""

    identity_pool_id: str
    user_pool_id: str
    client_id: str
    region: str
    policy_name: str


@dataclass
class AquaTruDeviceData:
    """Data from an AquaTru device."""

    device_id: str
    mac_address: str | None = None
    # TDS readings
    tds_tap: int | None = None
    tds_clean: int | None = None
    # Filter life percentages
    filter_pre_life: int | None = None
    filter_ro_life: int | None = None
    filter_voc_life: int | None = None
    # Connection status
    is_connected: bool = False
    connection_name: str | None = None  # WiFi network name
    # Usage statistics
    daily_usage: float | None = None
    weekly_usage: float | None = None
    monthly_usage: float | None = None
    total_usage: float | None = None  # purifiedAmount in gallons
    filtration_time: int | None = None  # Total filtration time in seconds
    # Savings statistics
    money_saved: float | None = None
    bottles_saved: int | None = None
    water_cost: float | None = None  # Cost per bottle
    bottle_size: float | None = None  # Bottle size in gallons
    # Device status flags
    is_filtering: bool = False
    is_clean_tank_full: bool = False
    is_tap_removed: bool = False
    is_tap_near_end: bool = False
    is_clean_removed: bool = False
    is_purifier_synced: bool = False
    is_cover_up: bool = False
    # Device info
    wifi_version: str | None = None
    mcu_version: str | None = None
    purchase_date: datetime | None = None
    is_voc_ph: bool = False  # Has VOC pH+ filter
    # Last update timestamp
    last_updated: datetime | None = None


class AquaTruApiClient:
    """API client for AquaTru."""

    def __init__(
        self,
        phone: str,
        password: str,
        country_code: str = DEFAULT_COUNTRY_CODE,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the API client."""
        # Store phone number - will add +1 prefix if needed during login
        self._phone = phone
        self._password = password
        self._country_code = country_code
        self._session = session
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._firmware_token: str | None = None
        self._token_expiry: datetime | None = None
        self._user_id: str | None = None
        self._dashboard_data: dict[str, Any] | None = None
        self._aws_settings: AquaTruAwsSettings | None = None
        self._close_session = False

    @property
    def aws_settings(self) -> AquaTruAwsSettings | None:
        """Return the AWS settings."""
        return self._aws_settings

    @property
    def access_token(self) -> str | None:
        """Return the access token."""
        return self._access_token

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure we have an active session."""
        if self._session is None or self._session.closed:
            # Use ThreadedResolver to avoid aiodns issues in Home Assistant
            connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
            self._session = aiohttp.ClientSession(connector=connector)
            self._close_session = True
        return self._session

    async def close(self) -> None:
        """Close the session if we created it."""
        if self._close_session and self._session and not self._session.closed:
            await self._session.close()

    def _get_headers(self, include_auth: bool = True, use_bearer: bool = True) -> dict[str, str]:
        """Get request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Dart/3.6 (dart:io)",
        }
        if include_auth and self._access_token:
            # Some endpoints use Bearer prefix, others use raw token
            if use_bearer:
                headers["Authorization"] = f"Bearer {self._access_token}"
            else:
                headers["authorization"] = self._access_token
        return headers

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        include_auth: bool = True,
        retry_auth: bool = True,
        use_bearer: bool = True,
    ) -> dict[str, Any]:
        """Make an API request."""
        session = await self._ensure_session()
        url = f"{API_BASE_URL}/{endpoint}"
        headers = self._get_headers(include_auth, use_bearer)

        try:
            async with session.request(
                method, url, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                try:
                    response_data = await response.json()
                except Exception as json_err:
                    _LOGGER.error("Failed to parse JSON response from %s: %s", endpoint, json_err)
                    response_data = {}

                if response.status == 401 and retry_auth and include_auth:
                    # Token expired, try to refresh
                    _LOGGER.debug("Token expired, attempting refresh")
                    await self._refresh_auth_token()
                    return await self._request(
                        method, endpoint, data, include_auth, retry_auth=False, use_bearer=use_bearer
                    )

                if response.status == 401:
                    raise AquaTruAuthError("Authentication failed")

                if response.status >= 400:
                    error_msg = response_data.get("message", "Unknown error") if isinstance(response_data, dict) else str(response_data)
                    _LOGGER.error(
                        "API error %s: %s - %s", response.status, endpoint, error_msg
                    )
                    raise AquaTruApiError(f"API error: {error_msg}")

                return response_data

        except aiohttp.ClientError as err:
            _LOGGER.error("Connection error: %s", err)
            raise AquaTruConnectionError(f"Connection failed: {err}") from err
        except asyncio.TimeoutError as err:
            _LOGGER.error("Request timeout for %s", endpoint)
            raise AquaTruConnectionError("Request timed out") from err

    async def async_login(self) -> bool:
        """Authenticate with the API."""
        # Ensure phone has + prefix
        phone = self._phone if self._phone.startswith("+") else f"+1{self._phone}"
        _LOGGER.debug("Attempting login for %s (country: %s)", phone, self._country_code)

        # Use the correct nested payload format discovered from traffic capture
        payload = {
            "phoneNumber": {
                "phone": phone,
                "countryCode": self._country_code,
            },
            "password": self._password,
            "devicePushToken": {"key": "fcm", "value": ""},
            "deviceToken": "",
            "firmwareToken": "",
            "appVersion": "2.0.43",
            "osVersion": "14",
            "mobilePlatform": "Android",
        }

        try:
            response = await self._request(
                "POST",
                ENDPOINT_LOGIN,
                data=payload,
                include_auth=False,
            )
        except AquaTruApiError as err:
            raise AquaTruAuthError(f"Login failed: {err}") from err

        if response is None:
            raise AquaTruAuthError("Login failed: No response received")

        # Extract tokens from response - format is credentials.accessToken, etc.
        credentials = response.get("credentials", {})
        dashboard = response.get("dashboard", {})

        self._access_token = credentials.get("accessToken")
        self._refresh_token = credentials.get("refreshToken")
        self._firmware_token = credentials.get("firmwareToken")

        # Store dashboard data for device listing
        self._dashboard_data = dashboard

        # Get user ID from dashboard
        user_data = dashboard.get("user", {})
        self._user_id = user_data.get("id")

        # Parse expiration date
        expiration_date = credentials.get("expirationDate")
        if expiration_date:
            try:
                # Parse ISO format: 2025-12-15T02:40:36.925Z
                self._token_expiry = datetime.fromisoformat(
                    expiration_date.replace("Z", "+00:00")
                )
            except ValueError:
                self._token_expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        else:
            self._token_expiry = datetime.now(timezone.utc) + timedelta(hours=24)

        if not self._access_token:
            _LOGGER.error("No access token in login response: %s", response)
            raise AquaTruAuthError("No access token received")

        _LOGGER.debug("Login successful, token expires at %s", self._token_expiry)
        return True

    async def _refresh_auth_token(self) -> bool:
        """Refresh the authentication token."""
        if not self._refresh_token:
            _LOGGER.debug("No refresh token, performing full login")
            return await self.async_login()

        try:
            response = await self._request(
                "POST",
                ENDPOINT_REFRESH_TOKEN,
                data={"refreshToken": self._refresh_token},
                include_auth=False,
                retry_auth=False,
            )

            if "data" in response:
                data = response["data"]
            else:
                data = response

            self._access_token = data.get("accessToken") or data.get("access_token") or data.get("token")
            new_refresh = data.get("refreshToken") or data.get("refresh_token")
            if new_refresh:
                self._refresh_token = new_refresh

            expires_in = data.get("expiresIn", data.get("expires_in", 3600))
            self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            _LOGGER.debug("Token refreshed successfully")
            return True

        except (AquaTruApiError, AquaTruAuthError):
            _LOGGER.debug("Token refresh failed, performing full login")
            return await self.async_login()

    async def async_get_settings(self) -> AquaTruAwsSettings | None:
        """Fetch AWS settings from the API.

        This endpoint returns the current AWS IoT configuration including
        Cognito identity pool, user pool, and other settings that may change.
        """
        session = await self._ensure_session()
        # Settings endpoint is on v2 API
        url = "https://api.aquatruwater.com/v2/auth/getSettings"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Dart/3.6 (dart:io)",
        }

        try:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status != 200:
                    _LOGGER.warning("Failed to get settings: %s", response.status)
                    return None

                data = await response.json()

                if not data.get("status"):
                    _LOGGER.warning("Settings response status is false")
                    return None

                settings_data = data.get("data", {})
                aws_details = settings_data.get("awsDetails", {})

                if not aws_details:
                    _LOGGER.warning("No AWS details in settings response")
                    return None

                self._aws_settings = AquaTruAwsSettings(
                    identity_pool_id=aws_details.get("identityPoolId", ""),
                    user_pool_id=aws_details.get("awsUserPoolId", ""),
                    client_id=aws_details.get("awsClientId", ""),
                    region=aws_details.get("region", "us-east-1"),
                    policy_name=aws_details.get("awsPolicyName", ""),
                )

                _LOGGER.debug(
                    "Got AWS settings: region=%s, identity_pool=%s",
                    self._aws_settings.region,
                    self._aws_settings.identity_pool_id,
                )
                return self._aws_settings

        except Exception as err:
            _LOGGER.warning("Error fetching settings: %s", err)
            return None

    async def async_ensure_authenticated(self) -> bool:
        """Ensure we have a valid authentication token."""
        if not self._access_token:
            return await self.async_login()

        # Refresh if token expires in less than 5 minutes
        if self._token_expiry and datetime.now(timezone.utc) >= self._token_expiry - timedelta(minutes=5):
            return await self._refresh_auth_token()

        return True

    async def async_get_devices(self) -> list[AquaTruDevice]:
        """Get list of devices for the user."""
        await self.async_ensure_authenticated()

        devices = []

        # Use dashboard data from login if available
        if self._dashboard_data:
            purifiers = self._dashboard_data.get("purifiers", [])
            for purifier_data in purifiers:
                device = self._parse_device(purifier_data)
                if device:
                    devices.append(device)
            _LOGGER.debug("Found %d devices from dashboard", len(devices))
            return devices

        # Fall back to API call
        try:
            response = await self._request("GET", ENDPOINT_PURIFIERS)

            device_list = response.get("data", response.get("purifiers", response))

            if isinstance(device_list, list):
                for device_data in device_list:
                    device = self._parse_device(device_data)
                    if device:
                        devices.append(device)

            _LOGGER.debug("Found %d devices", len(devices))
            return devices

        except AquaTruApiError as err:
            _LOGGER.error("Failed to get devices: %s", err)
            return []

    def _parse_device(self, data: dict[str, Any]) -> AquaTruDevice | None:
        """Parse device data from API response."""
        device_id = data.get("id") or data.get("deviceId") or data.get("purifierId")
        if not device_id:
            return None

        # Handle connectionStatus field from API
        is_connected = data.get("connectionStatus") == "connected" or data.get("isConnected", False)

        return AquaTruDevice(
            device_id=str(device_id),
            name=data.get("name") or data.get("deviceName") or f"AquaTru {device_id[:8]}",
            model=data.get("modelNumber") or data.get("model") or "AquaTru Classic Smart",
            serial_number=data.get("serialNumber") or data.get("serial"),
            mac_address=data.get("macAddress"),
            location=data.get("location") or data.get("locationName") or data.get("connectionName"),
            location_id=data.get("locationId"),
            is_connected=is_connected,
        )

    async def async_get_statistics(
        self, device_id: str, time_period: str, amount: int = 7
    ) -> list[dict[str, Any]]:
        """Get usage statistics for a device.

        Args:
            device_id: The device ID
            time_period: One of 'day', 'week', 'month', 'year'
            amount: Number of periods to retrieve

        Returns:
            List of dicts with 'amount' and 'period' keys
        """
        endpoint = f"{ENDPOINT_PURIFIERS}/{device_id}/statistic?amount={amount}&timePeriod={time_period}"
        try:
            response = await self._request("GET", endpoint, use_bearer=False)
            if isinstance(response, list):
                return response
            return []
        except AquaTruApiError as err:
            _LOGGER.warning("Failed to get %s statistics: %s", time_period, err)
            return []

    async def async_get_device_data(self, device_id: str) -> AquaTruDeviceData:
        """Get current data for a device."""
        await self.async_ensure_authenticated()

        device_data = AquaTruDeviceData(device_id=device_id)

        # Fetch fresh data from user/purifiers endpoint (uses raw token, not Bearer)
        try:
            response = await self._request(
                "GET",
                ENDPOINT_PURIFIERS,
                use_bearer=False,
            )

            _LOGGER.debug("Got purifiers response: %s", type(response))

            # Response is a list of purifiers
            if isinstance(response, list):
                _LOGGER.debug("Looking for device_id=%s in %d purifiers", device_id, len(response))
                for purifier in response:
                    purifier_id = purifier.get("id")
                    _LOGGER.debug("Comparing: purifier_id=%s (type=%s) vs device_id=%s (type=%s)",
                                  purifier_id, type(purifier_id).__name__, device_id, type(device_id).__name__)
                    if purifier_id == device_id:
                        self._parse_dashboard_purifier(purifier, device_data)
                        _LOGGER.debug("Parsed device data for %s", device_id)
                        break
                else:
                    _LOGGER.warning("Device %s not found in purifiers list", device_id)
            else:
                _LOGGER.warning("Unexpected response type: %s", type(response))
        except AquaTruApiError as err:
            _LOGGER.warning("Failed to get purifier data: %s", err)
        except Exception as err:
            _LOGGER.exception("Unexpected error getting device data: %s", err)

        # Fetch usage statistics
        try:
            await self._fetch_usage_statistics(device_id, device_data)
        except Exception as err:
            _LOGGER.warning("Failed to fetch usage statistics: %s", err)

        device_data.last_updated = datetime.now()
        return device_data

    async def _fetch_usage_statistics(
        self, device_id: str, device_data: AquaTruDeviceData
    ) -> None:
        """Fetch and parse usage statistics for daily, weekly, monthly usage."""
        today = datetime.now()

        # Get daily stats (last 7 days, find today's usage)
        daily_stats = await self.async_get_statistics(device_id, "day", 7)
        today_str = today.strftime("%Y-%m-%d")
        for stat in daily_stats:
            if stat.get("period") == today_str:
                device_data.daily_usage = self._safe_float(stat.get("amount"))
                break

        # Get weekly stats (last 4 weeks, find this week's usage)
        weekly_stats = await self.async_get_statistics(device_id, "week", 4)
        # Week format is YYYY-WW (ISO week number), use %G-%V for ISO week
        current_week = today.strftime("%G-%V")
        for stat in weekly_stats:
            if stat.get("period") == current_week:
                device_data.weekly_usage = self._safe_float(stat.get("amount"))
                break

        # Get monthly stats (last 3 months, find this month's usage)
        monthly_stats = await self.async_get_statistics(device_id, "month", 3)
        current_month = today.strftime("%Y-%m")
        for stat in monthly_stats:
            if stat.get("period") == current_month:
                device_data.monthly_usage = self._safe_float(stat.get("amount"))
                break

        _LOGGER.debug("Usage stats: daily=%s, weekly=%s, monthly=%s",
                      device_data.daily_usage, device_data.weekly_usage, device_data.monthly_usage)

    def _parse_dashboard_purifier(
        self, data: dict[str, Any], device_data: AquaTruDeviceData
    ) -> None:
        """Parse purifier data from dashboard response."""
        _LOGGER.debug("Parsing purifier data: tdsTap=%s, tdsClean=%s, connectionStatus=%s",
                      data.get("tdsTap"), data.get("tdsClean"), data.get("connectionStatus"))

        # MAC address
        device_data.mac_address = data.get("macAddress")

        # TDS readings
        device_data.tds_tap = self._safe_int(data.get("tdsTap"))
        device_data.tds_clean = self._safe_int(data.get("tdsClean"))

        # Filter life percentages from nested objects
        pre_filter = data.get("preFilter", {})
        ro_filter = data.get("revFilter", {})
        voc_filter = data.get("vocFilter", {})

        device_data.filter_pre_life = self._safe_int(pre_filter.get("health"))
        device_data.filter_ro_life = self._safe_int(ro_filter.get("health"))
        device_data.filter_voc_life = self._safe_int(voc_filter.get("health"))

        # Connection status
        device_data.is_connected = data.get("connectionStatus") == "connected"
        device_data.connection_name = data.get("connectionName")

        # Usage data
        device_data.total_usage = self._safe_float(data.get("purifiedAmount"))
        device_data.filtration_time = self._safe_int(data.get("filtrationTime"))

        # Money/bottle statistics
        money_stats = data.get("moneyStatistic", {})
        device_data.bottles_saved = self._safe_int(money_stats.get("bottleSaved"))
        device_data.money_saved = self._safe_float(money_stats.get("dollarsSaved"))
        device_data.water_cost = self._safe_float(money_stats.get("waterCost"))
        device_data.bottle_size = self._safe_float(money_stats.get("bottleSize"))

        # Device status flags
        device_data.is_filtering = data.get("isFiltering", False)
        device_data.is_clean_tank_full = data.get("isCleanTankFull", False)
        device_data.is_tap_removed = data.get("isTapRemoved", False)
        device_data.is_tap_near_end = data.get("isTapNearEnd", False)
        device_data.is_clean_removed = data.get("isCleanRemoved", False)
        device_data.is_purifier_synced = data.get("isPurifierSynced", False)
        device_data.is_cover_up = data.get("isCoverUp", False)

        # Device info
        device_data.wifi_version = data.get("wifiVersion")
        device_data.mcu_version = data.get("mcuVersion")
        device_data.is_voc_ph = data.get("isVocPH", False)

        # Parse purchase date
        purchase_date_str = data.get("purchaseDate")
        if purchase_date_str:
            try:
                device_data.purchase_date = datetime.fromisoformat(
                    purchase_date_str.replace("Z", "+00:00")
                )
            except ValueError:
                pass

    def _parse_purifier_data(
        self, response: dict[str, Any], device_data: AquaTruDeviceData
    ) -> None:
        """Parse purifier data from API response."""
        data = response.get("data", response)
        if isinstance(data, list) and data:
            data = data[0]

        # TDS readings
        device_data.tds_tap = self._safe_int(data.get("tdsTap") or data.get("tds_tap") or data.get("tapTds"))
        device_data.tds_clean = self._safe_int(data.get("tdsClean") or data.get("tds_clean") or data.get("cleanTds"))

        # Filter life percentages
        filters = data.get("filtersLife") or data.get("filters") or {}
        if isinstance(filters, dict):
            device_data.filter_pre_life = self._safe_int(
                filters.get(FILTER_PRE) or filters.get("preFilter") or filters.get("pre")
            )
            device_data.filter_ro_life = self._safe_int(
                filters.get(FILTER_RO) or filters.get("roFilter") or filters.get("ro") or filters.get("reverse")
            )
            device_data.filter_voc_life = self._safe_int(
                filters.get(FILTER_VOC) or filters.get("vocFilter") or filters.get("voc")
            )
        else:
            # Try direct fields
            device_data.filter_pre_life = self._safe_int(data.get("preFilterLife"))
            device_data.filter_ro_life = self._safe_int(data.get("roFilterLife") or data.get("revFilterLife"))
            device_data.filter_voc_life = self._safe_int(data.get("vocFilterLife"))

        # Connection status
        device_data.is_connected = data.get("isConnected", data.get("connected", False))

        # Usage data
        device_data.total_usage = self._safe_float(
            data.get("totalUsage") or data.get("totalFiltered") or data.get("gallonsFiltered")
        )

    def _parse_connection_status(
        self, response: dict[str, Any], device_data: AquaTruDeviceData
    ) -> None:
        """Parse connection status response."""
        data = response.get("data", response)
        if isinstance(data, list) and data:
            data = data[0]

        device_data.is_connected = data.get("isConnected", data.get("connected", device_data.is_connected))

    def _parse_savings_data(
        self, response: dict[str, Any], device_data: AquaTruDeviceData
    ) -> None:
        """Parse savings data response."""
        data = response.get("data", response)
        if isinstance(data, list) and data:
            data = data[0]

        device_data.money_saved = self._safe_float(
            data.get("moneySaved") or data.get("money_saved") or data.get("totalSavings")
        )
        device_data.bottles_saved = self._safe_int(
            data.get("bottlesSaved") or data.get("bottles_saved") or data.get("plasticBottles")
        )

        # Usage breakdown
        device_data.daily_usage = self._safe_float(data.get("dailyUsage") or data.get("daily"))
        device_data.weekly_usage = self._safe_float(data.get("weeklyUsage") or data.get("weekly"))
        device_data.monthly_usage = self._safe_float(data.get("monthlyUsage") or data.get("monthly"))

        if device_data.total_usage is None:
            device_data.total_usage = self._safe_float(
                data.get("totalUsage") or data.get("total") or data.get("totalFiltered")
            )

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        """Safely convert a value to int."""
        if value is None:
            return None
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _safe_float(value: Any) -> float | None:
        """Safely convert a value to float."""
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
