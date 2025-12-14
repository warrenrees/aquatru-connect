"""API client for AquaTru water purifiers."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

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
class AquaTruDeviceData:
    """Data from an AquaTru device."""

    device_id: str
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
        self._close_session = False

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure we have an active session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            self._close_session = True
        return self._session

    async def close(self) -> None:
        """Close the session if we created it."""
        if self._close_session and self._session and not self._session.closed:
            await self._session.close()

    def _get_headers(self, include_auth: bool = True) -> dict[str, str]:
        """Get request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AquaTru/2.0.43 (Android)",
        }
        if include_auth and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        return headers

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        include_auth: bool = True,
        retry_auth: bool = True,
    ) -> dict[str, Any]:
        """Make an API request."""
        session = await self._ensure_session()
        url = f"{API_BASE_URL}/{endpoint}"
        headers = self._get_headers(include_auth)

        try:
            async with session.request(
                method, url, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_data = await response.json()

                if response.status == 401 and retry_auth and include_auth:
                    # Token expired, try to refresh
                    _LOGGER.debug("Token expired, attempting refresh")
                    await self._refresh_auth_token()
                    return await self._request(
                        method, endpoint, data, include_auth, retry_auth=False
                    )

                if response.status == 401:
                    raise AquaTruAuthError("Authentication failed")

                if response.status >= 400:
                    error_msg = response_data.get("message", "Unknown error")
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

    async def async_get_device_data(self, device_id: str) -> AquaTruDeviceData:
        """Get current data for a device."""
        await self.async_ensure_authenticated()

        device_data = AquaTruDeviceData(device_id=device_id)

        # Try to use dashboard data from login first
        if self._dashboard_data:
            purifiers = self._dashboard_data.get("purifiers", [])
            for purifier in purifiers:
                if purifier.get("id") == device_id:
                    self._parse_dashboard_purifier(purifier, device_data)
                    device_data.last_updated = datetime.now()
                    return device_data

        # Fall back to API calls if dashboard data not available
        try:
            response = await self._request(
                "GET",
                f"{ENDPOINT_PURIFIERS_LIST}?deviceId={device_id}",
            )
            self._parse_purifier_data(response, device_data)
        except AquaTruApiError as err:
            _LOGGER.warning("Failed to get purifier data: %s", err)

        # Get connection status
        try:
            status_response = await self._request(
                "GET",
                f"{ENDPOINT_CONNECTION_STATUS}?deviceId={device_id}",
            )
            self._parse_connection_status(status_response, device_data)
        except AquaTruApiError as err:
            _LOGGER.warning("Failed to get connection status: %s", err)

        # Get usage/savings data
        try:
            savings_response = await self._request(
                "GET",
                f"{ENDPOINT_SAVINGS}?deviceId={device_id}",
            )
            self._parse_savings_data(savings_response, device_data)
        except AquaTruApiError as err:
            _LOGGER.warning("Failed to get savings data: %s", err)

        device_data.last_updated = datetime.now()
        return device_data

    def _parse_dashboard_purifier(
        self, data: dict[str, Any], device_data: AquaTruDeviceData
    ) -> None:
        """Parse purifier data from dashboard response."""
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
