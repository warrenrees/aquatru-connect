#!/usr/bin/env python3
"""Test client for debugging the AquaTru API library.

This is a standalone client that doesn't require Home Assistant.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from getpass import getpass
from typing import Any

import aiohttp

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
_LOGGER = logging.getLogger("aquatru_test")

# API Configuration
API_BASE_URL = "https://api.aquatruwater.com/v1"

# API Endpoints (note: /v1 prefix is included in base URL)
ENDPOINT_LOGIN = "user/auth/login"
ENDPOINT_SEND_CODE = "user/auth/send-code"
ENDPOINT_REFRESH_TOKEN = "auth/refreshToken"
ENDPOINT_SETTINGS = "auth/getSettingsP"
ENDPOINT_PURIFIERS = "user/purifiers"
ENDPOINT_PURIFIERS_LIST = "purifier/purifiersListUser"
ENDPOINT_CONNECTION_STATUS = "purifier/getPurifierConnectionStatus"
ENDPOINT_SAVINGS = "purifier/moneySavingCalculator"
ENDPOINT_GRAPH = "onGetGraphApi"

# Default country code
DEFAULT_COUNTRY_CODE = "CA"

# Filter types
FILTER_PRE = "pre_filter"
FILTER_RO = "rev_filter"
FILTER_VOC = "voc_filter"


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
    location: str | None = None
    is_connected: bool = False


@dataclass
class AquaTruDeviceData:
    """Data from an AquaTru device."""

    device_id: str
    tds_tap: int | None = None
    tds_clean: int | None = None
    filter_pre_life: int | None = None
    filter_ro_life: int | None = None
    filter_voc_life: int | None = None
    is_connected: bool = False
    daily_usage: float | None = None
    weekly_usage: float | None = None
    monthly_usage: float | None = None
    total_usage: float | None = None
    money_saved: float | None = None
    bottles_saved: int | None = None
    last_updated: datetime | None = None


class Colors:
    """ANSI color codes."""
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def print_header(text: str) -> None:
    """Print a formatted header."""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{text:^60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}\n")


def print_section(text: str) -> None:
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- {text} ---{Colors.END}\n")


def print_success(text: str) -> None:
    """Print success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_error(text: str) -> None:
    """Print error message."""
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def print_warning(text: str) -> None:
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def print_info(label: str, value: any) -> None:
    """Print labeled info."""
    if value is None:
        print(f"  {Colors.BLUE}{label}:{Colors.END} {Colors.YELLOW}(not available){Colors.END}")
    else:
        print(f"  {Colors.BLUE}{label}:{Colors.END} {value}")


def print_json(data: dict, indent: int = 2) -> None:
    """Print formatted JSON."""
    print(json.dumps(data, indent=indent, default=str))


class DebugApiClient:
    """API client for AquaTru with debug output."""

    def __init__(
        self,
        phone: str,
        password: str,
        country_code: str = DEFAULT_COUNTRY_CODE,
        session: aiohttp.ClientSession | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the API client."""
        # Ensure phone has +1 prefix for API
        self._phone = phone if phone.startswith("+") else f"+1{phone}"
        self._password = password
        self._country_code = country_code
        self._session = session
        self._verbose = verbose
        self._access_token: str | None = None
        self._refresh_token: str | None = None
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
        """Make an API request with debug output."""
        session = await self._ensure_session()
        url = f"{API_BASE_URL}/{endpoint}"
        headers = self._get_headers(include_auth)

        if self._verbose:
            print_section(f"API Request: {method} {endpoint}")
            print(f"  URL: {url}")
            if data:
                # Mask password in output
                safe_data = {k: ("***" if k == "password" else v) for k, v in data.items()}
                print(f"  Body: {json.dumps(safe_data)}")

        try:
            async with session.request(
                method, url, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_text = await response.text()

                if self._verbose:
                    print(f"\n  {Colors.BOLD}Response Status:{Colors.END} {response.status}")

                try:
                    response_data = json.loads(response_text)
                    if self._verbose:
                        print(f"  {Colors.BOLD}Response Body:{Colors.END}")
                        print_json(response_data)
                except json.JSONDecodeError:
                    response_data = {"raw": response_text}
                    if self._verbose:
                        print(f"  {Colors.BOLD}Response Body (raw):{Colors.END}")
                        print(f"  {response_text[:500]}...")

                if response.status == 401 and retry_auth and include_auth:
                    if self._verbose:
                        print_warning("Token expired, attempting refresh...")
                    await self._refresh_auth_token()
                    return await self._request(
                        method, endpoint, data, include_auth, retry_auth=False
                    )

                if response.status == 401:
                    raise AquaTruAuthError("Authentication failed")

                if response.status >= 400:
                    error_msg = response_data.get("message", "Unknown error") if isinstance(response_data, dict) else response_text
                    raise AquaTruApiError(f"API error ({response.status}): {error_msg}")

                return response_data

        except aiohttp.ClientError as err:
            print_error(f"Connection error: {err}")
            raise AquaTruConnectionError(f"Connection failed: {err}") from err
        except asyncio.TimeoutError as err:
            print_error(f"Request timeout for {endpoint}")
            raise AquaTruConnectionError("Request timed out") from err

    async def async_login(self) -> bool:
        """Authenticate with the API."""
        _LOGGER.debug("Attempting login for phone: %s, country: %s", self._phone, self._country_code)

        # Use the correct nested payload format discovered from traffic capture
        payload = {
            "phoneNumber": {
                "phone": self._phone,
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

        if self._verbose:
            print(f"  Login payload: phone={self._phone}, countryCode={self._country_code}")

        try:
            response = await self._request(
                "POST",
                ENDPOINT_LOGIN,
                data=payload,
                include_auth=False,
            )
        except AquaTruApiError as err:
            error_str = str(err)
            if "is_incorrect" in error_str:
                raise AquaTruAuthError("Invalid credentials - please check your phone number and password")
            elif "is_not_empty" in error_str:
                raise AquaTruAuthError("Missing required field in login request")
            else:
                raise AquaTruAuthError(f"Login failed: {err}")

        # Check for error response from API (status: false)
        if isinstance(response, dict) and response.get("status") is False:
            message = response.get("message", "Unknown error")
            raise AquaTruAuthError(f"Login failed: {message}")

        # Extract tokens from response - format is credentials.accessToken, etc.
        credentials = response.get("credentials", {})
        dashboard = response.get("dashboard", {})

        self._access_token = credentials.get("accessToken")
        self._refresh_token = credentials.get("refreshToken")
        self._dashboard_data = dashboard

        # Get user ID from dashboard
        user_data = dashboard.get("user", {})
        self._user_id = user_data.get("id")

        # Parse expiration date
        expiration_date = credentials.get("expirationDate")
        if expiration_date:
            try:
                self._token_expiry = datetime.fromisoformat(
                    expiration_date.replace("Z", "+00:00")
                )
            except ValueError:
                self._token_expiry = datetime.now() + timedelta(hours=24)
        else:
            self._token_expiry = datetime.now() + timedelta(hours=24)

        if not self._access_token:
            _LOGGER.error("No access token in login response")
            _LOGGER.debug("Full response: %s", response)
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
            self._token_expiry = datetime.now() + timedelta(seconds=expires_in)

            return True

        except (AquaTruApiError, AquaTruAuthError):
            _LOGGER.debug("Token refresh failed, performing full login")
            return await self.async_login()

    async def async_get_devices(self) -> list[AquaTruDevice]:
        """Get list of devices for the user."""
        devices = []

        # Use dashboard data from login if available
        if self._dashboard_data:
            purifiers = self._dashboard_data.get("purifiers", [])
            for purifier_data in purifiers:
                device = self._parse_device(purifier_data)
                if device:
                    devices.append(device)
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
            elif isinstance(device_list, dict):
                # Single device response
                device = self._parse_device(device_list)
                if device:
                    devices.append(device)

            return devices

        except AquaTruApiError as err:
            _LOGGER.error("Failed to get devices: %s", err)
            return []

    def _parse_device(self, data: dict[str, Any]) -> AquaTruDevice | None:
        """Parse device data from API response."""
        device_id = (
            data.get("id") or
            data.get("deviceId") or
            data.get("purifierId") or
            data.get("device_id")
        )
        if not device_id:
            return None

        # Handle connectionStatus field from dashboard
        is_connected = data.get("connectionStatus") == "connected" or data.get("isConnected", False)

        return AquaTruDevice(
            device_id=str(device_id),
            name=data.get("name") or data.get("deviceName") or f"AquaTru {str(device_id)[:8]}",
            model=data.get("modelNumber") or data.get("model") or "AquaTru Classic Smart",
            serial_number=data.get("serialNumber") or data.get("serial") or data.get("macAddress"),
            location=data.get("location") or data.get("locationName"),
            is_connected=is_connected,
        )

    async def async_get_device_data(self, device_id: str) -> AquaTruDeviceData:
        """Get current data for a device."""
        device_data = AquaTruDeviceData(device_id=device_id)

        # Try to use dashboard data from login first
        if self._dashboard_data:
            purifiers = self._dashboard_data.get("purifiers", [])
            for purifier in purifiers:
                if purifier.get("id") == device_id:
                    self._parse_dashboard_purifier(purifier, device_data)
                    device_data.last_updated = datetime.now()
                    return device_data

        # Fall back to API calls
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

        # Usage data - purifiedAmount is in gallons
        device_data.total_usage = self._safe_float(data.get("purifiedAmount"))

        # Money/bottle statistics
        money_stats = data.get("moneyStatistic", {})
        device_data.bottles_saved = self._safe_int(money_stats.get("bottleSaved"))
        device_data.money_saved = self._safe_float(money_stats.get("dollarsSaved"))

    def _parse_purifier_data(
        self, response: dict[str, Any], device_data: AquaTruDeviceData
    ) -> None:
        """Parse purifier data from API response."""
        data = response.get("data", response)
        if isinstance(data, list) and data:
            data = data[0]

        # TDS readings
        device_data.tds_tap = self._safe_int(
            data.get("tdsTap") or data.get("tds_tap") or data.get("tapTds")
        )
        device_data.tds_clean = self._safe_int(
            data.get("tdsClean") or data.get("tds_clean") or data.get("cleanTds")
        )

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

    async def test_endpoint(self, method: str, endpoint: str, data: dict | None = None) -> dict:
        """Test a specific endpoint."""
        return await self._request(method, endpoint, data)


async def test_raw_endpoints(client: DebugApiClient) -> None:
    """Test various API endpoints to discover response formats."""
    print_header("Testing Additional Endpoints")

    endpoints_to_test = [
        ("GET", "auth/getSettingsP", None),
        ("GET", "user/notifications", None),
    ]

    for method, endpoint, data in endpoints_to_test:
        try:
            print_section(f"Testing: {method} {endpoint}")
            result = await client.test_endpoint(method, endpoint, data)
            print_success("Endpoint responded")
            print_json(result)
        except Exception as e:
            print_error(f"Failed: {e}")


async def run_tests(phone: str, password: str, country_code: str = DEFAULT_COUNTRY_CODE, verbose: bool = False) -> None:
    """Run all API tests."""
    print_header("AquaTru API Test Client")
    print(f"Testing against: {API_BASE_URL}")
    print(f"Phone: {phone}")
    print(f"Country: {country_code}")
    print(f"Time: {datetime.now().isoformat()}")

    async with aiohttp.ClientSession() as session:
        client = DebugApiClient(phone, password, country_code, session, verbose=verbose)

        # Test 1: Login
        print_header("Test 1: Authentication")
        try:
            await client.async_login()
            print_success("Login successful!")
            print_info("Access Token", f"{client._access_token[:30]}..." if client._access_token else None)
            print_info("Refresh Token", f"{client._refresh_token[:30]}..." if client._refresh_token else None)
            print_info("User ID", client._user_id)
            print_info("Token Expiry", client._token_expiry)
        except AquaTruAuthError as e:
            print_error(f"Login failed: {e}")
            print_warning("The API might require different authentication. Check verbose output for details.")
            return
        except AquaTruConnectionError as e:
            print_error(f"Connection failed: {e}")
            return

        # Test 2: Get Devices
        print_header("Test 2: Get Devices")
        try:
            devices = await client.async_get_devices()
            if devices:
                print_success(f"Found {len(devices)} device(s)")
                for i, device in enumerate(devices, 1):
                    print_section(f"Device {i}")
                    print_info("ID", device.device_id)
                    print_info("Name", device.name)
                    print_info("Model", device.model)
                    print_info("Serial", device.serial_number)
                    print_info("Location", device.location)
                    print_info("Connected", device.is_connected)
            else:
                print_warning("No devices found - this might indicate a different API response format")
        except Exception as e:
            print_error(f"Failed to get devices: {e}")
            devices = []

        # Test 3: Get Device Data (for each device)
        if devices:
            print_header("Test 3: Get Device Data")
            for device in devices:
                print_section(f"Data for: {device.name}")
                try:
                    data = await client.async_get_device_data(device.device_id)
                    print_success("Data retrieved successfully!")

                    print(f"\n  {Colors.BOLD}TDS Readings:{Colors.END}")
                    print_info("Tap Water TDS", f"{data.tds_tap} ppm" if data.tds_tap else None)
                    print_info("Clean Water TDS", f"{data.tds_clean} ppm" if data.tds_clean else None)
                    if data.tds_tap and data.tds_clean and data.tds_tap > 0:
                        reduction = ((data.tds_tap - data.tds_clean) / data.tds_tap) * 100
                        print_info("TDS Reduction", f"{reduction:.1f}%")

                    print(f"\n  {Colors.BOLD}Filter Life:{Colors.END}")
                    print_info("Pre-Filter", f"{data.filter_pre_life}%" if data.filter_pre_life is not None else None)
                    print_info("RO Filter", f"{data.filter_ro_life}%" if data.filter_ro_life is not None else None)
                    print_info("VOC Filter", f"{data.filter_voc_life}%" if data.filter_voc_life is not None else None)

                    print(f"\n  {Colors.BOLD}Usage:{Colors.END}")
                    print_info("Daily", f"{data.daily_usage} gal" if data.daily_usage else None)
                    print_info("Weekly", f"{data.weekly_usage} gal" if data.weekly_usage else None)
                    print_info("Monthly", f"{data.monthly_usage} gal" if data.monthly_usage else None)
                    print_info("Total", f"{data.total_usage} gal" if data.total_usage else None)

                    print(f"\n  {Colors.BOLD}Savings:{Colors.END}")
                    print_info("Money Saved", f"${data.money_saved:.2f}" if data.money_saved else None)
                    print_info("Bottles Saved", data.bottles_saved)

                    print(f"\n  {Colors.BOLD}Status:{Colors.END}")
                    print_info("Connected", data.is_connected)
                    print_info("Last Updated", data.last_updated)

                except Exception as e:
                    print_error(f"Failed to get device data: {e}")

        # Test 4: Additional endpoints (always run in verbose mode for debugging)
        if verbose:
            await test_raw_endpoints(client)

        print_header("Tests Complete")

        if not devices or all(
            d.tds_tap is None and d.filter_pre_life is None
            for d in [await client.async_get_device_data(dev.device_id) for dev in devices]
        ) if devices else True:
            print_warning("\nIf data appears empty, run with -v flag to see raw API responses")
            print_warning("This will help identify the correct field names in the API response")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test client for AquaTru API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_client.py --phone 2895551234 -c CA
  python test_client.py --phone 2895551234 -p mypassword -c CA
  python test_client.py --phone 2895551234 -c CA -v  # Verbose mode

Environment variables:
  AQUATRU_PHONE        - Your AquaTru account phone number (without country prefix)
  AQUATRU_PASSWORD     - Your AquaTru account password
  AQUATRU_COUNTRY_CODE - Your country code (default: CA)
        """,
    )
    parser.add_argument(
        "--phone", "-n",
        help="AquaTru account phone number (without +1 prefix, e.g., 2895551234)",
    )
    parser.add_argument(
        "-p", "--password",
        help="AquaTru account password (or set AQUATRU_PASSWORD env var)",
    )
    parser.add_argument(
        "-c", "--country",
        default=DEFAULT_COUNTRY_CODE,
        help=f"Country code (default: {DEFAULT_COUNTRY_CODE})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output with raw API responses",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Reduce logging output",
    )

    args = parser.parse_args()

    # Get credentials
    phone = args.phone or os.environ.get("AQUATRU_PHONE")
    password = args.password or os.environ.get("AQUATRU_PASSWORD")
    country_code = args.country or os.environ.get("AQUATRU_COUNTRY_CODE", DEFAULT_COUNTRY_CODE)

    if not phone:
        phone = input("Enter your AquaTru phone number (e.g., 2895551234): ")

    if not password:
        password = getpass("Enter your AquaTru password: ")

    if not phone or not password:
        print_error("Phone number and password are required")
        sys.exit(1)

    # Adjust logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif not args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    # Run tests
    try:
        asyncio.run(run_tests(phone, password, country_code, args.verbose))
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
