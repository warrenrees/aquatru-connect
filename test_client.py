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
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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

# AWS IoT MQTT Configuration
AWS_IOT_ENDPOINT = "a3o7za1n1qr1kr-ats.iot.us-east-1.amazonaws.com"
AWS_REGION = "us-east-1"
COGNITO_IDENTITY_POOL_ID = "us-east-1:f89c5342-e044-46f9-b224-f8eded8fcf04"
COGNITO_USER_POOL_ID = "us-east-1_le1eG0zpY"
COGNITO_CLIENT_ID = "7ok90mtc4nn1qs597fqsaqe3u4"
COGNITO_IDENTITY_ENDPOINT = "https://cognito-identity.us-east-1.amazonaws.com"

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
    mac_address: str | None = None
    location: str | None = None
    is_connected: bool = False


@dataclass
class AquaTruDeviceData:
    """Data from an AquaTru device."""

    device_id: str
    mac_address: str | None = None
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


@dataclass
class CognitoCredentials:
    """AWS Cognito temporary credentials."""

    identity_id: str
    access_key_id: str
    secret_key: str
    session_token: str
    expiration: datetime


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

    def _get_headers(self, include_auth: bool = True, use_bearer: bool = True) -> dict[str, str]:
        """Get request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Dart/3.6 (dart:io)",
        }
        if include_auth and self._access_token:
            if use_bearer:
                headers["Authorization"] = f"Bearer {self._access_token}"
            else:
                headers["Authorization"] = self._access_token
        return headers

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        include_auth: bool = True,
        use_bearer: bool = True,
        retry_auth: bool = True,
    ) -> dict[str, Any]:
        """Make an API request with debug output."""
        session = await self._ensure_session()
        url = f"{API_BASE_URL}/{endpoint}"
        headers = self._get_headers(include_auth, use_bearer)

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
                        method, endpoint, data, include_auth, use_bearer, retry_auth=False
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
            response = await self._request("GET", ENDPOINT_PURIFIERS, use_bearer=False)

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
            serial_number=data.get("serialNumber") or data.get("serial"),
            mac_address=data.get("macAddress"),
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


@dataclass
class AwsSettings:
    """AWS settings fetched from API."""

    identity_pool_id: str
    user_pool_id: str
    client_id: str
    region: str


async def fetch_aws_settings(session: aiohttp.ClientSession, verbose: bool = False) -> AwsSettings | None:
    """Fetch AWS settings from the API."""
    url = "https://api.aquatruwater.com/v2/auth/getSettings"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Dart/3.6 (dart:io)",
    }

    if verbose:
        print_section("Fetching AWS Settings")
        print(f"  URL: {url}")

    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print_error(f"Failed to get settings: {resp.status}")
                return None

            data = await resp.json()

            if not data.get("status"):
                print_error("Settings response status is false")
                return None

            settings_data = data.get("data", {})
            aws_details = settings_data.get("awsDetails", {})

            if not aws_details:
                print_error("No AWS details in settings response")
                return None

            settings = AwsSettings(
                identity_pool_id=aws_details.get("identityPoolId", ""),
                user_pool_id=aws_details.get("awsUserPoolId", ""),
                client_id=aws_details.get("awsClientId", ""),
                region=aws_details.get("region", "us-east-1"),
            )

            if verbose:
                print_success("Got AWS settings from API")
                print_info("Identity Pool ID", settings.identity_pool_id)
                print_info("User Pool ID", settings.user_pool_id)
                print_info("Region", settings.region)

            return settings

    except Exception as err:
        print_error(f"Error fetching settings: {err}")
        return None


class MqttTestClient:
    """MQTT client for testing AWS IoT connectivity."""

    def __init__(
        self,
        device_mac: str,
        access_token: str,
        aws_settings: AwsSettings | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the MQTT test client."""
        self._device_mac = device_mac.replace(":", "").replace("-", "").lower()
        self._access_token = access_token
        self._verbose = verbose
        self._session: aiohttp.ClientSession | None = None
        self._credentials: CognitoCredentials | None = None
        self._mqtt_connection = None
        self._connected = False
        self._message_count = 0
        self._credential_refresh_task: asyncio.Task | None = None
        # Refresh credentials 5 minutes before expiration
        self._credential_refresh_buffer = timedelta(minutes=5)

        # Use provided settings or fall back to hardcoded defaults
        if aws_settings:
            self._identity_pool_id = aws_settings.identity_pool_id
            self._region = aws_settings.region
        else:
            self._identity_pool_id = COGNITO_IDENTITY_POOL_ID
            self._region = AWS_REGION

        self._cognito_endpoint = f"https://cognito-identity.{self._region}.amazonaws.com"
        self._iot_endpoint = AWS_IOT_ENDPOINT

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure we have an active HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def get_cognito_identity(self) -> str:
        """Get Cognito Identity ID."""
        session = await self._ensure_session()

        payload = {
            "IdentityPoolId": self._identity_pool_id,
        }

        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetId",
        }

        if self._verbose:
            print_section("Cognito GetId Request")
            print(f"  Endpoint: {self._cognito_endpoint}")
            print(f"  Payload: {json.dumps(payload)}")

        async with session.post(
            self._cognito_endpoint,
            json=payload,
            headers=headers,
        ) as resp:
            response_text = await resp.text()
            if self._verbose:
                print(f"  Status: {resp.status}")
                print(f"  Response: {response_text}")

            if resp.status != 200:
                raise Exception(f"Cognito GetId failed: {resp.status} - {response_text}")

            data = json.loads(response_text)
            return data.get("IdentityId")

    async def get_credentials(self, identity_id: str) -> CognitoCredentials:
        """Get temporary AWS credentials from Cognito."""
        session = await self._ensure_session()

        payload = {
            "IdentityId": identity_id,
        }

        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        }

        if self._verbose:
            print_section("Cognito GetCredentialsForIdentity Request")
            print(f"  Endpoint: {self._cognito_endpoint}")
            print(f"  IdentityId: {identity_id}")

        async with session.post(
            self._cognito_endpoint,
            json=payload,
            headers=headers,
        ) as resp:
            response_text = await resp.text()
            if self._verbose:
                print(f"  Status: {resp.status}")

            if resp.status != 200:
                raise Exception(f"Cognito GetCredentialsForIdentity failed: {resp.status} - {response_text}")

            data = json.loads(response_text)
            creds = data.get("Credentials", {})

            # Parse expiration
            expiration_ts = creds.get("Expiration", 0)
            if isinstance(expiration_ts, (int, float)):
                expiration = datetime.fromtimestamp(expiration_ts, tz=timezone.utc)
            else:
                expiration = datetime.now(timezone.utc) + timedelta(hours=1)

            credentials = CognitoCredentials(
                identity_id=identity_id,
                access_key_id=creds.get("AccessKeyId", ""),
                secret_key=creds.get("SecretKey", ""),
                session_token=creds.get("SessionToken", ""),
                expiration=expiration,
            )

            if self._verbose:
                print_success("Got AWS credentials")
                print_info("Access Key ID", f"{credentials.access_key_id[:20]}...")
                print_info("Expires", credentials.expiration.isoformat())

            return credentials

    def _credentials_need_refresh(self) -> bool:
        """Check if credentials need to be refreshed."""
        if not self._credentials:
            return True

        now = datetime.now(timezone.utc)
        expires_at = self._credentials.expiration

        # Refresh if we're within the buffer period of expiration
        return now >= (expires_at - self._credential_refresh_buffer)

    async def _refresh_credentials(self) -> bool:
        """Refresh AWS credentials and reconnect."""
        print_section("Refreshing Credentials")
        print_warning("Credentials expiring soon, refreshing...")

        # Disconnect current connection
        if self._mqtt_connection and self._connected:
            try:
                disconnect_future = self._mqtt_connection.disconnect()
                disconnect_future.result()
                print_success("Disconnected for credential refresh")
            except Exception as err:
                print_error(f"Error during disconnect: {err}")
            finally:
                self._connected = False
                self._mqtt_connection = None

        # Get new credentials
        try:
            identity_id = await self.get_cognito_identity()
            self._credentials = await self.get_credentials(identity_id)
            print_success(f"New credentials expire at {self._credentials.expiration.isoformat()}")

            # Reconnect
            return await self._connect_with_credentials()

        except Exception as err:
            print_error(f"Failed to refresh credentials: {err}")
            return False

    async def _connect_with_credentials(self) -> bool:
        """Connect to MQTT using current credentials."""
        if not self._credentials:
            print_error("No credentials available")
            return False

        try:
            from awscrt import auth, io, mqtt
            from awsiot import mqtt_connection_builder
        except ImportError:
            print_error("AWS IoT SDK not installed")
            return False

        try:
            # Create credentials provider
            credentials_provider = auth.AwsCredentialsProvider.new_static(
                access_key_id=self._credentials.access_key_id,
                secret_access_key=self._credentials.secret_key,
                session_token=self._credentials.session_token,
            )

            # Set up AWS CRT event loop
            event_loop_group = io.EventLoopGroup(num_threads=1)
            host_resolver = io.DefaultHostResolver(event_loop_group)
            client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

            # Build MQTT connection
            print(f"Connecting to {self._iot_endpoint}...")
            self._mqtt_connection = mqtt_connection_builder.websockets_with_default_aws_signing(
                endpoint=self._iot_endpoint,
                region=self._region,
                credentials_provider=credentials_provider,
                client_bootstrap=client_bootstrap,
                client_id=f"aquatru-test-{self._device_mac}",
                clean_session=True,
                keep_alive_secs=30,
            )

            # Connect
            connect_future = self._mqtt_connection.connect()
            connect_future.result()

            self._connected = True
            print_success("Connected to AWS IoT MQTT!")

            # Subscribe to topics
            await self._subscribe_to_topics(mqtt)

            return True

        except Exception as err:
            print_error(f"Connection failed: {err}")
            self._connected = False
            return False

    async def connect(self) -> bool:
        """Connect to AWS IoT MQTT broker."""
        try:
            # Check if awsiotsdk is installed
            try:
                from awscrt import auth, io, mqtt  # noqa: F401
                from awsiot import mqtt_connection_builder  # noqa: F401
            except ImportError:
                print_error("AWS IoT SDK not installed. Install with: pip install awsiotsdk")
                print_warning("Skipping MQTT connection test")
                return False

            print_section("MQTT Connection")

            # Get Cognito credentials
            print("Getting Cognito identity...")
            identity_id = await self.get_cognito_identity()
            print_success(f"Got identity: {identity_id}")

            print("Getting AWS credentials...")
            self._credentials = await self.get_credentials(identity_id)

            # Connect using credentials
            return await self._connect_with_credentials()

        except Exception as err:
            print_error(f"MQTT connection failed: {err}")
            import traceback
            traceback.print_exc()
            return False

    async def _subscribe_to_topics(self, mqtt_module) -> None:
        """Subscribe to device MQTT topics."""
        topics = [
            f"aws/{self._device_mac}/event/SENSOR-DATA",
            f"aws/{self._device_mac}/event/DEVICE-STATUS",
            f"aws/{self._device_mac}/event/MCU-VERSION",
            f"aws/{self._device_mac}/event/MCU-MODEL-ID",
            f"aws/{self._device_mac}/event/WELCOME",
        ]

        print_section("Subscribing to MQTT Topics")

        for topic in topics:
            try:
                subscribe_future, _ = self._mqtt_connection.subscribe(
                    topic=topic,
                    qos=mqtt_module.QoS.AT_LEAST_ONCE,
                    callback=self._on_message,
                )
                subscribe_future.result()
                print_success(f"Subscribed: {topic}")
            except Exception as err:
                print_error(f"Subscribe failed for {topic}: {err}")

    def _on_message(self, topic: str, payload: bytes, **kwargs) -> None:
        """Handle incoming MQTT message."""
        self._message_count += 1
        try:
            data = json.loads(payload.decode("utf-8"))
            print(f"\n{Colors.GREEN}[MQTT Message #{self._message_count}]{Colors.END}")
            print(f"  Topic: {topic}")
            print(f"  Payload:")
            print_json(data)
        except json.JSONDecodeError:
            print(f"\n{Colors.GREEN}[MQTT Message #{self._message_count}]{Colors.END}")
            print(f"  Topic: {topic}")
            print(f"  Payload (raw): {payload}")

    async def listen(self, duration: int = 60) -> None:
        """Listen for MQTT messages for a specified duration."""
        if not self._connected:
            print_error("Not connected to MQTT")
            return

        print_section(f"Listening for MQTT messages ({duration} seconds)")
        print("Press Ctrl+C to stop early...")
        print(f"\nWaiting for messages on device MAC: {self._device_mac}")

        if self._credentials:
            time_until_expiry = self._credentials.expiration - datetime.now(timezone.utc)
            print(f"Credentials expire in: {time_until_expiry}")

        # Check credentials every 10 minutes during long-running sessions
        check_interval = 600  # 10 minutes
        elapsed = 0

        try:
            while elapsed < duration:
                # Sleep for the check interval or remaining time, whichever is shorter
                sleep_time = min(check_interval, duration - elapsed)
                await asyncio.sleep(sleep_time)
                elapsed += sleep_time

                # Check if we need to refresh credentials
                if self._credentials_need_refresh() and elapsed < duration:
                    print(f"\n{Colors.YELLOW}[Credential Check]{Colors.END}")
                    await self._refresh_credentials()

        except asyncio.CancelledError:
            pass

        print(f"\nReceived {self._message_count} message(s)")

    async def disconnect(self) -> None:
        """Disconnect from MQTT."""
        if self._mqtt_connection and self._connected:
            try:
                disconnect_future = self._mqtt_connection.disconnect()
                disconnect_future.result()
                print_success("Disconnected from MQTT")
            except Exception as err:
                print_error(f"Disconnect error: {err}")

        if self._session and not self._session.closed:
            await self._session.close()


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


async def run_mqtt_test(client: DebugApiClient, device: AquaTruDevice, duration: int = 60) -> None:
    """Run MQTT connection test."""
    if not device.mac_address:
        print_error("Device MAC address not available, cannot test MQTT")
        return

    print_header("MQTT Real-Time Updates Test")
    print_info("Device", device.name)
    print_info("MAC Address", device.mac_address)

    # Fetch AWS settings dynamically
    async with aiohttp.ClientSession() as session:
        aws_settings = await fetch_aws_settings(session, verbose=True)
        if aws_settings:
            print_success("Using AWS settings from API")
        else:
            print_warning("Could not fetch AWS settings, using hardcoded defaults")

    mqtt_client = MqttTestClient(
        device_mac=device.mac_address,
        access_token=client._access_token,
        aws_settings=aws_settings,
        verbose=True,
    )

    try:
        if await mqtt_client.connect():
            await mqtt_client.listen(duration)
    finally:
        await mqtt_client.disconnect()


async def run_tests(
    phone: str,
    password: str,
    country_code: str = DEFAULT_COUNTRY_CODE,
    verbose: bool = False,
    test_mqtt: bool = False,
    mqtt_duration: int = 60,
) -> None:
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
        devices = []
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
                    print_info("MAC Address", device.mac_address)
                    print_info("Location", device.location)
                    print_info("Connected", device.is_connected)
            else:
                print_warning("No devices found - this might indicate a different API response format")
        except Exception as e:
            print_error(f"Failed to get devices: {e}")

        # Test 3: Get Device Data (for each device)
        if devices:
            print_header("Test 3: Get Device Data")
            for device in devices:
                print_section(f"Data for: {device.name}")
                try:
                    data = await client.async_get_device_data(device.device_id)
                    print_success("Data retrieved successfully!")

                    print(f"\n  {Colors.BOLD}Device Info:{Colors.END}")
                    print_info("MAC Address", data.mac_address)

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

        # Test 4: MQTT (if requested)
        if test_mqtt and devices:
            # Find first device with MAC address
            mqtt_device = next((d for d in devices if d.mac_address), None)
            if mqtt_device:
                await run_mqtt_test(client, mqtt_device, mqtt_duration)
            else:
                print_warning("No device with MAC address found for MQTT test")

        # Test 5: Additional endpoints (in verbose mode)
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
  python test_client.py --phone 2895551234 -c CA --mqtt  # Test MQTT
  python test_client.py --phone 2895551234 -c CA --mqtt --mqtt-duration 120  # MQTT for 2 min

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
    parser.add_argument(
        "--mqtt",
        action="store_true",
        help="Test MQTT real-time connection",
    )
    parser.add_argument(
        "--mqtt-duration",
        type=int,
        default=60,
        help="Duration in seconds to listen for MQTT messages (default: 60)",
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
        asyncio.run(run_tests(
            phone,
            password,
            country_code,
            args.verbose,
            test_mqtt=args.mqtt,
            mqtt_duration=args.mqtt_duration,
        ))
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
