#!/usr/bin/env python3
"""Test client for debugging the AquaTru API library.

This is a standalone client that uses the actual API client from the integration.
It provides colorful output and additional debugging capabilities.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from getpass import getpass
from typing import Any

import aiohttp

# Add the custom_components directory to the path so we can import from it
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from custom_components.aquatru.api import (
    AquaTruApiClient,
    AquaTruAuthError,
    AquaTruConnectionError,
    AquaTruApiError,
    AquaTruDevice,
    AquaTruDeviceData,
)
from custom_components.aquatru.const import (
    API_BASE_URL,
    AWS_IOT_ENDPOINT,
    AWS_REGION,
    COGNITO_IDENTITY_POOL_ID,
    DEFAULT_COUNTRY_CODE,
)
from custom_components.aquatru.mqtt import (
    AquaTruMqttClient,
    AwsIotSettings,
    CognitoCredentials,
)
from custom_components.aquatru.session import create_session

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
_LOGGER = logging.getLogger("aquatru_test")


class Colors:
    """ANSI color codes for terminal output."""
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


class DebugApiClient(AquaTruApiClient):
    """Extended API client with verbose debug output."""

    def __init__(
        self,
        phone: str,
        password: str,
        country_code: str = DEFAULT_COUNTRY_CODE,
        session: aiohttp.ClientSession | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the debug API client."""
        super().__init__(phone, password, country_code, session)
        self._verbose = verbose

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        include_auth: bool = True,
        retry_auth: bool = True,
        use_bearer: bool = True,
    ) -> dict[str, Any]:
        """Make an API request with verbose debug output."""
        if self._verbose:
            print_section(f"API Request: {method} {endpoint}")
            print(f"  URL: {API_BASE_URL}/{endpoint}")
            if data:
                # Mask password in output
                safe_data = {k: ("***" if k == "password" else v) for k, v in data.items()}
                print(f"  Body: {json.dumps(safe_data)}")

        result = await super()._request(method, endpoint, data, include_auth, retry_auth, use_bearer)

        if self._verbose:
            print(f"  {Colors.BOLD}Response:{Colors.END}")
            print_json(result)

        return result


async def fetch_aws_settings(session: aiohttp.ClientSession, verbose: bool = False) -> AwsIotSettings | None:
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

            settings = AwsIotSettings(
                identity_pool_id=aws_details.get("identityPoolId", COGNITO_IDENTITY_POOL_ID),
                region=aws_details.get("region", AWS_REGION),
                iot_endpoint=AWS_IOT_ENDPOINT,
            )

            if verbose:
                print_success("Got AWS settings from API")
                print_info("Identity Pool ID", settings.identity_pool_id)
                print_info("Region", settings.region)

            return settings

    except Exception as err:
        print_error(f"Error fetching settings: {err}")
        return None


class MqttTestClient:
    """MQTT client wrapper for testing with verbose output."""

    def __init__(
        self,
        device_mac: str,
        aws_settings: AwsIotSettings | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the MQTT test client."""
        self._device_mac = device_mac.replace(":", "").replace("-", "").lower()
        self._verbose = verbose
        self._message_count = 0

        # Use the actual MQTT client from the integration
        self._client = AquaTruMqttClient(
            device_mac=device_mac,
            aws_settings=aws_settings,
            on_message=self._on_message,
        )

    def _on_message(self, topic: str, data: dict[str, Any]) -> None:
        """Handle incoming MQTT message with formatted output."""
        self._message_count += 1
        print(f"\n{Colors.GREEN}[MQTT Message #{self._message_count}]{Colors.END}")
        print(f"  Topic: {topic}")
        print(f"  Payload:")
        print_json(data)

    async def connect(self) -> bool:
        """Connect to AWS IoT MQTT broker."""
        print_section("MQTT Connection")

        try:
            success = await self._client.async_connect()
            if success:
                print_success("Connected to AWS IoT MQTT!")
                if self._client.credentials_expiration:
                    print_info("Credentials expire", self._client.credentials_expiration.isoformat())
            else:
                print_error("Failed to connect to MQTT")
            return success

        except ImportError:
            print_error("AWS IoT SDK not installed. Install with: pip install awsiotsdk")
            print_warning("Skipping MQTT connection test")
            return False
        except Exception as err:
            print_error(f"MQTT connection failed: {err}")
            import traceback
            traceback.print_exc()
            return False

    async def listen(self, duration: int = 60) -> None:
        """Listen for MQTT messages for a specified duration."""
        if not self._client.is_connected:
            print_error("Not connected to MQTT")
            return

        print_section(f"Listening for MQTT messages ({duration} seconds)")
        print("Press Ctrl+C to stop early...")
        print(f"\nWaiting for messages on device MAC: {self._device_mac}")

        if self._client.credentials_expiration:
            time_until_expiry = self._client.credentials_expiration - datetime.now(timezone.utc)
            print(f"Credentials expire in: {time_until_expiry}")

        try:
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            pass

        print(f"\nReceived {self._message_count} message(s)")

    async def disconnect(self) -> None:
        """Disconnect from MQTT."""
        await self._client.async_disconnect()
        print_success("Disconnected from MQTT")


async def run_mqtt_test(client: DebugApiClient, device: AquaTruDevice, duration: int = 60) -> None:
    """Run MQTT connection test."""
    if not device.mac_address:
        print_error("Device MAC address not available, cannot test MQTT")
        return

    print_header("MQTT Real-Time Updates Test")
    print_info("Device", device.name)
    print_info("MAC Address", device.mac_address)

    # Fetch AWS settings dynamically (ThreadedResolver matches what HA uses and
    # avoids the aiodns resolver, which can be broken in local virtualenvs).
    async with create_session() as session:
        aws_settings = await fetch_aws_settings(session, verbose=True)
        if aws_settings:
            print_success("Using AWS settings from API")
        else:
            print_warning("Could not fetch AWS settings, using hardcoded defaults")

    mqtt_client = MqttTestClient(
        device_mac=device.mac_address,
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

    async with create_session() as session:
        client = DebugApiClient(phone, password, country_code, session, verbose=verbose)

        # Test 1: Login
        print_header("Test 1: Authentication")
        try:
            await client.async_login()
            print_success("Login successful!")
            print_info("Access Token", f"{client.access_token[:30]}..." if client.access_token else None)
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
