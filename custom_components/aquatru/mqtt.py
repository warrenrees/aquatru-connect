"""AWS IoT MQTT client for AquaTru real-time updates."""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import aiohttp
from aiohttp.resolver import ThreadedResolver

from awscrt import auth, io, mqtt
from awsiot import mqtt_connection_builder

from .const import (
    AWS_IOT_ENDPOINT,
    AWS_REGION,
    COGNITO_IDENTITY_ENDPOINT,
    COGNITO_IDENTITY_POOL_ID,
    MQTT_TOPIC_DEVICE_STATUS,
    MQTT_TOPIC_MCU_MODEL_ID,
    MQTT_TOPIC_MCU_VERSION,
    MQTT_TOPIC_SENSOR_DATA,
    MQTT_TOPIC_WELCOME,
)

_LOGGER = logging.getLogger(__name__)

# Refresh credentials 5 minutes before expiration
CREDENTIAL_REFRESH_BUFFER = timedelta(minutes=5)
# Check credentials every 10 minutes
CREDENTIAL_CHECK_INTERVAL = timedelta(minutes=10)


@dataclass
class CognitoCredentials:
    """AWS Cognito temporary credentials."""

    identity_id: str
    access_key_id: str
    secret_key: str
    session_token: str
    expiration: datetime


@dataclass
class AwsIotSettings:
    """AWS IoT settings for MQTT connection."""

    identity_pool_id: str
    region: str
    iot_endpoint: str = AWS_IOT_ENDPOINT

    @property
    def cognito_endpoint(self) -> str:
        """Return the Cognito Identity endpoint for this region."""
        return f"https://cognito-identity.{self.region}.amazonaws.com"


class AquaTruMqttClient:
    """MQTT client for AquaTru real-time updates via AWS IoT."""

    def __init__(
        self,
        device_mac: str,
        access_token: str,
        aws_settings: AwsIotSettings | None = None,
        on_message: Callable[[str, dict[str, Any]], None] | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the MQTT client.

        Args:
            device_mac: Device MAC address (without colons, lowercase)
            access_token: AquaTru API access token (used as Cognito login token)
            aws_settings: AWS IoT settings (if None, uses hardcoded defaults)
            on_message: Callback for received messages (topic, payload)
            session: Optional aiohttp session (if None, creates own session)
        """
        # Clean MAC address: remove colons/dashes and lowercase
        self._device_mac = device_mac.replace(":", "").replace("-", "").lower()

        # Use provided settings or fall back to hardcoded defaults
        if aws_settings:
            self._aws_settings = aws_settings
        else:
            self._aws_settings = AwsIotSettings(
                identity_pool_id=COGNITO_IDENTITY_POOL_ID,
                region=AWS_REGION,
                iot_endpoint=AWS_IOT_ENDPOINT,
            )
        self._access_token = access_token
        self._on_message = on_message
        self._credentials: CognitoCredentials | None = None
        self._mqtt_connection: mqtt.Connection | None = None
        self._session = session
        self._owns_session = session is None  # Track if we created the session
        self._connected = False
        self._subscribed_topics: list[str] = []
        self._reconnect_task: asyncio.Task | None = None
        self._credential_refresh_task: asyncio.Task | None = None

    @property
    def is_connected(self) -> bool:
        """Return True if MQTT is connected."""
        return self._connected

    @property
    def credentials_expiration(self) -> datetime | None:
        """Return the credential expiration time."""
        return self._credentials.expiration if self._credentials else None

    def _credentials_need_refresh(self) -> bool:
        """Check if credentials need to be refreshed."""
        if not self._credentials:
            return True

        now = datetime.now(timezone.utc)
        expires_at = self._credentials.expiration

        # Refresh if we're within the buffer period of expiration
        return now >= (expires_at - CREDENTIAL_REFRESH_BUFFER)

    async def _async_credential_refresh_loop(self) -> None:
        """Periodically check and refresh credentials."""
        while True:
            try:
                await asyncio.sleep(CREDENTIAL_CHECK_INTERVAL.total_seconds())

                if not self._connected:
                    _LOGGER.debug("Not connected, skipping credential check")
                    continue

                if self._credentials_need_refresh():
                    _LOGGER.info(
                        "Credentials expiring soon (at %s), refreshing...",
                        self._credentials.expiration.isoformat() if self._credentials else "unknown"
                    )
                    await self._async_refresh_credentials()
                else:
                    time_remaining = self._credentials.expiration - datetime.now(timezone.utc)
                    _LOGGER.debug(
                        "Credentials still valid for %s",
                        time_remaining
                    )

            except asyncio.CancelledError:
                _LOGGER.debug("Credential refresh loop cancelled")
                raise
            except Exception as err:
                _LOGGER.error("Error in credential refresh loop: %s", err)
                # Wait before retrying
                await asyncio.sleep(60)

    async def _async_refresh_credentials(self) -> bool:
        """Refresh credentials by disconnecting and reconnecting."""
        _LOGGER.info("Refreshing AWS credentials...")

        # Disconnect current connection
        if self._mqtt_connection and self._connected:
            try:
                disconnect_future = self._mqtt_connection.disconnect()
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, disconnect_future.result)
            except Exception as err:
                _LOGGER.warning("Error during disconnect for credential refresh: %s", err)
            finally:
                self._connected = False
                self._mqtt_connection = None

        # Get new credentials and reconnect
        try:
            identity_id = await self._get_cognito_identity()
            self._credentials = await self._get_credentials(identity_id)

            _LOGGER.info(
                "Got new credentials, expires at %s",
                self._credentials.expiration.isoformat()
            )

            # Reconnect with new credentials
            return await self._async_connect_with_credentials()

        except Exception as err:
            _LOGGER.error("Failed to refresh credentials: %s", err)
            # Schedule reconnection attempt
            if not self._reconnect_task or self._reconnect_task.done():
                self._reconnect_task = asyncio.create_task(self._async_reconnect())
            return False

    def _build_mqtt_connection(self) -> mqtt.Connection:
        """Build MQTT connection (runs in executor to avoid blocking)."""
        # Create credentials provider
        credentials_provider = auth.AwsCredentialsProvider.new_static(
            access_key_id=self._credentials.access_key_id,
            secret_access_key=self._credentials.secret_key,
            session_token=self._credentials.session_token,
        )

        # Set up event loop for AWS CRT
        event_loop_group = io.EventLoopGroup(num_threads=1)
        host_resolver = io.DefaultHostResolver(event_loop_group)
        client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

        # Build MQTT connection using WebSocket with AWS credentials
        return mqtt_connection_builder.websockets_with_default_aws_signing(
            endpoint=self._aws_settings.iot_endpoint,
            region=self._aws_settings.region,
            credentials_provider=credentials_provider,
            client_bootstrap=client_bootstrap,
            client_id=f"aquatru-ha-{self._device_mac}",
            clean_session=True,
            keep_alive_secs=30,
            on_connection_interrupted=self._on_connection_interrupted,
            on_connection_resumed=self._on_connection_resumed,
        )

    async def _async_connect_with_credentials(self) -> bool:
        """Connect to MQTT using current credentials."""
        if not self._credentials:
            _LOGGER.error("No credentials available for connection")
            return False

        try:
            # Build connection in executor to avoid blocking calls
            loop = asyncio.get_event_loop()
            self._mqtt_connection = await loop.run_in_executor(
                None, self._build_mqtt_connection
            )

            # Connect
            _LOGGER.info("Connecting to AWS IoT MQTT...")
            connect_future = self._mqtt_connection.connect()

            # Run in executor since awscrt uses its own event loop
            await loop.run_in_executor(None, connect_future.result)

            self._connected = True
            _LOGGER.info("Connected to AWS IoT MQTT")

            # Re-subscribe to device topics
            self._subscribed_topics = []
            await self._subscribe_to_topics()

            return True

        except Exception as err:
            _LOGGER.error("Failed to connect with credentials: %s", err)
            self._connected = False
            return False

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure we have an active HTTP session."""
        if self._session is None or self._session.closed:
            # Only create a session if we don't have one (i.e., none was injected)
            connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
            self._session = aiohttp.ClientSession(connector=connector)
            self._owns_session = True
        return self._session

    async def _get_cognito_identity(self) -> str:
        """Get Cognito Identity ID using the identity pool."""
        session = await self._ensure_session()

        # Try without logins first (unauthenticated identity)
        payload = {
            "IdentityPoolId": self._aws_settings.identity_pool_id,
        }

        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetId",
        }

        try:
            async with session.post(
                self._aws_settings.cognito_endpoint,
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    _LOGGER.error("Failed to get Cognito identity: %s", text)
                    raise Exception(f"Cognito GetId failed: {resp.status}")

                # Use content_type=None to accept application/x-amz-json-1.1
                data = await resp.json(content_type=None)
                identity_id = data.get("IdentityId")
                _LOGGER.debug("Got Cognito identity ID: %s", identity_id)
                return identity_id
        except Exception as err:
            _LOGGER.error("Error getting Cognito identity: %s", err)
            raise

    async def _get_credentials(self, identity_id: str) -> CognitoCredentials:
        """Get temporary AWS credentials from Cognito."""
        session = await self._ensure_session()

        payload = {
            "IdentityId": identity_id,
        }

        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        }

        try:
            async with session.post(
                self._aws_settings.cognito_endpoint,
                json=payload,
                headers=headers,
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    _LOGGER.error("Failed to get Cognito credentials: %s", text)
                    raise Exception(f"Cognito GetCredentialsForIdentity failed: {resp.status}")

                # Use content_type=None to accept application/x-amz-json-1.1
                data = await resp.json(content_type=None)
                creds = data.get("Credentials", {})

                # Parse expiration timestamp
                expiration_ts = creds.get("Expiration", 0)
                if isinstance(expiration_ts, (int, float)):
                    expiration = datetime.fromtimestamp(expiration_ts, tz=timezone.utc)
                else:
                    # Default to 1 hour from now
                    expiration = datetime.now(timezone.utc)

                credentials = CognitoCredentials(
                    identity_id=identity_id,
                    access_key_id=creds.get("AccessKeyId", ""),
                    secret_key=creds.get("SecretKey", ""),
                    session_token=creds.get("SessionToken", ""),
                    expiration=expiration,
                )

                _LOGGER.debug(
                    "Got Cognito credentials, expires: %s",
                    credentials.expiration.isoformat()
                )
                return credentials
        except Exception as err:
            _LOGGER.error("Error getting Cognito credentials: %s", err)
            raise

    async def async_connect(self) -> bool:
        """Connect to AWS IoT MQTT broker."""
        try:
            # Get Cognito identity and credentials
            identity_id = await self._get_cognito_identity()
            self._credentials = await self._get_credentials(identity_id)

            _LOGGER.info(
                "Got credentials, expires at %s",
                self._credentials.expiration.isoformat()
            )

            # Connect with the credentials
            if not await self._async_connect_with_credentials():
                return False

            # Start credential refresh loop
            if self._credential_refresh_task is None or self._credential_refresh_task.done():
                self._credential_refresh_task = asyncio.create_task(
                    self._async_credential_refresh_loop()
                )
                _LOGGER.debug("Started credential refresh loop")

            return True

        except Exception as err:
            _LOGGER.error("Failed to connect to AWS IoT MQTT: %s", err)
            self._connected = False
            return False

    async def _subscribe_to_topics(self) -> None:
        """Subscribe to device MQTT topics."""
        if not self._mqtt_connection:
            return

        topics = [
            MQTT_TOPIC_SENSOR_DATA.format(mac=self._device_mac),
            MQTT_TOPIC_DEVICE_STATUS.format(mac=self._device_mac),
            MQTT_TOPIC_MCU_VERSION.format(mac=self._device_mac),
            MQTT_TOPIC_MCU_MODEL_ID.format(mac=self._device_mac),
            MQTT_TOPIC_WELCOME.format(mac=self._device_mac),
        ]

        loop = asyncio.get_event_loop()

        for topic in topics:
            try:
                _LOGGER.debug("Subscribing to topic: %s", topic)
                subscribe_future, _ = self._mqtt_connection.subscribe(
                    topic=topic,
                    qos=mqtt.QoS.AT_LEAST_ONCE,
                    callback=self._on_mqtt_message,
                )
                await loop.run_in_executor(None, subscribe_future.result)
                self._subscribed_topics.append(topic)
                _LOGGER.debug("Subscribed to topic: %s", topic)
            except Exception as err:
                _LOGGER.error("Failed to subscribe to topic %s: %s", topic, err)

    def _on_mqtt_message(self, topic: str, payload: bytes, **kwargs) -> None:
        """Handle incoming MQTT message."""
        try:
            _LOGGER.debug("Received MQTT message on topic: %s", topic)

            # Parse JSON payload
            data = json.loads(payload.decode("utf-8"))
            _LOGGER.debug("MQTT payload: %s", data)

            # Call the callback if set
            if self._on_message:
                # Schedule callback on asyncio event loop
                try:
                    loop = asyncio.get_running_loop()
                    loop.call_soon_threadsafe(
                        lambda: asyncio.create_task(
                            self._async_on_message(topic, data)
                        )
                    )
                except RuntimeError:
                    # No running loop, call directly (shouldn't happen in HA)
                    _LOGGER.warning("No running event loop for MQTT callback")

        except json.JSONDecodeError as err:
            _LOGGER.error("Failed to parse MQTT message: %s", err)
        except Exception as err:
            _LOGGER.error("Error handling MQTT message: %s", err)

    async def _async_on_message(self, topic: str, data: dict[str, Any]) -> None:
        """Async wrapper for message callback."""
        if self._on_message:
            self._on_message(topic, data)

    def _on_connection_interrupted(self, connection, error, **kwargs) -> None:
        """Handle connection interruption."""
        _LOGGER.warning("MQTT connection interrupted: %s", error)
        self._connected = False

        # Schedule reconnection
        try:
            loop = asyncio.get_running_loop()
            self._reconnect_task = loop.create_task(self._async_reconnect())
        except RuntimeError:
            _LOGGER.error("Cannot schedule reconnection - no running event loop")

    def _on_connection_resumed(self, connection, return_code, session_present, **kwargs) -> None:
        """Handle connection resumption."""
        _LOGGER.info("MQTT connection resumed (return_code=%s)", return_code)
        self._connected = True

    async def _async_reconnect(self) -> None:
        """Attempt to reconnect after connection loss."""
        retry_delay = 5
        max_retries = 10

        for attempt in range(max_retries):
            _LOGGER.info("Attempting MQTT reconnection (attempt %d/%d)", attempt + 1, max_retries)

            await asyncio.sleep(retry_delay)

            try:
                # Refresh credentials and reconnect
                if await self.async_connect():
                    _LOGGER.info("MQTT reconnection successful")
                    return
            except Exception as err:
                _LOGGER.error("Reconnection attempt failed: %s", err)

            # Exponential backoff
            retry_delay = min(retry_delay * 2, 60)

        _LOGGER.error("MQTT reconnection failed after %d attempts", max_retries)

    async def async_disconnect(self) -> None:
        """Disconnect from AWS IoT MQTT broker."""
        # Cancel credential refresh task
        if self._credential_refresh_task:
            self._credential_refresh_task.cancel()
            try:
                await self._credential_refresh_task
            except asyncio.CancelledError:
                pass
            self._credential_refresh_task = None

        # Cancel reconnect task
        if self._reconnect_task:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None

        if self._mqtt_connection and self._connected:
            try:
                _LOGGER.info("Disconnecting from AWS IoT MQTT...")
                disconnect_future = self._mqtt_connection.disconnect()
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, disconnect_future.result)
                _LOGGER.info("Disconnected from AWS IoT MQTT")
            except Exception as err:
                _LOGGER.error("Error disconnecting from MQTT: %s", err)
            finally:
                self._connected = False

        # Only close the session if we created it
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    def update_access_token(self, access_token: str) -> None:
        """Update the access token (called when token is refreshed)."""
        self._access_token = access_token


def parse_sensor_data(payload: dict[str, Any]) -> dict[str, Any]:
    """Parse SENSOR-DATA MQTT message into device data fields.

    Actual payload format from device:
    {
        "correlationID": "111-222-333-444-555",
        "msgVer": "1.0",
        "body": {
            "isFiltering": true,
            "isCoverUp": false,
            "isTapRemoved": false,
            "isTapNearEnd": false,
            "isCleanRemoved": false,
            "isCleanTankFull": false,
            "purifiedAmount": 84,
            "preFilterHealth": 80,
            "revFilterHealth": 70,
            "vocFilterHealth": 40,
            "tdsTap": 193,
            "tdsClean": 10,
            "filtrationTime": 61,
            "connectionName": "htoc-internal",
            "newFilterTds": 209,
            "pumpRunningTime": 907
        }
    }
    """
    result = {}

    # Data is wrapped in "body" field
    body = payload.get("body", payload)

    # TDS readings
    if "tdsClean" in body:
        result["tds_clean"] = body["tdsClean"]
    if "tdsTap" in body:
        result["tds_tap"] = body["tdsTap"]

    # Filter life percentages
    if "preFilterHealth" in body:
        result["filter_pre_life"] = body["preFilterHealth"]
    if "revFilterHealth" in body:
        result["filter_ro_life"] = body["revFilterHealth"]
    if "vocFilterHealth" in body:
        result["filter_voc_life"] = body["vocFilterHealth"]

    # Usage data
    if "purifiedAmount" in body:
        result["total_usage"] = body["purifiedAmount"]
    if "filtrationTime" in body:
        result["filtration_time"] = body["filtrationTime"]

    # Connection info
    if "connectionName" in body:
        result["connection_name"] = body["connectionName"]

    # Device status flags (also included in SENSOR-DATA)
    status_mapping = {
        "isFiltering": "is_filtering",
        "isCleanTankFull": "is_clean_tank_full",
        "isTapRemoved": "is_tap_removed",
        "isTapNearEnd": "is_tap_near_end",
        "isCleanRemoved": "is_clean_removed",
        "isCoverUp": "is_cover_up",
    }

    for api_key, local_key in status_mapping.items():
        if api_key in body:
            result[local_key] = body[api_key]

    return result


def parse_device_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Parse DEVICE-STATUS MQTT message into device data fields.

    May also be wrapped in "body" field.
    """
    result = {}

    # Data may be wrapped in "body" field
    body = payload.get("body", payload)

    status_mapping = {
        "isFiltering": "is_filtering",
        "isCleanTankFull": "is_clean_tank_full",
        "isTapRemoved": "is_tap_removed",
        "isTapNearEnd": "is_tap_near_end",
        "isCleanRemoved": "is_clean_removed",
        "isPurifierSynced": "is_purifier_synced",
        "isCoverUp": "is_cover_up",
        "isConnected": "is_connected",
    }

    for api_key, local_key in status_mapping.items():
        if api_key in body:
            result[local_key] = body[api_key]

    return result
