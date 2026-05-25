"""Constants for the AquaTru integration."""
from datetime import timedelta
from typing import Final

DOMAIN: Final = "aquatru"

# API Configuration
API_BASE_URL: Final = "https://api.aquatruwater.com/v1"
API_TIMEOUT_SECONDS: Final = 30

# Polling intervals
DEFAULT_SCAN_INTERVAL: Final = timedelta(minutes=10)
# Longer polling interval when MQTT is connected (fallback only)
MQTT_FALLBACK_SCAN_INTERVAL: Final = timedelta(hours=6)

# MQTT Configuration
MQTT_KEEP_ALIVE_SECONDS: Final = 30
# Refresh credentials 5 minutes before expiration
CREDENTIAL_REFRESH_BUFFER: Final = timedelta(minutes=5)
# Check credentials every 10 minutes
CREDENTIAL_CHECK_INTERVAL: Final = timedelta(minutes=10)

# Connection failure handling
# Number of consecutive failures before creating a repair issue
CONNECTION_FAILURE_THRESHOLD: Final = 3

# API Endpoints (note: /v1 prefix is included in base URL)
ENDPOINT_LOGIN: Final = "user/auth/login"
ENDPOINT_REFRESH_TOKEN: Final = "auth/refreshToken"
ENDPOINT_PURIFIERS: Final = "user/purifiers"

# Configuration keys
CONF_PHONE: Final = "phone"
CONF_PASSWORD: Final = "password"
CONF_DEVICE_ID: Final = "device_id"
CONF_DEVICE_NAME: Final = "device_name"
CONF_DEVICE_MODEL: Final = "device_model"
CONF_DEVICE_MAC: Final = "device_mac"
CONF_COUNTRY_CODE: Final = "country_code"
DEFAULT_COUNTRY_CODE: Final = "CA"

# Sensor keys
SENSOR_TDS_TAP: Final = "tds_tap"
SENSOR_TDS_CLEAN: Final = "tds_clean"
SENSOR_TDS_REDUCTION: Final = "tds_reduction"
SENSOR_FILTER_PRE: Final = "filter_pre"
SENSOR_FILTER_RO: Final = "filter_ro"
SENSOR_FILTER_VOC: Final = "filter_voc"
SENSOR_USAGE_DAILY: Final = "usage_daily"
SENSOR_USAGE_WEEKLY: Final = "usage_weekly"
SENSOR_USAGE_MONTHLY: Final = "usage_monthly"
SENSOR_USAGE_TOTAL: Final = "usage_total"
SENSOR_MONEY_SAVED: Final = "money_saved"
SENSOR_BOTTLES_SAVED: Final = "bottles_saved"
SENSOR_CONNECTION_STATUS: Final = "connection_status"
SENSOR_FILTRATION_TIME: Final = "filtration_time"
SENSOR_WIFI_VERSION: Final = "wifi_version"
SENSOR_MCU_VERSION: Final = "mcu_version"
SENSOR_WIFI_NETWORK: Final = "wifi_network"
SENSOR_MQTT_STATUS: Final = "mqtt_status"

# Binary sensor keys
BINARY_SENSOR_FILTERING: Final = "is_filtering"
BINARY_SENSOR_CLEAN_TANK_FULL: Final = "clean_tank_full"
BINARY_SENSOR_TAP_REMOVED: Final = "tap_removed"
BINARY_SENSOR_TAP_NEAR_END: Final = "tap_near_end"
BINARY_SENSOR_CLEAN_REMOVED: Final = "clean_removed"
BINARY_SENSOR_SYNCED: Final = "synced"
BINARY_SENSOR_COVER_UP: Final = "cover_up"

# Units
UNIT_PPM: Final = "ppm"
UNIT_BOTTLES: Final = "bottles"

# Error codes
ERROR_AUTH_FAILED: Final = "auth_failed"
ERROR_CANNOT_CONNECT: Final = "cannot_connect"
ERROR_UNKNOWN: Final = "unknown"
ERROR_INVALID_CREDENTIALS: Final = "invalid_credentials"
ERROR_NO_DEVICES: Final = "no_devices"

# AWS IoT MQTT Configuration
AWS_IOT_ENDPOINT: Final = "a3o7za1n1qr1kr-ats.iot.us-east-1.amazonaws.com"
AWS_REGION: Final = "us-east-1"
COGNITO_IDENTITY_POOL_ID: Final = "us-east-1:f89c5342-e044-46f9-b224-f8eded8fcf04"

# MQTT Topics (use device MAC address without colons)
MQTT_TOPIC_SENSOR_DATA: Final = "aws/{mac}/event/SENSOR-DATA"
MQTT_TOPIC_DEVICE_STATUS: Final = "aws/{mac}/event/DEVICE-STATUS"
MQTT_TOPIC_MCU_VERSION: Final = "aws/{mac}/event/MCU-VERSION"
MQTT_TOPIC_MCU_MODEL_ID: Final = "aws/{mac}/event/MCU-MODEL-ID"
MQTT_TOPIC_WELCOME: Final = "aws/{mac}/event/WELCOME"
