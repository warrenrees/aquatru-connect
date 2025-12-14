"""Constants for the AquaTru integration."""
from datetime import timedelta
from typing import Final

DOMAIN: Final = "aquatru"

# API Configuration
API_BASE_URL: Final = "https://api.aquatruwater.com/v1"
DEFAULT_SCAN_INTERVAL: Final = timedelta(minutes=10)

# API Endpoints (note: /v1 prefix is included in base URL)
ENDPOINT_LOGIN: Final = "user/auth/login"
ENDPOINT_SEND_CODE: Final = "user/auth/send-code"
ENDPOINT_REFRESH_TOKEN: Final = "auth/refreshToken"
ENDPOINT_SETTINGS: Final = "auth/getSettingsP"
ENDPOINT_PURIFIERS: Final = "user/purifiers"
ENDPOINT_PURIFIERS_LIST: Final = "purifier/purifiersListUser"
ENDPOINT_PURIFIER_BY_LOCATION: Final = "purifier/purifierListByLocation"
ENDPOINT_CONNECTION_STATUS: Final = "purifier/getPurifierConnectionStatus"
ENDPOINT_RESET_FILTER: Final = "purifier/resetFilter"
ENDPOINT_SAVINGS: Final = "purifier/moneySavingCalculator"
ENDPOINT_GRAPH: Final = "onGetGraphApi"
ENDPOINT_WATER_SAFE: Final = "waterSafeResultApi"
ENDPOINT_NOTIFICATIONS: Final = "user/notifications"

# Configuration keys
CONF_PHONE: Final = "phone"
CONF_PASSWORD: Final = "password"
CONF_DEVICE_ID: Final = "device_id"
CONF_DEVICE_NAME: Final = "device_name"
CONF_DEVICE_MAC: Final = "device_mac"
CONF_COUNTRY_CODE: Final = "country_code"
DEFAULT_COUNTRY_CODE: Final = "CA"

# Data keys used in coordinator
DATA_COORDINATOR: Final = "coordinator"
DATA_CLIENT: Final = "client"

# Filter types
FILTER_PRE: Final = "pre_filter"
FILTER_RO: Final = "rev_filter"
FILTER_VOC: Final = "voc_filter"

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

# Device model types
MODEL_CLASSIC_SMART: Final = "AquaTru Classic Smart"
MODEL_AT2050: Final = "AT2050"
MODEL_UNDERSINK: Final = "AquaTru Under Sink"

# Units
UNIT_PPM: Final = "ppm"
UNIT_PERCENT: Final = "%"
UNIT_GALLONS: Final = "gal"
UNIT_LITERS: Final = "L"
UNIT_BOTTLES: Final = "bottles"
UNIT_CURRENCY: Final = "$"
UNIT_SECONDS: Final = "s"

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
COGNITO_USER_POOL_ID: Final = "us-east-1_le1eG0zpY"
COGNITO_CLIENT_ID: Final = "7ok90mtc4nn1qs597fqsaqe3u4"
COGNITO_IDENTITY_ENDPOINT: Final = "https://cognito-identity.us-east-1.amazonaws.com"

# MQTT Topics (use device MAC address without colons)
MQTT_TOPIC_SENSOR_DATA: Final = "aws/{mac}/event/SENSOR-DATA"
MQTT_TOPIC_DEVICE_STATUS: Final = "aws/{mac}/event/DEVICE-STATUS"
MQTT_TOPIC_MCU_VERSION: Final = "aws/{mac}/event/MCU-VERSION"
MQTT_TOPIC_MCU_MODEL_ID: Final = "aws/{mac}/event/MCU-MODEL-ID"
MQTT_TOPIC_WELCOME: Final = "aws/{mac}/event/WELCOME"

# Data keys for MQTT
DATA_MQTT_CLIENT: Final = "mqtt_client"
