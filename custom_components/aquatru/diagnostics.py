"""Diagnostics support for AquaTru."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import AquaTruConfigEntry

TO_REDACT = {
    "phone",
    "password",
    "access_token",
    "refresh_token",
    "mac_address",
    "serial_number",
    "identity_id",
    "access_key_id",
    "secret_key",
    "session_token",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: AquaTruConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data.coordinator

    # Get device data
    device_data = None
    if coordinator.data:
        device_data = {
            "device_id": coordinator.device_id,
            "device_name": coordinator.device_name,
            "mac_address": coordinator.device_mac,
            "tds_tap": coordinator.data.tds_tap,
            "tds_clean": coordinator.data.tds_clean,
            "filter_pre_life": coordinator.data.filter_pre_life,
            "filter_ro_life": coordinator.data.filter_ro_life,
            "filter_voc_life": coordinator.data.filter_voc_life,
            "is_connected": coordinator.data.is_connected,
            "is_filtering": coordinator.data.is_filtering,
            "is_clean_tank_full": coordinator.data.is_clean_tank_full,
            "is_tap_removed": coordinator.data.is_tap_removed,
            "is_tap_near_end": coordinator.data.is_tap_near_end,
            "is_clean_removed": coordinator.data.is_clean_removed,
            "is_cover_up": coordinator.data.is_cover_up,
            "daily_usage": coordinator.data.daily_usage,
            "weekly_usage": coordinator.data.weekly_usage,
            "monthly_usage": coordinator.data.monthly_usage,
            "total_usage": coordinator.data.total_usage,
            "filtration_time": coordinator.data.filtration_time,
            "money_saved": coordinator.data.money_saved,
            "bottles_saved": coordinator.data.bottles_saved,
            "wifi_version": coordinator.data.wifi_version,
            "mcu_version": coordinator.data.mcu_version,
            "connection_name": coordinator.data.connection_name,
        }

    # Get MQTT status
    mqtt_status = {
        "connected": coordinator.mqtt_connected,
    }
    if coordinator._mqtt_client:
        mqtt_status["credentials_expiration"] = (
            coordinator._mqtt_client.credentials_expiration.isoformat()
            if coordinator._mqtt_client.credentials_expiration
            else None
        )

    return async_redact_data(
        {
            "config_entry": {
                "entry_id": entry.entry_id,
                "version": entry.version,
                "domain": entry.domain,
                "title": entry.title,
                "data": dict(entry.data),
                "options": dict(entry.options),
            },
            "device_data": device_data,
            "mqtt_status": mqtt_status,
            "coordinator": {
                "last_update_success": coordinator.last_update_success,
                "update_interval": str(coordinator.update_interval),
            },
        },
        TO_REDACT,
    )
