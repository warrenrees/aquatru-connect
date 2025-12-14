"""Sensor platform for AquaTru integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTime, UnitOfVolume, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import AquaTruDeviceData

from .const import (
    DATA_COORDINATOR,
    DOMAIN,
    SENSOR_BOTTLES_SAVED,
    SENSOR_CONNECTION_STATUS,
    SENSOR_FILTER_PRE,
    SENSOR_FILTER_RO,
    SENSOR_FILTER_VOC,
    SENSOR_FILTRATION_TIME,
    SENSOR_MCU_VERSION,
    SENSOR_MONEY_SAVED,
    SENSOR_TDS_CLEAN,
    SENSOR_TDS_REDUCTION,
    SENSOR_TDS_TAP,
    SENSOR_USAGE_DAILY,
    SENSOR_USAGE_MONTHLY,
    SENSOR_USAGE_TOTAL,
    SENSOR_USAGE_WEEKLY,
    SENSOR_WIFI_NETWORK,
    SENSOR_WIFI_VERSION,
    UNIT_BOTTLES,
    UNIT_PPM,
)
from .coordinator import AquaTruDataUpdateCoordinator
from .entity import AquaTruEntity


@dataclass(frozen=True, kw_only=True)
class AquaTruSensorEntityDescription(SensorEntityDescription):
    """Describes an AquaTru sensor entity."""

    value_fn: Callable[[AquaTruDeviceData], Any]


SENSOR_DESCRIPTIONS: tuple[AquaTruSensorEntityDescription, ...] = (
    AquaTruSensorEntityDescription(
        key=SENSOR_TDS_TAP,
        translation_key="tds_tap",
        native_unit_of_measurement=UNIT_PPM,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:water",
        value_fn=lambda data: data.tds_tap,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_TDS_CLEAN,
        translation_key="tds_clean",
        native_unit_of_measurement=UNIT_PPM,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:water-check",
        value_fn=lambda data: data.tds_clean,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_TDS_REDUCTION,
        translation_key="tds_reduction",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:percent",
        value_fn=lambda data: _calculate_tds_reduction(data),
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_FILTER_PRE,
        translation_key="filter_pre",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:filter",
        value_fn=lambda data: data.filter_pre_life,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_FILTER_RO,
        translation_key="filter_ro",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:filter",
        value_fn=lambda data: data.filter_ro_life,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_FILTER_VOC,
        translation_key="filter_voc",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:filter",
        value_fn=lambda data: data.filter_voc_life,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_USAGE_DAILY,
        translation_key="usage_daily",
        native_unit_of_measurement=UnitOfVolume.GALLONS,
        device_class=SensorDeviceClass.WATER,
        state_class=SensorStateClass.TOTAL,
        icon="mdi:water-pump",
        value_fn=lambda data: data.daily_usage,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_USAGE_WEEKLY,
        translation_key="usage_weekly",
        native_unit_of_measurement=UnitOfVolume.GALLONS,
        device_class=SensorDeviceClass.WATER,
        state_class=SensorStateClass.TOTAL,
        icon="mdi:water-pump",
        value_fn=lambda data: data.weekly_usage,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_USAGE_MONTHLY,
        translation_key="usage_monthly",
        native_unit_of_measurement=UnitOfVolume.GALLONS,
        device_class=SensorDeviceClass.WATER,
        state_class=SensorStateClass.TOTAL,
        icon="mdi:water-pump",
        value_fn=lambda data: data.monthly_usage,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_USAGE_TOTAL,
        translation_key="usage_total",
        native_unit_of_measurement=UnitOfVolume.GALLONS,
        device_class=SensorDeviceClass.WATER,
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:water-pump",
        value_fn=lambda data: data.total_usage,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_MONEY_SAVED,
        translation_key="money_saved",
        native_unit_of_measurement="$",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:piggy-bank",
        value_fn=lambda data: data.money_saved,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_BOTTLES_SAVED,
        translation_key="bottles_saved",
        native_unit_of_measurement=UNIT_BOTTLES,
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:bottle-wine",
        value_fn=lambda data: data.bottles_saved,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_CONNECTION_STATUS,
        translation_key="connection_status",
        device_class=SensorDeviceClass.ENUM,
        icon="mdi:wifi",
        options=["connected", "disconnected"],
        value_fn=lambda data: "connected" if data.is_connected else "disconnected",
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_FILTRATION_TIME,
        translation_key="filtration_time",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:timer",
        value_fn=lambda data: data.filtration_time,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_WIFI_NETWORK,
        translation_key="wifi_network",
        icon="mdi:wifi",
        value_fn=lambda data: data.connection_name,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_WIFI_VERSION,
        translation_key="wifi_version",
        icon="mdi:chip",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.wifi_version,
    ),
    AquaTruSensorEntityDescription(
        key=SENSOR_MCU_VERSION,
        translation_key="mcu_version",
        icon="mdi:chip",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.mcu_version,
    ),
)


def _calculate_tds_reduction(data: AquaTruDeviceData) -> float | None:
    """Calculate the TDS reduction percentage."""
    if data.tds_tap is None or data.tds_clean is None or data.tds_tap == 0:
        return None
    return round(((data.tds_tap - data.tds_clean) / data.tds_tap) * 100, 1)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up AquaTru sensors based on a config entry."""
    coordinator: AquaTruDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id][
        DATA_COORDINATOR
    ]

    entities = [
        AquaTruSensor(coordinator, description)
        for description in SENSOR_DESCRIPTIONS
    ]

    async_add_entities(entities)


class AquaTruSensor(AquaTruEntity, SensorEntity):
    """AquaTru sensor entity."""

    entity_description: AquaTruSensorEntityDescription

    def __init__(
        self,
        coordinator: AquaTruDataUpdateCoordinator,
        description: AquaTruSensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        """Return the sensor value."""
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)
