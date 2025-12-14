"""Binary sensor platform for AquaTru integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AquaTruConfigEntry
from .api import AquaTruDeviceData
from .const import (
    BINARY_SENSOR_CLEAN_REMOVED,
    BINARY_SENSOR_CLEAN_TANK_FULL,
    BINARY_SENSOR_COVER_UP,
    BINARY_SENSOR_FILTERING,
    BINARY_SENSOR_SYNCED,
    BINARY_SENSOR_TAP_NEAR_END,
    BINARY_SENSOR_TAP_REMOVED,
)
from .coordinator import AquaTruDataUpdateCoordinator
from .entity import AquaTruEntity


@dataclass(frozen=True, kw_only=True)
class AquaTruBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes an AquaTru binary sensor entity."""

    value_fn: Callable[[AquaTruDeviceData], bool | None]


BINARY_SENSOR_DESCRIPTIONS: tuple[AquaTruBinarySensorEntityDescription, ...] = (
    AquaTruBinarySensorEntityDescription(
        key=BINARY_SENSOR_FILTERING,
        translation_key="is_filtering",
        device_class=BinarySensorDeviceClass.RUNNING,
        icon="mdi:water-sync",
        value_fn=lambda data: data.is_filtering,
    ),
    AquaTruBinarySensorEntityDescription(
        key=BINARY_SENSOR_CLEAN_TANK_FULL,
        translation_key="clean_tank_full",
        icon="mdi:water",
        value_fn=lambda data: data.is_clean_tank_full,
    ),
    AquaTruBinarySensorEntityDescription(
        key=BINARY_SENSOR_TAP_REMOVED,
        translation_key="tap_removed",
        device_class=BinarySensorDeviceClass.PROBLEM,
        icon="mdi:water-off",
        value_fn=lambda data: data.is_tap_removed,
    ),
    AquaTruBinarySensorEntityDescription(
        key=BINARY_SENSOR_TAP_NEAR_END,
        translation_key="tap_near_end",
        device_class=BinarySensorDeviceClass.PROBLEM,
        icon="mdi:water-alert",
        value_fn=lambda data: data.is_tap_near_end,
    ),
    AquaTruBinarySensorEntityDescription(
        key=BINARY_SENSOR_CLEAN_REMOVED,
        translation_key="clean_removed",
        device_class=BinarySensorDeviceClass.PROBLEM,
        icon="mdi:water-off",
        value_fn=lambda data: data.is_clean_removed,
    ),
    AquaTruBinarySensorEntityDescription(
        key=BINARY_SENSOR_SYNCED,
        translation_key="synced",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        icon="mdi:sync",
        value_fn=lambda data: data.is_purifier_synced,
    ),
    AquaTruBinarySensorEntityDescription(
        key=BINARY_SENSOR_COVER_UP,
        translation_key="cover_up",
        device_class=BinarySensorDeviceClass.OPENING,
        icon="mdi:door-open",
        value_fn=lambda data: data.is_cover_up,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AquaTruConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up AquaTru binary sensors based on a config entry."""
    coordinator = entry.runtime_data.coordinator

    entities = [
        AquaTruBinarySensor(coordinator, description)
        for description in BINARY_SENSOR_DESCRIPTIONS
    ]

    async_add_entities(entities)


class AquaTruBinarySensor(AquaTruEntity, BinarySensorEntity):
    """AquaTru binary sensor entity."""

    entity_description: AquaTruBinarySensorEntityDescription

    def __init__(
        self,
        coordinator: AquaTruDataUpdateCoordinator,
        description: AquaTruBinarySensorEntityDescription,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def is_on(self) -> bool | None:
        """Return the binary sensor state."""
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)
