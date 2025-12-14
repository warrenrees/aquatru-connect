"""Base entity for AquaTru integration."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AquaTruDataUpdateCoordinator


class AquaTruEntity(CoordinatorEntity[AquaTruDataUpdateCoordinator]):
    """Base entity for AquaTru."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AquaTruDataUpdateCoordinator,
        entity_key: str,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.device_id}_{entity_key}"
        self.entity_key = entity_key

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        info = DeviceInfo(
            identifiers={(DOMAIN, self.coordinator.device_id)},
            name=self.coordinator.device_name,
            manufacturer="AquaTru",
            model="Classic Smart",
        )

        # Add firmware versions if available
        if self.coordinator.data:
            if self.coordinator.data.mcu_version:
                info["sw_version"] = self.coordinator.data.mcu_version
            if self.coordinator.data.wifi_version:
                info["hw_version"] = self.coordinator.data.wifi_version

        return info

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success and self.coordinator.data is not None
