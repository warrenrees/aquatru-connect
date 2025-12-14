"""Config flow for AquaTru integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .api import (
    AquaTruApiClient,
    AquaTruAuthError,
    AquaTruConnectionError,
    AquaTruDevice,
)
from .const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_PHONE,
    DEFAULT_COUNTRY_CODE,
    DOMAIN,
    ERROR_AUTH_FAILED,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_CREDENTIALS,
    ERROR_NO_DEVICES,
    ERROR_UNKNOWN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PHONE): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_COUNTRY_CODE, default=DEFAULT_COUNTRY_CODE): str,
    }
)


async def validate_input(
    hass: HomeAssistant, data: dict[str, Any]
) -> tuple[dict[str, Any], list[AquaTruDevice]]:
    """Validate the user input allows us to connect."""
    # Don't use shared session - it has DNS resolution issues
    client = AquaTruApiClient(
        phone=data[CONF_PHONE],
        password=data[CONF_PASSWORD],
        country_code=data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
    )

    try:
        await client.async_login()
        devices = await client.async_get_devices()
    finally:
        await client.close()

    if not devices:
        raise NoDevicesError("No AquaTru devices found")

    return {"title": data[CONF_PHONE]}, devices


class NoDevicesError(Exception):
    """No devices found error."""


class AquaTruConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for AquaTru."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize config flow."""
        self._phone: str | None = None
        self._password: str | None = None
        self._country_code: str = DEFAULT_COUNTRY_CODE
        self._devices: list[AquaTruDevice] = []

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._phone = user_input[CONF_PHONE]
            self._password = user_input[CONF_PASSWORD]
            self._country_code = user_input.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE)

            try:
                info, self._devices = await validate_input(self.hass, user_input)
            except AquaTruAuthError:
                errors["base"] = ERROR_INVALID_CREDENTIALS
            except AquaTruConnectionError:
                errors["base"] = ERROR_CANNOT_CONNECT
            except NoDevicesError:
                errors["base"] = ERROR_NO_DEVICES
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = ERROR_UNKNOWN
            else:
                # Check if we already have an entry for this phone
                await self.async_set_unique_id(self._phone)
                self._abort_if_unique_id_configured()

                if len(self._devices) == 1:
                    # Only one device, create entry directly
                    device = self._devices[0]
                    return self.async_create_entry(
                        title=device.name,
                        data={
                            CONF_PHONE: self._phone,
                            CONF_PASSWORD: self._password,
                            CONF_COUNTRY_CODE: self._country_code,
                            CONF_DEVICE_ID: device.device_id,
                            CONF_DEVICE_NAME: device.name,
                            CONF_DEVICE_MAC: device.mac_address,
                        },
                    )

                # Multiple devices, ask user to select
                return await self.async_step_device()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle device selection step."""
        if user_input is not None:
            device_id = user_input[CONF_DEVICE_ID]
            device = next(
                (d for d in self._devices if d.device_id == device_id), None
            )

            if device:
                return self.async_create_entry(
                    title=device.name,
                    data={
                        CONF_PHONE: self._phone,
                        CONF_PASSWORD: self._password,
                        CONF_COUNTRY_CODE: self._country_code,
                        CONF_DEVICE_ID: device.device_id,
                        CONF_DEVICE_NAME: device.name,
                        CONF_DEVICE_MAC: device.mac_address,
                    },
                )

        device_options = {
            device.device_id: f"{device.name} ({device.model})"
            for device in self._devices
        }

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DEVICE_ID): vol.In(device_options),
                }
            ),
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Handle re-authentication."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle re-authentication confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None:
            reauth_entry = self._get_reauth_entry()

            try:
                await validate_input(
                    self.hass,
                    {
                        CONF_PHONE: reauth_entry.data[CONF_PHONE],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_COUNTRY_CODE: reauth_entry.data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE),
                    },
                )
            except AquaTruAuthError:
                errors["base"] = ERROR_INVALID_CREDENTIALS
            except AquaTruConnectionError:
                errors["base"] = ERROR_CANNOT_CONNECT
            except NoDevicesError:
                errors["base"] = ERROR_NO_DEVICES
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = ERROR_UNKNOWN
            else:
                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data_updates={CONF_PASSWORD: user_input[CONF_PASSWORD]},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            errors=errors,
        )
