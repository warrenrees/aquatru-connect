# AquaTru Connect for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/v/release/warrenrees/aquatru-connect)](https://github.com/warrenrees/aquatru-connect/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Home Assistant custom integration for AquaTru Connect (Classic Smart) WiFi water purifiers. Monitor your water quality, filter life, usage statistics, and device status directly from Home Assistant.

## Features

- **Water Quality Monitoring**: Real-time TDS (Total Dissolved Solids) readings for tap and filtered water
- **Filter Life Tracking**: Monitor remaining life for Pre-Filter, RO Filter, and VOC Filter
- **Usage Statistics**: Track daily, weekly, monthly, and total water consumption
- **Savings Calculator**: See how much money and plastic bottles you've saved
- **Device Status**: Real-time status indicators for tank levels, filtering state, and connectivity
- **Real-time Updates**: MQTT connection for instant TDS and status updates (when available)

## Supported Devices

- AquaTru Classic Smart (WiFi-enabled)
- AquaTru AT2050 (untested, may work)

## Installation

### HACS (Recommended)

1. Open HACS in your Home Assistant instance
2. Click the three dots in the top right corner
3. Select **Custom repositories**
4. Add `https://github.com/warrenrees/aquatru-connect` with category **Integration**
5. Click **Add**
6. Search for "AquaTru" in HACS and install it
7. Restart Home Assistant

### Manual Installation

1. Download the latest release from the [Releases page](https://github.com/warrenrees/aquatru-connect/releases)
2. Extract the `aquatru` folder to your Home Assistant `custom_components` directory:
   ```
   <config_directory>/
   └── custom_components/
       └── aquatru/
           ├── __init__.py
           ├── api.py
           ├── binary_sensor.py
           ├── config_flow.py
           ├── const.py
           ├── coordinator.py
           ├── diagnostics.py
           ├── entity.py
           ├── manifest.json
           ├── mqtt.py
           ├── sensor.py
           ├── strings.json
           └── translations/
               └── en.json
   ```
3. Restart Home Assistant

## Configuration

1. Go to **Settings** → **Devices & Services**
2. Click **+ Add Integration**
3. Search for "AquaTru Water Purifier"
4. Enter your credentials:
   - **Phone Number**: Your phone number without country prefix (e.g., `5551234567`)
   - **Password**: Your AquaTru account password
   - **Country Code**: Your two-letter country code (e.g., `US`, `CA`)

> **Note**: These are the same credentials you use in the AquaTru mobile app.

## Entities

### Sensors

| Entity | Description | Unit |
|--------|-------------|------|
| Tap Water TDS | TDS reading of incoming tap water | ppm |
| Clean Water TDS | TDS reading of filtered water | ppm |
| TDS Reduction | Percentage of dissolved solids removed | % |
| Pre-Filter Life | Remaining life of the pre-filter | % |
| RO Filter Life | Remaining life of the reverse osmosis filter | % |
| VOC Filter Life | Remaining life of the VOC carbon filter | % |
| Daily Water Usage | Water filtered today | gal |
| Weekly Water Usage | Water filtered this week | gal |
| Monthly Water Usage | Water filtered this month | gal |
| Total Water Filtered | Lifetime water filtered | gal |
| Money Saved | Estimated money saved vs. bottled water | $ |
| Bottles Saved | Estimated plastic bottles saved | bottles |
| Connection Status | Device connection status | connected/disconnected |
| Filtration Time | Total filtration time | seconds |
| WiFi Network | Connected WiFi network name | - |
| WiFi Version | WiFi module firmware version | - |
| MCU Version | Main controller firmware version | - |
| MQTT Status | Real-time connection status | connected/disconnected |

### Binary Sensors

| Entity | Description |
|--------|-------------|
| Filtering | Device is currently filtering water |
| Clean Tank Full | Clean water tank is full |
| Tap Tank Removed | Tap water tank has been removed |
| Tap Tank Low | Tap water tank is nearly empty |
| Clean Tank Removed | Clean water tank has been removed |
| Purifier Synced | Device is synced with cloud |
| Cover Open | Device cover is open |

## Example Automations

### Low Filter Alert

```yaml
automation:
  - alias: "AquaTru Filter Low Alert"
    trigger:
      - platform: numeric_state
        entity_id: sensor.aquatru_pre_filter_life
        below: 10
      - platform: numeric_state
        entity_id: sensor.aquatru_ro_filter_life
        below: 10
      - platform: numeric_state
        entity_id: sensor.aquatru_voc_filter_life
        below: 10
    action:
      - service: notify.mobile_app
        data:
          title: "AquaTru Filter Low"
          message: "One of your AquaTru filters is below 10%. Time to order a replacement!"
```

### Clean Tank Full Notification

```yaml
automation:
  - alias: "AquaTru Clean Tank Full"
    trigger:
      - platform: state
        entity_id: binary_sensor.aquatru_clean_tank_full
        to: "on"
    action:
      - service: notify.mobile_app
        data:
          title: "AquaTru"
          message: "Clean water tank is full!"
```

### Daily Usage Dashboard Card

```yaml
type: entities
title: AquaTru Water Purifier
entities:
  - entity: sensor.aquatru_tap_water_tds
  - entity: sensor.aquatru_clean_water_tds
  - entity: sensor.aquatru_tds_reduction
  - type: divider
  - entity: sensor.aquatru_pre_filter_life
  - entity: sensor.aquatru_ro_filter_life
  - entity: sensor.aquatru_voc_filter_life
  - type: divider
  - entity: sensor.aquatru_total_water_filtered
  - entity: sensor.aquatru_bottles_saved
  - entity: sensor.aquatru_money_saved
```

## Troubleshooting

### Cannot Connect / Invalid Credentials

- Verify your credentials work in the official AquaTru mobile app
- Ensure your phone number is entered without the country prefix (e.g., `5551234567`, not `+15551234567`)
- Check that you selected the correct country code

### No Data / Sensors Unavailable

- Ensure your AquaTru device is connected to WiFi and showing as online in the mobile app
- Try restarting Home Assistant
- Check the Home Assistant logs for any error messages

### Entity Names

Entity IDs are based on your device name in the AquaTru app. If you rename your device in the app, you may need to remove and re-add the integration.

## Data Refresh

The integration uses two methods for data updates:

- **Cloud Polling**: The AquaTru cloud API is polled every 5 minutes for comprehensive device data including filter life, usage statistics, and savings calculations.
- **MQTT Real-time Updates**: When available, the integration connects to AquaTru's MQTT service for instant updates to TDS readings and device status. AWS credentials are automatically refreshed every 6 hours.

The MQTT Status sensor indicates whether real-time updates are active.

## Known Limitations

- **Cloud Dependency**: This integration requires an active internet connection to communicate with AquaTru's cloud API. Local-only control is not supported.
- **Single Device per Entry**: Each config entry supports one AquaTru device. If you have multiple devices, add the integration multiple times.
- **Usage Statistics Delay**: Daily, weekly, and monthly usage statistics may be delayed by up to 24 hours as they are calculated server-side.
- **MQTT Availability**: Real-time MQTT updates depend on AquaTru's AWS IoT infrastructure. If MQTT is unavailable, the integration falls back to cloud polling.
- **Filter Reset**: Filter life cannot be reset through this integration; use the official AquaTru mobile app.

## Privacy & Security

- Credentials are stored securely in Home Assistant's encrypted storage
- All communication with AquaTru's API uses HTTPS
- No data is sent to third parties

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This integration is not affiliated with, endorsed by, or connected to AquaTru or Ideal Living LLC. AquaTru is a trademark of Ideal Living LLC.

## Acknowledgments

- Thanks to the Home Assistant community for their excellent documentation
- Built using the Home Assistant custom component architecture
