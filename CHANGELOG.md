## Changelog

### [Unreleased]
- Reduced cloud polling frequency: 10 minutes primary (was 1 minute), 6 hours with MQTT active (was 5 minutes)

### v1.1.0
- Added AWS IoT MQTT support for real-time updates
- Added MQTT status sensor entity
- Added diagnostics support
- Added re-authentication flow
- Added reconfiguration support
- Added comprehensive test suite (9 modules, 2000+ lines)
- Added proper translations and UI strings
- Improved performance with non-blocking AWS SDK initialization
- Improved reliability with automatic credential refresh
- Improved error handling and connection failure detection
- Fixed potential event loop blocking issues

### v1.0.0
- Initial release
- Water quality monitoring (TDS)
- Filter life tracking
- Usage statistics
- Savings calculations
- Device status sensors
- Binary sensors for tank and cover status
