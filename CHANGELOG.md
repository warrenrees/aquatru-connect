## Changelog

### [Unreleased]

### v1.1.3

#### Added
- Brand icon and logo (light and dark variants) served via the in-integration
  `brand/` folder, so Home Assistant shows AquaTru branding in the UI.
- GitHub Actions CI: `validate.yml` (hassfest + HACS validation) and `test.yml`
  (runs the pytest suite) on push and pull request.

### v1.1.2

#### Fixed
- **Daily Water Usage, Weekly Water Usage, and Money Saved** no longer show "Unknown".
  - Usage statistics now match the current period and fall back to the most recent
    period the API returns, instead of failing when the API omits the current day
    or formats the ISO week differently than expected.
  - Money Saved is now computed locally (the cloud returns `dollarsSaved: null`),
    matching the AquaTru app: `bottles = ceil(purifiedAmount / bottleSize)` and
    `money = (purifiedAmount / bottleSize / quantityInPack) * waterCost`.
- **Bottles Saved** now matches the value shown in the AquaTru app. It is derived
  from total water purified and the configured bottle size; the cloud's
  `bottleSaved` field uses a different bottle size and under-reported the count.
- Reworked MQTT reconnection so it no longer races the AWS IoT SDK's built-in
  auto-reconnect (which previously could create duplicate connections); a connect
  lock now serializes connection rebuilds.
- Credential refresh now also runs while temporarily disconnected, so an expiry
  that coincides with a dropped connection can recover (previously it could get
  stuck retrying with expired credentials).
- Removed unreachable authentication-error handling during setup; auth failures
  correctly trigger the re-authentication flow.
- Synced `strings.json` and `translations/en.json` and added the missing
  Country Code field labels to the login step.

#### Changed (Home Assistant standards)
- Removed `aiohttp` from manifest requirements (it is provided by Home Assistant core).
- Added `PARALLEL_UPDATES = 0` to the sensor and binary sensor platforms.
- Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()`.
- Demoted routine operational logs from INFO to DEBUG.
- Diagnostics now use a public coordinator property instead of accessing internals.
- The device model shown in Home Assistant now reflects the actual device model
  instead of a hardcoded value.
- Timestamps are now timezone-aware; modernized `datetime` usage.

#### Removed
- Dead `access_token` plumbing in the MQTT client (Cognito uses an unauthenticated
  identity, so the token was never sent).
- 27 unused constants.

#### Internal / tests
- Migrated the test suite to `MockConfigEntry`, added the required
  `enable_custom_integrations` fixture, and updated mocks/assertions for the
  current Home Assistant version. Full suite passing (77 tests).
- Applied `ruff` autofixes (import sorting, unused-import removal, pyupgrade).

### v1.1.1
- Reduced cloud polling frequency: 10 minutes primary (was 1 minute), 6 hours with MQTT active (was 5 minutes)
- Fixed MQTT callbacks not updating Home Assistant entities (stored event loop reference for thread-safe callbacks from AWS SDK threads)

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
