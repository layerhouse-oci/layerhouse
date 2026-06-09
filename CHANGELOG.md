# Changelog

All notable changes to Layerhouse are documented in this file.

## 0.0.3 - 2026-06-09

### Fixed

- Fixed proxy cache and mirror admin controls being unavailable when authentication is disabled.

## 0.0.2 - 2026-06-09

### Added

- Added provider-agnostic OIDC authentication with OAuth2 error handling.
- Added mirror sync job progress tracking and dashboard inspection.
- Added Docker/GHCR image release pipeline support for versioned and latest images.

### Changed

- Renamed the project to Layerhouse across release and deployment surfaces.
- Updated proxy diagnostics and release artifact job naming.
- Prepared Cargo, Helm, binary packaging, and release test-plan metadata for 0.0.2.

### Fixed

- Fixed mirror and proxy-cache pull-through behavior for Docker multi-arch image flows.
- Fixed mirror rule and proxy-cache stale cache invalidation after admin changes and warm jobs.
- Fixed SOCKS5 outbound proxy DNS handling by using SOCKS5h remote DNS.
- Fixed dashboard access controls for non-admin users and merged ID token groups into session permissions.
- Fixed auth scope challenges, cluster access, PAT revocation behavior, Secure cookies, stale session UX, and session cookie sizing.
- Fixed the personal access token form so repository patterns are explicit instead of defaulting to `qa/*`.
- Fixed dashboard build detection when `LAYERHOUSE_SKIP_DASHBOARD` is set to an empty value.

### Tests

- Added Docker proxy-cache smoke coverage for root and `/library/` prefix normalization.

## 0.0.1 - 2026-06-02

### Added

- Initial public release.
