# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.14](https://github.com/structured-id/sid/compare/v0.2.13...v0.2.14) - 2026-11-05

### Added

- *(authn)* renewable native sessions bound to the application key ([#397](https://github.com/structured-id/sid/pull/397))

### Fixed

- *(authn)* return a declined sign-in to the application ([#401](https://github.com/structured-id/sid/pull/401))
- *(ui-host)* end application sessions on back-channel logout ([#399](https://github.com/structured-id/sid/pull/399))

## [0.2.13](https://github.com/structured-id/sid/compare/v0.2.12...v0.2.13) - 2026-11-04

### Added

- *(server)* serve the issuer on a listener the caller holds ([#384](https://github.com/structured-id/sid/pull/384))

## [0.2.12](https://github.com/structured-id/sid/compare/v0.2.11...v0.2.12) - 2026-11-04

### Added

- *(operation)* keyed commands from proto retry rules under issued periods ([#380](https://github.com/structured-id/sid/pull/380))

## [0.2.11](https://github.com/structured-id/sid/compare/v0.2.10...v0.2.11) - 2026-11-03

### Other

- *(storage)* restore returns the backed-up state ([#353](https://github.com/structured-id/sid/pull/353))

## [0.2.10](https://github.com/structured-id/sid/compare/v0.2.9...v0.2.10) - 2026-11-03

### Fixed

- *(authn)* mail the password reset link ([#371](https://github.com/structured-id/sid/pull/371))
