# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.24](https://github.com/structured-id/sid/compare/v0.2.23...v0.2.24) - 2026-11-08

### Added

- *(authn)* deliver a completed sign-in again after a lost response ([#533](https://github.com/structured-id/sid/pull/533))
- *(sid)* an embedding host runs passwords with proof, projects, machines and devices ([#531](https://github.com/structured-id/sid/pull/531))
- *(storage)* portable snapshot that moves every stored record ([#525](https://github.com/structured-id/sid/pull/525))
- *(sid)* enroll and rotate device keys through their ceremony ([#523](https://github.com/structured-id/sid/pull/523))

### Other

- *(sid)* assemble the CE work an installation owes ([#529](https://github.com/structured-id/sid/pull/529))
- package the engine closure for external hosts ([#527](https://github.com/structured-id/sid/pull/527))
- *(sid)* move sign-in completions into the engine ([#519](https://github.com/structured-id/sid/pull/519))
- *(engine)* issuer discovery, keys and UserInfo in the engine library ([#517](https://github.com/structured-id/sid/pull/517))
- *(engine)* end-session endpoint in the engine library ([#515](https://github.com/structured-id/sid/pull/515))
- *(engine)* authorization endpoint in the engine library ([#513](https://github.com/structured-id/sid/pull/513))
- *(engine)* device approval and session queries in the engine library ([#511](https://github.com/structured-id/sid/pull/511))
- *(engine)* mailbox sign-in in the engine library ([#509](https://github.com/structured-id/sid/pull/509))
- *(engine)* second factors in the engine library ([#507](https://github.com/structured-id/sid/pull/507))
- *(engine)* passkey ceremonies in the engine library ([#505](https://github.com/structured-id/sid/pull/505))
- *(engine)* password replacement in the engine library ([#503](https://github.com/structured-id/sid/pull/503))
- *(engine)* self-registration in the engine library ([#501](https://github.com/structured-id/sid/pull/501))
- *(engine)* password sign-in in the engine library ([#499](https://github.com/structured-id/sid/pull/499))
- *(engine)* sign-in rules and sessions in the engine library ([#497](https://github.com/structured-id/sid/pull/497))
- *(engine)* OAuth endpoints in the engine library ([#495](https://github.com/structured-id/sid/pull/495))
- *(engine)* profile administration in the engine library ([#493](https://github.com/structured-id/sid/pull/493))
- *(engine)* upstream provider administration in the engine library ([#491](https://github.com/structured-id/sid/pull/491))
- *(engine)* personal access tokens in the engine library ([#489](https://github.com/structured-id/sid/pull/489))
- *(engine)* sign-in flow configuration in the engine library ([#487](https://github.com/structured-id/sid/pull/487))
- *(engine)* branding in the engine library ([#485](https://github.com/structured-id/sid/pull/485))
- *(engine)* provisioning connectors in the engine library ([#483](https://github.com/structured-id/sid/pull/483))
- *(engine)* security policy in the engine library ([#481](https://github.com/structured-id/sid/pull/481))
- *(engine)* self-service account in the engine library ([#479](https://github.com/structured-id/sid/pull/479))
- *(engine)* email provider settings in the engine library ([#477](https://github.com/structured-id/sid/pull/477))
- *(engine)* enrollment in the engine library ([#475](https://github.com/structured-id/sid/pull/475))
- *(engine)* profile management and governance in the engine library ([#473](https://github.com/structured-id/sid/pull/473))
- *(engine)* authorization management in the engine library ([#471](https://github.com/structured-id/sid/pull/471))
- *(engine)* an embedded installation decides permissions in process ([#466](https://github.com/structured-id/sid/pull/466))
- *(infra)* shared inbound gRPC adapters, cores without the transport ([#468](https://github.com/structured-id/sid/pull/468))
- *(engine)* project management in the engine library ([#469](https://github.com/structured-id/sid/pull/469))
- *(engine)* machine identity operations in the engine library ([#460](https://github.com/structured-id/sid/pull/460))
- *(engine)* engine library without the gRPC transport ([#462](https://github.com/structured-id/sid/pull/462))
- *(authn)* authenticate a caller without the gRPC transport ([#457](https://github.com/structured-id/sid/pull/457))
- *(engine)* the engine library is the sid package ([#449](https://github.com/structured-id/sid/pull/449))

## [0.2.23](https://github.com/structured-id/sid/compare/v0.2.22...v0.2.23) - 2026-11-06

### Added

- *(admin)* typed ids in admin, federation and session validation ([#452](https://github.com/structured-id/sid/pull/452))
- *(storage)* store sqlite ids as 16-byte blobs ([#447](https://github.com/structured-id/sid/pull/447))

## [0.2.22](https://github.com/structured-id/sid/compare/v0.2.21...v0.2.22) - 2026-11-06

### Added

- *(storage)* CoordiNode backend for embedding server hosts ([#436](https://github.com/structured-id/sid/pull/436))

## [0.2.21](https://github.com/structured-id/sid/compare/v0.2.20...v0.2.21) - 2026-11-06

### Added

- *(engine)* open an installation from typed settings ([#446](https://github.com/structured-id/sid/pull/446))
- *(engine)* consumable lifecycle for work and maintenance ([#443](https://github.com/structured-id/sid/pull/443))

## [0.2.20](https://github.com/structured-id/sid/compare/v0.2.19...v0.2.20) - 2026-11-06

### Added

- *(authz)* typed identifiers in authorization ([#429](https://github.com/structured-id/sid/pull/429))

## [0.2.19](https://github.com/structured-id/sid/compare/v0.2.18...v0.2.19) - 2026-11-05

### Other

- *(proto)* build on fields numbered in place ([#422](https://github.com/structured-id/sid/pull/422))
- *(authz)* resolve roles in a fixed number of reads ([#424](https://github.com/structured-id/sid/pull/424))

## [0.2.18](https://github.com/structured-id/sid/compare/v0.2.17...v0.2.18) - 2026-11-05

### Added

- *(operation)* bind keyed-creation identifiers in the operation store ([#416](https://github.com/structured-id/sid/pull/416))

## [0.2.17](https://github.com/structured-id/sid/compare/v0.2.16...v0.2.17) - 2026-11-05

### Other

- update Cargo.toml dependencies

## [0.2.16](https://github.com/structured-id/sid/compare/v0.2.15...v0.2.16) - 2026-11-05

### Added

- *(identity)* typed identity and account references ([#411](https://github.com/structured-id/sid/pull/411))

## [0.2.15](https://github.com/structured-id/sid/compare/v0.2.14...v0.2.15) - 2026-11-05

### Added

- *(authn)* binary references on the sign-in path ([#409](https://github.com/structured-id/sid/pull/409))
- *(authn)* binary OPAQUE login id and raw TOTP secret ([#406](https://github.com/structured-id/sid/pull/406))

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
