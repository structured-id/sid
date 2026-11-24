# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.41](https://github.com/structured-id/sid/compare/v0.2.40...v0.2.41) - 2026-11-24

### Other

- *(ui)* the account adapter calls its installation in process ([#775](https://github.com/structured-id/sid/pull/775))

## [0.2.40](https://github.com/structured-id/sid/compare/v0.2.39...v0.2.40) - 2026-11-24

### Fixed

- *(oidc)* confirm the consent page's context by its operation ([#768](https://github.com/structured-id/sid/pull/768))

## [0.2.39](https://github.com/structured-id/sid/compare/v0.2.38...v0.2.39) - 2026-11-24

### Added

- *(infra)* one flag selects a local publication's platform ([#765](https://github.com/structured-id/sid/pull/765))

## [0.2.38](https://github.com/structured-id/sid/compare/v0.2.37...v0.2.38) - 2026-11-24

### Added

- *(engine)* ce work without required mail or site ([#763](https://github.com/structured-id/sid/pull/763))

### Fixed

- *(oidc)* keep the sign-in page's hints on the consent page ([#758](https://github.com/structured-id/sid/pull/758))

### Other

- run tests and isolation checks in parallel groups ([#762](https://github.com/structured-id/sid/pull/762))

## [0.2.37](https://github.com/structured-id/sid/compare/v0.2.36...v0.2.37) - 2026-11-23

### Fixed

- *(embedded)* keep a lost master and serve browsers without a token signer ([#756](https://github.com/structured-id/sid/pull/756))

## [0.2.36](https://github.com/structured-id/sid/compare/v0.2.35...v0.2.36) - 2026-11-23

### Added

- *(authz)* withhold a group grant from its grantor ([#747](https://github.com/structured-id/sid/pull/747))

### Fixed

- *(identity)* carry primary contacts in ListProfiles ([#740](https://github.com/structured-id/sid/pull/740))

### Other

- *(storage)* serialize keyed commands only on their key ([#750](https://github.com/structured-id/sid/pull/750))
- migrate the shared test databases once per run ([#743](https://github.com/structured-id/sid/pull/743))

## [0.2.35](https://github.com/structured-id/sid/compare/v0.2.34...v0.2.35) - 2026-11-22

### Added

- *(server)* serve the account pages and console ([#735](https://github.com/structured-id/sid/pull/735))

## [0.2.34](https://github.com/structured-id/sid/compare/v0.2.33...v0.2.34) - 2026-11-21

### Other

- *(server)* drop settings a standalone installation derives or stores ([#730](https://github.com/structured-id/sid/pull/730))

## [0.2.33](https://github.com/structured-id/sid/compare/v0.2.32...v0.2.33) - 2026-11-21

### Added

- *(authn)* gate every authorization on recorded consent ([#726](https://github.com/structured-id/sid/pull/726))
- *(server)* serve the account client apart from the pages ([#717](https://github.com/structured-id/sid/pull/717))
- *(server)* account pages mount without a cabinet client ([#714](https://github.com/structured-id/sid/pull/714))

### Fixed

- *(authn)* select a receiver's issuer by its segment ([#722](https://github.com/structured-id/sid/pull/722))

## [0.2.32](https://github.com/structured-id/sid/compare/v0.2.31...v0.2.32) - 2026-11-19

### Added

- *(authn)* passwordless registration with a first passkey ([#706](https://github.com/structured-id/sid/pull/706))

### Fixed

- *(authn)* refuse the sign-in page's enrollment by its own reason ([#704](https://github.com/structured-id/sid/pull/704))
- *(oauth)* ask for the sign-in page at each request ([#702](https://github.com/structured-id/sid/pull/702))
- *(second-factor)* a refused TOTP finish keeps the enrollment ([#695](https://github.com/structured-id/sid/pull/695))

### Other

- *(transcoder)* a sign-in over annotated HTTP delivers its session cookie ([#698](https://github.com/structured-id/sid/pull/698))
- *(authn)* one browser session core, proxy off the decision service ([#697](https://github.com/structured-id/sid/pull/697))

## [0.2.31](https://github.com/structured-id/sid/compare/v0.2.30...v0.2.31) - 2026-11-18

### Added

- *(issuer)* root-address the installation base issuer ([#694](https://github.com/structured-id/sid/pull/694))

### Other

- *(deps)* replace chrono with jiff ([#687](https://github.com/structured-id/sid/pull/687))

## [0.2.30](https://github.com/structured-id/sid/compare/v0.2.29...v0.2.30) - 2026-11-17

### Added

- enforce each method's declared access rule ([#670](https://github.com/structured-id/sid/pull/670))
- *(fed)* carry the coordinating route's return address on its entry connection ([#662](https://github.com/structured-id/sid/pull/662))
- *(federation)* return an entry to a host page ([#654](https://github.com/structured-id/sid/pull/654))
- *(federation)* deliver the site's admission to the platform ([#650](https://github.com/structured-id/sid/pull/650))
- *(fed)* register another organization's site and read CA status apart ([#645](https://github.com/structured-id/sid/pull/645))
- *(federation)* receiving side of federated sign-in ([#643](https://github.com/structured-id/sid/pull/643))
- *(oauth)* keep a kept request's origin through redemption ([#641](https://github.com/structured-id/sid/pull/641))
- *(authn)* carry the Binding presentation in the ID token ([#639](https://github.com/structured-id/sid/pull/639))
- *(admin)* store and serve incoming Profile admission ([#629](https://github.com/structured-id/sid/pull/629))

### Fixed

- *(work)* end an abandoned last attempt with its alert ([#664](https://github.com/structured-id/sid/pull/664))

### Other

- *(audit)* keep audit chain digests as binary end to end ([#681](https://github.com/structured-id/sid/pull/681))
- *(ui-host)* qualify the browser adapter against a real issuer ([#679](https://github.com/structured-id/sid/pull/679))
- *(machine)* a lost rotation is replaced only by a new command ([#668](https://github.com/structured-id/sid/pull/668))
- *(oauth)* check a Profile's standing session; drop code redemption tracking ([#652](https://github.com/structured-id/sid/pull/652))
- durable delivery tails and sign-in codes through the server's work ([#647](https://github.com/structured-id/sid/pull/647))

## [0.2.29](https://github.com/structured-id/sid/compare/v0.2.28...v0.2.29) - 2026-11-13

### Fixed

- *(server)* mount no route for the platform CA publication ([#627](https://github.com/structured-id/sid/pull/627))
- *(ui-host)* end a session the API refused before its logout arrives ([#614](https://github.com/structured-id/sid/pull/614))

## [0.2.28](https://github.com/structured-id/sid/compare/v0.2.27...v0.2.28) - 2026-11-12

### Added

- *(authz)* replace a role assignment set at its revision ([#606](https://github.com/structured-id/sid/pull/606))
- *(authz)* make an envelope's maximum validity optional ([#604](https://github.com/structured-id/sid/pull/604))

### Other

- *(notify)* drop the trial onboarding mail from the defaults ([#579](https://github.com/structured-id/sid/pull/579))

## [0.2.27](https://github.com/structured-id/sid/compare/v0.2.26...v0.2.27) - 2026-11-10

### Added

- *(authn)* observe durable work in the runner ([#571](https://github.com/structured-id/sid/pull/571))

### Other

- *(storage)* keyed commits under one period no longer serialize ([#573](https://github.com/structured-id/sid/pull/573))
- *(work)* drop the backlog capacity from the work store ([#568](https://github.com/structured-id/sid/pull/568))

## [0.2.26](https://github.com/structured-id/sid/compare/v0.2.25...v0.2.26) - 2026-11-09

### Fixed

- *(authn)* compare only the newest depth passwords ([#564](https://github.com/structured-id/sid/pull/564))
- *(notify)* keyed template commands and bounded keyed results ([#558](https://github.com/structured-id/sid/pull/558))
- *(operation)* answer a retry of seven keyed methods ([#555](https://github.com/structured-id/sid/pull/555))
- *(authn)* store a sign-in code with the work mailing it ([#547](https://github.com/structured-id/sid/pull/547))
- *(serve)* password operations ready only with the ZKPP keys ([#543](https://github.com/structured-id/sid/pull/543))

### Other

- *(server)* keyed command retries across replicas and transports ([#562](https://github.com/structured-id/sid/pull/562))
- *(work)* commit a handler's next stage with its completion ([#551](https://github.com/structured-id/sid/pull/551))
- *(authn)* shared second-factor removal ([#540](https://github.com/structured-id/sid/pull/540))

## [0.2.25](https://github.com/structured-id/sid/compare/v0.2.24...v0.2.25) - 2026-11-08

### Other

- *(authn)* shared second-factor mechanism ([#537](https://github.com/structured-id/sid/pull/537))

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
