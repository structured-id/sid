// SPDX-License-Identifier: AGPL-3.0-only
//! The forward-auth decision and the transports that ask for it.
//!
//! - `decision`: the decision itself, independent of transport
//! - `forward_auth_grpc`: `ForwardAuthService.Verify` (HTTP via the transcoder)
//! - `ext_authz`: Envoy `Authorization.Check`
//! - `jwt`, `sender`, `policy`, `headers`: token verification, sender
//!   constraint, route policy and identity headers

pub mod decision;
pub mod ext_authz;
pub mod forward_auth_grpc;
pub mod headers;
pub mod jwt;
pub mod permission;
pub mod policy;
pub mod sender;
