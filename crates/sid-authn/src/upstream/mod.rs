// SPDX-License-Identifier: AGPL-3.0-only
//! Upstream Identity Provider implementations.
//!
//! SID acts as a Relying Party to upstream IdPs.
//! This module provides concrete implementations of `UpstreamIdpProvider`.

pub mod oidc;

pub use oidc::OidcProviderClient;
