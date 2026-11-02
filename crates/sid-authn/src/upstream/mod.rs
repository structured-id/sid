// SPDX-License-Identifier: Apache-2.0
//! Upstream Identity Provider implementations.
//!
//! SID acts as a Relying Party to upstream IdPs.
//! This module provides concrete implementations of `UpstreamIdpProvider`.

pub mod oidc;

pub use oidc::OidcProviderClient;
