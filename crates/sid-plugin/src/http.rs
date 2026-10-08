// SPDX-License-Identifier: AGPL-3.0-only
//! Outbound HTTP client construction.

/// A `reqwest` builder with this build's TLS provider already in place.
///
/// reqwest carries no pure-Rust provider of its own: it reads the process
/// default and panics when none is set, and its built-in choice is aws-lc-rs,
/// which a CE build does not link. The provider is therefore installed here,
/// before any client can exist. The engine is embedded by hosts that never
/// call our startup code, so a library that dials out installs it itself
/// rather than trusting a binary to have done it.
///
/// Installing twice is not a failure: the first call wins and every caller
/// here asks for the same provider.
pub fn client_builder() -> reqwest::ClientBuilder {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
}

#[cfg(test)]
mod tests;
