// SPDX-License-Identifier: AGPL-3.0-only
//! Outbound HTTP client construction.

/// Failure to construct an outbound client using the host's TLS selection.
#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    /// The host must select its process provider before constructing clients.
    #[error("the host has not selected a TLS crypto provider")]
    ProviderNotSelected,
    /// Client configuration, trust roots or resolver initialization failed.
    #[error("HTTP client configuration: {0}")]
    Configuration(#[from] reqwest::Error),
}

/// Construct a builder using the provider explicitly installed by the host.
/// Refuse an absent selection before reqwest can choose its own backend.
pub fn client_builder() -> Result<reqwest::ClientBuilder, HttpClientError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(HttpClientError::ProviderNotSelected);
    }
    Ok(reqwest::Client::builder())
}

#[cfg(test)]
mod tests;
