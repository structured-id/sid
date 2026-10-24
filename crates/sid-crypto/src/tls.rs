// SPDX-License-Identifier: Apache-2.0
//! Independent rustls providers. The host owns trust, identities and installation.

#[cfg(feature = "tls-rustcrypto")]
pub mod rustcrypto;

/// Explicit AWS-LC rustls adapter; its build does not establish FIPS compliance.
#[cfg(feature = "tls-aws-lc")]
pub mod aws_lc {
    /// Returns a provider without installing it as the process default.
    pub fn provider() -> rustls::crypto::CryptoProvider {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}
