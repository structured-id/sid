// SPDX-License-Identifier: Apache-2.0
//! Independent rustls providers. The host owns trust, identities and installation.
//!
//! Prefer passing a provider directly to rustls configuration builders. When a
//! consumer requires the process default, the application installs its selection
//! explicitly at startup, before constructing that consumer. Handle a conflict
//! instead of replacing another host's selection or choosing another backend:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(all(feature = "std", feature = "tls-rustcrypto"))]
//! # {
//! let selected = sid_crypto::tls::rustcrypto::provider();
//! selected.install_default()
//!     .map_err(|_| "a TLS provider was already selected by this host")?;
//! // Construct clients that consume the process default only after this point.
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! TLS selection does not initialize JWT. A host requiring JWT configures its
//! separate provider before the first JWT operation.

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
