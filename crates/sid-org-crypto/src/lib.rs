// SPDX-License-Identifier: AGPL-3.0-only
//! Per-org cryptographic state: envelope encryption + pluggable KEK source.
//!
//! ## Layers
//!
//! ```text
//!   Cluster KEK (KekSource — env / mounted file / HSM)
//!       │ wraps
//!       ▼
//!   Org DEK (per-org, random, stored encrypted in DB)
//!       │ wraps
//!       ▼
//!   the org's server-side secrets
//! ```
//!
//! ## Quickstart
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use sid_org_crypto::{envelope, kek_cache::KekCache, kek_source::EnvVarKekSource, KekSource};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let source: Arc<dyn KekSource> = Arc::new(EnvVarKekSource::from_env()?);
//! let cache = KekCache::new(source, Duration::from_secs(15 * 60));
//!
//! // Bootstrap an org's DEK: random + wrap with current KEK.
//! let dek = envelope::random_key();
//! let (kek_version, kek) = cache.current().await?;
//! let dek_wrapped = envelope::wrap_key(secrecy::ExposeSecret::expose_secret(&kek), &dek)?;
//! // Persist `dek_wrapped` and `kek_version` on the org row in DB.
//! # Ok(()) }
//! ```

pub mod envelope;
pub mod error;
pub mod file_kek_source;
pub mod kek_cache;
pub mod kek_source;

pub use error::OrgCryptoError;
pub use kek_source::KekSource;
