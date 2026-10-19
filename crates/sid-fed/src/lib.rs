// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Federation
//!
//! Verification of X.509 certificate chains, trust anchors, and instance
//! discovery. The certificates verified here are issued elsewhere.
//!
//! ## PKI Hierarchy
//!
//! ```text
//! RootCA (self-signed, 5-10y)
//!   └── InstanceCA (per-deployment, 1-3y)
//!         ├── BindingCertificate (per-service user identity, 30d)
//!         ├── ScopedCA (enterprise org, 1-2y)
//!         │     └── BindingCertificate (corporate bindings)
//!         └── SiteCertificate (federation member, 1y)
//! ```

pub mod chain_validator;
pub mod cross_instance_linking;
pub mod dns_verifier;
pub mod error;
pub mod trust_anchor;

#[cfg(test)]
mod test_fixtures;

pub use cross_instance_linking::{
    CrossInstanceLinkRevocation, CrossInstanceLinkingProof, LinkId, LinkStatus,
};
pub use dns_verifier::{DnsVerifyResult, dns_query_name, parse_dns_txt_token, verify_site_dns};
pub use error::PkiError;
pub use trust_anchor::{CrlCache, TrustAnchor};
