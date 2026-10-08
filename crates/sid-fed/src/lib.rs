// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Federation
//!
//! X.509 certificate chain management, trust anchors, and instance discovery.
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

pub mod cert_builder;
pub mod chain_validator;
pub mod cross_instance_linking;
pub mod dns_verifier;
pub mod enrollment;
pub mod error;
pub(crate) mod oid;
pub mod trust_anchor;

pub use cert_builder::GeneratedCert;
pub use cross_instance_linking::{
    CrossInstanceLinkRevocation, CrossInstanceLinkingProof, LinkId, LinkStatus,
};
pub use dns_verifier::{DnsVerifyResult, dns_query_name, parse_dns_txt_token, verify_site_dns};
pub use enrollment::{
    EnrollmentResult, issue_binding_for_enterprise, issue_scoped_ca_for_enterprise,
    revoke_enterprise,
};
pub use error::PkiError;
pub use trust_anchor::{CrlCache, TrustAnchor};
