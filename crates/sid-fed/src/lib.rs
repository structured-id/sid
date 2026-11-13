// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Federation
//!
//! What a recipient needs to verify an identity another SID installation
//! presents, and instance discovery. Everything verified here is issued
//! elsewhere: this crate holds no signing key and no issuance.
//!
//! ## What is verified
//!
//! ```text
//! platform intermediate            (the trust point a recipient admits)
//!   ├── Binding Passport           (a Personal connection to the recipient)
//!   └── organization authority     (scoped to one organization)
//!         └── Binding Passport     (a Corporate connection to the recipient)
//! ```
//!
//! - [`binding_passport`] reads what a passport states;
//! - [`purpose`] and [`organization_scope`] state what each authority may
//!   issue and for whom;
//! - [`passport_path`] verifies the signatures up to the trust point and
//!   applies those rules.

pub mod allocation;
pub mod binding_passport;
pub mod cross_instance_linking;
pub mod dns_verifier;
pub mod organization_scope;
pub mod passport_path;
pub mod purpose;

#[cfg(test)]
mod test_certificates;

pub use cross_instance_linking::{
    CrossInstanceLinkRevocation, CrossInstanceLinkingProof, LinkStatus, LinkingError,
};
pub use dns_verifier::{DnsVerifyResult, dns_query_name, parse_dns_txt_token, verify_site_dns};
