// SPDX-License-Identifier: AGPL-3.0-only
//! The scope of an organization's authority: what a verifier requires of its
//! certificate before anything it issued is taken as that organization's.
//!
//! In plain words: an organization's certificate authority may speak only
//! for that one organization. Its certificate must say so in a way software
//! is obliged to enforce, and this check refuses one that says nothing, says
//! it only as a hint, or names more than the organization.
//!
//! This is a check of the certificate's content. It verifies no signature:
//! it is applied to an authority found on a path that was verified.

use std::str::FromStr;

use x509_cert::Certificate;
use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;

/// Why a certificate is not an authority scoped to the organization.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    /// The subject is not exactly `O=<OrgId>`.
    #[error("the subject is not the organization's")]
    Subject,
    /// The name constraints are absent, not critical, or do not permit
    /// exactly the organization's subtree with nothing excluded.
    #[error("the name constraints do not scope the authority to its organization")]
    Constraints,
    /// The expected name could not be encoded.
    #[error("organization name encoding: {0}")]
    Encoding(String),
}

/// `certificate` is an authority scoped exactly to `organization`: its
/// subject is `O=<OrgId>` and a critical name constraint permits exactly that
/// `directoryName` subtree and excludes nothing (RFC 5280 §4.2.1.10). A
/// missing or broadened constraint is refused: path processing applies a
/// constraint it finds, and does not require one.
pub fn check_organization_scope(
    certificate: &Certificate,
    organization: uuid::Uuid,
) -> Result<(), ScopeError> {
    let expected = Name::from_str(&format!("O={organization}"))
        .map_err(|e| ScopeError::Encoding(e.to_string()))?;
    let tbs = certificate.tbs_certificate();
    if tbs.subject() != &expected {
        return Err(ScopeError::Subject);
    }
    let (critical, constraints) = tbs
        .get_extension::<NameConstraints>()
        .map_err(|_| ScopeError::Constraints)?
        .ok_or(ScopeError::Constraints)?;
    let permitted = [GeneralSubtree {
        base: GeneralName::DirectoryName(expected),
        minimum: 0,
        maximum: None,
    }];
    if !critical
        || constraints.permitted_subtrees.as_deref() != Some(&permitted[..])
        || constraints.excluded_subtrees.is_some()
    {
        return Err(ScopeError::Constraints);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
