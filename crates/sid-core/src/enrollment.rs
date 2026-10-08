// SPDX-License-Identifier: AGPL-3.0-only
//! Enrollment mode enforcement.
//!
//! Pure evaluation functions for enrollment policy — determines whether
//! a self-registration attempt should proceed based on the configured mode.

use crate::models::security_policy::{EnrollmentMode, EnrollmentPolicy};

/// Result of enrollment evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum EnrollmentDecision {
    /// Registration allowed to proceed.
    Allow,
    /// Registration denied.
    Deny(EnrollmentDenialReason),
}

/// Why enrollment was denied.
#[derive(Debug, Clone, PartialEq)]
pub enum EnrollmentDenialReason {
    /// Mode is AdminOnly — self-registration disabled.
    AdminOnly,
    /// Mode is InviteOnly but no invite code provided.
    InviteRequired,
    /// Mode is DomainRestricted and email domain not in allowed list.
    DomainNotAllowed {
        domain: String,
        allowed: Vec<String>,
    },
    /// Mode is DomainRestricted but no email provided.
    EmailRequired,
}

impl std::fmt::Display for EnrollmentDenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdminOnly => write!(f, "self-registration is disabled (admin-only mode)"),
            Self::InviteRequired => write!(f, "registration requires a valid invite code"),
            Self::DomainNotAllowed { domain, .. } => {
                write!(f, "email domain '{}' is not in the allowed list", domain)
            }
            Self::EmailRequired => {
                write!(f, "email is required for domain-restricted registration")
            }
        }
    }
}

/// Evaluate whether a self-registration should proceed.
///
/// This runs BEFORE credential creation (OPAQUE/WebAuthn).
/// Admin/SCIM provisioning bypasses this — modes control self-registration only.
///
/// # Arguments
/// * `policy` — current enrollment policy
/// * `email` — registrant's email (required for DomainRestricted mode)
/// * `invite_code` — invite code (required for InviteOnly mode)
///
/// Note: This does NOT validate the invite code itself (exists, active, not expired).
/// That's done separately via `StorageBackend::try_use_invite` after this check passes.
pub fn evaluate_enrollment(
    policy: &EnrollmentPolicy,
    email: Option<&str>,
    invite_code: Option<&str>,
) -> EnrollmentDecision {
    match policy.mode {
        EnrollmentMode::Open => EnrollmentDecision::Allow,

        EnrollmentMode::AdminOnly => EnrollmentDecision::Deny(EnrollmentDenialReason::AdminOnly),

        EnrollmentMode::InviteOnly => {
            if invite_code.is_some() {
                // Invite code presence check passes — actual validation
                // (exists, active, uses, expiry) happens in storage layer.
                EnrollmentDecision::Allow
            } else {
                EnrollmentDecision::Deny(EnrollmentDenialReason::InviteRequired)
            }
        }

        EnrollmentMode::DomainRestricted => {
            let Some(email) = email else {
                return EnrollmentDecision::Deny(EnrollmentDenialReason::EmailRequired);
            };
            let domain = extract_email_domain(email);
            if policy
                .allowed_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(domain))
            {
                EnrollmentDecision::Allow
            } else {
                EnrollmentDecision::Deny(EnrollmentDenialReason::DomainNotAllowed {
                    domain: domain.to_string(),
                    allowed: policy.allowed_domains.clone(),
                })
            }
        }
    }
}

/// Extract domain from email address.
/// Returns empty string if no @ found.
fn extract_email_domain(email: &str) -> &str {
    email.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

#[cfg(test)]
mod tests;
