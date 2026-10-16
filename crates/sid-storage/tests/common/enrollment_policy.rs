// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's stored enrollment policy.
//!
//! Needs a backend whose policy was never set (an isolated schema or a fresh
//! database): the scenario starts from the unset state.

use super::test_audit;
use sid_core::models::{EnrollmentMode, EnrollmentPolicy, InviteConfig};
use sid_plugin::storage::StorageBackend;

fn policy(mode: EnrollmentMode, allowed_domains: &[&str]) -> EnrollmentPolicy {
    EnrollmentPolicy {
        mode,
        invite: InviteConfig {
            default_max_uses: 3,
            default_expiry_hours: 48,
        },
        allowed_domains: allowed_domains.iter().map(|d| (*d).to_string()).collect(),
        track_source: false,
    }
}

/// Unset reads as none (the defaults then apply, decided by the caller); a
/// stored policy reads back whole; a second write replaces it, domains
/// included, rather than adding a row or merging fields.
pub async fn test_enrollment_policy_stored_and_replaced(backend: &dyn StorageBackend) {
    assert_eq!(backend.enrollment_policy().await.unwrap(), None);

    let restricted = policy(
        EnrollmentMode::DomainRestricted,
        &["acme.example", "partner.example"],
    );
    backend
        .set_enrollment_policy(&restricted, test_audit())
        .await
        .unwrap();
    assert_eq!(backend.enrollment_policy().await.unwrap(), Some(restricted));

    let admin_only = policy(EnrollmentMode::AdminOnly, &[]);
    backend
        .set_enrollment_policy(&admin_only, test_audit())
        .await
        .unwrap();
    assert_eq!(backend.enrollment_policy().await.unwrap(), Some(admin_only));
}

/// The invite defaults keep their full unsigned range: the largest value a
/// field can hold is stored and read back unchanged.
pub async fn test_enrollment_policy_keeps_invite_range(backend: &dyn StorageBackend) {
    let mut wide = policy(EnrollmentMode::InviteOnly, &[]);
    wide.invite = InviteConfig {
        default_max_uses: u32::MAX,
        default_expiry_hours: 0,
    };
    backend
        .set_enrollment_policy(&wide, test_audit())
        .await
        .unwrap();
    assert_eq!(backend.enrollment_policy().await.unwrap(), Some(wide));
}
