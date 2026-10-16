// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's stored enrollment policy.
//!
//! Needs a backend whose policy was never set (an isolated schema or a fresh
//! database): the scenario starts from the unset state.

use super::{create_test_profile, test_audit, test_invite};
use sid_core::enrollment::EnrollmentDenialReason;
use sid_core::models::{
    EnrollmentGate, EnrollmentMode, EnrollmentPolicy, InviteConfig, NewRegistration,
    SignupIdentifier,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

/// A self-registration of a fresh username through `gate`.
fn gated(name: &str, gate: EnrollmentGate) -> NewRegistration {
    NewRegistration::new(
        create_test_profile(name),
        SignupIdentifier::Username(name),
        None,
    )
    .unwrap()
    .admitted_by(gate)
}

fn plain_gate(invite_code: Option<&str>) -> EnrollmentGate {
    EnrollmentGate {
        pinned: None,
        email: None,
        invite_code: invite_code.map(str::to_string),
    }
}

/// The policy decides in the account's own transaction: a registration under
/// a closed policy stores nothing, and the same one is admitted once the
/// policy opens. A pinned mode applies over the stored one.
pub async fn test_registration_admitted_by_the_stored_policy(backend: &dyn StorageBackend) {
    let tag = Uuid::now_v7().simple().to_string();
    backend
        .set_enrollment_policy(&policy(EnrollmentMode::AdminOnly, &[]), test_audit())
        .await
        .unwrap();
    let closed = gated(&format!("closed_{}", &tag[..12]), plain_gate(None));
    let refused = backend.register_profile(&closed, test_audit()).await;
    assert!(
        matches!(
            refused,
            Err(sid_core::Error::RegistrationRestricted(
                EnrollmentDenialReason::AdminOnly
            ))
        ),
        "{refused:?}"
    );
    assert!(
        backend
            .get_profile(closed.profile.id)
            .await
            .unwrap()
            .is_none()
    );

    backend
        .set_enrollment_policy(&policy(EnrollmentMode::Open, &[]), test_audit())
        .await
        .unwrap();
    backend
        .register_profile(&closed, test_audit())
        .await
        .unwrap();

    let pinned = gated(
        &format!("pinned_{}", &tag[..12]),
        EnrollmentGate {
            pinned: Some(EnrollmentMode::AdminOnly),
            ..plain_gate(None)
        },
    );
    assert!(matches!(
        backend.register_profile(&pinned, test_audit()).await,
        Err(sid_core::Error::RegistrationRestricted(
            EnrollmentDenialReason::AdminOnly
        ))
    ));
}

/// Regression: an invited account was recorded as a self-signup, and the
/// tracking decision was read outside the account's transaction. The source
/// is decided by the admitting policy: by invite while tracked, none when
/// the policy does not track.
pub async fn test_admission_records_its_source(backend: &dyn StorageBackend) {
    use sid_core::models::RegistrationSourceType;
    let tag = Uuid::now_v7().simple().to_string();
    let admin = create_test_profile(&format!("srcadm_{}", &tag[..12]));
    backend.create_profile(&admin, test_audit()).await.unwrap();
    let invite = test_invite(admin.id, 5);
    backend.create_invite(&invite, test_audit()).await.unwrap();
    let mut tracked = policy(EnrollmentMode::InviteOnly, &[]);
    tracked.track_source = true;
    backend
        .set_enrollment_policy(&tracked, test_audit())
        .await
        .unwrap();

    let invited = gated(
        &format!("src_inv_{}", &tag[..12]),
        plain_gate(Some(&invite.code)),
    );
    backend
        .register_profile(&invited, test_audit())
        .await
        .unwrap();
    let source = backend
        .get_registration_source(invited.profile.id)
        .await
        .unwrap()
        .expect("a tracked registration records its source");
    assert_eq!(source.source_type, RegistrationSourceType::Invite);
    assert_eq!(
        source.source_id,
        format!("invite:{}", invite.code.to_uppercase())
    );

    let mut untracked = tracked;
    untracked.track_source = false;
    backend
        .set_enrollment_policy(&untracked, test_audit())
        .await
        .unwrap();
    let quiet = gated(
        &format!("src_off_{}", &tag[..12]),
        plain_gate(Some(&invite.code)),
    );
    backend
        .register_profile(&quiet, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .get_registration_source(quiet.profile.id)
            .await
            .unwrap()
            .is_none()
    );
}

/// Under an invite-only policy a single-use invite admits exactly one of two
/// concurrent registrations; the other, and one with an unknown code, store
/// nothing.
pub async fn test_invite_spent_once_by_concurrent_registrations(backend: &dyn StorageBackend) {
    let tag = Uuid::now_v7().simple().to_string();
    let admin = create_test_profile(&format!("inviter_{}", &tag[..12]));
    backend.create_profile(&admin, test_audit()).await.unwrap();
    let invite = test_invite(admin.id, 1);
    backend.create_invite(&invite, test_audit()).await.unwrap();
    backend
        .set_enrollment_policy(&policy(EnrollmentMode::InviteOnly, &[]), test_audit())
        .await
        .unwrap();

    let code = invite.code.to_lowercase();
    let a = gated(&format!("inv_a_{}", &tag[..12]), plain_gate(Some(&code)));
    let b = gated(&format!("inv_b_{}", &tag[..12]), plain_gate(Some(&code)));
    let (ra, rb) = tokio::join!(
        backend.register_profile(&a, test_audit()),
        backend.register_profile(&b, test_audit())
    );
    let invalid = |r: &sid_core::Result<()>| {
        matches!(
            r,
            Err(sid_core::Error::RegistrationRestricted(
                EnrollmentDenialReason::InviteInvalid
            ))
        )
    };
    assert!(
        (ra.is_ok() && invalid(&rb)) || (rb.is_ok() && invalid(&ra)),
        "{ra:?} {rb:?}"
    );
    let stored = |id| async move { backend.get_profile(id).await.unwrap().is_some() };
    assert_ne!(stored(a.profile.id).await, stored(b.profile.id).await);
    assert_eq!(
        backend
            .get_invite(invite.id)
            .await
            .unwrap()
            .unwrap()
            .use_count,
        1
    );

    let unknown = gated(
        &format!("inv_x_{}", &tag[..12]),
        plain_gate(Some("ZZZZ9999")),
    );
    assert!(invalid(
        &backend.register_profile(&unknown, test_audit()).await
    ));
    assert!(!stored(unknown.profile.id).await);
}

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
