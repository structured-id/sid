// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{AuditEntry, InviteConfig, MutationContext};

const SERVED: Served = Served {
    password_reset: true,
};

fn policy(mode: EnrollmentMode) -> EnrollmentPolicy {
    EnrollmentPolicy {
        mode,
        invite: InviteConfig {
            default_max_uses: 1,
            default_expiry_hours: 72,
        },
        allowed_domains: if mode == EnrollmentMode::DomainRestricted {
            vec!["acme.example".into()]
        } else {
            vec![]
        },
        track_source: false,
    }
}

async fn store(storage: &dyn StorageBackend, mode: EnrollmentMode) {
    let ctx = MutationContext::from(AuditEntry::admin(
        "test".to_owned(),
        "enrollment_policy.update",
        "installation".to_owned(),
    ));
    storage
        .set_enrollment_policy(&policy(mode), ctx)
        .await
        .unwrap();
}

/// A visitor may start a registration only where the policy admits one who
/// brings nothing: an invitation and an administrator's creation have their
/// own entries and do not open the page.
/// Bug prevented: "Create one" shown on an invite-only installation.
#[test]
fn test_registration_is_open_only_to_modes_a_visitor_can_use() {
    for (mode, open) in [
        (EnrollmentMode::Open, true),
        (EnrollmentMode::DomainRestricted, true),
        (EnrollmentMode::InviteOnly, false),
        (EnrollmentMode::AdminOnly, false),
    ] {
        assert_eq!(
            projection(&policy(mode), 1, SERVED).registration_open,
            open,
            "{mode:?}"
        );
    }
}

/// The projection names the methods the sign-in API offers after an
/// identifier, and the reset only where the composition serves it.
#[test]
fn test_projection_names_what_the_engine_serves() {
    let served = projection(&policy(EnrollmentMode::Open), 7, SERVED);
    assert_eq!(served.revision, 7);
    assert_eq!(served.sign_in_methods, ["opaque", "webauthn"]);
    assert!(served.password_reset_open);
    assert_eq!(served.registration_username_min_length, 3);
    assert_eq!(
        served.registration_principal_types,
        served.sign_in_principal_types
    );

    let without_reset = projection(
        &policy(EnrollmentMode::Open),
        7,
        Served {
            password_reset: false,
        },
    );
    assert!(!without_reset.password_reset_open);
}

/// Before any policy is stored the installation's default is projected at
/// revision 0; a stored change is served after a refresh, and to a reader
/// that subscribed before it.
#[tokio::test]
async fn test_refresh_serves_a_stored_change() {
    let storage = crate::test_support::storage().await;
    let settings = PublicSettings::open(storage.clone(), SERVED).await.unwrap();
    let default_open = open_to_visitors(SecurityPolicy::ce_default().enrollment.mode);
    assert_eq!(settings.current().revision, 0);
    assert_eq!(settings.current().registration_open, default_open);

    let mut reader = settings.subscribe();
    store(storage.as_ref(), EnrollmentMode::InviteOnly).await;
    // Nothing is read for a request: the change is not served until a refresh.
    assert_eq!(settings.current().revision, 0);
    settings.refresh().await.unwrap();
    assert_eq!(settings.current().revision, 1);
    assert!(!settings.current().registration_open);
    reader.changed().await.unwrap();
    assert_eq!(reader.borrow().revision, 1);

    // A refresh with nothing new replaces nothing.
    settings.refresh().await.unwrap();
    assert!(!reader.has_changed().unwrap());
}

/// A second process over the same store serves a change the first committed,
/// from its periodic read, and stops reading when told to.
/// Bug prevented: a replica serving a closed registration as open until restart.
#[tokio::test]
async fn test_follow_serves_a_change_committed_elsewhere() {
    let storage = crate::test_support::storage().await;
    let committer = PublicSettings::open(storage.clone(), SERVED).await.unwrap();
    let other = PublicSettings::open(storage.clone(), SERVED).await.unwrap();
    // Subscribed before the change: a reader sees only what comes after it.
    let mut reader = other.subscribe();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let following = {
        let other = other.clone();
        tokio::spawn(async move {
            other
                // Real time: the store's own timeouts run on the same clock.
                .follow(Duration::from_millis(20), async {
                    let _ = stopped.await;
                })
                .await;
        })
    };

    store(storage.as_ref(), EnrollmentMode::AdminOnly).await;
    committer.refresh().await.unwrap();
    assert_eq!(committer.current().revision, 1);

    tokio::time::timeout(Duration::from_secs(10), reader.changed())
        .await
        .expect("the other process serves the change from its periodic read")
        .unwrap();
    assert_eq!(reader.borrow().revision, 1);
    assert!(!reader.borrow().registration_open);

    stop.send(()).unwrap();
    following.await.unwrap();
}
