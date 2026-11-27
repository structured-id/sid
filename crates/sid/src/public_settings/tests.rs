// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{AuditEntry, InviteConfig, MutationContext};

const SERVED: Served = Served {
    registration: true,
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

/// The registration types named are the ones the mode admits: every type
/// where a visitor or an invited registrant may use any, the email alone
/// where the mode decides by the email's domain, none where only an
/// administrator creates accounts. Sign-in keeps every type under each mode.
/// Bug prevented: a page offering a phone or username registration that a
/// domain-restricted installation always refuses.
#[test]
fn test_registration_types_follow_the_mode() {
    let email = PrincipalType::Email as i32;
    let all = principal_types();
    for (mode, registration, minimum) in [
        (EnrollmentMode::Open, all.clone(), 3),
        (EnrollmentMode::InviteOnly, all.clone(), 3),
        (EnrollmentMode::DomainRestricted, vec![email], 0),
        (EnrollmentMode::AdminOnly, vec![], 0),
    ] {
        let served = projection(&policy(mode), 1, SERVED);
        assert_eq!(
            served.registration_principal_types, registration,
            "{mode:?}"
        );
        assert_eq!(served.registration_username_min_length, minimum, "{mode:?}");
        assert_eq!(served.sign_in_principal_types, all, "{mode:?}");
    }
}

/// A host that takes no self-registration publishes none: no type and no
/// username minimum, under whatever mode, an invitation included (a new
/// account registering with a code is a self-registration, which the
/// registration API refuses at its start and at its commit while the switch
/// is off). With the switch on, an invite-only mode keeps its types and
/// stays closed to a visitor. Sign-in is the holders' and does not follow it.
/// Bug prevented: an invite form shown where the first request is refused.
#[test]
fn test_a_host_without_self_registration_publishes_no_types() {
    let off = Served {
        registration: false,
        ..SERVED
    };
    let all = principal_types();
    for mode in [
        EnrollmentMode::Open,
        EnrollmentMode::InviteOnly,
        EnrollmentMode::DomainRestricted,
        EnrollmentMode::AdminOnly,
    ] {
        let served = projection(&policy(mode), 1, off);
        assert!(!served.registration_open, "{mode:?}");
        assert!(served.registration_principal_types.is_empty(), "{mode:?}");
        assert_eq!(served.registration_username_min_length, 0, "{mode:?}");
        assert_eq!(served.sign_in_principal_types, all, "{mode:?}");
    }

    let invite_only = projection(&policy(EnrollmentMode::InviteOnly), 1, SERVED);
    assert!(!invite_only.registration_open);
    assert_eq!(invite_only.registration_principal_types, all);
    assert_eq!(invite_only.registration_username_min_length, 3);
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

    let without_reset = projection(
        &policy(EnrollmentMode::Open),
        7,
        Served {
            registration: true,
            password_reset: false,
        },
    );
    assert!(!without_reset.password_reset_open);
}

/// The host's own registration switch closes the page under a mode that is
/// open, at once and at a newer revision; turned on again it opens it. The
/// same statement twice changes nothing.
/// Bug prevented: a registration the API refuses still advertised as open.
#[tokio::test]
async fn test_the_hosts_registration_switch_is_projected() {
    let storage = crate::test_support::storage().await;
    store(storage.as_ref(), EnrollmentMode::Open).await;
    let settings = PublicSettings::open(storage, SERVED).await.unwrap();
    let mut reader = settings.subscribe();
    let open = settings.current();
    assert!(open.registration_open);

    let off = Served {
        registration: false,
        ..SERVED
    };
    settings.serve(off);
    let closed = settings.current();
    assert!(!closed.registration_open);
    assert!(closed.revision > open.revision);
    reader.changed().await.unwrap();
    assert_eq!(*reader.borrow_and_update(), closed);

    settings.serve(off);
    assert!(!reader.has_changed().unwrap());

    settings.serve(SERVED);
    let reopened = settings.current();
    assert!(reopened.registration_open);
    assert!(reopened.revision > closed.revision);
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
