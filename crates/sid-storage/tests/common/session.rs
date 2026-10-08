// SPDX-License-Identifier: AGPL-3.0-only
//! Sessions: a create never replaces one, and recording an authentication
//! never brings back an ended session or undoes a concurrent authentication.

use chrono::{Duration, Utc};
use sid_core::Error;
use sid_core::models::Session;
use sid_core::models::session::{AuthLevel, Elevation};
use sid_plugin::storage::StorageBackend;

use super::{create_test_profile, create_test_session, test_audit, test_session_end};

/// A stored session of a new profile, as read back from the store.
async fn stored_session(backend: &dyn StorageBackend) -> Session {
    let profile = create_test_profile("session");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    backend.get_session(session.id).await.unwrap().unwrap()
}

/// Creating a session never replaces one, through either create path.
pub async fn test_create_session_never_replaces(backend: &dyn StorageBackend) {
    let session = stored_session(backend).await;
    let mut again = session.clone();
    again.amr = vec!["pwd".into(), "otp".into()];
    again.assurance_level = AuthLevel::Standard;

    let err = backend
        .create_session(&again, test_audit())
        .await
        .expect_err("a create over an existing session");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    for limit in [0, 5] {
        let err = backend
            .create_session_atomic(&again, limit, test_audit())
            .await
            .expect_err("a limited create over an existing session");
        assert!(matches!(err, Error::Conflict(_)), "limit {limit}: {err:?}");
    }
    let stored = backend.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(stored.authentication(), session.authentication());
}

/// An authentication recorded on a session that was ended meanwhile does not
/// bring it back: an ended session stays ended.
pub async fn test_record_authentication_keeps_ended_session_ended(backend: &dyn StorageBackend) {
    let session = stored_session(backend).await;
    let expected = session.authentication();
    let mut stepped_up = session.clone();
    stepped_up.as_active().unwrap().elevate(AuthLevel::Standard);

    backend
        .delete_session(session.id, &test_session_end(), test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .record_session_authentication(
                session.id,
                &expected,
                &stepped_up.authentication(),
                test_audit(),
            )
            .await
            .unwrap()
    );
    assert!(
        backend.get_session(session.id).await.unwrap().is_none(),
        "an ended session was recreated"
    );
}

/// Recording an authentication applies only over the state it was computed
/// from: of two concurrent step-ups one applies, and a stale one is refused.
pub async fn test_record_authentication_is_compare_and_swap(backend: &dyn StorageBackend) {
    let session = stored_session(backend).await;
    let expected = session.authentication();
    let with = |method: &str| {
        let mut s = session.clone();
        let mut active = s.as_active().unwrap();
        active.elevate(AuthLevel::Standard);
        active.add_amr(method);
        s.authentication()
    };
    let (otp, hwk) = (with("otp"), with("hwk"));

    let (a, b) = tokio::join!(
        backend.record_session_authentication(session.id, &expected, &otp, test_audit()),
        backend.record_session_authentication(session.id, &expected, &hwk, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one authentication must apply: {a} {b}");
    let stored = backend.get_session(session.id).await.unwrap().unwrap();
    let winner = if a { &otp } else { &hwk };
    assert_eq!(stored.amr, winner.amr);
    assert_eq!(stored.assurance_level, AuthLevel::Standard);

    assert!(
        !backend
            .record_session_authentication(session.id, &expected, &otp, test_audit())
            .await
            .unwrap(),
        "a stale authentication applied"
    );
}

/// An expired session records no authentication.
pub async fn test_record_authentication_refuses_expired_session(backend: &dyn StorageBackend) {
    let profile = create_test_profile("session_expired");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut session = create_test_session(profile.id);
    session.expires_at = Utc::now() - Duration::minutes(1);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    let stored = backend.get_session(session.id).await.unwrap().unwrap();

    let mut new = stored.authentication();
    new.elevation = Some(Elevation {
        level: AuthLevel::Critical,
        until: Utc::now() + Duration::minutes(15),
    });
    assert!(
        !backend
            .record_session_authentication(session.id, &stored.authentication(), &new, test_audit())
            .await
            .unwrap()
    );
    let after = backend.get_session(session.id).await.unwrap().unwrap();
    assert!(after.elevation.is_none());
}
