// SPDX-License-Identifier: AGPL-3.0-only
//! A session's time-bound step-up and its last authentication survive storage.

use chrono::{Duration, Utc};
use sid_core::models::session::{AuthLevel, Elevation};
use sid_plugin::storage::StorageBackend;

use super::{create_test_profile, create_test_session, test_audit};

/// A step-up is stored with its expiry and the base level beside it, with its
/// new authentication time; a lapsed step-up can be cleared again.
pub async fn test_session_elevation_roundtrip(backend: &dyn StorageBackend) {
    let profile = create_test_profile("elevation");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    let before = backend
        .get_session(session.id)
        .await
        .unwrap()
        .unwrap()
        .authentication();

    let until = Utc::now() + Duration::minutes(15);
    let mut stepped_up = before.clone();
    stepped_up.assurance_level = AuthLevel::Standard;
    stepped_up.elevation = Some(Elevation {
        level: AuthLevel::Critical,
        until,
    });
    stepped_up.authenticated_at = Utc::now() + Duration::seconds(5);
    assert!(
        backend
            .record_session_authentication(session.id, &before, &stepped_up, test_audit())
            .await
            .unwrap()
    );

    let stored = backend
        .get_session(session.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(stored.assurance_level, AuthLevel::Standard);
    let elevation = stored.elevation.expect("elevation kept");
    assert_eq!(elevation.level, AuthLevel::Critical);
    assert_eq!(elevation.until.timestamp_millis(), until.timestamp_millis());
    assert_eq!(
        stored.authenticated_at.timestamp_millis(),
        stepped_up.authenticated_at.timestamp_millis(),
        "a re-authentication was not stored"
    );
    assert_eq!(stored.assurance_at(until), AuthLevel::Standard);

    let mut cleared = stored.authentication();
    cleared.elevation = None;
    assert!(
        backend
            .record_session_authentication(
                session.id,
                &stored.authentication(),
                &cleared,
                test_audit()
            )
            .await
            .unwrap()
    );
    assert!(
        backend
            .get_session(session.id)
            .await
            .unwrap()
            .unwrap()
            .elevation
            .is_none()
    );
}

/// A step-up is never stored as the session's own level.
pub async fn test_session_base_level_refuses_step_up_levels(backend: &dyn StorageBackend) {
    let profile = create_test_profile("elevation_base");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut session = create_test_session(profile.id);
    session.assurance_level = AuthLevel::Elevated;
    assert!(
        backend
            .create_session(&session, test_audit())
            .await
            .is_err()
    );
    assert!(backend.get_session(session.id).await.unwrap().is_none());
}
