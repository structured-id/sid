// SPDX-License-Identifier: AGPL-3.0-only
//! Device authorization requests (RFC 8628): stored whole and never
//! replaced, decided once, polled no faster than their interval, and
//! redeemed for tokens exactly once.

use chrono::{Duration, Utc};
use sid_core::Error;
use sid_core::models::{
    DeviceAuthDecision, DeviceAuthStatus, DeviceAuthorizationCode, DeviceCodeRedemption,
    DevicePoll, Profile, ProjectId,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, exchange_records, test_audit};

/// A stored pending request and the profile that will decide it.
async fn stored_request(backend: &dyn StorageBackend) -> (DeviceAuthorizationCode, Profile) {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let profile = create_test_profile("device");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let tag = Uuid::now_v7().simple().to_string();
    let code = DeviceAuthorizationCode::new(
        "test-client".to_string(),
        Uuid::now_v7().as_bytes().to_vec(),
        tag[tag.len() - 8..].to_uppercase(),
        Some("openid".to_string()),
        super::application::grant_resource(backend).await,
        ProjectId::system(),
    );
    backend
        .create_device_auth_code(&code, test_audit())
        .await
        .unwrap();
    (code, profile)
}

/// A request reads back whole by device code and by user code, and a create
/// over an existing request is refused.
pub async fn test_device_auth_create_and_get(backend: &dyn StorageBackend) {
    let (code, _) = stored_request(backend).await;

    let by_device = backend
        .get_device_auth_by_device_code_hash(&code.device_code_hash)
        .await
        .unwrap()
        .expect("found by device code");
    assert_eq!(by_device.id, code.id);
    assert_eq!(by_device.user_code, code.user_code);
    assert_eq!(by_device.status, DeviceAuthStatus::Pending);
    assert_eq!(by_device.interval, code.interval);
    assert_eq!(by_device.resource, code.resource);
    assert!(by_device.last_polled_at.is_none());
    let by_user = backend
        .get_device_auth_by_user_code(&code.user_code)
        .await
        .unwrap()
        .expect("found by user code");
    assert_eq!(by_user.id, code.id);

    let err = backend
        .create_device_auth_code(&code, test_audit())
        .await
        .expect_err("a create over an existing request");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
}

/// A request is decided once: of a concurrent approval and denial one
/// applies, and an expired request takes no decision.
pub async fn test_device_auth_decided_once(backend: &dyn StorageBackend) {
    let (code, profile) = stored_request(backend).await;
    let (a, b) = tokio::join!(
        backend.decide_device_auth(
            code.id,
            DeviceAuthDecision::Authorize(profile.id),
            test_audit()
        ),
        backend.decide_device_auth(code.id, DeviceAuthDecision::Deny, test_audit()),
    );
    let (authorized, denied) = (a.unwrap(), b.unwrap());
    assert!(
        authorized ^ denied,
        "exactly one decision: {authorized} {denied}"
    );
    let stored = backend
        .get_device_auth_by_device_code_hash(&code.device_code_hash)
        .await
        .unwrap()
        .unwrap();
    if authorized {
        assert_eq!(stored.status, DeviceAuthStatus::Authorized);
        assert_eq!(stored.authorized_by, Some(profile.id));
        assert!(stored.authorized_at.is_some());
    } else {
        assert_eq!(stored.status, DeviceAuthStatus::Denied);
        assert!(stored.authorized_by.is_none());
    }

    let (mut expired, profile) = stored_request(backend).await;
    expired.id = sid_core::models::DeviceAuthCodeId::new();
    expired.device_code_hash = Uuid::now_v7().as_bytes().to_vec();
    expired.user_code = format!("X{}", &expired.user_code[1..]);
    expired.expires_at = Utc::now() - Duration::seconds(1);
    backend
        .create_device_auth_code(&expired, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .decide_device_auth(
                expired.id,
                DeviceAuthDecision::Authorize(profile.id),
                test_audit()
            )
            .await
            .unwrap(),
        "an expired request was authorized"
    );
}

/// A poll sooner than the interval is a slow-down and grows the interval by
/// five seconds; of two concurrent first polls one is allowed.
pub async fn test_device_poll_interval(backend: &dyn StorageBackend) {
    let (code, _) = stored_request(backend).await;
    let (a, b) = tokio::join!(
        backend.record_device_poll(code.id, test_audit()),
        backend.record_device_poll(code.id, test_audit()),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()];
    outcomes.sort_by_key(|o| *o == DevicePoll::SlowDown);
    assert_eq!(outcomes, [DevicePoll::Allowed, DevicePoll::SlowDown]);

    let stored = backend
        .get_device_auth_by_device_code_hash(&code.device_code_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.interval, code.interval + 5);
    assert!(stored.last_polled_at.is_some());
}

/// An authorized code is redeemed once: the winner's session and refresh
/// token are stored, a repeated or concurrent redemption stores nothing and
/// names the first session; a pending code redeems nothing.
pub async fn test_device_code_redeemed_once(backend: &dyn StorageBackend) {
    let (code, profile) = stored_request(backend).await;
    let (session, token) = exchange_records(backend, &profile).await;
    assert_eq!(
        backend
            .redeem_device_code(&code.device_code_hash, &session, &token, test_audit())
            .await
            .unwrap(),
        DeviceCodeRedemption::NotAuthorized,
        "a pending code was redeemed"
    );
    assert!(backend.get_session(session.id).await.unwrap().is_none());

    assert!(
        backend
            .decide_device_auth(
                code.id,
                DeviceAuthDecision::Authorize(profile.id),
                test_audit()
            )
            .await
            .unwrap()
    );
    let (a_session, a_token) = exchange_records(backend, &profile).await;
    let (b_session, b_token) = exchange_records(backend, &profile).await;
    let (a, b) = tokio::join!(
        backend.redeem_device_code(&code.device_code_hash, &a_session, &a_token, test_audit()),
        backend.redeem_device_code(&code.device_code_hash, &b_session, &b_token, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    let (winner, loser, other) = if a == DeviceCodeRedemption::Redeemed {
        (&a_session, &b_session, b)
    } else {
        (&b_session, &a_session, a)
    };
    assert_eq!(
        other,
        DeviceCodeRedemption::AlreadyRedeemed {
            session_id: Some(winner.id)
        },
        "{a:?} {b:?}"
    );
    assert!(backend.get_session(winner.id).await.unwrap().is_some());
    assert!(backend.get_session(loser.id).await.unwrap().is_none());

    let stored = backend
        .get_device_auth_by_device_code_hash(&code.device_code_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, DeviceAuthStatus::Redeemed);
    assert_eq!(stored.redeemed_session_id, Some(winner.id));
}
