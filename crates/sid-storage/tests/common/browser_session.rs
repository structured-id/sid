// SPDX-License-Identifier: AGPL-3.0-only
//! The IdP browser session: a session found by the hash of its cookie's
//! secret, and its last activity.

use std::sync::Arc;

use chrono::{Duration, DurationRound, Utc};
use sid_core::models::{
    BrowserSecretHash, LogoutDelivery, RevocationReason, Session, SessionEnd, SessionId, WorkState,
};
use sid_plugin::StorageBackend;

use super::{create_test_profile, create_test_session, test_audit};

/// A hash no other run of the suite on the same database uses.
fn hash() -> BrowserSecretHash {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    BrowserSecretHash::from_bytes(bytes)
}

/// A session a browser signed in with is found by its secret's hash, and
/// only by it: another hash or a session without one finds nothing.
pub async fn test_session_found_by_browser_secret(backend: &dyn StorageBackend) {
    let profile = create_test_profile("browser");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut signed_in = create_test_session(profile.id);
    let secret = hash();
    signed_in.browser_secret_hash = Some(secret);
    backend
        .create_session(&signed_in, test_audit())
        .await
        .unwrap();
    let native = create_test_session(profile.id);
    backend.create_session(&native, test_audit()).await.unwrap();

    let found = backend
        .get_session_by_browser_secret(&secret)
        .await
        .unwrap()
        .expect("the signed-in session");
    assert_eq!(found.id, signed_in.id);
    assert_eq!(found.browser_secret_hash, Some(secret));
    assert_eq!(
        backend
            .get_session(signed_in.id)
            .await
            .unwrap()
            .unwrap()
            .browser_secret_hash,
        Some(secret)
    );
    assert!(
        backend
            .get_session_by_browser_secret(&hash())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        backend
            .get_session(native.id)
            .await
            .unwrap()
            .unwrap()
            .browser_secret_hash,
        None
    );
}

/// One hash belongs to one session: a second session with it is refused,
/// so a cookie can never resolve to two.
pub async fn test_browser_secret_is_unique(backend: &dyn StorageBackend) {
    let profile = create_test_profile("browseruniq");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let secret = hash();
    let mut first = create_test_session(profile.id);
    first.browser_secret_hash = Some(secret);
    backend.create_session(&first, test_audit()).await.unwrap();
    let mut second = create_test_session(profile.id);
    second.browser_secret_hash = Some(secret);
    assert!(backend.create_session(&second, test_audit()).await.is_err());
    assert!(backend.get_session(second.id).await.unwrap().is_none());
}

/// A session redeemed from a grant ends with the IdP session it reuses:
/// ending an application's session leaves the IdP session, ending the IdP
/// session (directly or by the session limit) ends the sessions it
/// authenticated, each owing its own client's logout, and nothing else.
pub async fn test_ending_a_session_ends_what_it_authenticated(backend: &dyn StorageBackend) {
    let client =
        super::create_test_oauth2_client(&format!("sso_{}", uuid::Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, test_audit())
        .await
        .unwrap();
    let profile = create_test_profile("ssoend");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let end = SessionEnd::new(RevocationReason::UserRequested, "user");
    let redeemed = |sso: &Session| {
        let mut s =
            create_test_session(profile.id).with_grant_authentication(&sso.grant_authentication());
        s.client_id = Some(client.client_id.clone());
        s
    };
    let exists = |id: SessionId| async move { backend.get_session(id).await.unwrap().is_some() };

    let sso = create_test_session(profile.id);
    let unrelated = create_test_session(profile.id);
    let app = redeemed(&sso);
    assert_eq!(app.authenticated_by, Some(sso.id));
    for s in [&sso, &unrelated, &app] {
        backend.create_session(s, test_audit()).await.unwrap();
    }
    assert_eq!(
        backend
            .get_session(app.id)
            .await
            .unwrap()
            .unwrap()
            .authenticated_by,
        Some(sso.id)
    );

    // An application's sign-out does not end single sign-on.
    backend
        .delete_session(app.id, &end, test_audit())
        .await
        .unwrap();
    assert!(!exists(app.id).await);
    assert!(exists(sso.id).await);

    // Ending single sign-on ends what it authenticated, and owes its logout.
    let app = redeemed(&sso);
    backend.create_session(&app, test_audit()).await.unwrap();
    let mut ended = backend
        .delete_session(sso.id, &end, test_audit())
        .await
        .unwrap();
    ended.sort_by_key(|id| id.to_string());
    let mut expected = vec![sso.id, app.id];
    expected.sort_by_key(|id| id.to_string());
    assert_eq!(ended, expected);
    assert!(
        backend
            .delete_session(sso.id, &end, test_audit())
            .await
            .unwrap()
            .is_empty(),
        "a session already gone ends nothing"
    );
    assert!(!exists(sso.id).await);
    assert!(!exists(app.id).await);
    assert!(exists(unrelated.id).await);
    let logout = LogoutDelivery::for_ended_session(&app).expect("the client is owed a logout");
    assert_eq!(
        backend
            .get_work(logout.work().id)
            .await
            .unwrap()
            .map(|w| w.state),
        Some(WorkState::Pending),
        "the authenticated session's logout was not stored with the end"
    );

    // The session limit evicting the IdP session evicts its dependents too.
    backend
        .delete_sessions_by_profile(profile.id, &end, test_audit())
        .await
        .unwrap();
    let sso = create_test_session(profile.id);
    backend.create_session(&sso, test_audit()).await.unwrap();
    let app = redeemed(&sso);
    backend.create_session(&app, test_audit()).await.unwrap();
    let newest = create_test_session(profile.id);
    let evicted = backend
        .create_session_atomic(&newest, 2, test_audit())
        .await
        .unwrap();
    assert!(
        evicted.contains(&sso.id) && evicted.contains(&app.id),
        "{evicted:?}"
    );
    assert!(!exists(app.id).await);
    assert!(exists(newest.id).await);
}

/// Last activity only moves forward: an earlier time does not lower it,
/// concurrent touches keep the latest, and touching an unknown session
/// creates nothing.
pub async fn test_touch_session_keeps_latest_activity(backend: Arc<dyn StorageBackend>) {
    let profile = create_test_profile("touch");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();

    // Every store keeps at least milliseconds; compare at that precision.
    let now = Utc::now()
        .duration_trunc(Duration::milliseconds(1))
        .unwrap();
    backend.touch_session(session.id, now).await.unwrap();
    backend
        .touch_session(session.id, now - Duration::minutes(5))
        .await
        .unwrap();
    assert_eq!(
        backend
            .get_session(session.id)
            .await
            .unwrap()
            .unwrap()
            .last_activity_at,
        Some(now)
    );

    let times: Vec<_> = (1..=8).map(|i| now + Duration::seconds(i)).collect();
    let writers: Vec<_> = times
        .iter()
        .map(|at| {
            let backend = backend.clone();
            let at = *at;
            tokio::spawn(async move { backend.touch_session(session.id, at).await })
        })
        .collect();
    for writer in writers {
        writer.await.unwrap().unwrap();
    }
    assert_eq!(
        backend
            .get_session(session.id)
            .await
            .unwrap()
            .unwrap()
            .last_activity_at,
        times.last().copied()
    );

    let unknown = SessionId::generate();
    backend.touch_session(unknown, now).await.unwrap();
    assert!(backend.get_session(unknown).await.unwrap().is_none());
}
