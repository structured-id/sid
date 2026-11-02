// SPDX-License-Identifier: AGPL-3.0-only
//! What ending an IdP session owes the sessions it authenticated. How sessions
//! end together is the grant store's conformance; this is the work it owes.

use sid_core::models::{LogoutDelivery, RevocationReason, SessionEnd, WorkState};
use sid_plugin::StorageBackend;

use super::{create_test_profile, create_test_session, test_audit};

/// Ending the IdP session owes the logout of each application session it
/// authenticated, to that session's client, committed with the end.
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
    let sso = create_test_session(profile.id);
    let mut app =
        create_test_session(profile.id).with_grant_authentication(&sso.grant_authentication());
    app.client_id = Some(client.client_id.clone());
    for s in [&sso, &app] {
        backend.create_session(s, test_audit()).await.unwrap();
    }

    backend
        .delete_session(sso.id, &end, test_audit())
        .await
        .unwrap();

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
}
