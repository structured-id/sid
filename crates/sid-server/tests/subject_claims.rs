// SPDX-License-Identifier: AGPL-3.0-only
//! The subject an application receives from a standalone installation's own
//! issuer: the hop (issuer → selected Profile → recipient) decides it, not the
//! client's `subject_type` metadata. A local Profile at an application of the
//! installation's own organization gets its local ProfileId; CE has no opt-in
//! for internal application isolation. Ordinary tokens carry that subject and
//! no other identifier of the user: moving an application's users to another
//! identifier is a dedicated continuity flow, never an extra claim
//! (`sid_legacy_sub` or any equivalent).

mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::TestServices;
use common::mock_storage::MockStorage;
use common::oauth_client::{authorize_code, code_exchange};
use common::{test_client, test_profile};
use sid_core::models::{OAuth2Client, Profile, SubjectType};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

fn claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// The `sub` of `token`, asserting it carries no old identifier beside it.
fn subject(token: &str) -> String {
    let claims = claims(token);
    assert!(
        claims.get("sid_legacy_sub").is_none(),
        "ordinary token carries an old identifier: {claims}"
    );
    claims["sub"].as_str().expect("sub").to_string()
}

/// The subjects of the access and ID tokens `client` receives for `profile`
/// from the code exchange and from a refresh, in that order.
async fn subjects(client: OAuth2Client, profile: &Profile) -> Vec<String> {
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(client)
            .with_profile(profile.clone()),
    );
    let code = authorize_code(&svc, profile).await;
    let issued = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .unwrap()
        .into_inner();
    let refreshed = svc
        .auth
        .o_auth2_token(Request::new(OAuth2TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: issued.refresh_token.clone(),
            client_id: Some("test-client".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();

    let mut subjects = vec![
        subject(&issued.access_token),
        subject(&issued.id_token.expect("id_token for the openid scope")),
        subject(&refreshed.access_token),
    ];
    if let Some(id_token) = refreshed.id_token {
        subjects.push(subject(&id_token));
    }
    subjects
}

/// A local Profile at an application of the installation's own organization
/// gets its local ProfileId in every token of the code exchange and refresh.
#[tokio::test]
async fn own_application_gets_the_local_profile_id() {
    let profile = test_profile();
    for sub in subjects(test_client(), &profile).await {
        assert_eq!(sub, profile.id.to_string());
    }
}

/// A client stored with pairwise metadata does not change the hop: the
/// installation's own application still gets the local ProfileId. The former
/// resolver branched on the flag and gave such a client a BindingId, an
/// internal isolation CE does not offer.
#[tokio::test]
async fn pairwise_metadata_does_not_change_the_subject() {
    let profile = test_profile();
    let mut client = test_client();
    client.subject_type = SubjectType::Pairwise;
    for sub in subjects(client, &profile).await {
        assert_eq!(sub, profile.id.to_string());
    }
}
