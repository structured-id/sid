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

/// The account an application keeps for the user of an ID token: the pair
/// (issuer, subject), as OIDC Core 5.7 has it keyed.
async fn account(svc: &TestServices, profile: &Profile) -> (String, String) {
    let code = authorize_code(svc, profile).await;
    let issued = svc
        .auth
        .o_auth2_token(code_exchange(svc, &code))
        .await
        .unwrap()
        .into_inner();
    let claims = claims(&issued.id_token.expect("id_token for the openid scope"));
    (
        claims["iss"].as_str().expect("iss").to_string(),
        claims["sub"].as_str().expect("sub").to_string(),
    )
}

/// Moving the address browsers sign in at changes neither the issuer nor the
/// subject: an application that keyed its account by (issuer, subject) finds
/// the same record at the user's next sign-in, with no migration. Bug
/// prevented: an issuer identity that follows the installation's current
/// sign-in address, so every application loses its accounts when an
/// administrator moves that address.
#[tokio::test]
async fn a_moved_sign_in_address_keeps_the_applications_account() {
    use sid_proto::sid::v1::admin::UpdateInstallationAddressesRequest;
    use sid_proto::sid::v1::admin::realm_service_server::RealmService;

    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone()),
    );
    let before = account(&svc, &profile).await;
    assert_eq!(before.0, svc.issuer.canonical_url);
    // The application's own store of accounts.
    let accounts = std::collections::HashMap::from([(before.clone(), "the user's record")]);

    let realm = sid_server::grpc::realm_service::RealmServiceImpl::new(
        svc.mock_storage.clone(),
        common::test_jwt(),
        common::test_revocation(),
        common::test_key_manager(),
        common::test_web_settings(svc.mock_storage.clone()),
    );
    let mut moving = Request::new(UpdateInstallationAddressesRequest {
        public_url: Some("https://login.example.com/".to_string()),
        console_url: None,
    });
    let administrator =
        common::issue_admin_token(&common::test_jwt(), sid_core::models::ProfileId::generate());
    moving.metadata_mut().insert(
        "authorization",
        format!("Bearer {administrator}").parse().unwrap(),
    );
    common::name_new_command(moving.metadata_mut());
    let moved = realm
        .update_installation_addresses(moving)
        .await
        .expect("the address moves")
        .into_inner();
    assert_eq!(moved.public_url, "https://login.example.com/");
    assert!(moved.public_url_overridden);

    let after = account(&svc, &profile).await;
    assert_eq!(after, before, "the issuer and subject after the move");
    assert_eq!(accounts.get(&after), Some(&"the user's record"));
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
