// SPDX-License-Identifier: AGPL-3.0-only
//! A client's redirect URI through the authorization and token methods a
//! client calls: a native application's loopback port, and a callback that
//! was removed after a code was issued for it.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::oauth_client::{CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI};
use common::{fresh_token, issue_admin_token, oauth_error, test_client, test_profile};
use sid_core::models::{ApplicationType, Profile, ProfileId};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::o_auth2_authorize_response::Result as AuthzResult;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Status};

fn assert_refused(status: Status, code: Code, error: &str) {
    assert_eq!(status.code(), code, "{status:?}");
    assert_eq!(oauth_error(&status).as_deref(), Some(error), "{status:?}");
}

/// The answer of the authorization method to the test client's request
/// returning to `redirect_uri`, asked by a fresh session of `profile`, who
/// already approved the client.
async fn authorize(
    svc: &TestServices,
    profile: &Profile,
    redirect_uri: &str,
) -> Result<String, Status> {
    common::consented(&*svc.storage, profile.id, "test-client").await;
    let mut request = Request::new(OAuth2AuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: redirect_uri.to_string(),
        response_type: "code".to_string(),
        scope: Some("openid".to_string()),
        code_challenge: Some(CODE_CHALLENGE.to_string()),
        code_challenge_method: Some("S256".to_string()),
        state: Some("test-state".to_string()),
        nonce: Some("test-nonce".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", fresh_token(svc, profile).await)
            .parse()
            .unwrap(),
    );
    match svc
        .auth
        .o_auth2_authorize(request)
        .await?
        .into_inner()
        .result
    {
        Some(AuthzResult::AuthorizationCode(code)) => Ok(code),
        other => panic!("expected an authorization code, got {other:?}"),
    }
}

/// The token request redeeming `code` for the test client with
/// `redirect_uri`.
fn exchange(svc: &TestServices, code: &str, redirect_uri: &str) -> Request<OAuth2TokenRequest> {
    Request::new(OAuth2TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code.to_string()),
        redirect_uri: Some(redirect_uri.to_string()),
        client_id: Some("test-client".to_string()),
        code_verifier: Some(CODE_VERIFIER.to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    })
}

/// Services whose test client is of `application_type` and registered with
/// `redirect_uri` alone, and the account that signs in.
fn services(application_type: ApplicationType, redirect_uri: &str) -> (TestServices, Profile) {
    let mut client = test_client();
    client.application_type = application_type;
    client.redirect_uris = vec![redirect_uri.to_string()];
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_client(client)
            .with_profile(profile.clone()),
    );
    (svc, profile)
}

/// A native application registered with a loopback IP redirect authorizes
/// on the port it picked when it started (RFC 8252 §7.3) and redeems the
/// code with that same redirect. The code stays bound to the redirect it was
/// issued for: the registered spelling, without that port, does not redeem
/// it. A web client gets no such latitude: another port is refused at
/// authorization.
/// Bug prevented: a native application on an ephemeral port could not sign
/// anyone in, or the port latitude reaching browser clients.
#[tokio::test]
async fn a_native_loopback_port_goes_from_authorization_to_the_exchange() {
    const REGISTERED: &str = "http://127.0.0.1/callback";
    const PICKED: &str = "http://127.0.0.1:53211/callback";

    let (svc, profile) = services(ApplicationType::Native, REGISTERED);
    let code = authorize(&svc, &profile, PICKED)
        .await
        .expect("the picked port is authorized");
    let err = svc
        .auth
        .o_auth2_token(exchange(&svc, &code, REGISTERED))
        .await
        .unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_grant");

    let code = authorize(&svc, &profile, PICKED)
        .await
        .expect("the picked port is authorized");
    let tokens = svc
        .auth
        .o_auth2_token(exchange(&svc, &code, PICKED))
        .await
        .expect("the code is redeemed with the redirect it was issued for")
        .into_inner();
    assert!(!tokens.access_token.is_empty());

    // Only the port may differ.
    authorize(&svc, &profile, "http://127.0.0.1:53211/other")
        .await
        .expect_err("another path is not the registered redirect");

    let (svc, profile) = services(ApplicationType::Web, "http://127.0.0.1:3000/callback");
    authorize(&svc, &profile, "http://127.0.0.1:3001/callback")
        .await
        .expect_err("a web client's port is part of its redirect");
    authorize(&svc, &profile, "http://127.0.0.1:3000/callback")
        .await
        .expect("the registered redirect is authorized");
}

/// A callback the administrator removes from a client ends the codes
/// outstanding for it: the token method refuses the code, and no new
/// authorization returns there.
/// Bug prevented: a code issued for a removed callback still turned into
/// tokens for that destination.
#[tokio::test]
async fn a_removed_callback_ends_its_outstanding_code() {
    let (svc, profile) = services(ApplicationType::Spa, REDIRECT_URI);
    let code = authorize(&svc, &profile, REDIRECT_URI)
        .await
        .expect("the registered redirect is authorized");

    let mut update = Request::new(UpdateClientRoleRequest {
        client_id: "test-client".to_string(),
        redirect_uris: vec!["https://app.sid.example.com/other".to_string()],
        ..Default::default()
    });
    update.metadata_mut().insert(
        "authorization",
        format!(
            "Bearer {}",
            issue_admin_token(&svc.jwt, ProfileId::generate())
        )
        .parse()
        .unwrap(),
    );
    common::name_new_command(update.metadata_mut());
    svc.project
        .update_client_role(update)
        .await
        .expect("the administrator replaces the callback");

    let err = svc
        .auth
        .o_auth2_token(exchange(&svc, &code, REDIRECT_URI))
        .await
        .unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_grant");
    authorize(&svc, &profile, REDIRECT_URI)
        .await
        .expect_err("the removed callback starts no authorization");

    // The callback that replaced it works from authorization to exchange.
    let code = authorize(&svc, &profile, "https://app.sid.example.com/other")
        .await
        .expect("the new callback is authorized");
    svc.auth
        .o_auth2_token(exchange(&svc, &code, "https://app.sid.example.com/other"))
        .await
        .expect("its code is redeemed");
}
