// SPDX-License-Identifier: AGPL-3.0-only
//! Every refusal of the token endpoint names its OAuth 2.0 error code
//! (RFC 6749 §5.2) in `ErrorInfo.metadata["oauthError"]`, so a typed client
//! and the endpoint's RFC wire form see the same code; and a confidential
//! client can authenticate with HTTP Basic (RFC 6749 §2.3.1).

mod common;

use base64::Engine;
use common::TestServices;
use common::mock_storage::MockStorage;
use common::oauth_client::{authorize_code, code_exchange};
use common::{oauth_error, test_client, test_profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Status};

const SECRET: &str = "confidential-client-secret";

fn assert_refused(status: Status, code: Code, error: &str) {
    assert_eq!(status.code(), code, "{status:?}");
    assert_eq!(oauth_error(&status).as_deref(), Some(error), "{status:?}");
}

fn services() -> TestServices {
    TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(test_profile()),
    )
}

/// A confidential client with `SECRET`, id `confidential`.
fn confidential_services() -> TestServices {
    let mut client = test_client();
    client.client_id = "confidential".into();
    client.client_secret_hash = Some(
        sid_authn::oauth2::OAuth2Server::hash_client_secret(SECRET)
            .unwrap()
            .into_bytes(),
    );
    client.token_endpoint_auth_method =
        sid_core::models::TokenEndpointAuthMethod::ClientSecretBasic;
    client.grant_types = vec!["client_credentials".into()];
    TestServices::new(MockStorage::new().with_client(client))
}

fn token_request(
    svc: &TestServices,
    fill: impl FnOnce(&mut OAuth2TokenRequest),
) -> Request<OAuth2TokenRequest> {
    let mut req = OAuth2TokenRequest {
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    };
    fill(&mut req);
    Request::new(req)
}

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

#[tokio::test]
async fn unsupported_grant_type() {
    let svc = services();
    let err = svc
        .auth
        .o_auth2_token(token_request(&svc, |r| r.grant_type = "password".into()))
        .await
        .unwrap_err();
    assert_refused(err, Code::InvalidArgument, "unsupported_grant_type");
}

/// A missing required parameter is `invalid_request`.
#[tokio::test]
async fn missing_code_is_invalid_request() {
    let svc = services();
    let err = svc
        .auth
        .o_auth2_token(token_request(&svc, |r| {
            r.grant_type = "authorization_code".into();
            r.client_id = Some("test-client".into());
            r.redirect_uri = Some("https://app.sid.example.com/callback".into());
        }))
        .await
        .unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_request");
}

/// An unknown client is `invalid_client`.
#[tokio::test]
async fn unknown_client_is_invalid_client() {
    let svc = services();
    let err = svc
        .auth
        .o_auth2_token(token_request(&svc, |r| {
            r.grant_type = "authorization_code".into();
            r.client_id = Some("nobody".into());
            r.code = Some("c".into());
            r.redirect_uri = Some("https://app.sid.example.com/callback".into());
        }))
        .await
        .unwrap_err();
    assert_refused(err, Code::Unauthenticated, "invalid_client");
}

/// A code that does not exist, a code redeemed a second time and a wrong
/// PKCE verifier are all `invalid_grant` (RFC 6749 §5.2): the grant, not
/// the request, is bad.
#[tokio::test]
async fn bad_codes_are_invalid_grant() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone()),
    );
    let err = svc
        .auth
        .o_auth2_token(code_exchange(&svc, "no-such-code"))
        .await
        .unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_grant");

    let code = authorize_code(&svc, &profile).await;
    let mut wrong_verifier = code_exchange(&svc, &code);
    wrong_verifier.get_mut().code_verifier =
        Some("wrong-verifier-wrong-verifier-wrong-verifier-00".into());
    let err = svc.auth.o_auth2_token(wrong_verifier).await.unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_grant");

    let code = authorize_code(&svc, &profile).await;
    svc.auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .unwrap();
    let err = svc
        .auth
        .o_auth2_token(code_exchange(&svc, &code))
        .await
        .unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_grant");
}

/// An unknown refresh token is `invalid_grant`.
#[tokio::test]
async fn unknown_refresh_token_is_invalid_grant() {
    let svc = services();
    let err = svc
        .auth
        .o_auth2_token(token_request(&svc, |r| {
            r.grant_type = "refresh_token".into();
            r.client_id = Some("test-client".into());
            r.refresh_token = Some("no-such-token".into());
        }))
        .await
        .unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_grant");
}

/// A confidential client authenticates with HTTP Basic (RFC 6749 §2.3.1);
/// a wrong secret is `invalid_client`.
#[tokio::test]
async fn client_secret_basic_authenticates() {
    let svc = confidential_services();
    let mut req = token_request(&svc, |r| r.grant_type = "client_credentials".into());
    req.metadata_mut().insert(
        "authorization",
        basic("confidential", SECRET).parse().unwrap(),
    );
    let issued = svc.auth.o_auth2_token(req).await.unwrap().into_inner();
    assert!(!issued.access_token.is_empty());

    let mut req = token_request(&svc, |r| r.grant_type = "client_credentials".into());
    req.metadata_mut().insert(
        "authorization",
        basic("confidential", "wrong").parse().unwrap(),
    );
    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert_refused(err, Code::Unauthenticated, "invalid_client");
}

/// A confidential client authenticates only with the method it registered
/// (OIDC Core 1.0 §9, RFC 7591 §2 `token_endpoint_auth_method`): a secret
/// registered for HTTP Basic is not accepted from the body, and one
/// registered for the body is not accepted as HTTP Basic.
#[tokio::test]
async fn only_the_registered_method_authenticates() {
    let svc = confidential_services();
    let err = svc
        .auth
        .o_auth2_token(token_request(&svc, |r| {
            r.grant_type = "client_credentials".into();
            r.client_id = Some("confidential".into());
            r.client_secret = Some(SECRET.into());
        }))
        .await
        .unwrap_err();
    assert_refused(err, Code::Unauthenticated, "invalid_client");

    let mut client = test_client();
    client.client_id = "posting".into();
    client.client_secret_hash = Some(
        sid_authn::oauth2::OAuth2Server::hash_client_secret(SECRET)
            .unwrap()
            .into_bytes(),
    );
    client.token_endpoint_auth_method = sid_core::models::TokenEndpointAuthMethod::ClientSecretPost;
    client.grant_types = vec!["client_credentials".into()];
    let svc = TestServices::new(MockStorage::new().with_client(client));
    let mut req = token_request(&svc, |r| r.grant_type = "client_credentials".into());
    req.metadata_mut()
        .insert("authorization", basic("posting", SECRET).parse().unwrap());
    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert_refused(err, Code::Unauthenticated, "invalid_client");

    let issued = svc
        .auth
        .o_auth2_token(token_request(&svc, |r| {
            r.grant_type = "client_credentials".into();
            r.client_id = Some("posting".into());
            r.client_secret = Some(SECRET.into());
        }))
        .await
        .expect("the registered method authenticates");
    assert!(!issued.into_inner().access_token.is_empty());
}

/// Two ways of authenticating the client in one request are refused
/// (RFC 6749 §2.3: the client MUST NOT use more than one method), and so is
/// a Basic identity contradicting the body's `client_id`.
#[tokio::test]
async fn basic_with_another_method_is_invalid_request() {
    let svc = confidential_services();
    let mut req = token_request(&svc, |r| {
        r.grant_type = "client_credentials".into();
        r.client_secret = Some(SECRET.into());
    });
    req.metadata_mut().insert(
        "authorization",
        basic("confidential", SECRET).parse().unwrap(),
    );
    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_request");

    let mut req = token_request(&svc, |r| {
        r.grant_type = "client_credentials".into();
        r.client_id = Some("someone-else".into());
    });
    req.metadata_mut().insert(
        "authorization",
        basic("confidential", SECRET).parse().unwrap(),
    );
    let err = svc.auth.o_auth2_token(req).await.unwrap_err();
    assert_refused(err, Code::InvalidArgument, "invalid_request");
}
