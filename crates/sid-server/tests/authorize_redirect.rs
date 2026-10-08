// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization endpoint establishes the client and its exact redirect
//! URI before anything else, the caller included, and marks the two refusals
//! that must not be redirected (RFC 6749 §4.1.2.1). The front channel
//! redirects only what comes after that point.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, test_client, test_profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;
use tonic_types::StatusExt;

/// An authorization request at the authorization endpoint of the
/// installation's issuer.
fn authorize(
    svc: &TestServices,
    client_id: &str,
    redirect_uri: &str,
    response_type: &str,
) -> OAuth2AuthorizeRequest {
    OAuth2AuthorizeRequest {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        response_type: response_type.to_string(),
        scope: Some("openid".to_string()),
        state: Some("xyz".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: None,
        acr_values: None,
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    }
}

fn metadata(status: &tonic::Status, key: &str) -> Option<String> {
    status
        .get_details_error_info()
        .and_then(|info| info.metadata.get(key).cloned())
}

/// An unknown client is refused before the caller is looked at, as not found.
#[tokio::test]
async fn unknown_client_is_refused_before_sign_in() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));

    let err = svc
        .auth
        .o_auth2_authorize(Request::new(authorize(
            &svc,
            "no-such-client",
            "https://evil.example.com/callback",
            "code",
        )))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::NotFound);
}

/// A registered client asked for at an endpoint of an issuer that does not
/// serve it (an unknown handle, or none) is unknown there: refused as not
/// found, never redirected, and no other issuer stands in.
#[tokio::test]
async fn client_at_another_issuers_endpoint_is_unknown() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));
    for handle in [
        sid_core::models::IssuerHandle::generate().to_string(),
        String::new(),
    ] {
        let mut request = authorize(
            &svc,
            "test-client",
            "https://app.sid.example.com/callback",
            "code",
        );
        request.issuer_handle = handle.clone();
        let err = svc
            .auth
            .o_auth2_authorize(Request::new(request))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::NotFound, "{handle:?}");
        assert_eq!(metadata(&err, "field").as_deref(), Some("client_id"));
        assert_eq!(metadata(&err, "oauthError"), None);
    }
}

/// A redirect URI the client did not register is refused before the caller
/// is looked at, marked so the front channel does not redirect to it.
#[tokio::test]
async fn unregistered_redirect_uri_is_refused_before_sign_in() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));

    let err = svc
        .auth
        .o_auth2_authorize(Request::new(authorize(
            &svc,
            "test-client",
            "https://evil.example.com/callback",
            "code",
        )))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(metadata(&err, "field").as_deref(), Some("redirect_uri"));
    assert_eq!(metadata(&err, "oauthError"), None);
}

/// Once client and redirect URI are established, a missing sign-in is
/// reported (the front channel sends the user to log in).
#[tokio::test]
async fn established_request_without_sign_in_asks_for_it() {
    let svc = TestServices::new(MockStorage::new().with_client(test_client()));

    let err = svc
        .auth
        .o_auth2_authorize(Request::new(authorize(
            &svc,
            "test-client",
            "https://app.sid.example.com/callback",
            "code",
        )))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// A later refusal carries the RFC 6749 §4.1.2.1 `error` code to be sent to
/// the established redirect URI.
#[tokio::test]
async fn later_refusal_carries_the_oauth_error_code() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_client(test_client()),
    );
    let mut request = Request::new(authorize(
        &svc,
        "test-client",
        "https://app.sid.example.com/callback",
        "token",
    ));
    let token = common::fresh_token(&svc, &profile).await;
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());

    let err = svc.auth.o_auth2_authorize(request).await.unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        metadata(&err, "oauthError").as_deref(),
        Some("unsupported_response_type")
    );
}
