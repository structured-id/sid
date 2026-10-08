// SPDX-License-Identifier: AGPL-3.0-only
//! The client side of the authorization-code flow, driven against test services.
#![allow(dead_code)]

use super::{TestServices, fresh_token};
use sid_core::models::Profile;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::o_auth2_authorize_response::Result as AuthzResult;
use sid_proto::sid::v1::*;
use tonic::Request;

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// PKCE verifier of every test authorization (RFC 7636 Appendix B).
pub const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// Its S256 challenge.
pub const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// Redirect URI registered for the test client.
pub const REDIRECT_URI: &str = "https://app.sid.example.com/callback";

/// An authorization code for `profile` from the test client, authorized by a
/// fresh stored session.
pub async fn authorize_code(svc: &TestServices, profile: &Profile) -> String {
    let bearer = fresh_token(svc, profile).await;
    let req = authed_request(
        OAuth2AuthorizeRequest {
            client_id: "test-client".to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            response_type: "code".to_string(),
            scope: Some("openid".to_string()),
            code_challenge: Some(CODE_CHALLENGE.to_string()),
            code_challenge_method: Some("S256".to_string()),
            state: Some("test-state".to_string()),
            nonce: Some("test-nonce".to_string()),
            issuer_handle: svc.issuer.handle.to_string(),
            ..Default::default()
        },
        &bearer,
    );
    match svc
        .auth
        .o_auth2_authorize(req)
        .await
        .unwrap()
        .into_inner()
        .result
    {
        Some(AuthzResult::AuthorizationCode(c)) => c,
        other => panic!("expected authorization_code, got {:?}", other),
    }
}

/// The token request exchanging `code` for the test client, at the token
/// endpoint of the installation's issuer.
pub fn code_exchange(svc: &TestServices, code: &str) -> Request<OAuth2TokenRequest> {
    Request::new(OAuth2TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code.to_string()),
        redirect_uri: Some(REDIRECT_URI.to_string()),
        client_id: Some("test-client".to_string()),
        code_verifier: Some(CODE_VERIFIER.to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    })
}
