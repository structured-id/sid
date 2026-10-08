// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use axum::http::HeaderValue;

#[test]
fn test_presented_bearer() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer eyJhbGciOiJFZERTQSJ9.test.sig"),
    );
    assert_eq!(
        presented_token(&headers),
        Some(Presented::Bearer("eyJhbGciOiJFZERTQSJ9.test.sig"))
    );
}

/// Auth schemes are case-insensitive (RFC 7235 §2.1), and `DPoP` is told
/// apart from `Bearer` so a bound token is checked against its proof.
#[test]
fn test_presented_scheme_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("bearer tok"));
    assert_eq!(presented_token(&headers), Some(Presented::Bearer("tok")));
    headers.insert("authorization", HeaderValue::from_static("dpop tok"));
    assert_eq!(presented_token(&headers), Some(Presented::DPoP("tok")));
}

/// The IdP's own `sid_session` cookie is no credential for a protected
/// application: forward auth reads no cookie at all, so a browser signed in
/// to SID does not open an application with that session.
#[test]
fn test_session_cookie_is_not_a_credential() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_static("other=val; sid_session=my_token_here; foo=bar"),
    );
    assert_eq!(presented_token(&headers), None);
}

/// Another scheme is not an access token of this edge.
#[test]
fn test_presented_other_scheme() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Basic dXNlcg=="));
    assert_eq!(presented_token(&headers), None);
}

#[test]
fn test_presented_none() {
    let headers = HeaderMap::new();
    assert_eq!(presented_token(&headers), None);
}

/// The claims forward auth acts on come from the verified access token; its
/// key binding is kept so the sender check applies, and no profile claim is
/// invented for a token that carries none.
#[test]
fn test_claims_from_an_access_token() {
    let claims = sid_authn::jwt::AccessTokenClaims {
        sub: "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e".into(),
        pid: None,
        iss: "https://sid.example.com/i/0123456789abcdef0123456789abcdef".into(),
        aud: vec!["https://api.example.com/orders".into()],
        client_id: Some("orders-web".into()),
        exp: 2,
        iat: 1,
        auth_time: 1,
        acr: "urn:sid:acr:basic".into(),
        scope: "orders.read".into(),
        roles: "reader".into(),
        sid: "sess".into(),
        amr: vec![],
        jti: "tok".into(),
        cnf: Some(sid_authn::jwt::CnfClaim {
            jkt: "thumb".into(),
        }),
        act: None,
    };
    let forwarded = ForwardAuthClaims::from(claims);
    assert_eq!(forwarded.sub, "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e");
    assert_eq!(forwarded.scope, "orders.read");
    assert_eq!(forwarded.roles, "reader");
    assert_eq!(forwarded.jti, "tok");
    assert_eq!(forwarded.cnf.map(|c| c.jkt).as_deref(), Some("thumb"));
    assert!(forwarded.email.is_none() && forwarded.groups.is_none());
}
