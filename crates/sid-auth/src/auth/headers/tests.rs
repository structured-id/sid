// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn test_claims() -> ForwardAuthClaims {
    ForwardAuthClaims {
        sub: "up_01HY000000000000000000".into(),
        iss: "https://sid.example.com".into(),
        exp: 9999999999,
        iat: 1000000000,
        auth_time: 1000000000,
        acr: "standard".into(),
        scope: "openid profile email".into(),
        roles: "admin editor".into(),
        sid: "sess_01HY000000000000000000".into(),
        jti: "tok_01HY000000000000000000".into(),
        email: Some("user@sid.example.com".into()),
        name: Some("Test User".into()),
        preferred_username: Some("testuser".into()),
        groups: None,
        cnf: None,
    }
}

#[test]
fn test_default_headers() {
    let claims = test_claims();
    let headers = build_auth_headers(&claims, &[], None);
    assert_eq!(
        headers.get(X_FORWARDED_USER).unwrap().to_str().unwrap(),
        "up_01HY000000000000000000"
    );
    assert_eq!(
        headers.get(X_SID_AUTH_LEVEL).unwrap().to_str().unwrap(),
        "standard"
    );
    // Email not included by default
    assert!(headers.get(X_AUTH_REQUEST_EMAIL).is_none());
}

#[test]
fn test_inject_email_with_scope() {
    let claims = test_claims(); // scope = "openid profile email"
    let inject = vec!["user".into(), "email".into()];
    let headers = build_auth_headers(&claims, &inject, None);
    assert_eq!(
        headers.get(X_AUTH_REQUEST_EMAIL).unwrap().to_str().unwrap(),
        "user@sid.example.com"
    );
}

#[test]
fn test_inject_email_without_scope() {
    let mut claims = test_claims();
    claims.scope = "openid profile".into(); // no email scope
    let inject = vec!["user".into(), "email".into()];
    let headers = build_auth_headers(&claims, &inject, None);
    // Email not injected without email scope (PII protection)
    assert!(headers.get(X_AUTH_REQUEST_EMAIL).is_none());
}

#[test]
fn test_inject_groups() {
    let claims = test_claims();
    let inject = vec!["groups".into()];
    let headers = build_auth_headers(&claims, &inject, None);
    assert_eq!(
        headers
            .get(X_AUTH_REQUEST_GROUPS)
            .unwrap()
            .to_str()
            .unwrap(),
        "admin,editor"
    );
}

#[test]
fn test_inject_name_and_username() {
    let claims = test_claims();
    let inject = vec!["name".into(), "preferred_username".into()];
    let headers = build_auth_headers(&claims, &inject, None);
    assert_eq!(
        headers.get(X_AUTH_REQUEST_NAME).unwrap().to_str().unwrap(),
        "Test User"
    );
    assert_eq!(
        headers
            .get(X_AUTH_REQUEST_PREFERRED_USERNAME)
            .unwrap()
            .to_str()
            .unwrap(),
        "testuser"
    );
}

#[test]
fn test_inject_access_token() {
    let claims = test_claims();
    let inject = vec!["access_token".into()];
    let headers = build_auth_headers(&claims, &inject, Some("eyJhbGciOiJFZERTQSJ9.test.sig"));
    assert_eq!(
        headers
            .get(X_AUTH_REQUEST_ACCESS_TOKEN)
            .unwrap()
            .to_str()
            .unwrap(),
        "eyJhbGciOiJFZERTQSJ9.test.sig"
    );
}

#[test]
fn test_missing_optional_fields() {
    let mut claims = test_claims();
    claims.email = None;
    claims.name = None;
    claims.preferred_username = None;
    let inject = vec!["email".into(), "name".into(), "preferred_username".into()];
    let headers = build_auth_headers(&claims, &inject, None);
    assert!(headers.get(X_AUTH_REQUEST_EMAIL).is_none());
    assert!(headers.get(X_AUTH_REQUEST_NAME).is_none());
    assert!(headers.get(X_AUTH_REQUEST_PREFERRED_USERNAME).is_none());
}

/// Whatever a route injects, every emitted header is one a proxy is told to
/// strip from the client's request.
#[test]
fn test_every_emitted_header_is_an_identity_header() {
    let inject: Vec<String> = [
        "user",
        "email",
        "groups",
        "name",
        "preferred_username",
        "access_token",
        "auth_level",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let headers = build_auth_headers(&test_claims(), &inject, Some("t.o.k"));
    assert_eq!(headers.len(), IDENTITY_HEADERS.len());
    for name in headers.keys() {
        assert!(IDENTITY_HEADERS.contains(&name.as_str()), "{name}");
    }
}
