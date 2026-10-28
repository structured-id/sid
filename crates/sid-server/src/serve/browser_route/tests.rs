// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// The handle and the gRPC path are split off `/i/{handle}/api/...`.
#[test]
fn addressed_path_names_handle_and_method() {
    assert_eq!(
        addressed("/i/0123abcd/api/sid.v1.authn.AuthService/OpaqueLoginStart"),
        Some(("0123abcd", "/sid.v1.authn.AuthService/OpaqueLoginStart"))
    );
}

/// Each endpoint's cookie capability is the one its session contract names:
/// authorization reads the session, end-session reads and clears it, the
/// ceremonies that complete a sign-in issue it and TOTP reads the pending
/// context it completes. Protocol endpoints, ceremony steps that complete
/// nothing, near-miss paths and unpublished methods get none.
#[test]
fn each_endpoint_gets_its_own_cookie_capability() {
    let session = |endpoint: &str| issuer_cookies(endpoint).session;
    assert_eq!(session("/oauth2/authorize"), Some(SessionCookieUse::Read));
    assert_eq!(
        session("/oauth2/end-session"),
        Some(SessionCookieUse::ReadAndClear)
    );
    assert_eq!(
        session("/api/sid.v1.authn.AuthService/VerifyTotp"),
        Some(SessionCookieUse::ReadAndIssue)
    );
    for method in ISSUING_METHODS {
        assert_eq!(
            session(&format!("/api{method}")),
            Some(SessionCookieUse::Issue),
            "{method}"
        );
    }
    for endpoint in [
        "/oauth2/token",
        "/oauth2/userinfo",
        "/oauth2/introspect",
        "/oauth2/revoke",
        "/jwks",
        "/.well-known/openid-configuration",
        "/oauth2/authorize/x",
        "/api/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/api/sid.v1.authn.AuthService/OAuth2Authorize",
        "/api/sid.v1.authn.AuthService/CompleteStepUp",
        "/api/sid.v1.authn.AuthService/VerifyRecoveryCode",
        "/api/sid.v1.IdentityService/GetCurrentProfile",
        "/apix/sid.v1.authn.AuthService/OpaqueLoginFinish",
        "/auth/federation/callback",
    ] {
        assert_eq!(
            issuer_cookies(endpoint),
            IssuerCookies::default(),
            "{endpoint}"
        );
    }
}

/// A method that sets the session is published on the sign-in surface: the
/// capability never names a method the issuer path does not serve.
#[test]
fn every_issuing_method_is_published() {
    for method in ISSUING_METHODS
        .iter()
        .chain(&["/sid.v1.authn.AuthService/VerifyTotp"])
    {
        assert!(BROWSER_METHODS.contains(method), "{method}");
    }
}

/// The capability's directions: what reads the session receives it, what
/// issues or clears it may set it, and only a returning entry receives its
/// correlation cookie while both entry endpoints may set one.
#[test]
fn capabilities_name_their_directions() {
    let with = |session| IssuerCookies {
        session: Some(session),
        entry: None,
    };
    assert!(with(SessionCookieUse::Read).receives_session());
    assert!(!with(SessionCookieUse::Read).sets_session());
    assert!(!with(SessionCookieUse::Issue).receives_session());
    assert!(with(SessionCookieUse::Issue).sets_session());
    assert!(with(SessionCookieUse::ReadAndIssue).receives_session());
    assert!(with(SessionCookieUse::ReadAndIssue).sets_session());
    assert!(with(SessionCookieUse::ReadAndClear).receives_session());
    assert!(with(SessionCookieUse::ReadAndClear).sets_session());
    let entry = |entry| IssuerCookies {
        session: None,
        entry: Some(entry),
    };
    assert!(!entry(EntryCookieUse::Start).receives_entry());
    assert!(entry(EntryCookieUse::Start).sets_entry());
    assert!(entry(EntryCookieUse::Return).receives_entry());
    assert!(entry(EntryCookieUse::Return).sets_entry());
    let none = IssuerCookies::default();
    assert!(!none.receives_session() && !none.sets_session());
    assert!(!none.receives_entry() && !none.sets_entry());
}

/// Anything else is no addressed call: no handle, no `api` segment, a longer
/// segment that only starts with it, the transport-named mount the API path
/// replaced, another issuer endpoint, a root gRPC path.
#[test]
fn other_paths_are_not_addressed() {
    for path in [
        "/i/",
        "/i/0123abcd",
        "/i/0123abcd/api",
        "/i/0123abcd/apix/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/i/0123abcd/grpc/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/i/0123abcd/oauth2/token",
        "/sid.v1.authn.AuthService/OpaqueLoginStart",
    ] {
        assert_eq!(addressed(path), None, "{path}");
    }
}

/// Every published path is a gRPC path (`/package.Service/Method`), listed
/// once.
#[test]
fn browser_methods_are_distinct_grpc_paths() {
    let mut seen = std::collections::HashSet::new();
    for method in BROWSER_METHODS {
        let (service, name) = method
            .strip_prefix('/')
            .and_then(|m| m.split_once('/'))
            .unwrap_or_else(|| panic!("{method}"));
        assert!(
            service.contains('.') && !name.is_empty() && !name.contains('/'),
            "{method}"
        );
        assert!(seen.insert(method), "{method} listed twice");
    }
}
