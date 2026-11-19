// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// The root routes of the base issuer, read from the proto rules, are its
/// protocol endpoints only: the browser API mount, the cabinet, Central's
/// hosted entry and the scoped forms are not, so an edge never sends them to
/// the base issuer.
#[test]
fn the_root_issuer_endpoints_are_its_protocol_routes() {
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/jwks",
        "/userinfo",
        "/oauth2/authorize",
        "/oauth2/end-session",
        "/oauth2/token",
        "/oauth2/introspect",
        "/oauth2/revoke",
        "/oauth2/device",
        "/oauth2/register",
        "/oauth2/register/client-1",
        "/auth/federation/start",
        "/auth/federation/callback",
        "/auth/federation/connections",
    ] {
        assert_eq!(root_issuer_endpoint(path), Some(path), "{path}");
    }
    for path in [
        "/",
        "/dashboard/",
        "/api/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/auth/entry",
        "/oauth2",
        "/oauth2/unknown",
        "/oauth2/register/",
        "/oauth2/register/client-1/x",
        "/jwksx",
        "/.well-known/oauth-authorization-server/i/0123456789abcdef0123456789abcdef",
        "/i/0123456789abcdef0123456789abcdef/jwks",
    ] {
        assert_eq!(root_issuer_endpoint(path), None, "{path}");
    }
}

/// The sign-in surface a page is told to use is the route that serves the
/// issuer: `/api` on a single-authority origin, `/i/<handle>/api` when the
/// call reached its issuer addressed on a shared host. A root-addressed base
/// issuer (`iss` with no path) on a shared host therefore gets its handle's
/// route, not `iss + /api`.
#[test]
fn ceremony_api_is_the_serving_route() {
    assert_eq!(
        ceremony_api("https://sid.example.com", None),
        "https://sid.example.com/api"
    );
    let iss = "https://dev.sid.example.com";
    let route = ceremony_api(iss, Some("0123456789abcdef0123456789abcdef"));
    assert_eq!(
        route,
        "https://dev.sid.example.com/i/0123456789abcdef0123456789abcdef/api"
    );
    assert_ne!(route, format!("{iss}{API_MOUNT}"));
}

/// The gRPC path is split off `/api/...`.
#[test]
fn api_method_names_the_grpc_path() {
    assert_eq!(
        api_method("/api/sid.v1.authn.AuthService/OpaqueLoginStart"),
        Some("/sid.v1.authn.AuthService/OpaqueLoginStart")
    );
}

/// Anything else is outside the mount: the bare mount, a longer segment that
/// only starts with it, the transport-named mount it replaced, a root gRPC
/// path, an issuer-addressed path.
#[test]
fn other_paths_are_outside_the_api_mount() {
    for path in [
        "/api",
        "/apix/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/grpc/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/i/0123abcd/api/sid.v1.authn.AuthService/OpaqueLoginStart",
    ] {
        assert_eq!(api_method(path), None, "{path}");
    }
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
        session(&format!("/api{PENDING_COMPLETING_METHOD}")),
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
        "/auth/federation/connections",
        "/auth/federation/callback/x",
        "/auth/federation/0123456789abcdef0123456789abcdef/callback",
    ] {
        assert_eq!(
            issuer_cookies(endpoint),
            IssuerCookies::default(),
            "{endpoint}"
        );
    }
}

/// A federated entry's start sets the correlation cookie of the entry it
/// starts and reads nothing; its return reads that cookie and sets the
/// session it admits. Bug prevented: an edge that drops the correlation
/// cookie on the way to the callback, so no entry ever completes, or one
/// that hands the session cookie to the start.
#[test]
fn a_federated_entry_gets_its_correlation_cookie() {
    assert_eq!(
        issuer_cookies("/auth/federation/start"),
        IssuerCookies {
            entry: Some(EntryCookieUse::Start),
            ..IssuerCookies::default()
        }
    );
    assert_eq!(
        issuer_cookies("/auth/federation/callback"),
        IssuerCookies {
            session: Some(SessionCookieUse::Issue),
            entry: Some(EntryCookieUse::Return),
            ..IssuerCookies::default()
        }
    );
}

/// A passwordless registration's verify sets its context cookie and its
/// passkey steps receive it; nothing else exchanges it, and no registration
/// step touches the session. Bug prevented: an edge that drops the context
/// cookie either way, so a registration through a shared host never gets
/// past its address.
#[test]
fn a_registration_gets_its_context_cookie() {
    assert_eq!(
        issuer_cookies(&format!("/api{REGISTRATION_OPENING_METHOD}")),
        IssuerCookies {
            registration: Some(RegistrationCookieUse::Open),
            ..IssuerCookies::default()
        }
    );
    for method in REGISTRATION_CONTEXT_METHODS {
        assert_eq!(
            issuer_cookies(&format!("/api{method}")),
            IssuerCookies {
                registration: Some(RegistrationCookieUse::Present),
                ..IssuerCookies::default()
            },
            "{method}"
        );
    }
    for endpoint in [
        "/api/sid.v1.authn.AuthService/StartEmailRegistration",
        "/api/sid.v1.authn.AuthService/ResendEmailRegistration",
        "/api/sid.v1.authn.AuthService/OpaqueLoginFinish",
    ] {
        assert_eq!(issuer_cookies(endpoint).registration, None, "{endpoint}");
    }
    let open = IssuerCookies {
        registration: Some(RegistrationCookieUse::Open),
        ..IssuerCookies::default()
    };
    assert!(open.sets_registration() && !open.receives_registration());
    let present = IssuerCookies {
        registration: Some(RegistrationCookieUse::Present),
        ..IssuerCookies::default()
    };
    assert!(present.receives_registration() && !present.sets_registration());
    assert_eq!(
        registration_cookie("__Host-sid_session-ab12"),
        "__Host-sid_session-ab12_registration"
    );
}

/// The capability's directions: what reads the session receives it, what
/// issues or clears it may set it, and only a returning entry receives its
/// correlation cookie while both entry endpoints may set one.
#[test]
fn capabilities_name_their_directions() {
    let with = |session| IssuerCookies {
        session: Some(session),
        ..IssuerCookies::default()
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
        entry: Some(entry),
        ..IssuerCookies::default()
    };
    assert!(!entry(EntryCookieUse::Start).receives_entry());
    assert!(entry(EntryCookieUse::Start).sets_entry());
    assert!(entry(EntryCookieUse::Return).receives_entry());
    assert!(entry(EntryCookieUse::Return).sets_entry());
    let none = IssuerCookies::default();
    assert!(!none.receives_session() && !none.sets_session());
    assert!(!none.receives_entry() && !none.sets_entry());
}
