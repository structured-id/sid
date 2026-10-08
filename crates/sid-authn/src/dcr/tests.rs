use super::*;
use sid_core::models::ProjectId;

fn valid_request() -> ClientRegistrationRequest {
    ClientRegistrationRequest {
        client_name: "Test App".into(),
        redirect_uris: vec!["https://app.sid.example.com/callback".into()],
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        application_type: ApplicationType::Spa,
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec!["admin@sid.example.com".into()],
        scope: vec!["openid".into(), "profile".into()],
        post_logout_redirect_uris: vec!["https://app.sid.example.com/signed-out".into()],
    }
}

fn valid_iat() -> InitialAccessToken {
    InitialAccessToken {
        id: InitialAccessTokenId::new(),
        token_hash: vec![0; 32],
        project_id: ProjectId::system(),
        max_clients: 10,
        clients_registered: 0,
        allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
        allowed_grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        allowed_redirect_patterns: vec!["https://*.sid.example.com/*".into()],
        expires_at: Utc::now() + chrono::Duration::hours(24),
        created_at: Utc::now(),
        created_by: "admin".into(),
        revoked: false,
    }
}

// ── check_subject_metadata tests ────────────────────────────

/// Registration metadata A: `public` is the only subject type, and a sector
/// is never accepted; each refusal names its field.
#[test]
fn only_public_without_a_sector_is_accepted() {
    assert!(check_subject_metadata(SubjectType::Public, None).is_ok());
    assert!(matches!(
        check_subject_metadata(SubjectType::Pairwise, None),
        Err(DcrError::IncompatibleMetadata {
            field: "subject_type",
            ..
        })
    ));
    assert!(matches!(
        check_subject_metadata(
            SubjectType::Public,
            Some("https://rp.sid.example.com/s.json")
        ),
        Err(DcrError::IncompatibleMetadata {
            field: "sector_identifier_uri",
            ..
        })
    ));
}

/// The refusal text tells the registrant what to send instead
/// (authentication-flow.md, registration metadata A).
#[test]
fn pairwise_refusal_names_the_supported_value() {
    let err = check_subject_metadata(SubjectType::Pairwise, None).unwrap_err();
    assert_eq!(
        err.to_string(),
        "subject_type 'pairwise' is not supported by this issuer. Supported value: 'public'."
    );
}

// ── validate_registration_request tests ─────────────────────

#[test]
fn test_valid_request_passes() {
    assert!(validate_registration_request(&valid_request()).is_ok());
}

/// A post-logout redirect URI is held to the rules of a redirect URI of the
/// client's type (no plain http to a remote host, no fragment) and refused as
/// `invalid_client_metadata` naming its field (RFC 7591 §3.2.2).
#[test]
fn post_logout_redirect_uris_are_validated_like_redirect_uris() {
    for bad in [
        "http://app.sid.example.com/signed-out",
        "https://app.sid.example.com/signed-out#top",
        "not a uri",
    ] {
        let mut req = valid_request();
        req.post_logout_redirect_uris = vec![bad.into()];
        let err = validate_registration_request(&req).unwrap_err();
        assert!(
            matches!(err, DcrError::InvalidPostLogoutRedirectUri(ref uri) if uri == bad),
            "{bad}: {err:?}"
        );
        assert_eq!(
            err.metadata_error(),
            Some(("invalid_client_metadata", "post_logout_redirect_uris"))
        );
    }
    let mut native = valid_request();
    native.application_type = ApplicationType::Native;
    native.post_logout_redirect_uris = vec!["http://127.0.0.1:8400/signed-out".into()];
    assert!(validate_registration_request(&native).is_ok());
}

/// The initial access token's redirect patterns bound post-logout URIs too:
/// otherwise a constrained token could register a logout redirect anywhere.
#[test]
fn iat_patterns_bound_post_logout_redirect_uris() {
    let iat = valid_iat();
    assert!(validate_iat_policy(&iat, &valid_request()).is_ok());
    let mut req = valid_request();
    req.post_logout_redirect_uris = vec!["https://elsewhere.example.org/bye".into()];
    assert!(matches!(
        validate_iat_policy(&iat, &req),
        Err(DcrError::InvalidPostLogoutRedirectUri(_))
    ));
}

/// A registration request carrying incompatible subject metadata is refused
/// before any other check.
#[test]
fn test_incompatible_subject_metadata_is_refused() {
    let mut pairwise = valid_request();
    pairwise.subject_type = SubjectType::Pairwise;
    pairwise.client_name = "".into();
    assert!(matches!(
        validate_registration_request(&pairwise),
        Err(DcrError::IncompatibleMetadata {
            field: "subject_type",
            ..
        })
    ));
    let mut sector = valid_request();
    sector.sector_identifier_uri = Some("https://sid.example.com/sector.json".into());
    assert!(matches!(
        validate_registration_request(&sector),
        Err(DcrError::IncompatibleMetadata {
            field: "sector_identifier_uri",
            ..
        })
    ));
}

#[test]
fn test_missing_client_name() {
    let mut req = valid_request();
    req.client_name = "".into();
    assert!(matches!(
        validate_registration_request(&req),
        Err(DcrError::MissingClientName)
    ));
}

#[test]
fn test_missing_redirect_uris_for_spa() {
    let mut req = valid_request();
    req.redirect_uris = vec![];
    assert!(matches!(
        validate_registration_request(&req),
        Err(DcrError::MissingRedirectUris(ApplicationType::Spa))
    ));
}

#[test]
fn test_api_client_no_redirect_uris_ok() {
    let mut req = valid_request();
    req.application_type = ApplicationType::Api;
    req.redirect_uris = vec![];
    req.grant_types = vec!["client_credentials".into()];
    assert!(validate_registration_request(&req).is_ok());
}

#[test]
fn test_invalid_redirect_uri_http() {
    let mut req = valid_request();
    req.redirect_uris = vec!["http://evil.com/callback".into()];
    assert!(matches!(
        validate_registration_request(&req),
        Err(DcrError::InvalidRedirectUri(_))
    ));
}

#[test]
fn test_localhost_http_allowed() {
    let mut req = valid_request();
    req.redirect_uris = vec!["http://localhost:3000/callback".into()];
    assert!(validate_registration_request(&req).is_ok());
}

#[test]
fn test_native_app_http_localhost_allowed() {
    let mut req = valid_request();
    req.application_type = ApplicationType::Native;
    req.redirect_uris = vec!["http://localhost:8080/callback".into()];
    assert!(validate_registration_request(&req).is_ok());
}

#[test]
fn test_native_app_custom_scheme_allowed() {
    let mut req = valid_request();
    req.application_type = ApplicationType::Native;
    req.redirect_uris = vec!["com.example.app://callback".into()];
    assert!(validate_registration_request(&req).is_ok());
}

#[test]
fn test_fragment_in_redirect_uri_rejected() {
    let mut req = valid_request();
    req.redirect_uris = vec!["https://app.sid.example.com/callback#fragment".into()];
    assert!(matches!(
        validate_registration_request(&req),
        Err(DcrError::InvalidRedirectUri(_))
    ));
}

/// Public subjects need no common host: redirect URIs on several hosts are
/// valid, each still checked on its own.
#[test]
fn test_redirect_uris_on_several_hosts_are_valid() {
    let mut req = valid_request();
    req.redirect_uris = vec![
        "https://app1.sid.example.com/callback".into(),
        "https://app2.other.com/callback".into(),
    ];
    assert!(validate_registration_request(&req).is_ok());
    req.redirect_uris
        .push("http://app3.other.com/callback".into());
    assert!(matches!(
        validate_registration_request(&req),
        Err(DcrError::InvalidRedirectUri(_))
    ));
}

#[test]
fn test_invalid_grant_type() {
    let mut req = valid_request();
    req.grant_types = vec!["implicit".into()]; // not supported
    assert!(matches!(
        validate_registration_request(&req),
        Err(DcrError::InvalidGrantType(_))
    ));
}

// ── validate_iat_constraints tests ──────────────────────────

#[test]
fn test_valid_iat_passes() {
    assert!(validate_iat_constraints(&valid_iat(), &valid_request()).is_ok());
}

#[test]
fn test_iat_expired() {
    let mut iat = valid_iat();
    iat.expires_at = Utc::now() - chrono::Duration::hours(1);
    assert!(matches!(
        validate_iat_constraints(&iat, &valid_request()),
        Err(DcrError::IatExpired)
    ));
}

#[test]
fn test_iat_revoked() {
    let mut iat = valid_iat();
    iat.revoked = true;
    assert!(matches!(
        validate_iat_constraints(&iat, &valid_request()),
        Err(DcrError::IatRevoked)
    ));
}

#[test]
fn test_iat_client_limit_reached() {
    let mut iat = valid_iat();
    iat.max_clients = 5;
    iat.clients_registered = 5;
    assert!(matches!(
        validate_iat_constraints(&iat, &valid_request()),
        Err(DcrError::IatClientLimitReached { max: 5 })
    ));
}

#[test]
fn test_iat_unlimited_clients() {
    let mut iat = valid_iat();
    iat.max_clients = 0; // unlimited
    iat.clients_registered = 999;
    assert!(validate_iat_constraints(&iat, &valid_request()).is_ok());
}

#[test]
fn test_iat_scope_not_allowed() {
    let mut req = valid_request();
    req.scope = vec!["openid".into(), "admin".into()]; // admin not in IAT
    assert!(matches!(
        validate_iat_constraints(&valid_iat(), &req),
        Err(DcrError::ScopeNotAllowed(s)) if s == "admin"
    ));
}

#[test]
fn test_iat_empty_scopes_allows_all() {
    let mut iat = valid_iat();
    iat.allowed_scopes = vec![]; // empty = no restriction
    let mut req = valid_request();
    req.scope = vec!["anything".into()];
    assert!(validate_iat_constraints(&iat, &req).is_ok());
}

#[test]
fn test_iat_grant_type_not_allowed() {
    let mut req = valid_request();
    req.grant_types = vec!["client_credentials".into()]; // not in IAT
    assert!(matches!(
        validate_iat_constraints(&valid_iat(), &req),
        Err(DcrError::GrantTypeNotAllowed(_))
    ));
}

#[test]
fn test_iat_redirect_pattern_mismatch() {
    let mut req = valid_request();
    req.redirect_uris = vec!["https://evil.com/callback".into()];
    assert!(matches!(
        validate_iat_constraints(&valid_iat(), &req),
        Err(DcrError::RedirectPatternMismatch(_))
    ));
}

#[test]
fn test_iat_redirect_pattern_match() {
    let req = valid_request(); // https://app.sid.example.com/callback
    let iat = valid_iat(); // pattern: https://*.sid.example.com/*
    assert!(validate_iat_constraints(&iat, &req).is_ok());
}

/// Every refusal of requested metadata names its RFC 7591 §3.2.2 code and
/// field: redirect URI problems are `invalid_redirect_uri`, the rest
/// `invalid_client_metadata`; errors about credentials carry none.
#[test]
fn test_metadata_error_codes() {
    use DcrError::*;
    for (error, expected) in [
        (
            InvalidRedirectUri("x".into()),
            Some(("invalid_redirect_uri", "redirect_uris")),
        ),
        (
            RedirectPatternMismatch("x".into()),
            Some(("invalid_redirect_uri", "redirect_uris")),
        ),
        (
            MissingClientName,
            Some(("invalid_client_metadata", "client_name")),
        ),
        (
            InvalidResponseType("token".into()),
            Some(("invalid_client_metadata", "response_types")),
        ),
        (
            GrantTypeNotAllowed("x".into()),
            Some(("invalid_client_metadata", "grant_types")),
        ),
        (
            ScopeNotAllowed("admin".into()),
            Some(("invalid_client_metadata", "scope")),
        ),
        (IatExpired, None),
        (InvalidRegistrationAccessToken, None),
    ] {
        let label = error.to_string();
        assert_eq!(error.metadata_error(), expected, "{label}");
    }
}

/// Omitted grant and response types get their RFC 7591 §2 defaults; given
/// ones are kept.
#[test]
fn test_metadata_defaults() {
    let (mut grants, mut responses) = (vec![], vec![]);
    apply_metadata_defaults(&mut grants, &mut responses);
    assert_eq!(
        (grants, responses),
        (
            vec!["authorization_code".to_string()],
            vec!["code".to_string()]
        )
    );

    let (mut grants, mut responses) = (
        vec!["client_credentials".to_string()],
        vec!["code".to_string()],
    );
    apply_metadata_defaults(&mut grants, &mut responses);
    assert_eq!(grants, ["client_credentials"]);
}

/// A response type other than `code` is refused as a response type, not as
/// a grant type.
#[test]
fn test_invalid_response_type_is_named() {
    let mut req = valid_request();
    req.response_types = vec!["token".into()];
    assert!(matches!(
        validate_registration_request(&req),
        Err(DcrError::InvalidResponseType(rt)) if rt == "token"
    ));
}

// ── redirect pattern tests ─────────────────────────────────

#[test]
fn test_glob_exact_match() {
    assert!(redirect_pattern_matches(
        "https://example.com/cb",
        "https://example.com/cb"
    ));
    assert!(!redirect_pattern_matches(
        "https://example.com/cb",
        "https://other.com/cb"
    ));
}

#[test]
fn test_glob_wildcard_subdomain() {
    assert!(redirect_pattern_matches(
        "https://*.example.com/callback",
        "https://app.example.com/callback"
    ));
    assert!(!redirect_pattern_matches(
        "https://*.example.com/callback",
        "https://evil.com/callback"
    ));
}

#[test]
fn test_glob_wildcard_path() {
    assert!(redirect_pattern_matches(
        "https://example.com/*",
        "https://example.com/anything"
    ));
}

/// A native application's custom-scheme URI has no host; the pattern
/// compares scheme and path.
#[test]
fn test_glob_custom_scheme() {
    assert!(redirect_pattern_matches(
        "com.example.app:/oauth/*",
        "com.example.app:/oauth/callback"
    ));
    assert!(!redirect_pattern_matches(
        "com.example.app:/oauth/*",
        "com.evil.app:/oauth/callback"
    ));
}

/// Within one component `*` matches any run of characters, including none.
#[test]
fn test_glob_within_one_component() {
    assert!(glob_match("app-*", "app-eu"));
    assert!(glob_match("cb*", "cb"));
    assert!(!glob_match("ab*bc", "abc"));
}

#[test]
fn test_glob_multiple_wildcards() {
    assert!(redirect_pattern_matches(
        "https://*.example.com/*/callback",
        "https://app.example.com/v1/callback"
    ));
}

/// A wildcard stays inside its URI component: in the host it matches within
/// one label and cannot carry the URI to another host (through a path,
/// userinfo or extra labels); in the path it matches within one segment.
#[test]
fn test_glob_wildcard_cannot_leave_its_component() {
    for (pattern, uri) in [
        // The host escapes into the path.
        (
            "https://*.example.com/callback",
            "https://evil.com/.example.com/callback",
        ),
        // The host is set by userinfo.
        (
            "https://*.example.com/callback",
            "https://app.example.com@evil.com/callback",
        ),
        (
            "https://app.example.com/*",
            "https://app.example.com@evil.com/x",
        ),
        // One label, not several.
        (
            "https://*.example.com/callback",
            "https://evil.com.attacker.example.com/callback",
        ),
        // One path segment, not several, and no query smuggled in.
        (
            "https://app.example.com/*/callback",
            "https://app.example.com/a/b/callback",
        ),
        (
            "https://app.example.com/cb*",
            "https://app.example.com/cb?next=https://evil.com",
        ),
        // Scheme and port are exact.
        ("https://*.example.com/cb", "http://app.example.com/cb"),
        (
            "https://*.example.com/cb",
            "https://app.example.com:8443/cb",
        ),
    ] {
        assert!(
            !redirect_pattern_matches(pattern, uri),
            "{pattern} admitted {uri}"
        );
    }
}

/// Matching compares the parsed URI, so equivalent spellings of an allowed
/// URI match: host case (RFC 3986 §3.2.2) and the scheme's default port.
#[test]
fn test_glob_compares_parsed_uris() {
    assert!(redirect_pattern_matches(
        "https://*.example.com/callback",
        "https://APP.Example.com/callback"
    ));
    assert!(redirect_pattern_matches(
        "https://*.example.com/callback",
        "https://app.example.com:443/callback"
    ));
}
