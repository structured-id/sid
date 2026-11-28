use super::*;

fn make_public_client() -> OAuth2Client {
    OAuth2Client {
        client_id: "test-public".to_string(),
        project_id: ProjectId::SYSTEM,
        application_id: ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Spa,
        client_secret_hash: None,
        jwks: None,
        participant_admission: None,
        redirect_uris: vec![
            "https://app.sid.example.com/callback".to_string(),
            "https://app.sid.example.com/auth".to_string(),
        ],
        allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: "Test Public".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Timestamp::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec!["https://app.sid.example.com/signed-out".to_string()],
        claim_mappings: vec![],
        claim_requests: vec![],
        org_id: None,
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        revision: 0,
        created_at: Timestamp::now(),
    }
}

fn make_confidential_client() -> OAuth2Client {
    OAuth2Client {
        client_id: "test-confidential".to_string(),
        project_id: ProjectId::SYSTEM,
        application_id: ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: Some(b"$argon2id$fake_hash".to_vec()),
        jwks: None,
        participant_admission: None,
        redirect_uris: vec!["https://api.sid.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".into(), "profile".into()],
        grant_types: vec![
            "authorization_code".into(),
            "client_credentials".into(),
            "refresh_token".into(),
        ],
        client_name: "Test Confidential".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Timestamp::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: Some(AuthLevel::Standard),
        required_amr: vec!["pwd".into()],
        enforcement_mode: EnforcementMode::Hard,
        min_device_assurance: Some(DeviceAssurance::Trusted),
        require_verified_email: Some(true),
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        claim_requests: vec![],
        org_id: None,
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        revision: 0,
        created_at: Timestamp::now(),
    }
}

/// Only a registered post-logout URI is followed, compared exactly: a prefix,
/// another query or a redirect URI of the client does not qualify (OIDC
/// RP-Initiated Logout 1.0 §3).
#[test]
fn post_logout_redirect_uri_matches_exactly() {
    let client = make_public_client();
    assert!(client.is_post_logout_redirect_uri_allowed("https://app.sid.example.com/signed-out"));
    for other in [
        "https://app.sid.example.com/signed-out/",
        "https://app.sid.example.com/signed-out?x=1",
        "https://app.sid.example.com/signed",
        "https://app.sid.example.com/callback",
    ] {
        assert!(
            !client.is_post_logout_redirect_uri_allowed(other),
            "{other}"
        );
    }
    assert!(!make_confidential_client().is_post_logout_redirect_uri_allowed(""));
}

#[test]
fn test_public_client() {
    assert!(make_public_client().is_public());
}

#[test]
fn test_confidential_client() {
    assert!(!make_confidential_client().is_public());
}

/// A client is public by its registered method, not by lacking a secret: a
/// `private_key_jwt` client has no secret and must still authenticate.
#[test]
fn a_key_client_is_confidential_and_needs_its_keys() {
    let mut client = make_confidential_client();
    client.client_secret_hash = None;
    client.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    assert!(!client.is_public());
    assert!(client.credential_problem().is_some());
    client.jwks = Some(
        ClientKeySet::from_json(
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k"}]}"#,
        )
        .unwrap(),
    );
    assert_eq!(client.credential_problem(), None);
}

/// A secret method without a secret could never authenticate.
#[test]
fn a_secret_client_needs_its_secret() {
    let mut client = make_confidential_client();
    assert_eq!(client.credential_problem(), None);
    client.client_secret_hash = None;
    assert!(client.credential_problem().is_some());
}

#[test]
fn test_redirect_uri_allowed() {
    let client = make_public_client();
    assert!(client.is_redirect_uri_allowed("https://app.sid.example.com/callback"));
    assert!(client.is_redirect_uri_allowed("https://app.sid.example.com/auth"));
}

#[test]
fn test_redirect_uri_not_allowed() {
    let client = make_public_client();
    assert!(!client.is_redirect_uri_allowed("https://evil.com/callback"));
    assert!(!client.is_redirect_uri_allowed(""));
}

#[test]
fn test_redirect_uri_exact_match() {
    let client = make_public_client();
    // Trailing slash = different URI
    assert!(!client.is_redirect_uri_allowed("https://app.sid.example.com/callback/"));
}

/// A native client's loopback IP redirect is allowed on any port, since the
/// application binds whichever port is free (RFC 8252 §7.3); everything else
/// about it still matches exactly.
/// Bug prevented: exact matching refused every native application that
/// listens on an ephemeral port.
#[test]
fn a_native_loopback_redirect_is_allowed_on_any_port() {
    let mut client = make_public_client();
    client.application_type = ApplicationType::Native;
    client.redirect_uris = vec![
        "http://127.0.0.1/callback".into(),
        "http://[::1]:7000/callback".into(),
        "http://localhost:7000/callback".into(),
        "com.example.app:/callback".into(),
    ];
    assert!(client.is_redirect_uri_allowed("http://127.0.0.1/callback"));
    assert!(client.is_redirect_uri_allowed("http://127.0.0.1:53211/callback"));
    assert!(client.is_redirect_uri_allowed("http://[::1]:53211/callback"));
    assert!(client.is_redirect_uri_allowed("http://[::1]/callback"));
    assert!(client.is_redirect_uri_allowed("com.example.app:/callback"));

    for refused in [
        // Another path, a query, another address family or scheme.
        "http://127.0.0.1:53211/other",
        "http://127.0.0.1:53211/callback?x=1",
        "https://127.0.0.1:53211/callback",
        "http://127.0.0.2:53211/callback",
        // Credentials or a fragment never match.
        "http://user@127.0.0.1:53211/callback",
        "http://127.0.0.1:53211/callback#f",
        // The rule covers loopback IP literals; a host name stays exact
        // (RFC 8252 §8.3).
        "http://localhost:53211/callback",
        // Not a URI.
        "127.0.0.1:53211/callback",
        // Only the port may differ: a spelling a URL parser would
        // normalize into the registered one is another string.
        "http://127.0.0.1:53211/other/../callback",
        "http://127.0.0.1:53211/./callback",
        "http://127.1:53211/callback",
        "http://0x7f.0.0.1:53211/callback",
        "HTTP://127.0.0.1:53211/callback",
        "http://[0:0:0:0:0:0:0:1]:53211/callback",
        "http://127.0.0.1:53211/callback/",
        "http://127.0.0.1:/callback",
        "http://127.0.0.1:53211x/callback",
    ] {
        assert!(!client.is_redirect_uri_allowed(refused), "{refused}");
    }
}

/// A web or single-page client's loopback redirect matches exactly, port
/// included: the any-port rule is the native application's alone.
/// Bug prevented: extending the native rule to browser clients, where the
/// port is part of the origin another local program may hold.
#[test]
fn a_web_loopback_redirect_keeps_its_port() {
    for application_type in [ApplicationType::Web, ApplicationType::Spa] {
        let mut client = make_public_client();
        client.application_type = application_type;
        client.redirect_uris = vec!["http://127.0.0.1:3000/callback".into()];
        assert!(client.is_redirect_uri_allowed("http://127.0.0.1:3000/callback"));
        assert!(
            !client.is_redirect_uri_allowed("http://127.0.0.1:3001/callback"),
            "{application_type:?}"
        );
    }
}

#[test]
fn test_grant_type_allowed() {
    let client = make_public_client();
    assert!(client.is_grant_type_allowed("authorization_code"));
    assert!(client.is_grant_type_allowed("refresh_token"));
    assert!(!client.is_grant_type_allowed("client_credentials"));
}

#[test]
fn test_confidential_grant_types() {
    let client = make_confidential_client();
    assert!(client.is_grant_type_allowed("client_credentials"));
}

#[test]
fn test_filter_scopes_all_allowed() {
    let client = make_public_client();
    let requested = vec!["openid".into(), "profile".into()];
    let filtered = client.filter_scopes(&requested);
    assert_eq!(filtered, vec!["openid", "profile"]);
}

#[test]
fn test_filter_scopes_removes_disallowed() {
    let client = make_public_client();
    let requested = vec!["openid".into(), "admin".into(), "profile".into()];
    let filtered = client.filter_scopes(&requested);
    assert_eq!(filtered, vec!["openid", "profile"]);
}

#[test]
fn test_filter_scopes_empty_request() {
    let client = make_public_client();
    let filtered = client.filter_scopes(&[]);
    assert!(filtered.is_empty());
}

#[test]
fn test_filter_scopes_no_match() {
    let client = make_public_client();
    let requested = vec!["admin".into(), "superuser".into()];
    let filtered = client.filter_scopes(&requested);
    assert!(filtered.is_empty());
}

// ── ApplicationType tests ────────────────────────────────────

#[test]
fn test_application_type_default() {
    assert_eq!(ApplicationType::default(), ApplicationType::Web);
}

#[test]
fn test_application_type_as_str() {
    assert_eq!(ApplicationType::Web.as_str(), "web");
    assert_eq!(ApplicationType::Native.as_str(), "native");
    assert_eq!(ApplicationType::Api.as_str(), "api");
    assert_eq!(ApplicationType::Spa.as_str(), "spa");
}

#[test]
fn test_application_type_requires_secret() {
    assert!(ApplicationType::Web.requires_secret());
    assert!(ApplicationType::Api.requires_secret());
    assert!(!ApplicationType::Native.requires_secret());
    assert!(!ApplicationType::Spa.requires_secret());
}

#[test]
fn test_application_type_uses_redirect_uris() {
    assert!(ApplicationType::Web.uses_redirect_uris());
    assert!(ApplicationType::Native.uses_redirect_uris());
    assert!(ApplicationType::Spa.uses_redirect_uris());
    assert!(!ApplicationType::Api.uses_redirect_uris());
}

#[test]
fn test_application_type_serde_roundtrip() {
    let t = ApplicationType::Native;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"native\"");
    let parsed: ApplicationType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ApplicationType::Native);
}

#[test]
fn test_application_type_display() {
    assert_eq!(format!("{}", ApplicationType::Api), "api");
}

// ── Security policy override tests ──────────────────────────

#[test]
fn test_public_client_no_policy_overrides() {
    let client = make_public_client();
    assert!(client.required_acr.is_none());
    assert!(client.required_amr.is_empty());
    assert_eq!(client.enforcement_mode, EnforcementMode::Audit);
    assert!(client.min_device_assurance.is_none());
    assert!(client.require_verified_email.is_none());
    assert!(client.require_verified_phone.is_none());
}

#[test]
fn test_confidential_client_policy_overrides() {
    let client = make_confidential_client();
    assert_eq!(client.required_acr, Some(AuthLevel::Standard));
    assert_eq!(client.required_amr, vec!["pwd"]);
    assert_eq!(client.enforcement_mode, EnforcementMode::Hard);
    assert_eq!(client.min_device_assurance, Some(DeviceAssurance::Trusted));
    assert_eq!(client.require_verified_email, Some(true));
    assert!(client.require_verified_phone.is_none());
}

#[test]
fn test_enforcement_mode_default() {
    assert_eq!(EnforcementMode::default(), EnforcementMode::Audit);
}

#[test]
fn test_enforcement_mode_as_str() {
    assert_eq!(EnforcementMode::Audit.as_str(), "audit");
    assert_eq!(EnforcementMode::Soft.as_str(), "soft");
    assert_eq!(EnforcementMode::Hard.as_str(), "hard");
}

#[test]
fn test_enforcement_mode_serde_roundtrip() {
    let m = EnforcementMode::Hard;
    let json = serde_json::to_string(&m).unwrap();
    assert_eq!(json, "\"hard\"");
    let parsed: EnforcementMode = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, EnforcementMode::Hard);
}

// ── SubjectType tests ───────────────────────────────────────

#[test]
fn test_subject_type_default_is_public() {
    assert_eq!(SubjectType::default(), SubjectType::Public);
}

#[test]
fn test_subject_type_as_str() {
    assert_eq!(SubjectType::Pairwise.as_str(), "pairwise");
    assert_eq!(SubjectType::Public.as_str(), "public");
}

#[test]
fn test_subject_type_display() {
    assert_eq!(format!("{}", SubjectType::Pairwise), "pairwise");
    assert_eq!(format!("{}", SubjectType::Public), "public");
}

#[test]
fn test_subject_type_serde_roundtrip() {
    let s = SubjectType::Pairwise;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"pairwise\"");
    let parsed: SubjectType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SubjectType::Pairwise);
}

// ── TokenEndpointAuthMethod tests ───────────────────────────

/// A registration that names no method gets `client_secret_basic`
/// (RFC 7591 §2).
#[test]
fn test_token_endpoint_auth_method_default() {
    assert_eq!(
        TokenEndpointAuthMethod::default(),
        TokenEndpointAuthMethod::ClientSecretBasic
    );
}

#[test]
fn test_token_endpoint_auth_method_as_str() {
    assert_eq!(
        TokenEndpointAuthMethod::ClientSecretPost.as_str(),
        "client_secret_post"
    );
    assert_eq!(
        TokenEndpointAuthMethod::ClientSecretBasic.as_str(),
        "client_secret_basic"
    );
    assert_eq!(TokenEndpointAuthMethod::None.as_str(), "none");
    assert_eq!(
        TokenEndpointAuthMethod::PrivateKeyJwt.as_str(),
        "private_key_jwt"
    );
}

#[test]
fn test_token_endpoint_auth_method_serde_roundtrip() {
    let m = TokenEndpointAuthMethod::PrivateKeyJwt;
    let json = serde_json::to_string(&m).unwrap();
    assert_eq!(json, "\"private_key_jwt\"");
    let parsed: TokenEndpointAuthMethod = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, TokenEndpointAuthMethod::PrivateKeyJwt);
}

// ── RegistrationPolicy tests ────────────────────────────────

#[test]
fn test_registration_policy_default() {
    assert_eq!(
        RegistrationPolicy::default(),
        RegistrationPolicy::AdminApproval
    );
}

#[test]
fn test_registration_policy_as_str() {
    assert_eq!(RegistrationPolicy::AdminApproval.as_str(), "admin_approval");
    assert_eq!(RegistrationPolicy::Authenticated.as_str(), "authenticated");
}

#[test]
fn test_registration_policy_serde_roundtrip() {
    let p = RegistrationPolicy::Authenticated;
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(json, "\"authenticated\"");
    let parsed: RegistrationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, RegistrationPolicy::Authenticated);
}

// ── InitialAccessToken tests ────────────────────────────────

#[test]
fn test_initial_access_token_id_unique() {
    let id1 = InitialAccessTokenId::generate();
    let id2 = InitialAccessTokenId::generate();
    assert_ne!(id1, id2);
}

// ── DCR fields on client tests ──────────────────────────────

#[test]
fn test_public_client_dcr_defaults() {
    let client = make_public_client();
    assert_eq!(
        client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::None
    );
    assert_eq!(client.response_types, vec!["code"]);
    assert_eq!(client.subject_type, SubjectType::Public);
    assert!(client.sector_identifier_uri.is_none());
    assert!(client.contacts.is_empty());
    assert!(client.client_secret_expires_at.is_none());
    assert!(client.registration_iat.is_none());
    assert!(client.registration_access_token_hash.is_none());
}

#[test]
fn test_confidential_client_dcr_defaults() {
    let client = make_confidential_client();
    assert_eq!(
        client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::ClientSecretPost
    );
    assert!(client.registration_iat.is_none());
}

#[test]
fn test_login_strategy_default() {
    assert_eq!(LoginStrategy::default(), LoginStrategy::LocalFirst);
}

#[test]
fn test_login_strategy_as_str_roundtrip() {
    let strategies = [
        LoginStrategy::LocalFirst,
        LoginStrategy::ShowBoth,
        LoginStrategy::FederationFirst,
        LoginStrategy::FederationOnly,
    ];
    for s in strategies {
        assert_eq!(s.as_str().parse::<LoginStrategy>(), Ok(s));
    }
}

/// Stored client settings read back as written, and a value no variant
/// writes is refused: an unknown subject type is never read as `public`
/// (which would hand a pairwise client the ProfileId), an unknown mode never
/// as `audit`, and a `recognized` device requirement never as `unknown`.
#[test]
fn test_stored_client_settings_parse_strictly() {
    fn check<T>(variants: &[T], stored: impl Fn(&T) -> &'static str)
    where
        T: std::str::FromStr<Err = String> + PartialEq + std::fmt::Debug,
    {
        for v in variants {
            assert_eq!(stored(v).parse::<T>().as_ref(), Ok(v));
        }
        assert!("unknown_value".parse::<T>().is_err());
        assert!("".parse::<T>().is_err());
    }
    check(
        &[LoginStrategy::LocalFirst, LoginStrategy::FederationOnly],
        LoginStrategy::as_str,
    );
    check(
        &[SubjectType::Public, SubjectType::Pairwise],
        SubjectType::as_str,
    );
    check(
        &[
            TokenEndpointAuthMethod::ClientSecretPost,
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::None,
            TokenEndpointAuthMethod::PrivateKeyJwt,
        ],
        TokenEndpointAuthMethod::as_str,
    );
    check(
        &[
            RegistrationPolicy::AdminApproval,
            RegistrationPolicy::Authenticated,
        ],
        RegistrationPolicy::as_str,
    );
    check(
        &[
            ApplicationType::Web,
            ApplicationType::Native,
            ApplicationType::Api,
            ApplicationType::Spa,
        ],
        ApplicationType::as_str,
    );
    check(
        &[
            EnforcementMode::Audit,
            EnforcementMode::Soft,
            EnforcementMode::Hard,
        ],
        EnforcementMode::as_str,
    );
    check(
        &[
            DeviceAssurance::Unknown,
            DeviceAssurance::Recognized,
            DeviceAssurance::Trusted,
            DeviceAssurance::Managed,
        ],
        DeviceAssurance::as_str,
    );
}

#[test]
fn test_login_strategy_serde_roundtrip() {
    let s = LoginStrategy::FederationFirst;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"federation_first\"");
    let parsed: LoginStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, LoginStrategy::FederationFirst);
}

#[test]
fn test_login_strategy_display() {
    assert_eq!(LoginStrategy::ShowBoth.to_string(), "show_both");
    assert_eq!(LoginStrategy::FederationOnly.to_string(), "federation_only");
}
