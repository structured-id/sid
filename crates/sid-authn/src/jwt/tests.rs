use super::*;

fn generate_test_keys() -> (Vec<u8>, Vec<u8>) {
    let private_pem = include_bytes!("../../tests/fixtures/test_ed25519_private.pem");
    let public_pem = include_bytes!("../../tests/fixtures/test_ed25519_public.pem");
    (private_pem.to_vec(), public_pem.to_vec())
}

fn create_test_profile() -> Profile {
    let mut profile = Profile::new(Some("alice"));
    profile.given_name = Some("Alice".to_string());
    profile
}

fn create_test_email() -> ProfileEmail {
    ProfileEmail {
        id: sid_core::models::ProfileEmailId::new(),
        profile_id: sid_core::models::ProfileId::generate(),
        email: "alice@sid.example.com".to_string(),
        label: sid_core::models::EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn create_test_session(profile: &Profile) -> Session {
    Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    )
}

/// Helper: issue_id_token with default primary email, no phone
fn issue_test_id_token(
    jwt: &JwtService,
    profile: &Profile,
    session: &Session,
    nonce: Option<&str>,
) -> String {
    let email = create_test_email();
    jwt.issue_id_token(
        &profile.id.to_string(),
        profile,
        session,
        "test-client",
        nonce,
        Some(&email),
        None,
    )
    .expect("ID token issuance failed")
}

#[test]
fn test_jwt_roundtrip() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let session = create_test_session(&profile);
    let scopes = vec!["openid".to_string(), "profile".to_string()];

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &scopes,
            None,
            None,
        )
        .expect("Token issuance failed");

    let claims = jwt
        .validate_access_token(&token)
        .expect("Token validation failed");

    assert_eq!(claims.sub, profile.id.to_string());
    assert_eq!(claims.iss, "https://sid.example.com");
    assert_eq!(claims.scope, "openid profile");
    assert_eq!(claims.sid, session.id.to_string());
    assert_eq!(claims.auth_time, session.authenticated_at.timestamp());
}

/// An application token is typed `at+jwt`, names the protected resource it
/// is for as `aud` and the requesting client as `client_id`, which need not
/// be in `aud` (RFC 9068 §2.2, auth/oauth-resource-model.md); the
/// installation's own session token keeps `aud` = issuer, no `client_id`
/// and no type. An application token is not accepted where a session token
/// is expected.
#[test]
fn test_access_token_audience() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();
    let profile = create_test_profile();
    let session = create_test_session(&profile);
    let scopes = vec!["openid".to_string()];
    let payload = |token: &str| -> serde_json::Value {
        let part = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    };

    let app = jwt
        .access_token_signed_by(
            &jwt,
            TokenAudience::Resource {
                indicator: "https://resources.example/orders",
                client_id: "banking-app",
            },
            "subject",
            None,
            &profile,
            &session,
            &scopes,
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        jsonwebtoken::decode_header(&app).unwrap().typ.as_deref(),
        Some(ACCESS_TOKEN_TYP)
    );
    let claims = payload(&app);
    assert_eq!(
        claims["aud"],
        serde_json::json!(["https://resources.example/orders"])
    );
    assert_eq!(claims["client_id"], "banking-app");
    assert!(jwt.validate_access_token(&app).is_err());

    let own = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &scopes,
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        jsonwebtoken::decode_header(&own).unwrap().typ.as_deref(),
        Some("JWT")
    );
    let claims = payload(&own);
    assert_eq!(
        claims["aud"],
        serde_json::json!(["https://sid.example.com"])
    );
    assert!(claims.get("client_id").is_none(), "{claims}");
    assert!(jwt.validate_access_token(&own).is_ok());
}

/// A client acting for itself gets an `at+jwt` for one resource that names
/// its own principal as `sub` and the credential it authenticated with as
/// `sid` (so the resource can check both again), carries no ProfileId, no
/// roles and no human authentication, and lives no longer than the client's
/// own cap (RFC 9068 §2.2, RFC 6749 §4.4).
#[test]
fn test_client_access_token() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();
    let scopes = vec!["tenant.read".to_string()];
    let payload = |token: &str| -> serde_json::Value {
        let part = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    };
    let grant = |max_lifetime| ClientGrant {
        resource: "https://resources.sid.example.com/tenants",
        client_id: "mu_orchestrator",
        subject: "mu_orchestrator",
        credential: "kid_abc",
        scopes: &scopes,
        dpop: None,
        max_lifetime,
    };

    let token = jwt
        .client_access_token_signed_by(&jwt, &grant(None))
        .unwrap();
    assert_eq!(
        jsonwebtoken::decode_header(&token).unwrap().typ.as_deref(),
        Some(ACCESS_TOKEN_TYP)
    );
    let claims = payload(&token);
    assert_eq!(
        claims["aud"],
        serde_json::json!(["https://resources.sid.example.com/tenants"])
    );
    assert_eq!(claims["client_id"], "mu_orchestrator");
    assert_eq!(claims["sub"], "mu_orchestrator");
    assert_eq!(claims["sid"], "kid_abc");
    assert_eq!(claims["scope"], "tenant.read");
    assert!(claims.get("pid").is_none(), "{claims}");
    assert!(claims.get("roles").is_none(), "{claims}");
    assert!(claims.get("amr").is_none(), "{claims}");
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        jwt.access_token_ttl_secs()
    );

    // A shorter cap of the client wins; a longer one does not extend.
    let capped = payload(
        &jwt.client_access_token_signed_by(&jwt, &grant(Some(Duration::seconds(60))))
            .unwrap(),
    );
    assert_eq!(
        capped["exp"].as_i64().unwrap() - capped["iat"].as_i64().unwrap(),
        60
    );
    let longer = payload(
        &jwt.client_access_token_signed_by(&jwt, &grant(Some(Duration::days(1))))
            .unwrap(),
    );
    assert_eq!(
        longer["exp"].as_i64().unwrap() - longer["iat"].as_i64().unwrap(),
        jwt.access_token_ttl_secs()
    );
}

#[test]
fn test_id_token() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let session = create_test_session(&profile);

    let token = issue_test_id_token(&jwt, &profile, &session, Some("test-nonce-123"));

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);
    validation.set_audience(&["test-client"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).expect("Decode failed");

    assert_eq!(token_data.claims.sub, profile.id.to_string());
    assert_eq!(token_data.claims.aud, "test-client");
    assert_eq!(token_data.claims.nonce.as_deref(), Some("test-nonce-123"));
    assert_eq!(
        token_data.claims.email.as_deref(),
        Some("alice@sid.example.com")
    );
    assert_eq!(token_data.claims.email_verified, Some(true));
    assert_eq!(
        token_data.claims.auth_time,
        session.authenticated_at.timestamp()
    );
}

#[test]
fn test_expired_token_rejected() {
    let (private_pem, public_pem) = generate_test_keys();
    let mut jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    // Set TTL to negative to create an expired token (must exceed jsonwebtoken's 60s leeway)
    jwt.access_token_ttl = Duration::seconds(-120);

    let profile = create_test_profile();
    let session = create_test_session(&profile);

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &[],
            None,
            None,
        )
        .expect("Token issuance failed");

    let result = jwt.validate_access_token(&token);
    assert!(result.is_err());
}

#[test]
fn test_roles_claim_in_access_token() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let mut profile = create_test_profile();
    profile.roles = vec!["admin".to_string(), "operator".to_string()];
    let session = create_test_session(&profile);

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap();
    let claims = jwt.validate_access_token(&token).unwrap();

    assert_eq!(claims.roles, "admin operator");
}

#[test]
fn test_amr_claim_in_access_token() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let mut session = create_test_session(&profile);
    {
        let mut active = session.as_active().unwrap();
        active.add_amr("pwd");
        active.add_amr("otp");
    }

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap();
    let claims = jwt.validate_access_token(&token).unwrap();

    assert_eq!(claims.amr, vec!["pwd", "otp"]);
}

#[test]
fn test_amr_claim_in_id_token() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let mut session = create_test_session(&profile);
    session.as_active().unwrap().add_amr("hwk");

    let token = issue_test_id_token(&jwt, &profile, &session, None);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).expect("Decode failed");

    assert_eq!(token_data.claims.amr, vec!["hwk"]);
}

#[test]
fn test_empty_amr_not_serialized() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let session = create_test_session(&profile); // amr = []

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap();
    let claims = jwt.validate_access_token(&token).unwrap();

    assert!(claims.amr.is_empty());
}

#[test]
fn test_empty_roles_not_serialized() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile(); // roles = []
    let session = create_test_session(&profile);

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap();
    let claims = jwt.validate_access_token(&token).unwrap();

    assert!(claims.roles.is_empty());
}

#[test]
fn test_jwks_generation() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let jwks = jwt.jwks();
    assert_eq!(jwks.keys.len(), 1);

    let key = &jwks.keys[0];
    assert_eq!(key.kty, "OKP");
    assert_eq!(key.alg, "EdDSA");
    assert_eq!(key.crv, "Ed25519");
    assert!(!key.x.is_empty());
    assert_eq!(key.kid, jwt.key_id);
}

/// `auth_time` is when the user last authenticated (OIDC Core §2), which a
/// step-up moves forward; it is not when the session was created.
#[test]
fn test_auth_time_is_last_authentication() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let mut session = create_test_session(&profile);
    session.created_at -= Duration::hours(2);
    session.authenticated_at -= Duration::minutes(10);

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &[],
            None,
            None,
        )
        .unwrap();
    let claims = jwt.validate_access_token(&token).unwrap();

    assert_eq!(claims.auth_time, session.authenticated_at.timestamp());
    assert!(claims.auth_time <= claims.iat);
}

// ── Custom claims tests (AUTH-017) ────────────────────────────

#[test]
fn test_access_token_with_custom_claims() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let session = create_test_session(&profile);

    let mut custom = std::collections::HashMap::new();
    custom.insert("department".to_string(), serde_json::json!("engineering"));
    custom.insert("employee_id".to_string(), serde_json::json!("EMP-42"));

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            None,
            Some(&custom),
        )
        .unwrap();

    // Decode raw JWT payload to verify custom claims are present
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(payload["department"], "engineering");
    assert_eq!(payload["employee_id"], "EMP-42");
    // Standard claims still present
    assert_eq!(payload["iss"], "https://sid.example.com");
    assert_eq!(payload["scope"], "openid");
}

#[test]
fn test_access_token_empty_custom_claims_same_as_none() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let session = create_test_session(&profile);
    let empty = std::collections::HashMap::new();

    // Both should succeed and produce valid tokens
    let t1 = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap();
    let t2 = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            None,
            Some(&empty),
        )
        .unwrap();

    let c1 = jwt.validate_access_token(&t1).unwrap();
    let c2 = jwt.validate_access_token(&t2).unwrap();
    assert_eq!(c1.sub, c2.sub);
    assert_eq!(c1.scope, c2.scope);
}

// ── Logout token tests ──────────────────────────────────────

// ── Impersonation token tests (TOKEN-009) ─────────────────────

#[test]
fn test_impersonation_token_roundtrip() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let session = Session::new(
        sid_core::models::ProfileId::generate(),
        "127.0.0.1".into(),
        Utc::now() + Duration::seconds(300),
    );
    let token = jwt
        .issue_impersonation_token(
            "target-profile-id",
            &session,
            "mu_ci_deploy",
            &["read".into(), "write".into()],
        )
        .unwrap();

    let claims = jwt.validate_access_token(&token).unwrap();
    assert_eq!(claims.sub, "target-profile-id");
    assert_eq!(claims.scope, "read write");
    assert_eq!(claims.acr, "urn:sid:acr:impersonation");
    assert_eq!(claims.amr, vec!["token_exchange"]);
    assert_eq!(claims.sid, session.id.to_string());
    assert!(claims.act.is_some());
    assert_eq!(claims.act.unwrap().sub, "mu_ci_deploy");
}

/// An impersonation token never outlives the impersonation session it
/// belongs to.
#[test]
fn test_impersonation_token_ends_with_its_session() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");
    let session = Session::new(
        sid_core::models::ProfileId::generate(),
        "127.0.0.1".into(),
        Utc::now() + Duration::seconds(60),
    );

    let token = jwt
        .issue_impersonation_token("target", &session, "actor", &["read".into()])
        .unwrap();

    let claims = jwt.validate_access_token(&token).unwrap();
    assert_eq!(claims.exp, session.expires_at.timestamp());
}

#[test]
fn test_impersonation_token_ttl_capped_at_300s() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let session = Session::new(
        sid_core::models::ProfileId::generate(),
        "127.0.0.1".into(),
        Utc::now() + Duration::hours(1),
    );
    let token = jwt
        .issue_impersonation_token("target", &session, "actor", &["read".into()])
        .unwrap();

    let claims = jwt.validate_access_token(&token).unwrap();
    let ttl = claims.exp - claims.iat;
    assert_eq!(ttl, 300);
}

#[test]
fn test_impersonation_token_act_not_in_regular_token() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let session = create_test_session(&profile);

    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".into()],
            None,
            None,
        )
        .unwrap();

    let claims = jwt.validate_access_token(&token).unwrap();
    assert!(claims.act.is_none());
}

#[test]
fn test_reissue_elevated_token() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");

    let profile = create_test_profile();
    let mut session = create_test_session(&profile);
    let scopes = vec!["openid".into(), "profile".into()];

    // Issue original token at Basic level.
    let original_token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &scopes,
            None,
            None,
        )
        .unwrap();
    let original_claims = jwt.validate_access_token(&original_token).unwrap();
    assert_eq!(original_claims.acr, "urn:sid:acr:basic");

    // Elevate session to Standard via type-state gateway.
    {
        let mut active = session.as_active().unwrap();
        active.elevate(sid_core::models::session::AuthLevel::Standard);
        active.add_amr("otp");
    }

    // Reissue with elevated state.
    let elevated_token = jwt
        .reissue_elevated_token(&original_claims, &session)
        .unwrap();
    let elevated_claims = jwt.validate_access_token(&elevated_token).unwrap();

    // ACR and AMR updated.
    assert_eq!(elevated_claims.acr, "urn:sid:acr:standard");
    assert!(elevated_claims.amr.contains(&"otp".to_string()));

    // Sub, pid, scope preserved.
    assert_eq!(elevated_claims.sub, original_claims.sub);
    assert_eq!(elevated_claims.pid, original_claims.pid);
    assert_eq!(elevated_claims.scope, original_claims.scope);

    // New JTI (distinct from original).
    assert_ne!(elevated_claims.jti, original_claims.jti);
}

/// A token claiming a step-up does not outlive the step-up, and once the
/// step-up has lapsed new tokens carry the session's own level again.
#[test]
fn test_elevated_token_ends_with_its_elevation() {
    use sid_core::models::session::{AuthLevel, Elevation};

    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JwtService creation failed");
    let profile = create_test_profile();
    let mut session = create_test_session(&profile);
    session.as_active().unwrap().elevate(AuthLevel::Standard);
    let until = Utc::now() + Duration::seconds(90);
    session.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until,
    });

    let issue = |session: &Session| {
        let token = jwt
            .issue_access_token(
                &profile.id.to_string(),
                Some(&profile.id.to_string()),
                &profile,
                session,
                &["openid".into()],
                None,
                None,
            )
            .unwrap();
        jwt.validate_access_token(&token).unwrap()
    };

    let elevated = issue(&session);
    assert_eq!(elevated.acr, "urn:sid:acr:elevated");
    assert_eq!(elevated.exp, until.timestamp(), "outlives its step-up");

    session.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until: Utc::now() - Duration::seconds(1),
    });
    let lapsed = issue(&session);
    assert_eq!(lapsed.acr, "urn:sid:acr:standard");
    assert!(lapsed.exp > until.timestamp());
}

// ── OIDC §5.1 Standard Claims tests ──

#[test]
fn test_id_token_structured_name_claims() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let mut profile = create_test_profile();
    profile.given_name = Some("Alice".to_string());
    profile.family_name = Some("Smith".to_string());
    profile.middle_name = Some("Marie".to_string());
    let session = create_test_session(&profile);

    let token = issue_test_id_token(&jwt, &profile, &session, None);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    assert_eq!(token_data.claims.given_name.as_deref(), Some("Alice"));
    assert_eq!(token_data.claims.family_name.as_deref(), Some("Smith"));
    assert_eq!(token_data.claims.middle_name.as_deref(), Some("Marie"));
    assert_eq!(token_data.claims.name.as_deref(), Some("Alice Marie Smith"));
}

#[test]
fn test_id_token_mononym_no_family_name() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let mut profile = create_test_profile();
    profile.given_name = Some("Bono".to_string());
    profile.family_name = None;
    profile.middle_name = None;
    let session = create_test_session(&profile);

    let token = issue_test_id_token(&jwt, &profile, &session, None);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    assert_eq!(token_data.claims.given_name.as_deref(), Some("Bono"));
    assert!(token_data.claims.family_name.is_none());
    assert!(token_data.claims.middle_name.is_none());
    assert_eq!(token_data.claims.name.as_deref(), Some("Bono"));
}

#[test]
fn test_id_token_no_name_fields() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let mut profile = create_test_profile();
    profile.given_name = None;
    profile.family_name = None;
    profile.middle_name = None;
    let session = create_test_session(&profile);

    let token = issue_test_id_token(&jwt, &profile, &session, None);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    assert!(token_data.claims.given_name.is_none());
    assert!(token_data.claims.family_name.is_none());
    assert!(token_data.claims.middle_name.is_none());
    assert!(token_data.claims.name.is_none());
}

#[test]
fn test_id_token_phone_claims_absent_without_profile_phone() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let profile = create_test_profile();
    let session = create_test_session(&profile);

    let token = issue_test_id_token(&jwt, &profile, &session, None);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    // Profile.phone is None → phone claims absent
    assert!(token_data.claims.phone_number.is_none());
    assert!(token_data.claims.phone_number_verified.is_none());
}

#[test]
fn test_id_token_phone_claims_present_when_verified() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let profile = create_test_profile();
    let session = create_test_session(&profile);
    let email = create_test_email();
    let phone = ProfilePhone {
        id: sid_core::models::ProfilePhoneId::new(),
        profile_id: profile.id,
        e164: 380501234567,
        extension: None,
        label: sid_core::models::PhoneLabel::Mobile,
        custom_label: None,
        is_primary: true,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: true,
        verified_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let token = jwt
        .issue_id_token(
            &profile.id.to_string(),
            &profile,
            &session,
            "test-client",
            None,
            Some(&email),
            Some(&phone),
        )
        .unwrap();

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    assert_eq!(
        token_data.claims.phone_number.as_deref(),
        Some("+380501234567")
    );
    assert_eq!(token_data.claims.phone_number_verified, Some(true));
}

#[test]
fn test_id_token_phone_claims_present_unverified() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let profile = create_test_profile();
    let session = create_test_session(&profile);
    let email = create_test_email();
    let phone = ProfilePhone {
        id: sid_core::models::ProfilePhoneId::new(),
        profile_id: profile.id,
        e164: 14155551234,
        extension: None,
        label: sid_core::models::PhoneLabel::Mobile,
        custom_label: None,
        is_primary: true,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let token = jwt
        .issue_id_token(
            &profile.id.to_string(),
            &profile,
            &session,
            "test-client",
            None,
            Some(&email),
            Some(&phone),
        )
        .unwrap();

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    assert_eq!(
        token_data.claims.phone_number.as_deref(),
        Some("+14155551234")
    );
    assert_eq!(token_data.claims.phone_number_verified, Some(false));
}

#[test]
fn test_id_token_updated_at_claim() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let profile = create_test_profile();
    let expected_updated_at = profile.updated_at.timestamp();
    let session = create_test_session(&profile);

    let token = issue_test_id_token(&jwt, &profile, &session, None);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    assert_eq!(token_data.claims.updated_at, Some(expected_updated_at));
}

#[test]
fn test_id_token_email_verified_absent_when_no_email() {
    let (private_pem, public_pem) = generate_test_keys();
    let jwt = JwtService::new(
        &private_pem,
        &public_pem,
        "https://sid.example.com".to_string(),
    )
    .unwrap();

    let profile = create_test_profile();
    let session = create_test_session(&profile);
    // No primary email → email claims should be absent
    let token = jwt
        .issue_id_token(
            &profile.id.to_string(),
            &profile,
            &session,
            "test-client",
            None,
            None,
            None,
        )
        .unwrap();

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://sid.example.com"]);
    validation.set_audience(&["test-client"]);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

    let token_data: TokenData<IdTokenClaims> =
        decode(&token, &jwt.decoding_key, &validation).unwrap();

    // No email → email_verified should be absent (not false)
    assert!(token_data.claims.email.is_none());
    assert!(token_data.claims.email_verified.is_none());
}
