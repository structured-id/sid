use super::*;
use secrecy::ExposeSecret;

fn basic(raw: &str) -> String {
    format!("Basic {}", STANDARD.encode(raw))
}

fn parse(
    authorization: Option<&str>,
    client_id: Option<&str>,
    secret: Option<&str>,
    assertion: Option<&str>,
) -> Result<ClientAuthentication, TokenError> {
    ClientAuthentication::from_request(
        authorization,
        client_id,
        secret,
        assertion,
        Some(JWT_BEARER_ASSERTION_TYPE),
    )
}

/// Each method is recognized with its client and credential.
#[test]
fn test_methods() {
    let auth = parse(Some(&basic("app:s3cret")), None, None, None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::ClientSecretBasic);
    assert_eq!(auth.client_id(), "app");
    assert_eq!(auth.secret().unwrap().expose_secret(), "s3cret");

    let auth = parse(None, Some("app"), Some("s3cret"), None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::ClientSecretPost);
    assert_eq!(auth.secret().unwrap().expose_secret(), "s3cret");

    let auth = parse(None, Some("app"), None, Some("jwt")).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::PrivateKeyJwt);
    assert!(auth.secret().is_none());

    let auth = parse(None, Some("app"), None, None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::None);
    assert_eq!(auth.client_id(), "app");
}

/// Basic credentials are form-urlencoded before encoding (RFC 6749 §2.3.1);
/// only the first colon separates them (RFC 7617 §2); the scheme name is
/// case-insensitive.
#[test]
fn test_basic_decoding() {
    let auth = parse(Some(&basic("my%3Aapp:a%2Bb+c:d%")), None, None, None).unwrap();
    assert_eq!(auth.client_id(), "my:app");
    assert_eq!(auth.secret().unwrap().expose_secret(), "a+b c:d%");

    let lower = format!("basic {}", STANDARD.encode("app:s"));
    assert_eq!(
        parse(Some(&lower), None, None, None).unwrap().client_id(),
        "app"
    );
}

/// A Basic value that does not decode to `id:secret` fails authentication.
#[test]
fn test_malformed_basic_is_invalid_client() {
    for value in [
        "Basic !!!".to_string(),
        basic("no-colon"),
        basic(":secret"),
        format!("Basic {}", STANDARD.encode([0xff, b':', b's'])),
        basic("app%ff:s"),
    ] {
        assert!(
            matches!(
                parse(Some(&value), None, None, None),
                Err(TokenError::InvalidClient)
            ),
            "{value}"
        );
    }
}

/// Another Authorization scheme is not a client credential.
#[test]
fn test_other_scheme_is_ignored() {
    let auth = parse(Some("Bearer abc"), Some("app"), Some("s"), None).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::ClientSecretPost);
}

/// More than one method, or a body client_id contradicting Basic, is
/// `invalid_request` (RFC 6749 §5.2); the same client_id repeated is fine.
#[test]
fn test_ambiguous_requests_are_invalid_request() {
    let b = basic("app:s");
    for (authorization, client_id, secret, assertion) in [
        (Some(b.as_str()), None, Some("s"), None),
        (Some(b.as_str()), None, None, Some("jwt")),
        (None, Some("app"), Some("s"), Some("jwt")),
        (Some(b.as_str()), Some("other"), None, None),
    ] {
        assert!(matches!(
            parse(authorization, client_id, secret, assertion),
            Err(TokenError::InvalidRequest)
        ));
    }
    assert!(parse(Some(&b), Some("app"), None, None).is_ok());
}

/// Without Basic, the client must name itself; an empty value is omitted
/// (RFC 6749 §3.2).
#[test]
fn test_missing_client_id_is_invalid_request() {
    assert!(matches!(
        parse(None, None, Some("s"), None),
        Err(TokenError::InvalidRequest)
    ));
    assert!(matches!(
        parse(None, Some(""), None, None),
        Err(TokenError::InvalidRequest)
    ));
    let auth = parse(None, Some("app"), Some(""), Some("")).unwrap();
    assert_eq!(auth.method(), TokenEndpointAuthMethod::None);
}

/// An assertion of an unsupported type cannot authenticate the client
/// (RFC 7521 §4.2.1).
#[test]
fn test_unsupported_assertion_type_is_invalid_client() {
    let result = ClientAuthentication::from_request(
        None,
        Some("app"),
        None,
        Some("jwt"),
        Some("urn:example:other"),
    );
    assert!(matches!(result, Err(TokenError::InvalidClient)));
}

mod verify {
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use sid_core::models::*;
    use sid_plugin::cache::{CacheBackend, CacheError, CacheResult, InMemoryCacheBackend};

    use super::*;
    use crate::client_assertion::AssertionJtiCache;
    use crate::jwt::JwtService;
    use crate::oauth2::OAuth2Server;

    const ISSUER: &str = "https://sid.example.com/i/cabinet";
    const CLIENT: &str = "cabinet";
    const PRIVATE_PEM: &[u8] = include_bytes!("../../tests/fixtures/test_ed25519_private.pem");
    const PUBLIC_PEM: &[u8] = include_bytes!("../../tests/fixtures/test_ed25519_public.pem");

    fn oauth2() -> OAuth2Server {
        OAuth2Server::new(Arc::new(
            JwtService::new(PRIVATE_PEM, PUBLIC_PEM, ISSUER.to_owned()).expect("JWT service"),
        ))
    }

    /// The registered key of [`PRIVATE_PEM`] as a JWK set.
    fn keys() -> ClientKeySet {
        let pem = std::str::from_utf8(PUBLIC_PEM).unwrap();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = STANDARD.decode(body).unwrap();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der[12..]);
        ClientKeySet::try_from(serde_json::json!({
            "keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "k1"}]
        }))
        .unwrap()
    }

    /// An active confidential web client authenticating with `private_key_jwt`.
    fn client() -> OAuth2Client {
        OAuth2Client {
            client_id: CLIENT.into(),
            project_id: ProjectId::system(),
            application_id: ApplicationId::generate(),
            default_resource: None,
            application_type: ApplicationType::Web,
            client_secret_hash: None,
            jwks: Some(keys()),
            redirect_uris: vec!["https://cabinet.example/callback".into()],
            allowed_scopes: vec!["account".into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            client_name: "Cabinet".into(),
            logo_uri: None,
            active: true,
            token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
            response_types: vec!["code".into()],
            subject_type: SubjectType::Public,
            sector_identifier_uri: None,
            contacts: vec![],
            client_id_issued_at: Utc::now(),
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
            post_logout_redirect_uris: vec![],
            claim_mappings: vec![],
            login_strategy: LoginStrategy::LocalFirst,
            show_federation_button: true,
            federation_timeout_ms: 500,
            unified_input: false,
            org_id: None,
            revision: 0,
            created_at: Utc::now(),
        }
    }

    /// An assertion of [`CLIENT`] for `audience`, signed with its key.
    fn assertion(audience: &str, jti: &str) -> ClientAuthentication {
        let now = Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": CLIENT, "sub": CLIENT, "aud": audience,
            "exp": now + 120, "iat": now, "jti": jti,
        });
        let header = Header {
            kid: Some("k1".into()),
            ..Header::new(Algorithm::EdDSA)
        };
        let jwt = encode(
            &header,
            &claims,
            &EncodingKey::from_ed_pem(PRIVATE_PEM).unwrap(),
        )
        .unwrap();
        ClientAuthentication::Assertion {
            client_id: CLIENT.into(),
            assertion: jwt,
        }
    }

    fn token_endpoint() -> String {
        crate::issuer::token_endpoint(ISSUER)
    }

    fn post(secret: &str) -> ClientAuthentication {
        ClientAuthentication::Post {
            client_id: CLIENT.into(),
            secret: SecretBox::new(Box::new(secret.to_owned())),
        }
    }

    fn jti_cache() -> AssertionJtiCache {
        AssertionJtiCache::new(Arc::new(InMemoryCacheBackend::new()))
    }

    async fn verify(
        auth: &ClientAuthentication,
        client: &OAuth2Client,
        cache: &AssertionJtiCache,
    ) -> Result<(), ClientRefusal> {
        auth.verify(client, ISSUER, &oauth2(), cache).await
    }

    fn refused(result: Result<(), ClientRefusal>) -> bool {
        matches!(result, Err(ClientRefusal::Refused))
    }

    // An assertion for this issuer's token endpoint authenticates the client
    // once; the same assertion again is a replay (RFC 7523 §3 item 7), and one
    // for another audience never authenticates it (RFC 7523 §3 item 3).
    #[tokio::test]
    async fn test_assertion_for_this_token_endpoint_once() {
        let cache = jti_cache();
        let first = assertion(&token_endpoint(), "jti-1");
        verify(&first, &client(), &cache).await.unwrap();
        assert!(refused(verify(&first, &client(), &cache).await));
        let elsewhere = assertion("https://sid.example.com/i/other/oauth2/token", "jti-2");
        assert!(refused(verify(&elsewhere, &client(), &cache).await));
    }

    // An inactive client, another client's request, a client without
    // registered keys and a method other than the registered one are refused.
    #[tokio::test]
    async fn test_client_mismatches_are_refused() {
        let cache = jti_cache();
        let inactive = OAuth2Client {
            active: false,
            ..client()
        };
        let other = OAuth2Client {
            client_id: "other".into(),
            ..client()
        };
        let keyless = OAuth2Client {
            jwks: None,
            ..client()
        };
        for (n, registered) in [inactive, other, keyless].iter().enumerate() {
            let auth = assertion(&token_endpoint(), &format!("jti-mismatch-{n}"));
            assert!(refused(verify(&auth, registered, &cache).await), "{n}");
        }
        assert!(refused(verify(&post("s3cret"), &client(), &cache).await));
    }

    // A public client presents no credential (RFC 6749 §2.1); presenting one
    // is refused.
    #[tokio::test]
    async fn test_public_client_presents_no_credential() {
        let cache = jti_cache();
        let public = OAuth2Client {
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            jwks: None,
            ..client()
        };
        let none = ClientAuthentication::None {
            client_id: CLIENT.into(),
        };
        verify(&none, &public, &cache).await.unwrap();
        assert!(refused(verify(&post("s3cret"), &public, &cache).await));
    }

    // A secret client is authenticated by its secret only.
    #[tokio::test]
    async fn test_secret_client() {
        let cache = jti_cache();
        let secret_client = OAuth2Client {
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            client_secret_hash: Some(
                OAuth2Server::hash_client_secret("s3cret")
                    .unwrap()
                    .into_bytes(),
            ),
            jwks: None,
            ..client()
        };
        verify(&post("s3cret"), &secret_client, &cache)
            .await
            .unwrap();
        assert!(refused(
            verify(&post("wrong"), &secret_client, &cache).await
        ));
    }

    struct Down;

    #[async_trait::async_trait]
    impl CacheBackend for Down {
        async fn get(&self, _: &str) -> CacheResult<Option<Vec<u8>>> {
            Err(CacheError::Connection("down".into()))
        }
        async fn set(&self, _: &str, _: &[u8], _: Duration) -> CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
        async fn delete(&self, _: &str) -> CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
        async fn take(&self, _: &str) -> CacheResult<Option<Vec<u8>>> {
            Err(CacheError::Connection("down".into()))
        }
        async fn set_nx(&self, _: &str, _: &[u8], _: Duration) -> CacheResult<bool> {
            Err(CacheError::Connection("down".into()))
        }
        async fn publish(&self, _: &str, _: &[u8]) -> CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
        async fn subscribe(
            &self,
            _: &str,
        ) -> CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
            Err(CacheError::Connection("down".into()))
        }
        async fn health_check(&self) -> CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
    }

    // An unreachable replay record cannot rule out a replay: the assertion is
    // not accepted, and the failure is told apart from a bad credential.
    #[tokio::test]
    async fn test_unreachable_replay_record_is_not_success() {
        let cache = AssertionJtiCache::new(Arc::new(Down));
        let auth = assertion(&token_endpoint(), "jti-down");
        assert!(matches!(
            verify(&auth, &client(), &cache).await,
            Err(ClientRefusal::ReplayRecordUnavailable(_))
        ));
    }
}

#[test]
fn test_token_error_codes() {
    assert_eq!(TokenError::InvalidClient.code(), "invalid_client");
    assert_eq!(TokenError::InvalidDpopProof.code(), "invalid_dpop_proof");
    assert_eq!(
        TokenError::UnsupportedGrantType.code(),
        "unsupported_grant_type"
    );
    assert_eq!(
        TokenError::AuthorizationPending.code(),
        "authorization_pending"
    );
    assert_eq!(TokenError::SlowDown.code(), "slow_down");
    assert_eq!(TokenError::ExpiredToken.code(), "expired_token");
}
