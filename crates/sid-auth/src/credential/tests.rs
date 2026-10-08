// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const BASE: &str = "https://sid.example.com";
const ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";
const ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGnMIVUgwI0tTO1AANoNzICml1zLy8M4WqrJlomrTGlU\n-----END PRIVATE KEY-----";

/// A file holding `content`, removed when dropped.
struct File(std::path::PathBuf);

impl File {
    fn with(content: &str) -> Self {
        let path = std::env::temp_dir().join(format!("sid-auth-checker-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }

    fn path(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for File {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

fn config(issuer: &str, authentication: ClientAuthentication) -> ClientCredentialConfig {
    ClientCredentialConfig {
        issuer: issuer.into(),
        client_id: "route-checker".into(),
        authentication,
    }
}

fn basic(file: &File) -> ClientAuthentication {
    ClientAuthentication::ClientSecretBasic {
        secret_file: file.path(),
    }
}

fn load(config: &ClientCredentialConfig) -> Result<ClientCredential, CredentialError> {
    ClientCredential::checker(config, BASE, crate::test_channel())
}

/// A checker's tokens are for its issuer's authorization API with the
/// permission-question scope; a caller's are for the resource it calls,
/// with no scope required.
#[tokio::test]
async fn a_credential_names_the_resource_its_tokens_are_for() {
    let secret = File::with("s3cret");
    let checker = load(&config(ISSUER, basic(&secret))).unwrap();
    assert_eq!(
        checker.resource,
        sid_authn::issuer::authorization_api_endpoint(ISSUER)
    );
    assert_eq!(checker.scope, Some(sid_core::models::AUTHZ_CHECK));
    let caller = ClientCredential::for_resource(
        &config(ISSUER, basic(&secret)),
        BASE,
        crate::test_channel(),
        "https://tenants.sid.example.com/",
    )
    .unwrap();
    assert_eq!(caller.resource, "https://tenants.sid.example.com/");
    assert_eq!(caller.scope, None);
}

/// Each supported method loads from its file, for an issuer of this
/// installation, keeping that issuer.
#[tokio::test]
async fn a_credential_loads_for_an_issuer_of_the_installation() {
    let secret = File::with("s3cret\n");
    let key = File::with(ED_PRIVATE_PEM);
    for authentication in [
        basic(&secret),
        ClientAuthentication::ClientSecretPost {
            secret_file: secret.path(),
        },
        ClientAuthentication::PrivateKeyJwt {
            key_file: key.path(),
            algorithm: "EdDSA".into(),
            key_id: Some("checker-1".into()),
        },
    ] {
        let credential = load(&config(ISSUER, authentication)).unwrap();
        assert_eq!(credential.issuer(), ISSUER);
        assert_eq!(credential.handle, "0123456789abcdef0123456789abcdef");
    }
}

/// A credential that cannot authenticate stops start-up: an issuer of
/// another installation or no issuer handle, an empty or missing secret, a
/// key that does not parse for its algorithm, an unsupported algorithm.
#[tokio::test]
async fn a_credential_that_cannot_authenticate_does_not_load() {
    let secret = File::with("s3cret");
    let empty = File::with(" \n");
    let key = File::with(ED_PRIVATE_PEM);
    let jwt = |algorithm: &str| ClientAuthentication::PrivateKeyJwt {
        key_file: key.path(),
        algorithm: algorithm.into(),
        key_id: None,
    };
    let cases = [
        (
            "another installation",
            config(
                "https://other.example.com/i/0123456789abcdef0123456789abcdef",
                basic(&secret),
            ),
        ),
        (
            "not an issuer handle",
            config("https://sid.example.com/i/orders", basic(&secret)),
        ),
        ("an empty secret", config(ISSUER, basic(&empty))),
        (
            "a missing file",
            config(
                ISSUER,
                ClientAuthentication::ClientSecretPost {
                    secret_file: "/nonexistent/sid-auth-secret".into(),
                },
            ),
        ),
        ("an Ed25519 key read as ES256", config(ISSUER, jwt("ES256"))),
        ("an unsupported algorithm", config(ISSUER, jwt("HS256"))),
    ];
    for (case, config) in cases {
        assert!(
            matches!(load(&config), Err(CredentialError::Config(_))),
            "{case}"
        );
    }
    let mut nameless = config(ISSUER, basic(&secret));
    nameless.client_id = String::new();
    assert!(matches!(load(&nameless), Err(CredentialError::Config(_))));
}

/// Basic credentials are form-urlencoded before they are joined (RFC 6749
/// §2.3.1), so the token endpoint reads back exactly the client and secret,
/// including a colon, spaces, `+` and `%`.
#[test]
fn basic_credentials_read_back_exactly() {
    use secrecy::ExposeSecret;
    let secret = SecretString::from("p@ss: word+%41/é".to_owned());
    let header = basic_authorization("svc:checker 1", &secret).unwrap();
    assert!(header.is_sensitive());
    let read = sid_authn::client_auth::ClientAuthentication::from_request(
        Some(header.to_str().unwrap()),
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(read.client_id(), "svc:checker 1");
    assert_eq!(read.secret().unwrap().expose_secret(), "p@ss: word+%41/é");
}

/// The client assertion names the client as issuer and subject, the token
/// endpoint as audience, and is short-lived and unique (RFC 7523 §3).
#[tokio::test]
async fn the_client_assertion_names_the_client_and_the_token_endpoint() {
    let key = File::with(ED_PRIVATE_PEM);
    let credential = load(&config(
        ISSUER,
        ClientAuthentication::PrivateKeyJwt {
            key_file: key.path(),
            algorithm: "EdDSA".into(),
            key_id: Some("checker-1".into()),
        },
    ))
    .unwrap();
    let Credential::Assertion {
        key,
        algorithm,
        key_id,
    } = &credential.credential
    else {
        panic!("a private_key_jwt credential");
    };
    let audience = sid_authn::issuer::token_endpoint(ISSUER);
    let first = credential
        .assertion(&audience, key, *algorithm, key_id.as_deref())
        .unwrap();
    let second = credential
        .assertion(&audience, key, *algorithm, key_id.as_deref())
        .unwrap();
    let header = jsonwebtoken::decode_header(&first).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.kid.as_deref(), Some("checker-1"));
    let claims = |jwt: &str| -> serde_json::Value {
        use base64::Engine;
        let payload = jwt.split('.').nth(1).unwrap();
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap()
    };
    let (first, second) = (claims(&first), claims(&second));
    assert_eq!(first["iss"], "route-checker");
    assert_eq!(first["sub"], "route-checker");
    assert_eq!(first["aud"], audience.as_str());
    assert_eq!(
        first["exp"].as_i64().unwrap() - first["iat"].as_i64().unwrap(),
        ASSERTION_LIFETIME_SECS
    );
    assert_ne!(first["jti"], second["jti"]);
}

/// A token the API refused is dropped so the next call requests another;
/// a refusal of an older token leaves a newer one in place.
#[tokio::test]
async fn a_refused_token_is_dropped_only_if_still_held() {
    let secret = File::with("s3cret");
    let credential = load(&config(ISSUER, basic(&secret))).unwrap();
    let value = |token: &str| -> AsciiMetadataValue { format!("Bearer {token}").parse().unwrap() };
    *credential.held.write().await = Some(std::sync::Arc::new(Held {
        authorization: value("current"),
        refresh_at: Instant::now() + Duration::from_secs(60),
    }));
    assert_eq!(
        credential.fresh().await.unwrap().authorization,
        value("current")
    );

    credential.refused(&value("older")).await;
    assert!(credential.fresh().await.is_some(), "a newer token stays");

    credential.refused(&value("current")).await;
    assert!(credential.fresh().await.is_none());
}

/// A held token past its renewal point is not handed out.
#[tokio::test]
async fn a_token_past_renewal_is_not_fresh() {
    let secret = File::with("s3cret");
    let credential = load(&config(ISSUER, basic(&secret))).unwrap();
    *credential.held.write().await = Some(std::sync::Arc::new(Held {
        authorization: "Bearer old".parse().unwrap(),
        refresh_at: Instant::now(),
    }));
    assert!(credential.fresh().await.is_none());
}
