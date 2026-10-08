// SPDX-License-Identifier: AGPL-3.0-only
//! A `private_key_jwt` client (RFC 7523 §2.2) authenticates at the token
//! endpoint with an assertion signed by one of its registered keys
//! (RFC 7591 §2 `jwks`); without its keys it cannot authenticate at all.

mod common;

use base64::Engine;
use common::TestServices;
use common::mock_storage::MockStorage;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sid_core::models::{
    Application, ApplicationId, AuditEntry, ClientKeySet, ProjectId, ProtectedResource,
    ResourceAccess, ResourceId, ResourceIndicator, ResourceState, TokenEndpointAuthMethod,
};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

const ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGnMIVUgwI0tTO1AANoNzICml1zLy8M4WqrJlomrTGlU\n-----END PRIVATE KEY-----";
const ED_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqK9dvWXRiLy73AXFvVRAMzmlQwKF6q/R/UJmjngfLLs=\n-----END PUBLIC KEY-----";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ACCOUNT_API: &str = "https://resources.example/account";
const KID: &str = "bff-1";

/// The test key's JWK Set: the Ed25519 key follows a 12-byte
/// SubjectPublicKeyInfo prefix.
fn key_set() -> ClientKeySet {
    let body: String = ED_PUBLIC_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der[12..]);
    ClientKeySet::try_from(serde_json::json!({
        "keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": KID, "use": "sig"}]
    }))
    .unwrap()
}

/// A confidential client authenticating with `private_key_jwt`, holding
/// `jwks`, allowed `client_credentials`, with access to the account API.
async fn key_client(jwks: Option<ClientKeySet>) -> TestServices {
    let mut client = common::test_client();
    client.client_id = "key-client".into();
    client.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    client.jwks = jwks;
    client.grant_types = vec!["client_credentials".into()];
    client.allowed_scopes = vec!["account".into()];
    let svc = TestServices::new(MockStorage::new().with_system_project().with_client(client));
    let now = chrono::Utc::now();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: "Account API".into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: svc.issuer.id,
        indicator: ResourceIndicator::parse(ACCOUNT_API).unwrap(),
        scopes: vec!["account".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    svc.storage
        .create_application(
            &app,
            None,
            Some(&resource),
            AuditEntry::system("test", "api").into(),
        )
        .await
        .unwrap();
    svc.storage
        .set_resource_access(
            &ResourceAccess {
                client_id: "key-client".into(),
                resource_id: resource.id,
                scopes: vec!["account".into()],
                created_at: now,
            },
            AuditEntry::system("test", "access").into(),
        )
        .await
        .unwrap();
    svc
}

/// An assertion (RFC 7523 §3) of `key-client` for `audience`, signed by the
/// test key under `kid`.
fn assertion(audience: &str, jti: &str, kid: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "key-client", "sub": "key-client", "aud": audience,
        "iat": now, "exp": now + 60, "jti": jti,
    });
    let header = Header {
        kid: Some(kid.to_owned()),
        ..Header::new(Algorithm::EdDSA)
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(ED_PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn token_request(svc: &TestServices, assertion: Option<String>) -> Request<OAuth2TokenRequest> {
    Request::new(OAuth2TokenRequest {
        grant_type: "client_credentials".into(),
        client_id: Some("key-client".into()),
        client_assertion_type: assertion.as_ref().map(|_| ASSERTION_TYPE.to_owned()),
        client_assertion: assertion,
        resource: vec![ACCOUNT_API.into()],
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    })
}

fn token_endpoint(svc: &TestServices) -> String {
    format!("{}/oauth2/token", svc.issuer.canonical_url)
}

/// The registered key's assertion for this issuer's token endpoint
/// authenticates the client, and the token is for the resource it may reach.
#[tokio::test]
async fn a_key_client_authenticates_with_its_assertion() {
    let svc = key_client(Some(key_set())).await;
    let signed = assertion(&token_endpoint(&svc), "jti-ok", KID);
    let body = svc
        .auth
        .o_auth2_token(token_request(&svc, Some(signed)))
        .await
        .unwrap()
        .into_inner();
    assert!(!body.access_token.is_empty());
}

/// A key client presenting nothing is not a public client: before keys were
/// registered, a keyless `private_key_jwt` client counted as public and was
/// served without any credential.
#[tokio::test]
async fn a_key_client_without_an_assertion_is_refused() {
    for jwks in [Some(key_set()), None] {
        let svc = key_client(jwks).await;
        let err = svc
            .auth
            .o_auth2_token(token_request(&svc, None))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
    }
}

/// An assertion made for another token endpoint, naming an unregistered key,
/// or replayed, authenticates nobody; a client without keys cannot use one.
#[tokio::test]
async fn a_misdirected_unknown_or_replayed_assertion_is_refused() {
    let svc = key_client(Some(key_set())).await;
    let elsewhere = assertion("https://other.example/oauth2/token", "jti-aud", KID);
    let unknown = assertion(&token_endpoint(&svc), "jti-kid", "other-key");
    for signed in [elsewhere, unknown] {
        let err = svc
            .auth
            .o_auth2_token(token_request(&svc, Some(signed)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
    }

    let once = assertion(&token_endpoint(&svc), "jti-once", KID);
    svc.auth
        .o_auth2_token(token_request(&svc, Some(once.clone())))
        .await
        .unwrap();
    let err = svc
        .auth
        .o_auth2_token(token_request(&svc, Some(once)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");

    let keyless = key_client(None).await;
    let signed = assertion(&token_endpoint(&keyless), "jti-keyless", KID);
    let err = keyless
        .auth
        .o_auth2_token(token_request(&keyless, Some(signed)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
}

/// The key client's access token, obtained with its assertion.
async fn issued_token(svc: &TestServices) -> String {
    let signed = assertion(&token_endpoint(svc), "jti-issue", KID);
    svc.auth
        .o_auth2_token(token_request(svc, Some(signed)))
        .await
        .unwrap()
        .into_inner()
        .access_token
}

fn token_jti(token: &str) -> String {
    let body = token.split('.').nth(1).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .unwrap(),
    )
    .unwrap();
    claims["jti"].as_str().unwrap().to_owned()
}

/// A key client revokes its token with its assertion, as it authenticates at
/// the token endpoint (RFC 7009 §2.1); without one it is refused and the
/// token stays valid. Before, the revocation endpoint dropped the assertion,
/// so a `private_key_jwt` client could never revoke what it held.
#[tokio::test]
async fn a_key_client_revokes_with_its_assertion() {
    let svc = key_client(Some(key_set())).await;
    let token = issued_token(&svc).await;
    let revoke = |assertion: Option<String>| OAuth2RevokeRequest {
        token: token.clone(),
        issuer_handle: svc.issuer.handle.to_string(),
        client_id: Some("key-client".into()),
        client_assertion_type: assertion.as_ref().map(|_| ASSERTION_TYPE.to_owned()),
        client_assertion: assertion,
        ..Default::default()
    };

    let err = svc
        .auth
        .o_auth2_revoke(Request::new(revoke(None)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");
    assert!(
        !svc.revocation_cache
            .is_revoked(&token_jti(&token), "")
            .await
            .unwrap()
    );

    let signed = assertion(&token_endpoint(&svc), "jti-revoke", KID);
    svc.auth
        .o_auth2_revoke(Request::new(revoke(Some(signed))))
        .await
        .unwrap();
    assert!(
        svc.revocation_cache
            .is_revoked(&token_jti(&token), "")
            .await
            .unwrap()
    );
}

/// The introspection endpoint authenticates a key client by its assertion
/// too (RFC 7662 §2.1); without one the caller is unauthenticated.
#[tokio::test]
async fn a_key_client_introspects_with_its_assertion() {
    let svc = key_client(Some(key_set())).await;
    let token = issued_token(&svc).await;
    let introspect = |assertion: Option<String>| OAuth2IntrospectRequest {
        token: token.clone(),
        issuer_handle: svc.issuer.handle.to_string(),
        client_id: Some("key-client".into()),
        client_assertion_type: assertion.as_ref().map(|_| ASSERTION_TYPE.to_owned()),
        client_assertion: assertion,
        ..Default::default()
    };
    let err = svc
        .auth
        .o_auth2_introspect(Request::new(introspect(None)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");

    let signed = assertion(&token_endpoint(&svc), "jti-introspect", KID);
    svc.auth
        .o_auth2_introspect(Request::new(introspect(Some(signed))))
        .await
        .unwrap();
}

/// A key client starts a device authorization with its assertion (RFC 8628
/// §3.1: authenticated as at the token endpoint).
#[tokio::test]
async fn a_key_client_starts_device_authorization_with_its_assertion() {
    let mut client = common::test_client();
    client.client_id = "key-client".into();
    client.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    client.jwks = Some(key_set());
    client.grant_types = vec!["urn:ietf:params:oauth:grant-type:device_code".into()];
    let svc = TestServices::new(MockStorage::new().with_system_project().with_client(client));
    let start = |assertion: Option<String>| DeviceAuthorizationRequest {
        client_id: Some("key-client".into()),
        scope: Some("openid".into()),
        issuer_handle: svc.issuer.handle.to_string(),
        client_assertion_type: assertion.as_ref().map(|_| ASSERTION_TYPE.to_owned()),
        client_assertion: assertion,
        ..Default::default()
    };
    let err = svc
        .auth
        .start_device_authorization(Request::new(start(None)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err:?}");

    let signed = assertion(&token_endpoint(&svc), "jti-device", KID);
    let started = svc
        .auth
        .start_device_authorization(Request::new(start(Some(signed))))
        .await
        .unwrap()
        .into_inner();
    assert!(!started.device_code.is_empty());
}
