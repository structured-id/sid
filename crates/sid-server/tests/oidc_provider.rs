// SPDX-License-Identifier: AGPL-3.0-only
//! An issuer's public metadata and key set, served by the identity service as
//! gRPC and reached over HTTP through the transcoder, as relying parties and
//! gateways (Kong, Envoy) fetch them.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::TestServices;
use common::mock_storage::MockStorage;
use serde_json::{Value, json};
use sid_proto::sid::v1::oidc_provider_service_server::{
    OidcProviderService, OidcProviderServiceServer,
};
use sid_proto::sid::v1::{IssuerHandleRequest, JsonWebKeySet, ProviderMetadata};
use sid_server::grpc::oidc_provider_service::OidcProviderServiceImpl;
use tonic::{Code, Request};

fn provider_of(svc: &TestServices) -> OidcProviderServiceImpl {
    provider_signing_in_at(svc, None)
}

/// The provider sending a user who must sign in to `login_url`.
fn provider_signing_in_at(svc: &TestServices, login_url: Option<&str>) -> OidcProviderServiceImpl {
    OidcProviderServiceImpl::new(
        svc.issuers.clone(),
        svc.storage.clone(),
        svc.revocation_cache.clone(),
        svc.cache.clone(),
        svc.auth.clone(),
        svc.project.clone(),
        login_url.map(|url| url::Url::parse(url).unwrap()),
    )
}

fn services() -> (TestServices, OidcProviderServiceImpl) {
    let svc = TestServices::new(MockStorage::new());
    let provider = provider_of(&svc);
    (svc, provider)
}

fn handle(svc: &TestServices) -> Request<IssuerHandleRequest> {
    Request::new(IssuerHandleRequest {
        issuer_handle: svc.issuer.handle.to_string(),
    })
}

/// Discovery lists `private_key_jwt` with the algorithms its assertions may
/// use (RFC 8414 §2 requires the list whenever the method is offered), and
/// never a symmetric or `none` algorithm.
#[tokio::test]
async fn metadata_offers_private_key_jwt_with_its_algorithms() {
    let (svc, provider) = services();
    let metadata: ProviderMetadata = provider
        .get_provider_metadata(handle(&svc))
        .await
        .unwrap()
        .into_inner();
    assert!(
        metadata
            .token_endpoint_auth_methods_supported
            .contains(&"private_key_jwt".to_owned())
    );
    let algorithms = &metadata.token_endpoint_auth_signing_alg_values_supported;
    assert!(algorithms.contains(&"EdDSA".to_owned()));
    assert!(
        !algorithms
            .iter()
            .any(|alg| alg == "none" || alg.starts_with("HS"))
    );
    // Revocation and introspection authenticate a client as the token
    // endpoint does, so they list the method and the same algorithms; left
    // out, RFC 8414 §2 would mean `client_secret_basic` only.
    for (methods, algs) in [
        (
            &metadata.revocation_endpoint_auth_methods_supported,
            &metadata.revocation_endpoint_auth_signing_alg_values_supported,
        ),
        (
            &metadata.introspection_endpoint_auth_methods_supported,
            &metadata.introspection_endpoint_auth_signing_alg_values_supported,
        ),
    ] {
        assert!(methods.contains(&"private_key_jwt".to_owned()));
        assert_eq!(algs, algorithms);
    }
    // Only an authenticated caller introspects (RFC 7662 §2.1).
    assert!(
        !metadata
            .introspection_endpoint_auth_methods_supported
            .contains(&"none".to_owned())
    );
}

/// The metadata names the stored issuer URL byte for byte and puts every
/// endpoint under it (OIDC Discovery 1.0 §4.3, RFC 8414 §3.3).
#[tokio::test]
async fn metadata_is_the_issuers_own() {
    let (svc, provider) = services();
    let metadata: ProviderMetadata = provider
        .get_provider_metadata(handle(&svc))
        .await
        .unwrap()
        .into_inner();
    let issuer = &svc.issuer.canonical_url;

    assert_eq!(&metadata.issuer, issuer);
    assert_eq!(
        metadata.authorization_endpoint,
        format!("{issuer}/oauth2/authorize")
    );
    assert_eq!(metadata.token_endpoint, format!("{issuer}/oauth2/token"));
    assert_eq!(metadata.userinfo_endpoint, format!("{issuer}/userinfo"));
    assert_eq!(metadata.jwks_uri, format!("{issuer}/jwks"));
    assert_eq!(
        metadata.end_session_endpoint,
        format!("{issuer}/oauth2/end-session")
    );
    assert_eq!(
        metadata.introspection_endpoint,
        format!("{issuer}/oauth2/introspect")
    );
    assert_eq!(
        metadata.revocation_endpoint,
        format!("{issuer}/oauth2/revoke")
    );
    assert_eq!(
        metadata.device_authorization_endpoint,
        format!("{issuer}/oauth2/device")
    );
    assert_eq!(metadata.subject_types_supported, ["public"]);
    assert_eq!(metadata.id_token_signing_alg_values_supported, ["EdDSA"]);
    assert_eq!(metadata.code_challenge_methods_supported, ["S256"]);
    assert!(metadata.authorization_response_iss_parameter_supported);
}

/// The key set holds this issuer's keys: the key that signs its tokens is
/// in it, and HTTP caches are told how long to keep it.
#[tokio::test]
async fn jwks_holds_the_issuers_signing_key() {
    let (svc, provider) = services();
    let response = provider.get_jwks(handle(&svc)).await.unwrap();
    assert_eq!(
        response.metadata().get("cache-control").unwrap(),
        "public, max-age=3600, stale-while-revalidate=600"
    );
    let jwks: JsonWebKeySet = response.into_inner();

    let signer = svc.issuers.signer(&svc.issuer).await.unwrap();
    let expected = &signer.jwks().keys[0];
    assert_eq!(jwks.keys.len(), 1);
    let key = &jwks.keys[0];
    assert_eq!(key.kid, expected.kid);
    assert_eq!(key.x, expected.x);
    assert_eq!(
        (
            key.kty.as_str(),
            key.r#use.as_str(),
            key.alg.as_str(),
            key.crv.as_str()
        ),
        ("OKP", "sig", "EdDSA", "Ed25519")
    );
}

/// A handle this installation does not have is NOT_FOUND, never another
/// issuer's documents.
#[tokio::test]
async fn unknown_handle_is_not_found() {
    let (_, provider) = services();
    // A well-formed handle of no issuer, and text that is no handle at all.
    for handle in ["0123456789abcdef0123456789abcdef", "not-a-handle"] {
        let unknown = || {
            Request::new(IssuerHandleRequest {
                issuer_handle: handle.into(),
            })
        };
        assert_eq!(
            provider
                .get_provider_metadata(unknown())
                .await
                .unwrap_err()
                .code(),
            Code::NotFound,
            "{handle}"
        );
        assert_eq!(
            provider.get_jwks(unknown()).await.unwrap_err().code(),
            Code::NotFound,
            "{handle}"
        );
    }
}

/// GET `url` with a client carrying this build's TLS provider.
async fn get(url: String) -> reqwest::Response {
    sid_plugin::client_builder()
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap()
}

/// The provider behind the transcoder, as the server serves it (the same
/// transcoder, calling the provider in process): returns the HTTP base URL.
async fn over_http(provider: OidcProviderServiceImpl) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let proxy = sid_server::serve::http_transcoder(Some("127.0.0.1:0"), None, None)
        .unwrap()
        .expect("a bind address gives a transcoder");
    // The server's own composition of what the transcoder calls.
    let routes = sid_server::serve::transcoder_upstream(tonic::service::Routes::new(
        OidcProviderServiceServer::new(provider),
    ));
    // Bound before the task starts: a request queues until it is accepted.
    // Serves until the test's runtime ends.
    tokio::spawn(async move {
        sid_infra::http::serve_on(
            &proxy,
            routes,
            listener,
            std::future::pending(),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
    });
    format!("http://{addr}")
}

/// Over HTTP both discovery locations answer the same document, with the
/// registered metadata names (OIDC Discovery 1.0 §3, RFC 8414 §2, §3).
#[tokio::test]
async fn discovery_over_http_uses_the_registered_names() {
    let (svc, provider) = services();
    let base = over_http(provider).await;
    let handle = svc.issuer.handle.to_string();
    let issuer = &svc.issuer.canonical_url;

    let oidc: Value = get(format!(
        "{base}/i/{handle}/.well-known/openid-configuration"
    ))
    .await
    .error_for_status()
    .unwrap()
    .json()
    .await
    .unwrap();
    let rfc8414: Value = get(format!(
        "{base}/.well-known/oauth-authorization-server/i/{handle}"
    ))
    .await
    .error_for_status()
    .unwrap()
    .json()
    .await
    .unwrap();

    assert_eq!(oidc, rfc8414);
    assert_eq!(oidc["issuer"], json!(issuer));
    assert_eq!(oidc["jwks_uri"], json!(format!("{issuer}/jwks")));
    assert_eq!(
        oidc["token_endpoint"],
        json!(format!("{issuer}/oauth2/token"))
    );
    assert_eq!(oidc["subject_types_supported"], json!(["public"]));
    assert_eq!(
        oidc["authorization_response_iss_parameter_supported"],
        json!(true)
    );
    assert!(
        oidc.get("jwksUri").is_none(),
        "a ProtoJSON name leaked: {oidc}"
    );
}

/// Every endpoint the discovery document advertises is a route the
/// transcoder serves: a client following discovery never meets a path the
/// server does not have (RFC 8414 §2). A path no route answers is 404; a
/// served one answers its handler, or 405 for another method.
#[tokio::test]
async fn advertised_endpoints_are_served() {
    let (svc, provider) = services();
    let base = over_http(provider).await;
    let handle = svc.issuer.handle.to_string();
    let issuer = url::Url::parse(&svc.issuer.canonical_url).unwrap();

    let discovery: Value = get(format!(
        "{base}/i/{handle}/.well-known/openid-configuration"
    ))
    .await
    .error_for_status()
    .unwrap()
    .json()
    .await
    .unwrap();
    let endpoints: Vec<(&String, &str)> = discovery
        .as_object()
        .unwrap()
        .iter()
        .filter(|(name, _)| name.ends_with("_endpoint") || *name == "jwks_uri")
        .map(|(name, value)| (name, value.as_str().unwrap()))
        .collect();
    assert!(
        endpoints.iter().any(|(name, _)| *name == "token_endpoint"),
        "{discovery}"
    );
    // The probe tells a missing route apart.
    assert_eq!(
        get(format!("{base}/i/{handle}/oauth2/not-an-endpoint"))
            .await
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    for (name, endpoint) in endpoints {
        let url = url::Url::parse(endpoint).unwrap();
        assert_eq!(url.origin(), issuer.origin(), "{name}: {endpoint}");
        let response = get(format!("{base}{}", url.path())).await;
        assert_ne!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{name}: {endpoint} is not served"
        );
    }
}

/// Over HTTP the key set is a JWK Set with the registered member names, and
/// carries the cache lifetime.
#[tokio::test]
async fn jwks_over_http_is_a_jwk_set() {
    let (svc, provider) = services();
    let signer = svc.issuers.signer(&svc.issuer).await.unwrap();
    let kid = signer.jwks().keys[0].kid.clone();
    let base = over_http(provider).await;

    let response = get(format!("{base}/i/{}/jwks", svc.issuer.handle))
        .await
        .error_for_status()
        .unwrap();
    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "public, max-age=3600, stale-while-revalidate=600"
    );
    let jwks: Value = response.json().await.unwrap();
    assert_eq!(jwks["keys"][0]["kid"], json!(kid));
    assert_eq!(jwks["keys"][0]["use"], json!("sig"));
    assert_eq!(jwks["keys"][0]["kty"], json!("OKP"));
}

// ── UserInfo ───────────────────────────────────────────────────────────

/// RFC 7638 thumbprint of the test ES256 key that signs DPoP proofs.
const TEST_JKT: &str = "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA";

/// A signed-in user: a profile with a verified primary email and its stored
/// session, behind the services.
struct SignedIn {
    svc: TestServices,
    provider: OidcProviderServiceImpl,
    profile: sid_core::models::Profile,
    session: sid_core::models::Session,
    /// The browser's `Cookie` header for this session, as the sign-in
    /// ceremony set it.
    cookie: String,
}

/// The `Cookie` header a browser sends for `secret`.
fn cookie_of(secret: &sid_authn::browser_session::BrowserSecret) -> String {
    secret
        .set_cookie(3600)
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn signed_in() -> SignedIn {
    let mut profile = sid_core::models::Profile::new(Some("alice"));
    profile.given_name = Some("Alice".into());
    profile.family_name = Some("Smith".into());
    let mut session = sid_core::models::Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let secret = sid_authn::browser_session::BrowserSecret::generate();
    session.browser_secret_hash = Some(secret.hash());
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_session(session.clone()),
    );
    let now = chrono::Utc::now();
    svc.storage
        .create_profile_email(
            &sid_core::models::ProfileEmail {
                id: sid_core::models::ProfileEmailId::new(),
                profile_id: profile.id,
                email: "alice@sid.example.com".into(),
                label: sid_core::models::EmailLabel::Personal,
                custom_label: None,
                is_primary: true,
                verified: true,
                verified_at: Some(now),
                created_at: now,
                updated_at: now,
            },
            sid_core::models::AuditEntry::system("test", "email").into(),
        )
        .await
        .unwrap();
    let provider = provider_of(&svc);
    SignedIn {
        svc,
        provider,
        profile,
        session,
        cookie: cookie_of(&secret),
    }
}

impl SignedIn {
    /// An access token the issuer gives the test client for this session and
    /// its UserInfo resource, with `sub` = the ProfileId (the installation's
    /// own application).
    async fn token(&self, scopes: &[&str], jkt: Option<&str>) -> String {
        self.token_for(&self.endpoint(), scopes, jkt).await
    }

    /// An access token like [`Self::token`] for the resource `audience`.
    async fn token_for(&self, audience: &str, scopes: &[&str], jkt: Option<&str>) -> String {
        let signer = self.svc.issuers.signer(&self.svc.issuer).await.unwrap();
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        let binding = jkt.map(sid_core::models::dpop::DPopBinding::new);
        self.svc
            .jwt
            .access_token_signed_by(
                signer.as_ref(),
                sid_authn::jwt::TokenAudience::Resource {
                    indicator: audience,
                    client_id: "test-client",
                },
                &self.profile.id.to_string(),
                None,
                &self.profile,
                &self.session,
                &scopes,
                binding.as_ref(),
                None,
            )
            .unwrap()
    }

    fn endpoint(&self) -> String {
        format!("{}/userinfo", self.svc.issuer.canonical_url)
    }

    fn request(
        &self,
        authorization: Option<&str>,
        dpop: Option<&str>,
    ) -> Request<IssuerHandleRequest> {
        let mut request = handle(&self.svc);
        if let Some(value) = authorization {
            request
                .metadata_mut()
                .insert("authorization", value.parse().unwrap());
        }
        if let Some(proof) = dpop {
            request
                .metadata_mut()
                .insert("dpop", proof.parse().unwrap());
        }
        request
    }
}

/// A DPoP proof by the test ES256 key for `htm htu`, naming `token`.
fn dpop_proof(htm: &str, htu: &str, token: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256",
        "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
        "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(jwk);
    let claims = json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "ath": sid_authn::dpop::access_token_hash(token),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../sid-authn/tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &claims, &key).unwrap()
}

fn challenges(status: &tonic::Status) -> Vec<String> {
    status
        .metadata()
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// The claims the scopes grant, about the token's subject; the others are
/// absent rather than empty (OIDC Core 1.0 §5.3.2, §5.4).
#[tokio::test]
async fn user_info_answers_the_granted_claims() {
    let user = signed_in().await;
    let token = user.token(&["openid", "profile", "email"], None).await;
    let info = user
        .provider
        .get_user_info(user.request(Some(&format!("Bearer {token}")), None))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(info.sub, user.profile.id.to_string());
    assert_eq!(info.given_name.as_deref(), Some("Alice"));
    assert_eq!(info.family_name.as_deref(), Some("Smith"));
    assert_eq!(info.preferred_username.as_deref(), Some("alice"));
    assert_eq!(info.email.as_deref(), Some("alice@sid.example.com"));
    assert_eq!(info.email_verified, Some(true));
    assert!(info.phone_number.is_none());

    let openid_only = user.token(&["openid"], None).await;
    let info = user
        .provider
        .post_user_info(user.request(Some(&format!("Bearer {openid_only}")), None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.sub, user.profile.id.to_string());
    assert!(info.given_name.is_none());
    assert!(info.email.is_none());
}

/// Without a token both schemes are offered, without an error code
/// (RFC 6750 §3, RFC 9449 §7.1).
#[tokio::test]
async fn user_info_without_a_token_offers_both_schemes() {
    let user = signed_in().await;
    let err = user
        .provider
        .get_user_info(user.request(None, None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    let offered = challenges(&err);
    assert_eq!(offered[0], "Bearer");
    assert!(offered[1].starts_with("DPoP algs=\""), "{offered:?}");
}

/// A sign-in token of the installation is not one this issuer signed for an
/// application: refused as an invalid token.
#[tokio::test]
async fn user_info_refuses_a_token_of_another_issuer() {
    let user = signed_in().await;
    let sign_in = common::issue_token(&user.svc.jwt, &user.profile, &["openid".to_string()]);
    let err = user
        .provider
        .get_user_info(user.request(Some(&format!("Bearer {sign_in}")), None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(challenges(&err), [r#"Bearer error="invalid_token""#]);
}

/// A token this issuer signed for another resource is not a UserInfo
/// credential: an application's access token is never forwarded to UserInfo
/// (RFC 9068 §4 audience check, RFC 6750 §3.1 `invalid_token`).
#[tokio::test]
async fn user_info_refuses_a_token_for_another_resource() {
    let user = signed_in().await;
    let orders = user
        .token_for("https://resources.example/orders", &["openid"], None)
        .await;
    let err = user
        .provider
        .get_user_info(user.request(Some(&format!("Bearer {orders}")), None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(challenges(&err), [r#"Bearer error="invalid_token""#]);
}

/// A token not issued for OpenID Connect is refused with insufficient_scope
/// (RFC 6750 §3.1).
#[tokio::test]
async fn user_info_needs_the_openid_scope() {
    let user = signed_in().await;
    let token = user.token(&["profile"], None).await;
    let err = user
        .provider
        .get_user_info(user.request(Some(&format!("Bearer {token}")), None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        challenges(&err),
        [r#"Bearer error="insufficient_scope", scope="openid""#]
    );
}

/// A token whose session is gone answers nothing about the user.
#[tokio::test]
async fn user_info_refuses_an_ended_session() {
    let user = signed_in().await;
    let token = user.token(&["openid"], None).await;
    user.svc
        .storage
        .delete_session(
            user.session.id,
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "test",
            ),
            sid_core::models::AuditEntry::system("test", "logout").into(),
        )
        .await
        .unwrap();
    let err = user
        .provider
        .get_user_info(user.request(Some(&format!("Bearer {token}")), None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// The native gRPC address of a UserInfo RPC: what its proof names.
fn user_info_rpc(method: &str) -> String {
    format!("https://sid.example.com/sid.v1.authn.OidcProviderService/{method}")
}

/// A key-bound token is accepted only under DPoP with its proof for this
/// request: as a bearer token it is refused; a gRPC call's proof names the
/// RPC, so the GetUserInfo proof does not open PostUserInfo, nor does the
/// REST endpoint's proof open the RPC (RFC 9449 §4.3, §7.1).
#[tokio::test]
async fn user_info_honours_the_key_binding() {
    let user = signed_in().await;
    let token = user.token(&["openid"], Some(TEST_JKT)).await;

    let err = user
        .provider
        .get_user_info(user.request(Some(&format!("Bearer {token}")), None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(challenges(&err), [r#"DPoP error="invalid_token""#]);

    let get_proof = dpop_proof("POST", &user_info_rpc("GetUserInfo"), &token);
    let info = user
        .provider
        .get_user_info(user.request(Some(&format!("DPoP {token}")), Some(&get_proof)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.sub, user.profile.id.to_string());

    for (case, proof) in [
        (
            "another RPC's proof",
            dpop_proof("POST", &user_info_rpc("GetUserInfo"), &token),
        ),
        (
            "the REST endpoint's proof",
            dpop_proof("POST", &user.endpoint(), &token),
        ),
    ] {
        let err = user
            .provider
            .post_user_info(user.request(Some(&format!("DPoP {token}")), Some(&proof)))
            .await
            .unwrap_err();
        assert_eq!(
            challenges(&err),
            [r#"DPoP error="invalid_dpop_proof""#],
            "{case}"
        );
    }
}

/// When a proof's single use cannot be recorded, the request is not admitted
/// and the caller is told to retry: the proof itself was not found wrong.
#[tokio::test]
async fn user_info_without_the_replay_record_is_unavailable() {
    let user = signed_in().await;
    let token = user.token(&["openid"], Some(TEST_JKT)).await;
    let provider = OidcProviderServiceImpl::new(
        user.svc.issuers.clone(),
        user.svc.storage.clone(),
        user.svc.revocation_cache.clone(),
        std::sync::Arc::new(common::NoReplayRecord(user.svc.cache.clone())),
        user.svc.auth.clone(),
        user.svc.project.clone(),
        None,
    );
    let proof = dpop_proof("POST", &user_info_rpc("GetUserInfo"), &token);
    let err = provider
        .get_user_info(user.request(Some(&format!("DPoP {token}")), Some(&proof)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable, "{err:?}");
}

/// Over HTTP, through the transcoder the server embeds, a proof names the
/// REST request as received at the configured origin: GET and POST each with
/// their own proof, never one for the other method or for the RPC, and never
/// a proof used twice (RFC 9449 §4.3, §11.1).
#[tokio::test]
async fn user_info_key_binding_over_http() {
    let user = signed_in().await;
    let token = user.token(&["openid"], Some(TEST_JKT)).await;
    let url = format!(
        "{}/i/{}/userinfo",
        over_http(provider_of(&user.svc)).await,
        user.svc.issuer.handle
    );
    let client = sid_plugin::client_builder().build().unwrap();
    let call = |method: &str, proof: &str| {
        let request = match method {
            "GET" => client.get(&url),
            _ => client.post(&url).body(""),
        };
        request
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", proof)
            .send()
    };

    for method in ["GET", "POST"] {
        let proof = dpop_proof(method, &user.endpoint(), &token);
        let response = call(method, &proof).await.unwrap();
        assert_eq!(response.status(), 200, "{method}");
        let replayed = call(method, &proof).await.unwrap();
        assert_eq!(replayed.status(), 401, "{method} replayed");
    }
    for (case, method, proof) in [
        (
            "a GET proof on POST",
            "POST",
            dpop_proof("GET", &user.endpoint(), &token),
        ),
        (
            "the RPC's proof",
            "GET",
            dpop_proof("POST", &user_info_rpc("GetUserInfo"), &token),
        ),
        (
            "a proof for the listener's own address",
            "GET",
            dpop_proof("GET", &url, &token),
        ),
    ] {
        let response = call(method, &proof).await.unwrap();
        assert_eq!(response.status(), 401, "{case}");
    }
}

/// Over HTTP, GET and POST answer the claims with their registered names,
/// and a refusal is a 401 carrying the challenge (RFC 6750 §3).
#[tokio::test]
async fn user_info_over_http() {
    let user = signed_in().await;
    let token = user.token(&["openid", "email"], None).await;
    let url = format!(
        "{}/i/{}/userinfo",
        over_http(provider_of(&user.svc)).await,
        user.svc.issuer.handle
    );
    let client = sid_plugin::client_builder().build().unwrap();

    for request in [client.get(&url), client.post(&url).body("")] {
        let response = request.bearer_auth(&token).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["sub"], json!(user.profile.id.to_string()));
        assert_eq!(body["email_verified"], json!(true));
        assert!(body.get("given_name").is_none(), "{body}");
        assert!(body.get("emailVerified").is_none(), "{body}");
    }

    let refused = client.get(&url).send().await.unwrap();
    assert_eq!(refused.status(), 401);
    assert!(
        refused
            .headers()
            .get_all("www-authenticate")
            .iter()
            .any(|v| v == "Bearer"),
        "{:?}",
        refused.headers()
    );
}

// ── OAuth endpoints in their HTTP form ─────────────────────────────────

const SERVICE_SECRET: &str = "service-client-secret";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// A confidential client `client_id` registered for HTTP Basic with `secret`
/// and the client_credentials grant.
fn confidential_client(client_id: &str, secret: &str) -> sid_core::models::OAuth2Client {
    let mut client = common::test_client();
    client.client_id = client_id.into();
    client.client_secret_hash = Some(
        sid_authn::oauth2::OAuth2Server::hash_client_secret(secret)
            .unwrap()
            .into_bytes(),
    );
    client.token_endpoint_auth_method =
        sid_core::models::TokenEndpointAuthMethod::ClientSecretBasic;
    client.grant_types = vec!["client_credentials".into()];
    client
}

const OTHER_SECRET: &str = "other-client-secret";

/// The installation's issuer behind the transcoder, with confidential clients
/// `service` and `other` registered for HTTP Basic and a public device client
/// `device-app`.
async fn oauth_endpoints() -> (TestServices, String) {
    let mut device = common::test_client();
    device.client_id = "device-app".into();
    device.grant_types = vec![DEVICE_GRANT.into()];
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(confidential_client("service", SERVICE_SECRET))
            .with_client(confidential_client("other", OTHER_SECRET))
            .with_client(device),
    );
    let base = over_http(provider_of(&svc)).await;
    let endpoints = format!("{base}/i/{}/oauth2", svc.issuer.handle);
    (svc, endpoints)
}

/// POST `pairs` as `application/x-www-form-urlencoded` (RFC 6749 §3.2), with
/// HTTP Basic client authentication when given.
async fn post_form(
    url: &str,
    pairs: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> reqwest::Response {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut request = sid_plugin::client_builder()
        .build()
        .unwrap()
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body);
    if let Some((id, secret)) = basic {
        request = request.basic_auth(id, Some(secret));
    }
    request.send().await.unwrap()
}

/// An RFC 6749 §5.2 error answer: `status`, a JSON body whose `error` is
/// `error`, and nothing of the gRPC error shape.
async fn assert_oauth_error(response: reqwest::Response, status: u16, error: &str) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], json!(error), "{body}");
    assert!(
        body.get("code").is_none() && body.get("details").is_none(),
        "{body}"
    );
    body
}

/// The token endpoint speaks RFC 6749 over HTTP: a form in, §5.1 JSON out
/// with `no-store`, numbers as numbers; HTTP Basic authenticates the client
/// (§2.3.1) and its failure is a 401 with a Basic challenge (§5.2).
#[tokio::test]
async fn token_endpoint_over_http() {
    let (_svc, endpoints) = oauth_endpoints().await;
    let token_url = format!("{endpoints}/token");

    let issued = post_form(
        &token_url,
        &[("grant_type", "client_credentials")],
        Some(("service", SERVICE_SECRET)),
    )
    .await;
    assert_eq!(issued.status(), 200);
    assert_eq!(issued.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(issued.headers().get("pragma").unwrap(), "no-cache");
    assert!(
        issued.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    let body: Value = issued.json().await.unwrap();
    assert!(body["access_token"].is_string(), "{body}");
    assert_eq!(body["token_type"], json!("Bearer"));
    assert!(body["expires_in"].is_u64(), "{body}");
    assert!(body.get("refresh_token").is_none(), "{body}");

    let refused = post_form(
        &token_url,
        &[("grant_type", "client_credentials")],
        Some(("service", "wrong")),
    )
    .await;
    let challenge = refused
        .headers()
        .get("www-authenticate")
        .expect("a Basic challenge")
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.starts_with("Basic "), "{challenge}");
    assert_oauth_error(refused, 401, "invalid_client").await;

    let unsupported = post_form(&token_url, &[("grant_type", "password")], None).await;
    assert_oauth_error(unsupported, 400, "unsupported_grant_type").await;
}

/// A request with two `DPoP` headers is refused (RFC 9449 §4.3 step 1): both
/// reach the token endpoint through the transcoder, which must not keep one.
#[tokio::test]
async fn token_endpoint_refuses_two_dpop_headers_over_http() {
    let (svc, endpoints) = oauth_endpoints().await;
    // A proof valid on its own: a transcoder that forwarded only the first
    // header would let the request through.
    let valid = dpop_proof(
        "POST",
        &format!("{}/oauth2/token", svc.issuer.canonical_url),
        "unused",
    );
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .finish();
    let response = sid_plugin::client_builder()
        .build()
        .unwrap()
        .post(format!("{endpoints}/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("dpop", valid)
        .header("dpop", "d.e.f")
        .basic_auth("service", Some(SERVICE_SECRET))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_oauth_error(response, 400, "invalid_dpop_proof").await;
}

/// The token endpoint reads only its form (RFC 6749 §3.2): another content
/// type, or a parameter sent twice, is `invalid_request`.
#[tokio::test]
async fn token_endpoint_reads_only_its_form() {
    let (_svc, endpoints) = oauth_endpoints().await;
    let token_url = format!("{endpoints}/token");

    let json_body = sid_plugin::client_builder()
        .build()
        .unwrap()
        .post(&token_url)
        .header("content-type", "application/json")
        .body(r#"{"grant_type":"client_credentials"}"#)
        .send()
        .await
        .unwrap();
    assert_oauth_error(json_body, 400, "invalid_request").await;

    let repeated = post_form(
        &token_url,
        &[
            ("grant_type", "client_credentials"),
            ("grant_type", "client_credentials"),
        ],
        Some(("service", SERVICE_SECRET)),
    )
    .await;
    assert_oauth_error(repeated, 400, "invalid_request").await;
}

/// The device flow over HTTP: the device authorization endpoint answers
/// RFC 8628 §3.2 JSON with numbers as numbers, and the token endpoint's
/// device_code grant answers `authorization_pending` until the user decides
/// (RFC 8628 §3.5).
#[tokio::test]
async fn device_flow_over_http() {
    let (_svc, endpoints) = oauth_endpoints().await;

    let started = post_form(
        &format!("{endpoints}/device"),
        &[("client_id", "device-app"), ("scope", "openid")],
        None,
    )
    .await;
    assert_eq!(started.status(), 200);
    let started: Value = started.json().await.unwrap();
    let device_code = started["device_code"].as_str().unwrap().to_string();
    assert!(started["user_code"].is_string(), "{started}");
    assert!(started["verification_uri"].is_string(), "{started}");
    assert!(started["expires_in"].is_u64(), "{started}");
    assert!(started["interval"].is_u64(), "{started}");

    let pending = post_form(
        &format!("{endpoints}/token"),
        &[
            ("grant_type", DEVICE_GRANT),
            ("device_code", &device_code),
            ("client_id", "device-app"),
        ],
        None,
    )
    .await;
    assert_oauth_error(pending, 400, "authorization_pending").await;
}

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE_MACHINE: &str = "mu_http_exchange";
const EXCHANGE_SECRET: &str = "http-exchange-secret";

/// Token exchange over HTTP (RFC 8693): the answer names the issued token
/// type (§2.2.1), and the form's `requested_token_type` and `audience` reach
/// the grant: another token type is `invalid_request`, a named target
/// `invalid_target` (§2.2.2).
#[tokio::test]
async fn token_exchange_over_http() {
    use sid_core::models::machine_user::{
        MachineCredentialType, MachineUser, MachineUserCredential, OwnerType,
    };
    use sid_core::models::{ImpersonationGrant, ImpersonationTargetType, ProjectId};

    let profile = common::test_profile();
    let machine = MachineUser::new(
        ProjectId::system(),
        EXCHANGE_MACHINE,
        "HTTP exchange bot",
        OwnerType::System,
        "system",
    );
    let credential = MachineUserCredential::new(
        machine.id,
        "kid_http_exchange",
        MachineCredentialType::ClientSecret,
        sid_authn::bearer_secret::verifier_of(EXCHANGE_SECRET),
    );
    let grant = ImpersonationGrant::new(
        machine.id,
        ImpersonationTargetType::User,
        profile.id.to_string(),
        vec!["openid".to_string()],
    );
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_machine_user(machine)
            .with_machine_credential(credential)
            .with_impersonation_grant(grant),
    );
    let base = over_http(provider_of(&svc)).await;
    let token_url = format!("{base}/i/{}/oauth2/token", svc.issuer.handle);
    let exchange = |extra: &'static [(&'static str, &'static str)]| {
        let subject_token = common::issue_token(&svc.jwt, &profile, &["openid".to_string()]);
        let token_url = token_url.clone();
        async move {
            let mut pairs = vec![
                ("grant_type", TOKEN_EXCHANGE),
                ("client_id", EXCHANGE_MACHINE),
                ("client_secret", EXCHANGE_SECRET),
                ("subject_token", subject_token.as_str()),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("scope", "openid"),
            ];
            pairs.extend_from_slice(extra);
            post_form(&token_url, &pairs, None).await
        }
    };

    let issued = exchange(&[("requested_token_type", ACCESS_TOKEN_TYPE)]).await;
    assert_eq!(issued.status(), 200);
    let body: Value = issued.json().await.unwrap();
    assert_eq!(
        body["issued_token_type"],
        json!(ACCESS_TOKEN_TYPE),
        "{body}"
    );

    let other_type = exchange(&[(
        "requested_token_type",
        "urn:ietf:params:oauth:token-type:refresh_token",
    )])
    .await;
    assert_oauth_error(other_type, 400, "invalid_request").await;

    let named = exchange(&[("audience", "https://resources.example/orders")]).await;
    assert_oauth_error(named, 400, "invalid_target").await;
}

/// An access token the token endpoint issues to `service` for itself.
async fn service_token(endpoints: &str) -> String {
    let issued: Value = post_form(
        &format!("{endpoints}/token"),
        &[("grant_type", "client_credentials")],
        Some(("service", SERVICE_SECRET)),
    )
    .await
    .error_for_status()
    .unwrap()
    .json()
    .await
    .unwrap();
    issued["access_token"].as_str().unwrap().to_string()
}

/// Introspect `token` at `endpoints` as the client `basic` authenticates.
async fn introspect(
    endpoints: &str,
    token: &str,
    basic: Option<(&str, &str)>,
) -> reqwest::Response {
    post_form(
        &format!("{endpoints}/introspect"),
        &[("token", token)],
        basic,
    )
    .await
}

/// Introspection of a token this issuer does not vouch for is exactly
/// `{"active":false}` (RFC 7662 §2.2); revocation of an unknown token is a
/// 200 with nothing in it (RFC 7009 §2.2).
#[tokio::test]
async fn introspection_and_revocation_over_http() {
    let (_svc, endpoints) = oauth_endpoints().await;
    let service = Some(("service", SERVICE_SECRET));

    let introspected = introspect(&endpoints, "not-a-token", service).await;
    assert_eq!(introspected.status(), 200);
    let body: Value = introspected.json().await.unwrap();
    assert_eq!(body, json!({ "active": false }));

    let revoked = post_form(
        &format!("{endpoints}/revoke"),
        &[("token", "not-a-token")],
        service,
    )
    .await;
    assert_eq!(revoked.status(), 200);
    assert!(revoked.bytes().await.unwrap().is_empty());

    let no_token = post_form(&format!("{endpoints}/introspect"), &[], service).await;
    assert_oauth_error(no_token, 400, "invalid_request").await;
}

/// Introspection requires an authenticated client (RFC 7662 §2.1, §4) and
/// tells any other caller nothing about the token: a request naming no
/// client is `invalid_request`, as at the token endpoint; a public client
/// naming itself and a wrong secret are `invalid_client`.
#[tokio::test]
async fn introspection_needs_an_authenticated_client() {
    let (_svc, endpoints) = oauth_endpoints().await;
    let token = service_token(&endpoints).await;

    let anonymous = introspect(&endpoints, &token, None).await;
    assert_oauth_error(anonymous, 400, "invalid_request").await;

    let public = post_form(
        &format!("{endpoints}/introspect"),
        &[("token", &token), ("client_id", "device-app")],
        None,
    )
    .await;
    assert_oauth_error(public, 400, "invalid_client").await;

    let wrong = introspect(&endpoints, &token, Some(("service", "wrong"))).await;
    assert_oauth_error(wrong, 401, "invalid_client").await;
}

/// Give the client `other` the token inspector role on the resource the test
/// clients' tokens are for.
async fn other_inspects(svc: &TestServices) {
    common::grant_inspection(
        svc,
        sid_core::models::RoleAssignmentPrincipal::OAuthClient("other".into()),
        common::userinfo_resource(svc).await,
    )
    .await;
}

/// A token is active only to an inspector holding the inspection permission
/// on its resource, with its client, scope and times as JSON numbers (RFC
/// 7662 §2.2), although the inspector is not the token's client. To an
/// authenticated client without it, the token's own client included, it is
/// inactive (RFC 7662 §4).
#[tokio::test]
async fn introspection_answers_only_an_authorized_inspector() {
    let (svc, endpoints) = oauth_endpoints().await;
    let token = service_token(&endpoints).await;

    for (id, secret) in [("other", OTHER_SECRET), ("service", SERVICE_SECRET)] {
        let refused = introspect(&endpoints, &token, Some((id, secret))).await;
        assert_eq!(refused.status(), 200);
        assert_eq!(
            refused.json::<Value>().await.unwrap(),
            json!({ "active": false }),
            "{id}"
        );
    }

    other_inspects(&svc).await;
    let inspected = introspect(&endpoints, &token, Some(("other", OTHER_SECRET))).await;
    assert_eq!(inspected.status(), 200);
    assert_eq!(
        inspected.headers().get("cache-control").unwrap(),
        "no-store"
    );
    let body: Value = inspected.json().await.unwrap();
    assert_eq!(body["active"], json!(true), "{body}");
    assert_eq!(body["client_id"], json!("service"), "{body}");
    assert_eq!(body["sub"], json!("service"), "{body}");
    assert!(body["exp"].is_i64(), "{body}");
    assert!(body["iat"].is_i64(), "{body}");
}

/// Only the client a token was issued to revokes it (RFC 7009 §2.1): another
/// client is refused with `unauthorized_client` and the token stays active,
/// even one that may inspect it; the owner's revocation ends it.
#[tokio::test]
async fn revocation_is_for_the_tokens_client() {
    let (svc, endpoints) = oauth_endpoints().await;
    other_inspects(&svc).await;
    let token = service_token(&endpoints).await;
    let revoke = |basic| {
        let endpoints = endpoints.clone();
        let token = token.clone();
        async move { post_form(&format!("{endpoints}/revoke"), &[("token", &token)], basic).await }
    };
    let active = || async {
        introspect(&endpoints, &token, Some(("other", OTHER_SECRET)))
            .await
            .json::<Value>()
            .await
            .unwrap()["active"]
            .clone()
    };

    assert_oauth_error(revoke(None).await, 400, "invalid_request").await;
    assert_oauth_error(
        revoke(Some(("other", OTHER_SECRET))).await,
        400,
        "unauthorized_client",
    )
    .await;
    assert_eq!(active().await, json!(true));

    let revoked = revoke(Some(("service", SERVICE_SECRET))).await;
    assert_eq!(revoked.status(), 200);
    assert_eq!(active().await, json!(false));
}

// ── Dynamic registration (RFC 7591) and client management (RFC 7592) ──

const IAT: &str = "http-registration-initial-access-token";

/// The issuer behind the transcoder with an initial access token `IAT` that
/// admits clients under `https://*.sid.example.com/*`; returns the base of
/// the issuer's endpoints.
async fn registration_endpoints() -> (TestServices, String) {
    use sha2::{Digest, Sha256};
    let iat = sid_core::models::InitialAccessToken {
        id: sid_core::models::InitialAccessTokenId::new(),
        token_hash: Sha256::digest(IAT.as_bytes()).to_vec(),
        project_id: sid_core::models::ProjectId::system(),
        max_clients: 10,
        clients_registered: 0,
        allowed_scopes: vec!["openid".into(), "profile".into()],
        allowed_grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        allowed_redirect_patterns: vec!["https://*.sid.example.com/*".into()],
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        created_at: chrono::Utc::now(),
        created_by: "test".into(),
        revoked: false,
    };
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_initial_access_token(iat),
    );
    let base = over_http(provider_of(&svc)).await;
    let endpoints = format!("{base}/i/{}/oauth2", svc.issuer.handle);
    (svc, endpoints)
}

/// Send `body` as JSON with `method` to `url`, with `token` as a bearer.
async fn json_request(
    method: reqwest::Method,
    url: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> reqwest::Response {
    let mut request = sid_plugin::client_builder()
        .build()
        .unwrap()
        .request(method, url);
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap()
}

fn metadata() -> Value {
    json!({
        "client_name": "CI pipeline",
        "redirect_uris": ["https://ci.sid.example.com/callback"],
        "scope": "openid profile",
        "contacts": ["ops@sid.example.com"],
        "post_logout_redirect_uris": ["https://ci.sid.example.com/signed-out"],
        "software_statement_ignored_extension": "x",
    })
}

/// Registration over HTTP (RFC 7591 §3): 201 with every registered value in
/// its RFC form, the credentials, and the management location under the
/// client's issuer; discovery names the endpoint (RFC 8414 §2).
#[tokio::test]
async fn registration_over_http() {
    let (svc, endpoints) = registration_endpoints().await;
    let issuer = &svc.issuer.canonical_url;

    let created = json_request(
        reqwest::Method::POST,
        &format!("{endpoints}/register"),
        Some(metadata()),
        Some(IAT),
    )
    .await;
    assert_eq!(created.status(), 201);
    assert_eq!(created.headers().get("cache-control").unwrap(), "no-store");
    let body: Value = created.json().await.unwrap();
    let client_id = body["client_id"].as_str().unwrap();
    assert!(body["client_secret"].is_string(), "{body}");
    assert_eq!(body["client_secret_expires_at"], json!(0));
    assert!(body["client_id_issued_at"].is_i64(), "{body}");
    assert!(body["registration_access_token"].is_string(), "{body}");
    assert_eq!(
        body["registration_client_uri"],
        json!(format!("{issuer}/oauth2/register/{client_id}"))
    );
    // RFC 7591 §2 defaults and the registered names.
    assert_eq!(body["grant_types"], json!(["authorization_code"]));
    assert_eq!(body["response_types"], json!(["code"]));
    assert_eq!(
        body["token_endpoint_auth_method"],
        json!("client_secret_basic")
    );
    assert_eq!(body["application_type"], json!("web"));
    assert_eq!(body["subject_type"], json!("public"));
    assert_eq!(body["scope"], json!("openid profile"));
    assert_eq!(
        body["post_logout_redirect_uris"],
        json!(["https://ci.sid.example.com/signed-out"])
    );
    assert!(body.get("clientSecret").is_none(), "{body}");

    let discovered: Value = get(format!(
        "{}/.well-known/openid-configuration",
        endpoints.trim_end_matches("/oauth2")
    ))
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(
        discovered["registration_endpoint"],
        json!(format!("{issuer}/oauth2/register"))
    );
}

/// Refusals over HTTP: metadata the issuer refuses is 400 with its RFC 7591
/// §3.2.2 code; no initial access token is 401 with a bare `Bearer`
/// challenge, a wrong one 401 with `invalid_token` (RFC 6750 §3); an unknown
/// issuer is 404. None registers a client.
#[tokio::test]
async fn registration_refusals_over_http() {
    let (svc, endpoints) = registration_endpoints().await;
    let register = |body, token| {
        let url = format!("{endpoints}/register");
        async move { json_request(reqwest::Method::POST, &url, Some(body), token).await }
    };

    let mut pairwise = metadata();
    pairwise["subject_type"] = json!("pairwise");
    assert_oauth_error(
        register(pairwise, Some(IAT)).await,
        400,
        "invalid_client_metadata",
    )
    .await;

    let mut outside = metadata();
    outside["redirect_uris"] = json!(["https://evil.example.org/callback"]);
    assert_oauth_error(
        register(outside, Some(IAT)).await,
        400,
        "invalid_redirect_uri",
    )
    .await;

    // A post-logout redirect outside the token's patterns, or one a redirect
    // URI could not be, is client metadata the issuer refuses.
    for uri in [
        "https://evil.example.org/signed-out",
        "http://ci.sid.example.com/signed-out",
    ] {
        let mut logout = metadata();
        logout["post_logout_redirect_uris"] = json!([uri]);
        let body = assert_oauth_error(
            register(logout, Some(IAT)).await,
            400,
            "invalid_client_metadata",
        )
        .await;
        assert!(
            body["error_description"]
                .as_str()
                .is_some_and(|d| d.contains("post-logout")),
            "{uri}: {body}"
        );
    }

    let mut malformed = metadata();
    malformed["redirect_uris"] = json!("https://ci.sid.example.com/callback");
    assert_oauth_error(
        register(malformed, Some(IAT)).await,
        400,
        "invalid_client_metadata",
    )
    .await;

    let anonymous = register(metadata(), None).await;
    assert_eq!(anonymous.status(), 401);
    assert_eq!(
        anonymous.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );

    let wrong = register(metadata(), Some("not-the-token")).await;
    assert_eq!(
        wrong.headers().get("www-authenticate").unwrap(),
        r#"Bearer error="invalid_token""#
    );
    assert_oauth_error(wrong, 401, "invalid_token").await;

    let elsewhere = endpoints.replace(
        &svc.issuer.handle.to_string(),
        "0123456789abcdef0123456789abcdef",
    );
    let not_found = json_request(
        reqwest::Method::POST,
        &format!("{elsewhere}/register"),
        Some(metadata()),
        Some(IAT),
    )
    .await;
    assert_eq!(not_found.status(), 404);

    let clients = svc.storage.list_oauth2_clients(0, 100).await.unwrap();
    assert!(clients.iter().all(|c| !c.client_id.starts_with("dyn_")));
}

/// Client management over HTTP (RFC 7592): read answers the metadata without
/// credentials; an update replaces the metadata and must name the client;
/// delete is 204, after which the token manages nothing (401, not 404).
#[tokio::test]
async fn client_management_over_http() {
    let (_svc, endpoints) = registration_endpoints().await;
    let created: Value = json_request(
        reqwest::Method::POST,
        &format!("{endpoints}/register"),
        Some(metadata()),
        Some(IAT),
    )
    .await
    .json()
    .await
    .unwrap();
    let uri = created["registration_client_uri"].as_str().unwrap();
    let rat = created["registration_access_token"].as_str().unwrap();
    let client_id = created["client_id"].as_str().unwrap();
    // The transcoder serves the issuer's path under the test base URL.
    let manage = format!("{endpoints}/register/{client_id}");
    assert!(
        uri.ends_with(&format!("/oauth2/register/{client_id}")),
        "{uri}"
    );

    let read = json_request(reqwest::Method::GET, &manage, None, Some(rat)).await;
    assert_eq!(read.status(), 200);
    let read: Value = read.json().await.unwrap();
    assert_eq!(read["client_name"], json!("CI pipeline"));
    assert!(read.get("client_secret").is_none(), "{read}");
    assert!(read.get("registration_access_token").is_none(), "{read}");

    // Contacts left out are removed (RFC 7592 §2.2).
    let mut replacement = metadata();
    replacement["client_id"] = json!(client_id);
    replacement["client_name"] = json!("Renamed");
    replacement.as_object_mut().unwrap().remove("contacts");
    let updated = json_request(
        reqwest::Method::PUT,
        &manage,
        Some(replacement.clone()),
        Some(rat),
    )
    .await;
    assert_eq!(updated.status(), 200);
    let updated: Value = updated.json().await.unwrap();
    assert_eq!(updated["client_name"], json!("Renamed"));
    assert!(updated.get("contacts").is_none(), "{updated}");

    replacement["client_id"] = json!("dyn_someone_else");
    let unnamed = json_request(reqwest::Method::PUT, &manage, Some(replacement), Some(rat)).await;
    assert_oauth_error(unnamed, 400, "invalid_client_metadata").await;

    let deleted = json_request(reqwest::Method::DELETE, &manage, None, Some(rat)).await;
    assert_eq!(deleted.status(), 204);
    let after = json_request(reqwest::Method::GET, &manage, None, Some(rat)).await;
    assert_eq!(after.status(), 401);
}

// ── Authorization endpoint and RP-Initiated Logout ─────────────────────

const REDIRECT_URI: &str = "https://app.sid.example.com/callback";
const LOGIN_URL: &str = "https://login.sid.example.com/sign-in";
const VERIFIER: &str = "a-verifier-long-enough-for-pkce-a-verifier-long-enough";

/// An HTTP client that shows redirects instead of following them.
fn no_redirects() -> reqwest::Client {
    sid_plugin::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// `base` with `pairs` as its query.
fn with_query<V: AsRef<str>>(base: &str, pairs: &[(&str, V)]) -> String {
    let mut url = url::Url::parse(base).unwrap();
    url.query_pairs_mut()
        .extend_pairs(pairs.iter().map(|(k, v)| (*k, v.as_ref())));
    url.into()
}

/// A code-flow authorization request of the test client, with `redirect_uri`.
fn authorize_query(redirect_uri: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".into()),
        ("client_id", "test-client".into()),
        ("redirect_uri", redirect_uri.into()),
        ("scope", "openid".into()),
        ("state", "xyz".into()),
        ("nonce", "n-1".into()),
        (
            "code_challenge",
            sid_authn::oauth2::compute_s256_challenge(VERIFIER),
        ),
        ("code_challenge_method", "S256".into()),
    ]
}

/// A signed-in user (profile with a stored session), the test client, and the
/// issuer's authorization endpoint behind the transcoder.
struct Browser {
    user: SignedIn,
    authorize: String,
    end_session: String,
}

async fn browser(login_url: Option<&str>) -> Browser {
    browser_with(login_url, common::test_client()).await
}

/// A browser whose test client is `client`.
async fn browser_with(login_url: Option<&str>, client: sid_core::models::OAuth2Client) -> Browser {
    let user = signed_in().await;
    common::store_client(&*user.svc.storage, &client)
        .await
        .unwrap();
    common::open_userinfo_to_clients(&user.svc).await;
    let base = over_http(provider_signing_in_at(&user.svc, login_url)).await;
    let issuer = format!("{base}/i/{}", user.svc.issuer.handle);
    Browser {
        user,
        authorize: format!("{issuer}/oauth2/authorize"),
        end_session: format!("{issuer}/oauth2/end-session"),
    }
}

impl Browser {
    /// `url`, at the issuer's canonical URL, on the test server.
    fn local(&self, url: &str) -> String {
        let issuer = &self.user.svc.issuer.canonical_url;
        let local = self.authorize.trim_end_matches("/oauth2/authorize");
        assert!(url.starts_with(issuer.as_str()), "{url}");
        url.replacen(issuer.as_str(), local, 1)
    }

    /// Where a redirect to this issuer's authorization endpoint continues:
    /// the kept request's GET, carrying only the client and the reference.
    fn continuation(&self, location: &str) -> String {
        let url = url::Url::parse(location).unwrap();
        let query: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        assert_eq!(query.len(), 2, "{location}");
        assert_eq!(query["client_id"], "test-client");
        assert!(
            query["request_uri"].starts_with("urn:ietf:params:oauth:request_uri:"),
            "{location}"
        );
        self.local(location)
    }

    /// GET `url` as this browser: its IdP session cookie, no redirects followed.
    async fn get(&self, url: &str) -> reqwest::Response {
        no_redirects()
            .get(url)
            .header("cookie", &self.user.cookie)
            .send()
            .await
            .unwrap()
    }

    /// POST the authorization request `form` from another site: no cookie
    /// (`SameSite=Lax`); returns where it continues.
    async fn post_cross_site(&self, form: &[(&str, String)]) -> String {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let posted = no_redirects()
            .post(&self.authorize)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(posted.status(), 303, "{:?}", posted.headers());
        self.continuation(posted.headers()["location"].to_str().unwrap())
    }
}

/// The query of a redirect's `location`, when it goes to `prefix`.
fn redirect_query(
    response: &reqwest::Response,
    prefix: &str,
) -> std::collections::HashMap<String, String> {
    assert_eq!(response.status(), 303, "{:?}", response.headers());
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with(prefix), "{location}");
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// The `resource` parameter reaches the core over GET and a POSTed form
/// (RFC 8707 §2): a resource the client may use gets a code, one it may not,
/// or two distinct ones, send `invalid_target` to the client with its state.
#[tokio::test]
async fn authorize_selects_the_named_resource() {
    let browser = browser(None).await;
    let userinfo = sid_authn::issuer::userinfo_endpoint(&browser.user.svc.issuer.canonical_url);
    let with = |resources: &[&str]| {
        let mut query = authorize_query(REDIRECT_URI);
        query.extend(resources.iter().map(|r| ("resource", r.to_string())));
        query
    };

    let got = browser
        .get(&with_query(
            &browser.authorize,
            &with(&[&userinfo, &userinfo]),
        ))
        .await;
    assert!(redirect_query(&got, REDIRECT_URI).contains_key("code"));

    for refused in [
        vec!["https://resources.example/orders"],
        vec![userinfo.as_str(), "https://resources.example/orders"],
    ] {
        let got = browser
            .get(&with_query(&browser.authorize, &with(&refused)))
            .await;
        let query = redirect_query(&got, REDIRECT_URI);
        assert_eq!(query["error"], "invalid_target", "{refused:?}");
        assert_eq!(query["state"], "xyz");
    }

    let continued = browser
        .post_cross_site(&with(&["https://resources.example/orders"]))
        .await;
    assert_eq!(
        redirect_query(&browser.get(&continued).await, REDIRECT_URI)["error"],
        "invalid_target"
    );
}

/// A signed-in browser is redirected to the client with a code, the state
/// and the issuer (RFC 6749 §4.1.2, RFC 9207 §2), over GET and over a form
/// POSTed from the client's site (OIDC Core 1.0 §3.1.2.1). The POST arrives
/// without the `SameSite=Lax` cookie; it continues on this host by a GET that
/// carries it, and the user is not asked to sign in again. A continuation is
/// used once.
#[tokio::test]
async fn authorize_redirects_the_signed_in_user_with_a_code() {
    let browser = browser(None).await;
    let issuer = &browser.user.svc.issuer.canonical_url;

    let got = browser
        .get(&with_query(
            &browser.authorize,
            &authorize_query(REDIRECT_URI),
        ))
        .await;
    let query = redirect_query(&got, REDIRECT_URI);
    assert!(query.contains_key("code"), "{query:?}");
    assert_eq!(query["state"], "xyz");
    assert_eq!(&query["iss"], issuer);

    let continued = browser
        .post_cross_site(&authorize_query(REDIRECT_URI))
        .await;
    let query = redirect_query(&browser.get(&continued).await, REDIRECT_URI);
    assert!(query.contains_key("code"), "{query:?}");
    assert_eq!(query["state"], "xyz");

    let again = browser.get(&continued).await;
    assert_eq!(again.status(), 400);
    assert!(again.headers().get("location").is_none());
}

/// Sign `browser`'s user in again in the same browser, as the sign-in page's
/// ceremony does: a new session whose secret the new cookie holds.
async fn sign_in_again(browser: &mut Browser) -> sid_core::models::Session {
    let secret = sid_authn::browser_session::BrowserSecret::generate();
    let mut session = sid_core::models::Session::new(
        browser.user.profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.browser_secret_hash = Some(secret.hash());
    browser
        .user
        .svc
        .storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
    browser.user.cookie = cookie_of(&secret);
    session
}

/// A browser without a session goes to the sign-in page, told to return to a
/// continuation of this request that carries none of its parameters; back
/// there after signing in it gets its code without signing in again. Without
/// a sign-in page the client gets `login_required`.
#[tokio::test]
async fn authorize_sends_an_anonymous_user_to_sign_in() {
    let mut browser = browser(Some(LOGIN_URL)).await;
    let response = no_redirects()
        .get(with_query(
            &browser.authorize,
            &authorize_query(REDIRECT_URI),
        ))
        .send()
        .await
        .unwrap();
    let query = redirect_query(&response, LOGIN_URL);
    let back = browser.continuation(&query["rd"]);

    sign_in_again(&mut browser).await;
    let query = redirect_query(&browser.get(&back).await, REDIRECT_URI);
    assert!(query.contains_key("code"), "{query:?}");
    assert_eq!(query["state"], "xyz");

    let browser = browser_without_login().await;
    let response = no_redirects()
        .get(with_query(
            &browser.authorize,
            &authorize_query(REDIRECT_URI),
        ))
        .send()
        .await
        .unwrap();
    let query = redirect_query(&response, REDIRECT_URI);
    assert_eq!(query["error"], "login_required");
    assert_eq!(query["state"], "xyz");
    assert!(!query.contains_key("code"));
}

async fn browser_without_login() -> Browser {
    browser(None).await
}

/// An unregistered redirect URI, an unknown client, an unknown issuer or a
/// repeated parameter is shown, never redirected (RFC 6749 §3.1, §4.1.2.1).
#[tokio::test]
async fn authorize_shows_what_it_cannot_redirect() {
    let browser = browser(Some(LOGIN_URL)).await;

    let evil = browser
        .get(&with_query(
            &browser.authorize,
            &authorize_query("https://evil.example.com/callback"),
        ))
        .await;
    assert_eq!(evil.status(), 400);
    assert!(evil.headers().get("location").is_none());

    let mut unknown_client = authorize_query(REDIRECT_URI);
    unknown_client[1].1 = "nobody".into();
    let unknown = no_redirects()
        .get(with_query(&browser.authorize, &unknown_client))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 400);
    assert!(unknown.headers().get("location").is_none());

    let elsewhere = browser.authorize.replace(
        &browser.user.svc.issuer.handle.to_string(),
        "0123456789abcdef0123456789abcdef",
    );
    let not_found = no_redirects()
        .get(with_query(&elsewhere, &authorize_query(REDIRECT_URI)))
        .send()
        .await
        .unwrap();
    assert_eq!(not_found.status(), 404);
    assert!(not_found.headers().get("location").is_none());

    let repeated = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(authorize_query(REDIRECT_URI))
        .append_pair("state", "again")
        .finish();
    let posted = no_redirects()
        .post(&browser.authorize)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(repeated)
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 400);
    assert!(posted.headers().get("location").is_none());

    // A POST whose redirect URI is not registered is not kept either.
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(authorize_query("https://evil.example.com/callback"))
        .finish();
    let posted = no_redirects()
        .post(&browser.authorize)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 400);
    assert!(posted.headers().get("location").is_none());
}

/// A signed-in user whose session lacks a method the client requires signs in
/// again (OIDC Core 1.0 §3.1.2.3), sent back to this request afterwards;
/// without a sign-in page the client gets `login_required` (§3.1.2.6). No code
/// is issued either way.
#[tokio::test]
async fn authorize_sends_a_user_below_the_clients_requirement_to_sign_in_again() {
    let mut client = common::test_client();
    client.required_amr = vec!["hwk".into()];

    let browser = browser_with(Some(LOGIN_URL), client.clone()).await;
    let response = browser
        .get(&with_query(
            &browser.authorize,
            &authorize_query(REDIRECT_URI),
        ))
        .await;
    let query = redirect_query(&response, LOGIN_URL);
    browser.continuation(&query["rd"]);

    let browser = browser_with(None, client).await;
    let response = browser
        .get(&with_query(
            &browser.authorize,
            &authorize_query(REDIRECT_URI),
        ))
        .await;
    let query = redirect_query(&response, REDIRECT_URI);
    assert_eq!(query["error"], "login_required");
    assert_eq!(query["state"], "xyz");
    assert!(!query.contains_key("code"), "{query:?}");
}

/// Once the client and its redirect URI are established, a refusal of the
/// request itself goes back to the client with its code, the state and the
/// issuer (RFC 6749 §4.1.2.1, RFC 9207 §2): a public client without PKCE is
/// `invalid_request` (RFC 7636 §4.4.1), another response type
/// `unsupported_response_type`.
#[tokio::test]
async fn authorize_returns_a_refused_request_to_the_client() {
    let browser = browser(Some(LOGIN_URL)).await;

    let without_pkce: Vec<_> = authorize_query(REDIRECT_URI)
        .into_iter()
        .filter(|(name, _)| !name.starts_with("code_challenge"))
        .collect();
    let mut token_response = authorize_query(REDIRECT_URI);
    token_response[0].1 = "token".into();

    for (query, error) in [
        (without_pkce, "invalid_request"),
        (token_response, "unsupported_response_type"),
    ] {
        let response = browser.get(&with_query(&browser.authorize, &query)).await;
        let answer = redirect_query(&response, REDIRECT_URI);
        assert_eq!(answer["error"], error, "{answer:?}");
        assert_eq!(answer["state"], "xyz");
        assert_eq!(answer["iss"], browser.user.svc.issuer.canonical_url);
        assert!(!answer.contains_key("code"), "{answer:?}");
    }
}

/// `authorize_query` with `extra` parameters appended.
fn query_with(extra: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    let mut query = authorize_query(REDIRECT_URI);
    query.extend(extra.iter().map(|(k, v)| (*k, v.to_string())));
    query
}

/// `prompt=none` shows nothing: a browser without a session sends the client
/// `login_required` even with a sign-in page, and a signed-in one gets its
/// code (OIDC Core 1.0 §3.1.2.1, §3.1.2.6).
#[tokio::test]
async fn authorize_prompt_none_never_shows_sign_in() {
    let browser = browser(Some(LOGIN_URL)).await;
    let url = with_query(&browser.authorize, &query_with(&[("prompt", "none")]));

    let anonymous = no_redirects().get(&url).send().await.unwrap();
    let query = redirect_query(&anonymous, REDIRECT_URI);
    assert_eq!(query["error"], "login_required");
    assert_eq!(query["state"], "xyz");

    let signed_in = redirect_query(&browser.get(&url).await, REDIRECT_URI);
    assert!(signed_in.contains_key("code"), "{signed_in:?}");
}

/// `prompt=login` and `max_age=0` need an authentication after the request:
/// the signed-in browser goes to sign-in, and only a sign-in after the request
/// completes it, once, without another round; returning with the old session
/// goes to sign-in again. `max_age` covering the session's authentication
/// gives a code at once (OIDC Core 1.0 §3.1.2.1).
#[tokio::test]
async fn authorize_fresh_authentication_ends_without_a_loop() {
    for fresh in [("prompt", "login"), ("max_age", "0")] {
        let mut browser = browser(Some(LOGIN_URL)).await;
        let url = with_query(&browser.authorize, &query_with(&[fresh]));

        let first = redirect_query(&browser.get(&url).await, LOGIN_URL);
        let back = browser.continuation(&first["rd"]);
        // Back with the old session: still not fresh, a new continuation.
        let again = redirect_query(&browser.get(&back).await, LOGIN_URL);
        assert_ne!(again["rd"], first["rd"], "{fresh:?}");
        let back = browser.continuation(&again["rd"]);

        sign_in_again(&mut browser).await;
        let done = redirect_query(&browser.get(&back).await, REDIRECT_URI);
        assert!(done.contains_key("code"), "{fresh:?}: {done:?}");
    }

    let browser = browser(Some(LOGIN_URL)).await;
    let url = with_query(&browser.authorize, &query_with(&[("max_age", "3600")]));
    assert!(redirect_query(&browser.get(&url).await, REDIRECT_URI).contains_key("code"));
}

/// An invalid `prompt` is the client's `invalid_request`, sent back to it once
/// the client is established.
#[tokio::test]
async fn authorize_refuses_an_invalid_prompt() {
    let browser = browser(Some(LOGIN_URL)).await;
    for prompt in ["none login", "create"] {
        let url = with_query(&browser.authorize, &query_with(&[("prompt", prompt)]));
        let query = redirect_query(&browser.get(&url).await, REDIRECT_URI);
        assert_eq!(query["error"], "invalid_request", "{prompt}");
        assert!(!query.contains_key("code"));
    }
}

/// A cookie whose session has ended, expired or is provisional authorizes
/// nothing: the browser signs in. A session is found only by its own secret.
#[tokio::test]
async fn authorize_needs_a_live_full_session() {
    let url = |browser: &Browser| with_query(&browser.authorize, &authorize_query(REDIRECT_URI));

    let signed_out = browser(Some(LOGIN_URL)).await;
    signed_out
        .user
        .svc
        .storage
        .delete_session(
            signed_out.user.session.id,
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "user",
            ),
            sid_core::models::AuditEntry::system("test", "sign-out").into(),
        )
        .await
        .unwrap();
    redirect_query(&signed_out.get(&url(&signed_out)).await, LOGIN_URL);

    for limited in [
        |s: &mut sid_core::models::Session| {
            s.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1)
        },
        |s: &mut sid_core::models::Session| s.is_provisional = true,
    ] {
        let mut browser = browser(Some(LOGIN_URL)).await;
        let secret = sid_authn::browser_session::BrowserSecret::generate();
        let mut session = browser.user.session.clone();
        session.id = sid_core::models::SessionId::generate();
        session.browser_secret_hash = Some(secret.hash());
        limited(&mut session);
        browser
            .user
            .svc
            .storage
            .create_session(
                &session,
                sid_core::models::AuditEntry::system("test", "session").into(),
            )
            .await
            .unwrap();
        browser.user.cookie = cookie_of(&secret);
        redirect_query(&browser.get(&url(&browser)).await, LOGIN_URL);
    }

    let mut browser = browser(Some(LOGIN_URL)).await;
    browser.user.cookie = cookie_of(&sid_authn::browser_session::BrowserSecret::generate());
    redirect_query(&browser.get(&url(&browser)).await, LOGIN_URL);
}

/// A continuation reference that was never issued, belongs to another
/// client, or is not one at all is shown, never followed.
#[tokio::test]
async fn authorize_refuses_a_forged_continuation() {
    let browser = browser(Some(LOGIN_URL)).await;
    let continued = browser
        .post_cross_site(&authorize_query(REDIRECT_URI))
        .await;
    let other_client = continued.replace("client_id=test-client", "client_id=other-client");
    for url in [
        with_query(
            &browser.authorize,
            &[
                ("client_id", "test-client"),
                ("request_uri", "urn:ietf:params:oauth:request_uri:forged"),
            ],
        ),
        with_query(
            &browser.authorize,
            &[
                ("client_id", "test-client"),
                ("request_uri", "https://evil.example.com/r"),
            ],
        ),
        other_client,
    ] {
        let response = browser.get(&url).await;
        assert_eq!(response.status(), 400, "{url}");
        assert!(response.headers().get("location").is_none(), "{url}");
    }
}

/// An accepted authorization records the session's activity; a refused one
/// does not.
#[tokio::test]
async fn authorize_records_activity_only_on_accepted_use() {
    let browser = browser(Some(LOGIN_URL)).await;
    let last = || async {
        browser
            .user
            .svc
            .storage
            .get_session(browser.user.session.id)
            .await
            .unwrap()
            .unwrap()
            .last_activity_at
    };
    assert_eq!(last().await, None);

    let refused = with_query(&browser.authorize, &query_with(&[("prompt", "none login")]));
    redirect_query(&browser.get(&refused).await, REDIRECT_URI);
    assert_eq!(last().await, None);

    let before = chrono::Utc::now();
    let accepted = with_query(&browser.authorize, &authorize_query(REDIRECT_URI));
    assert!(redirect_query(&browser.get(&accepted).await, REDIRECT_URI).contains_key("code"));
    assert!(last().await.is_some_and(|at| at >= before));
}

/// Behind a load balancer: a form POSTed to one replica continues on the
/// other, whose authorization endpoint finds the kept request and the
/// browser's session in the shared stores.
#[tokio::test]
async fn authorize_continues_on_another_replica() {
    let (a, b) = TestServices::replicas(MockStorage::new()).await;
    common::store_client(&*a.storage, &common::test_client())
        .await
        .unwrap();
    common::open_userinfo_to_clients(&a).await;
    let profile = sid_core::models::Profile::new(Some("replica"));
    a.storage
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("test", "profile").into(),
        )
        .await
        .unwrap();
    let secret = sid_authn::browser_session::BrowserSecret::generate();
    let mut session = sid_core::models::Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.browser_secret_hash = Some(secret.hash());
    a.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();

    let at = |base: String| format!("{base}/i/{}/oauth2/authorize", a.issuer.handle);
    let authorize_a = at(over_http(provider_signing_in_at(&a, Some(LOGIN_URL))).await);
    let authorize_b = at(over_http(provider_signing_in_at(&b, Some(LOGIN_URL))).await);

    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(authorize_query(REDIRECT_URI))
        .finish();
    let posted = no_redirects()
        .post(&authorize_a)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 303);
    let location = posted.headers()["location"].to_str().unwrap();
    let continued = location.replacen(
        &format!("{}/oauth2/authorize", a.issuer.canonical_url),
        &authorize_b,
        1,
    );

    let answer = no_redirects()
        .get(&continued)
        .header("cookie", cookie_of(&secret))
        .send()
        .await
        .unwrap();
    let query = redirect_query(&answer, REDIRECT_URI);
    assert!(query.contains_key("code"), "{query:?}");
}

impl Browser {
    /// The application session the test client got from this browser's IdP
    /// session by a code, stored, and the ID token naming it.
    async fn application_session(&self) -> (sid_core::models::Session, String) {
        let svc = &self.user.svc;
        let mut session = sid_core::models::Session::new(
            self.user.profile.id,
            "127.0.0.1".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .with_grant_authentication(&self.user.session.grant_authentication());
        session.client_id = Some("test-client".into());
        svc.storage
            .create_session(
                &session,
                sid_core::models::AuditEntry::system("test", "session").into(),
            )
            .await
            .unwrap();
        let signer = svc.issuers.signer(&svc.issuer).await.unwrap();
        let id_token = svc
            .jwt
            .id_token_signed_by(
                signer.as_ref(),
                &self.user.profile.id.to_string(),
                &self.user.profile,
                &session,
                "test-client",
                None,
                None,
                None,
            )
            .unwrap();
        (session, id_token)
    }

    async fn exists(&self, id: sid_core::models::SessionId) -> bool {
        self.user
            .svc
            .storage
            .get_session(id)
            .await
            .unwrap()
            .is_some()
    }

    /// POST `form` to the end-session endpoint as this browser.
    async fn post_end_session(&self, form: &[(&str, &str)]) -> reqwest::Response {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        no_redirects()
            .post(&self.end_session)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", &self.user.cookie)
            .body(body)
            .send()
            .await
            .unwrap()
    }
}

/// Whether `response` clears the IdP session cookie.
fn clears_the_cookie(response: &reqwest::Response) -> bool {
    response.headers().get_all("set-cookie").iter().any(|v| {
        v.to_str().unwrap().starts_with("__Host-sid_session=;")
            && v.to_str().unwrap().ends_with("Max-Age=0")
    })
}

/// The confirmation value of a confirmation page, after checking it cannot
/// be framed or post elsewhere.
async fn confirmation_of(response: reqwest::Response) -> String {
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let html = response.text().await.unwrap();
    html.split("name=\"confirmation\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("no confirmation form: {html}"))
        .to_string()
}

/// A valid `id_token_hint` whose application session reuses this browser's
/// IdP session ends both and clears the cookie; the application's access
/// tokens stop. An unregistered post_logout_redirect_uri is not followed
/// (RP-Initiated Logout 1.0 §2, §3); an unknown issuer is 404.
#[tokio::test]
async fn end_session_with_the_browsers_hint_ends_single_sign_on() {
    let browser = browser(None).await;
    let (application, id_token) = browser.application_session().await;

    let ended = browser
        .get(&with_query(
            &browser.end_session,
            &[
                ("id_token_hint", id_token.as_str()),
                ("client_id", "test-client"),
                ("post_logout_redirect_uri", "https://evil.example.com/"),
            ],
        ))
        .await;
    assert_eq!(ended.status(), 200);
    assert!(ended.headers().get("location").is_none());
    assert!(clears_the_cookie(&ended));
    assert!(!browser.exists(browser.user.session.id).await);
    assert!(!browser.exists(application.id).await);
    assert!(
        browser
            .user
            .svc
            .revocation_cache
            .is_revoked("unrelated-jti", &application.id.to_string())
            .await
            .unwrap(),
        "the application's access tokens still pass"
    );

    let elsewhere = browser.end_session.replace(
        &browser.user.svc.issuer.handle.to_string(),
        "0123456789abcdef0123456789abcdef",
    );
    assert_eq!(browser.get(&elsewhere).await.status(), 404);
}

/// A valid hint from a browser without that IdP session ends only the
/// application's own session: single sign-on and the cookie stay, and this
/// browser is offered to end its own IdP session by confirming.
#[tokio::test]
async fn end_session_with_another_browsers_hint_ends_only_the_application() {
    let first = browser(None).await;
    let (application, id_token) = first.application_session().await;

    let anonymous = no_redirects()
        .post(&first.end_session)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("id_token_hint={id_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 200);
    assert!(!clears_the_cookie(&anonymous));
    assert!(!first.exists(application.id).await);
    assert!(first.exists(first.user.session.id).await);

    // Another browser session of the same user: its SSO is not the hint's.
    let mut other = browser(None).await;
    let (application, id_token) = other.application_session().await;
    sign_in_again(&mut other).await;
    let response = other
        .post_end_session(&[("id_token_hint", &id_token)])
        .await;
    assert!(!clears_the_cookie(&response));
    confirmation_of(response).await;
    assert!(!other.exists(application.id).await);
    assert!(other.exists(other.user.session.id).await);
}

/// Without a valid hint nothing ends until the user confirms: the page's form
/// ends the browser's IdP session and clears the cookie; its value works once
/// and only in the browser it was given to. An invalid hint (another
/// issuer's token, another client, not an ID token) is no hint.
#[tokio::test]
async fn end_session_without_a_valid_hint_needs_confirmation() {
    let browser = browser(None).await;
    let (application, id_token) = browser.application_session().await;
    let access = browser.user.token(&["openid"], None).await;

    for hint in [
        vec![],
        vec![("id_token_hint", "not-a-token")],
        vec![("id_token_hint", access.as_str())],
        vec![
            ("id_token_hint", id_token.as_str()),
            ("client_id", "other-client"),
        ],
    ] {
        let page = browser.get(&with_query(&browser.end_session, &hint)).await;
        assert!(!clears_the_cookie(&page), "{hint:?}");
        confirmation_of(page).await;
        assert!(browser.exists(browser.user.session.id).await, "{hint:?}");
        assert!(browser.exists(application.id).await, "{hint:?}");
    }

    let confirmation = confirmation_of(browser.get(&browser.end_session).await).await;
    // Posted without the cookie: from another browser it ends nothing.
    let elsewhere = no_redirects()
        .post(&browser.end_session)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("confirmation={confirmation}"))
        .send()
        .await
        .unwrap();
    assert!(!clears_the_cookie(&elsewhere));
    assert!(browser.exists(browser.user.session.id).await);

    let confirmation = confirmation_of(browser.get(&browser.end_session).await).await;
    let confirmed = browser
        .post_end_session(&[("confirmation", &confirmation)])
        .await;
    assert!(clears_the_cookie(&confirmed));
    assert!(!browser.exists(browser.user.session.id).await);
    assert!(!browser.exists(application.id).await);

    // Used once: a second post finds no session and ends nothing more.
    let again = browser
        .post_end_session(&[("confirmation", &confirmation)])
        .await;
    assert!(!clears_the_cookie(&again));
}

const SIGNED_OUT: &str = "https://app.sid.example.com/signed-out";

/// A browser whose test client registered [`SIGNED_OUT`] as its post-logout
/// redirect URI.
async fn browser_returning() -> Browser {
    let mut client = common::test_client();
    client.post_logout_redirect_uris = vec![SIGNED_OUT.into()];
    browser_with(None, client).await
}

/// The `href` of a page's return link, unescaped, if it has one.
fn return_link(html: &str) -> Option<String> {
    html.split("<a href=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .map(|href| href.replace("&amp;", "&"))
}

/// A valid hint whose client registered exactly the requested URI returns the
/// browser there with the relying party's `state`, after single sign-on ended
/// and the cookie was cleared (RP-Initiated Logout 1.0 §3).
#[tokio::test]
async fn end_session_returns_to_a_registered_uri_with_state() {
    let browser = browser_returning().await;
    let (application, id_token) = browser.application_session().await;

    let ended = browser
        .get(&with_query(
            &browser.end_session,
            &[
                ("id_token_hint", id_token.as_str()),
                ("post_logout_redirect_uri", SIGNED_OUT),
                ("state", "s 1&x"),
            ],
        ))
        .await;
    let query = redirect_query(&ended, SIGNED_OUT);
    assert_eq!(query.len(), 1, "{query:?}");
    assert_eq!(query["state"], "s 1&x");
    assert!(clears_the_cookie(&ended));
    assert!(!browser.exists(browser.user.session.id).await);
    assert!(!browser.exists(application.id).await);
}

/// Only an exact registered URI named by a valid hint is followed: a variant
/// of it, the client's redirect URI, or a URI with only `client_id` (no hint
/// proves the client asked) gets a page, never a redirect (RP-Initiated
/// Logout 1.0 §2, §3). The request still does what it would without it.
#[tokio::test]
async fn end_session_follows_no_unproven_return() {
    let browser = browser_returning().await;
    let (_, id_token) = browser.application_session().await;

    for uri in [
        "https://app.sid.example.com/signed-out/",
        "https://app.sid.example.com/signed-out?x=1",
        "https://app.sid.example.com/callback",
    ] {
        let page = browser
            .get(&with_query(
                &browser.end_session,
                &[
                    ("id_token_hint", id_token.as_str()),
                    ("client_id", "other-client"),
                    ("post_logout_redirect_uri", uri),
                ],
            ))
            .await;
        assert!(page.headers().get("location").is_none(), "{uri}");
        assert!(browser.exists(browser.user.session.id).await, "{uri}");
    }

    let only_client = browser
        .get(&with_query(
            &browser.end_session,
            &[
                ("client_id", "test-client"),
                ("post_logout_redirect_uri", SIGNED_OUT),
            ],
        ))
        .await;
    assert!(only_client.headers().get("location").is_none());
    let html = only_client.text().await.unwrap();
    assert_eq!(return_link(&html), None, "{html}");
    assert!(browser.exists(browser.user.session.id).await);

    let variant = browser
        .get(&with_query(
            &browser.end_session,
            &[
                ("id_token_hint", id_token.as_str()),
                (
                    "post_logout_redirect_uri",
                    "https://app.sid.example.com/callback",
                ),
            ],
        ))
        .await;
    assert_eq!(variant.status(), 200);
    assert!(variant.headers().get("location").is_none());
    assert!(clears_the_cookie(&variant));
}

/// When the browser keeps its IdP session, the confirmation page links back
/// to the registered URI with `state`, and confirming returns there too after
/// ending the IdP session; the return is kept server-side, not in the form.
#[tokio::test]
async fn end_session_confirmation_returns_to_the_registered_uri() {
    let mut browser = browser_returning().await;
    let (application, id_token) = browser.application_session().await;
    let current = sign_in_again(&mut browser).await;

    let target = format!("{SIGNED_OUT}?state=a%22b%3Cc");
    let page = browser
        .post_end_session(&[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", SIGNED_OUT),
            ("state", "a\"b<c"),
        ])
        .await;
    assert!(!clears_the_cookie(&page));
    assert!(!browser.exists(application.id).await);
    let html = page.text().await.unwrap();
    assert!(!html.contains("a\"b<c"), "unescaped state: {html}");
    assert_eq!(
        return_link(&html).as_deref(),
        Some(target.as_str()),
        "{html}"
    );
    let confirmation = html
        .split("name=\"confirmation\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_string();

    let confirmed = browser
        .post_end_session(&[("confirmation", &confirmation)])
        .await;
    let query = redirect_query(&confirmed, SIGNED_OUT);
    assert_eq!(query["state"], "a\"b<c");
    assert!(clears_the_cookie(&confirmed));
    assert!(!browser.exists(current.id).await);
}

/// A deactivated client returns nobody: its registered URI is not followed.
#[tokio::test]
async fn end_session_returns_nobody_to_an_inactive_client() {
    let mut client = common::test_client();
    client.post_logout_redirect_uris = vec![SIGNED_OUT.into()];
    client.active = false;
    let browser = browser_with(None, client).await;
    let (_, id_token) = browser.application_session().await;

    let ended = browser
        .get(&with_query(
            &browser.end_session,
            &[
                ("id_token_hint", id_token.as_str()),
                ("post_logout_redirect_uri", SIGNED_OUT),
            ],
        ))
        .await;
    assert_eq!(ended.status(), 200);
    assert!(ended.headers().get("location").is_none());
}

/// Logging out an older session never clears a newer account's cookie: the
/// confirmation of the old session posted with the new cookie ends nothing.
#[tokio::test]
async fn an_older_sessions_confirmation_does_not_end_a_newer_one() {
    let mut browser = browser(None).await;
    let old = confirmation_of(browser.get(&browser.end_session).await).await;
    let old_session = browser.user.session.id;
    sign_in_again(&mut browser).await;

    let response = browser.post_end_session(&[("confirmation", &old)]).await;
    assert!(!clears_the_cookie(&response));
    assert!(browser.exists(old_session).await);
    confirmation_of(response).await;
}

/// A cache that cannot be reached.
struct DownCache;

#[async_trait::async_trait]
impl sid_plugin::cache::CacheBackend for DownCache {
    async fn get(&self, _: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Err(down())
    }
    async fn set(&self, _: &str, _: &[u8], _: Duration) -> sid_plugin::cache::CacheResult<()> {
        Err(down())
    }
    async fn delete(&self, _: &str) -> sid_plugin::cache::CacheResult<()> {
        Err(down())
    }
    async fn take(&self, _: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Err(down())
    }
    async fn publish(&self, _: &str, _: &[u8]) -> sid_plugin::cache::CacheResult<()> {
        Err(down())
    }
    async fn subscribe(
        &self,
        _: &str,
    ) -> sid_plugin::cache::CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(down())
    }
    async fn health_check(&self) -> sid_plugin::cache::CacheResult<()> {
        Err(down())
    }
}

fn down() -> sid_plugin::cache::CacheError {
    sid_plugin::cache::CacheError::Connection("down".into())
}

/// When the revocation state cannot be written, logout is an error to retry,
/// never a "Signed out" that left the tokens live, and it clears no cookie.
#[tokio::test]
async fn end_session_without_revocation_state_fails() {
    let profile = sid_core::models::Profile::new(Some("alice"));
    let secret = sid_authn::browser_session::BrowserSecret::generate();
    let mut session = sid_core::models::Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.browser_secret_hash = Some(secret.hash());
    let svc = TestServices::with_cache(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_session(session.clone()),
        std::sync::Arc::new(DownCache),
    );
    let base = over_http(provider_of(&svc)).await;

    let response = no_redirects()
        .get(format!("{base}/i/{}/oauth2/end-session", svc.issuer.handle))
        .header("cookie", cookie_of(&secret))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_server_error(), "{}", response.status());
    assert!(!clears_the_cookie(&response));
}
