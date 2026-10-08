// SPDX-License-Identifier: AGPL-3.0-only
//! How gRPC services read the caller's access token.
//!
//! A DPoP-bound token must not be accepted as a plain bearer token, or a
//! stolen token works without the key it is bound to (RFC 9449 §7.1); a
//! service that only verifies tokens must be able to do so with the public
//! key alone.

#![cfg(feature = "grpc")]

use sid_authn::caller::{authenticate, bearer_token};
use sid_authn::jwt::{JwtService, TokenVerifier};
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::dpop::DPopBinding;
use sid_core::models::{Profile, Session};
use tonic::{Code, Request};

const ISSUER: &str = "https://sid.example.com";
const PUBLIC_KEY: &[u8] = include_bytes!("fixtures/test_ed25519_public.pem");

fn jwt() -> JwtService {
    JwtService::new(
        include_bytes!("fixtures/test_ed25519_private.pem"),
        PUBLIC_KEY,
        ISSUER.to_string(),
    )
    .expect("JWT service")
}

fn revocation() -> RevocationCache {
    RevocationCache::new(
        std::time::Duration::from_secs(3600),
        std::sync::Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    )
}

/// An access token for a fresh profile, DPoP-bound when `binding` is given.
fn token(binding: Option<&DPopBinding>) -> (Profile, String) {
    let profile = Profile::new(Some("alice"));
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let token = jwt()
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile,
            &session,
            &["openid".to_string()],
            binding,
            None,
        )
        .expect("issue token");
    (profile, token)
}

fn request(authorization: &str) -> Request<()> {
    let mut req = Request::new(());
    req.metadata_mut()
        .insert("authorization", authorization.parse().unwrap());
    req
}

/// A DPoP-bound token sent with the `Bearer` scheme is refused.
#[tokio::test]
async fn dpop_bound_token_is_not_accepted_as_bearer() {
    let (_, token) = token(Some(&DPopBinding::new("thumbprint-of-client-key")));
    let err = authenticate(
        &request(&format!("Bearer {token}")),
        jwt().verifier(),
        &revocation(),
    )
    .await
    .expect_err("a DPoP-bound token without its proof");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// The `DPoP` scheme is refused while these services do not verify proofs:
/// accepting it would drop the sender constraint.
#[tokio::test]
async fn dpop_scheme_is_refused() {
    let (_, token) = token(Some(&DPopBinding::new("thumbprint-of-client-key")));
    let err = authenticate(
        &request(&format!("DPoP {token}")),
        jwt().verifier(),
        &revocation(),
    )
    .await
    .expect_err("DPoP scheme without proof verification");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// The auth-scheme is case-insensitive (RFC 7235 §2.1).
#[test]
fn bearer_scheme_is_case_insensitive() {
    let (_, token) = token(None);
    let req = request(&format!("bearer {token}"));
    assert_eq!(bearer_token(&req).expect("lowercase scheme"), token);
}

/// No `authorization` header, another scheme, or a scheme with no separating
/// space is not a bearer credential.
#[test]
fn malformed_authorization_is_unauthenticated() {
    assert_eq!(
        bearer_token(&Request::new(())).unwrap_err().code(),
        Code::Unauthenticated
    );
    for value in ["Basic dXNlcjpwYXNz", "Bearertoken", "Bearer   "] {
        assert_eq!(
            bearer_token(&request(value)).unwrap_err().code(),
            Code::Unauthenticated,
            "{value}"
        );
    }
}

/// A verifier built from the public key alone authenticates a token the
/// signing service issued, so verify-only services need no private key.
#[tokio::test]
async fn public_key_verifier_authenticates_the_caller() {
    let verifier = TokenVerifier::new(PUBLIC_KEY, ISSUER.to_string()).expect("verifier");
    let (profile, token) = token(None);
    let caller = authenticate(
        &request(&format!("Bearer {token}")),
        &verifier,
        &revocation(),
    )
    .await
    .expect("valid token");
    assert_eq!(caller.profile_id, profile.id);
}

/// A token exchanged from a personal access token without a resource-bound
/// grant is not an installation caller credential: such a PAT is bound to no
/// registered resource, so no service may admit what was exchanged from it.
#[tokio::test]
async fn token_exchanged_from_unbound_pat_is_refused() {
    let profile = Profile::new(Some("alice"));
    let now = chrono::Utc::now().timestamp();
    let claims = sid_authn::jwt::AccessTokenClaims {
        sub: profile.id.to_string(),
        pid: Some(profile.id.to_string()),
        iss: ISSUER.to_string(),
        aud: vec![ISSUER.to_string()],
        client_id: None,
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: "urn:sid:acr:pat".to_string(),
        scope: "openid".to_string(),
        roles: String::new(),
        sid: "pat-1".to_string(),
        amr: vec!["pat".to_string()],
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
    };
    let key =
        jsonwebtoken::EncodingKey::from_ed_pem(include_bytes!("fixtures/test_ed25519_private.pem"))
            .expect("signing key");
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        &claims,
        &key,
    )
    .expect("sign");
    let err = authenticate(
        &request(&format!("Bearer {token}")),
        jwt().verifier(),
        &revocation(),
    )
    .await
    .expect_err("a token exchanged from an unbound PAT");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// A token from another issuer is refused by the verifier.
#[tokio::test]
async fn verifier_refuses_another_issuer() {
    let verifier =
        TokenVerifier::new(PUBLIC_KEY, "https://other.example.com".to_string()).expect("verifier");
    let (_, token) = token(None);
    let err = authenticate(
        &request(&format!("Bearer {token}")),
        &verifier,
        &revocation(),
    )
    .await
    .expect_err("foreign issuer");
    assert_eq!(err.code(), Code::Unauthenticated);
}
