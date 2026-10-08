// SPDX-License-Identifier: AGPL-3.0-only
//! DPoP at the token endpoint (RFC 9449): the proof comes from the `DPoP`
//! header only, names the request as it was received (the REST request a
//! transcoder made the call from, or the gRPC call itself), a valid one binds
//! the issued access token to the key, and a refused one is reported as
//! `invalid_dpop_proof`.

mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::TestServices;
use common::mock_storage::MockStorage;
use common::oauth_client::{authorize_code, code_exchange};
use common::{test_client, test_profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

/// The token endpoint of the installation's issuer, as its discovery
/// document advertises it: the `htu` a proof sent there names.
fn token_endpoint(svc: &TestServices) -> String {
    format!("{}/oauth2/token", svc.issuer.canonical_url)
}

/// The installation's public origin.
const ORIGIN: &str = "https://sid.example.com";

/// The token endpoint's RPC as a native gRPC client calls it: the `htu` its
/// proof names.
fn token_rpc() -> String {
    format!("{ORIGIN}/sid.v1.authn.AuthService/OAuth2Token")
}

/// `req` as the transcoder hands it over for a REST `POST` to the issuer's
/// token endpoint.
fn over_rest(svc: &TestServices, req: Request<OAuth2TokenRequest>) -> Request<OAuth2TokenRequest> {
    over_rest_as(svc, req, "POST")
}

fn over_rest_as(
    svc: &TestServices,
    mut req: Request<OAuth2TokenRequest>,
    method: &str,
) -> Request<OAuth2TokenRequest> {
    let path = token_endpoint(svc).strip_prefix(ORIGIN).unwrap().to_owned();
    req.extensions_mut()
        .insert(sid_authn::resource::TranscodedRequest::new(method, path));
    req
}

/// JWK thumbprint of the test ES256 key.
const TEST_JKT: &str = "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA";

/// A DPoP proof for `POST htu`, signed with the test ES256 key.
fn proof(htu: &str) -> String {
    proof_for("POST", htu)
}

/// A DPoP proof for `htm htu`, signed with the test ES256 key.
fn proof_for(htm: &str, htu: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
        "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk);
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../sid-authn/tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &claims, &key).unwrap()
}

fn claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

async fn services() -> (TestServices, String) {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone()),
    );
    let code = authorize_code(&svc, &profile).await;
    (svc, code)
}

fn with_dpop(mut req: Request<OAuth2TokenRequest>, proof: &str) -> Request<OAuth2TokenRequest> {
    req.metadata_mut().append("dpop", proof.parse().unwrap());
    req
}

/// A proof in the `DPoP` header binds the access token to its key, over
/// REST (naming the REST request) and over native gRPC (naming the RPC).
#[tokio::test]
async fn proof_in_header_binds_the_token() {
    let (svc, code) = services().await;
    let issued = svc
        .auth
        .o_auth2_token(with_dpop(
            over_rest(&svc, code_exchange(&svc, &code)),
            &proof(&token_endpoint(&svc)),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(issued.token_type, "DPoP");
    assert_eq!(claims(&issued.access_token)["cnf"]["jkt"], TEST_JKT);

    let (svc, code) = services().await;
    let issued = svc
        .auth
        .o_auth2_token(with_dpop(code_exchange(&svc, &code), &proof(&token_rpc())))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(issued.token_type, "DPoP");
    assert_eq!(claims(&issued.access_token)["cnf"]["jkt"], TEST_JKT);
}

/// A proof names the request it was made for: a REST proof does not open a
/// gRPC call, an RPC proof does not open a REST request, and a proof for
/// another method does not open either (RFC 9449 §4.3 `htm`, `htu`).
#[tokio::test]
async fn a_proof_for_another_request_is_refused() {
    for (case, over_rest_method, proof) in [
        ("REST proof on gRPC", None, proof_for("POST", "REST")),
        ("RPC proof on REST", Some("POST"), proof(&token_rpc())),
        (
            "GET proof on REST POST",
            Some("POST"),
            proof_for("GET", "REST"),
        ),
        (
            "POST proof on REST GET",
            Some("GET"),
            proof_for("POST", "REST"),
        ),
    ] {
        let (svc, code) = services().await;
        let proof = proof.replace("REST", "unused");
        let rest_proof = |htm: &str| proof_for(htm, &token_endpoint(&svc));
        let proof = match case {
            "REST proof on gRPC" => rest_proof("POST"),
            "GET proof on REST POST" => rest_proof("GET"),
            "POST proof on REST GET" => rest_proof("POST"),
            _ => proof,
        };
        let req = code_exchange(&svc, &code);
        let req = match over_rest_method {
            Some(method) => over_rest_as(&svc, req, method),
            None => req,
        };
        let err = svc
            .auth
            .o_auth2_token(with_dpop(req, &proof))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{case}");
    }
}

/// A proof names the endpoint it was made for: one for the issuer-less
/// root token endpoint does not open the issuer's (RFC 9449 §4.3 `htu`).
#[tokio::test]
async fn proof_for_the_root_endpoint_is_refused_at_the_issuers() {
    let (svc, code) = services().await;

    let err = svc
        .auth
        .o_auth2_token(with_dpop(
            over_rest(&svc, code_exchange(&svc, &code)),
            &proof("https://sid.example.com/oauth2/token"),
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::InvalidArgument);
}

/// The body is not where a proof travels: one placed there binds nothing.
#[tokio::test]
async fn proof_in_body_is_ignored() {
    let (svc, code) = services().await;
    let mut req = code_exchange(&svc, &code);
    req.get_mut().dpop_proof = Some(proof(&token_endpoint(&svc)));

    let issued = svc.auth.o_auth2_token(req).await.unwrap().into_inner();

    assert_eq!(issued.token_type, "Bearer");
    assert!(claims(&issued.access_token).get("cnf").is_none());
}

/// A proof for another endpoint is refused with `invalid_dpop_proof`.
#[tokio::test]
async fn invalid_proof_is_reported_as_invalid_dpop_proof() {
    let (svc, code) = services().await;

    let err = svc
        .auth
        .o_auth2_token(with_dpop(
            code_exchange(&svc, &code),
            &proof("https://sid.example.com/other"),
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::InvalidArgument);
    let details = tonic_types::StatusExt::get_error_details(&err);
    let info = details.error_info().expect("ErrorInfo");
    assert_eq!(
        info.metadata.get("oauthError").map(String::as_str),
        Some("invalid_dpop_proof")
    );
}

fn refresh(svc: &TestServices, token: &str) -> Request<OAuth2TokenRequest> {
    Request::new(OAuth2TokenRequest {
        grant_type: "refresh_token".to_string(),
        refresh_token: Some(token.to_string()),
        client_id: Some("test-client".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    })
}

/// A public client's refresh token obtained with DPoP is bound to the key:
/// without a proof for that key it is refused, with one it rotates, and the
/// new token stays bound (RFC 9449 §5).
#[tokio::test]
async fn refresh_token_is_bound_to_the_dpop_key() {
    let (svc, code) = services().await;
    let endpoint = token_endpoint(&svc);
    let issued = svc
        .auth
        .o_auth2_token(with_dpop(
            over_rest(&svc, code_exchange(&svc, &code)),
            &proof(&endpoint),
        ))
        .await
        .unwrap()
        .into_inner();
    let first = issued.refresh_token.unwrap();

    let err = svc
        .auth
        .o_auth2_token(refresh(&svc, &first))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let details = tonic_types::StatusExt::get_error_details(&err);
    assert_eq!(
        details
            .error_info()
            .and_then(|i| i.metadata.get("oauthError"))
            .map(String::as_str),
        Some("invalid_dpop_proof")
    );

    let rotated = svc
        .auth
        .o_auth2_token(with_dpop(
            over_rest(&svc, refresh(&svc, &first)),
            &proof(&endpoint),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rotated.token_type, "DPoP");

    let second = rotated.refresh_token.unwrap();
    let err = svc
        .auth
        .o_auth2_token(refresh(&svc, &second))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Code::InvalidArgument,
        "rotation dropped the binding"
    );
}

/// Replicas over one store and one shared cache (the test stack's Redis).
async fn replicas_over_redis() -> (TestServices, TestServices, sid_core::models::Profile) {
    let profile = test_profile();
    let svc = TestServices::with_cache(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone()),
        common::test_redis().await,
    );
    let other = svc.restarted().await;
    (svc, other, profile)
}

/// A proof is admitted once across replicas: sent to two replicas at once,
/// at most one admits it, and a replica started later refuses it too, so a
/// restart does not reopen its window (RFC 9449 §11.1).
#[tokio::test]
async fn a_proof_is_admitted_once_across_replicas() {
    let (a, b, profile) = replicas_over_redis().await;
    let proof = proof(&token_rpc());
    let first = code_exchange(&a, &authorize_code(&a, &profile).await);
    let second = code_exchange(&a, &authorize_code(&a, &profile).await);
    let (on_a, on_b) = tokio::join!(
        a.auth.o_auth2_token(with_dpop(first, &proof)),
        b.auth.o_auth2_token(with_dpop(second, &proof)),
    );
    let admitted = [&on_a, &on_b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(admitted, 1, "{on_a:?} / {on_b:?}");

    let restarted = a.restarted().await;
    let third = code_exchange(&a, &authorize_code(&a, &profile).await);
    let err = restarted
        .auth
        .o_auth2_token(with_dpop(third, &proof))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

/// When a proof's single use cannot be recorded, nothing is issued and the
/// caller is told to retry: the proof itself was not found wrong.
#[tokio::test]
async fn without_the_replay_record_the_token_endpoint_is_unavailable() {
    let profile = test_profile();
    let svc = TestServices::with_cache(
        MockStorage::new()
            .with_client(test_client())
            .with_profile(profile.clone()),
        std::sync::Arc::new(common::NoReplayRecord(std::sync::Arc::new(
            sid_plugin::cache::InMemoryCacheBackend::new(),
        ))),
    );
    let code = authorize_code(&svc, &profile).await;
    let err = svc
        .auth
        .o_auth2_token(with_dpop(code_exchange(&svc, &code), &proof(&token_rpc())))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable, "{err:?}");
}

/// More than one `DPoP` header is refused (RFC 9449 §4.3).
#[tokio::test]
async fn two_dpop_headers_are_refused() {
    let (svc, code) = services().await;
    let endpoint = token_endpoint(&svc);
    let req = with_dpop(
        with_dpop(code_exchange(&svc, &code), &proof(&endpoint)),
        &proof(&endpoint),
    );

    let err = svc.auth.o_auth2_token(req).await.unwrap_err();

    assert_eq!(err.code(), Code::InvalidArgument);
}
