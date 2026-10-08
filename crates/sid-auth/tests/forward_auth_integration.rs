// SPDX-License-Identifier: AGPL-3.0-only
//! Forward auth end to end through the service's own transports.
//!
//! A real gRPC server stands in for the SID server (issuer registry and
//! sid-authz). The decision service runs as it does in a deployment: its gRPC
//! services on a port, reverse-proxy HTTP through the embedded transcoder,
//! Envoy through ext_authz.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{
    HttpRequest as EnvoyHttpRequest, Request as EnvoyAttributeRequest,
};
use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse as EnvoyHttpResponse;
use envoy_types::pb::envoy::service::auth::v3::{AttributeContext, CheckRequest};
use sid_proto::sid::v1::authz::*;
use sid_proto::sid::v1::authz_service_server::{AuthzService, AuthzServiceServer};
use sid_proto::sid::v1::oidc_issuer_service_server::{OidcIssuerService, OidcIssuerServiceServer};
use sid_proto::sid::v1::{
    GetOidcIssuerRequest, GetProtectedResourceRequest, IssuerPublicKey, OidcIssuer,
    ProtectedResourceTarget,
};
use tokio::net::TcpListener;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};
use tower::ServiceExt;

// ── Mock SID server ──

/// sid-authz, counting the permission questions it is asked.
#[derive(Default)]
struct MockAuthz {
    asked: Arc<std::sync::atomic::AtomicUsize>,
}

#[tonic::async_trait]
impl AuthzService for MockAuthz {
    async fn check_permission(
        &self,
        _request: TonicRequest<CheckPermissionRequest>,
    ) -> Result<TonicResponse<CheckPermissionResponse>, Status> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(TonicResponse::new(CheckPermissionResponse {
            reason: None,
            zookie: None,
            outcome: PermissionOutcome::Allowed.into(),
        }))
    }
    async fn batch_check_permission(
        &self,
        _r: TonicRequest<BatchCheckPermissionRequest>,
    ) -> Result<TonicResponse<BatchCheckPermissionResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn list_objects(
        &self,
        _r: TonicRequest<ListObjectsRequest>,
    ) -> Result<TonicResponse<ListObjectsResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn list_subjects(
        &self,
        _r: TonicRequest<ListSubjectsRequest>,
    ) -> Result<TonicResponse<ListSubjectsResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn create_role(
        &self,
        _r: TonicRequest<CreateRoleRequest>,
    ) -> Result<TonicResponse<CreateRoleResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn get_role(
        &self,
        _r: TonicRequest<GetRoleRequest>,
    ) -> Result<TonicResponse<GetRoleResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn update_role(
        &self,
        _r: TonicRequest<UpdateRoleRequest>,
    ) -> Result<TonicResponse<UpdateRoleResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn delete_role(
        &self,
        _r: TonicRequest<DeleteRoleRequest>,
    ) -> Result<TonicResponse<DeleteRoleResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn list_roles(
        &self,
        _r: TonicRequest<ListRolesRequest>,
    ) -> Result<TonicResponse<ListRolesResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn assign_role(
        &self,
        _r: TonicRequest<AssignRoleRequest>,
    ) -> Result<TonicResponse<AssignRoleResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn revoke_role(
        &self,
        _r: TonicRequest<RevokeRoleRequest>,
    ) -> Result<TonicResponse<RevokeRoleResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn list_role_assignments(
        &self,
        _r: TonicRequest<ListRoleAssignmentsRequest>,
    ) -> Result<TonicResponse<ListRoleAssignmentsResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn create_group(
        &self,
        _r: TonicRequest<CreateGroupRequest>,
    ) -> Result<TonicResponse<CreateGroupResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn get_group(
        &self,
        _r: TonicRequest<GetGroupRequest>,
    ) -> Result<TonicResponse<GetGroupResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn update_group(
        &self,
        _r: TonicRequest<UpdateGroupRequest>,
    ) -> Result<TonicResponse<UpdateGroupResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn delete_group(
        &self,
        _r: TonicRequest<DeleteGroupRequest>,
    ) -> Result<TonicResponse<DeleteGroupResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn list_groups(
        &self,
        _r: TonicRequest<ListGroupsRequest>,
    ) -> Result<TonicResponse<ListGroupsResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn add_to_group(
        &self,
        _r: TonicRequest<AddToGroupRequest>,
    ) -> Result<TonicResponse<AddToGroupResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn remove_from_group(
        &self,
        _r: TonicRequest<RemoveFromGroupRequest>,
    ) -> Result<TonicResponse<RemoveFromGroupResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn list_group_members(
        &self,
        _r: TonicRequest<ListGroupMembersRequest>,
    ) -> Result<TonicResponse<ListGroupMembersResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn create_policy(
        &self,
        _r: TonicRequest<CreatePolicyRequest>,
    ) -> Result<TonicResponse<CreatePolicyResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn get_policy(
        &self,
        _r: TonicRequest<GetPolicyRequest>,
    ) -> Result<TonicResponse<GetPolicyResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn update_policy(
        &self,
        _r: TonicRequest<UpdatePolicyRequest>,
    ) -> Result<TonicResponse<UpdatePolicyResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn delete_policy(
        &self,
        _r: TonicRequest<DeletePolicyRequest>,
    ) -> Result<TonicResponse<DeletePolicyResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn list_policies(
        &self,
        _r: TonicRequest<ListPoliciesRequest>,
    ) -> Result<TonicResponse<ListPoliciesResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn evaluate_policy(
        &self,
        _r: TonicRequest<EvaluatePolicyRequest>,
    ) -> Result<TonicResponse<EvaluatePolicyResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn validate_policy(
        &self,
        _r: TonicRequest<ValidatePolicyRequest>,
    ) -> Result<TonicResponse<ValidatePolicyResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn check_sod_conflicts(
        &self,
        _r: TonicRequest<CheckSodConflictsRequest>,
    ) -> Result<TonicResponse<CheckSodConflictsResponse>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn simulate_policy(
        &self,
        _r: TonicRequest<SimulatePolicyRequest>,
    ) -> Result<TonicResponse<SimulatePolicyResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}

const HANDLE: &str = "0123456789abcdef0123456789abcdef";
const ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";
const ORDERS: &str = "https://api.example.com/orders";
const WIKI: &str = "https://wiki.example.com/";
const SUBJECT: &str = "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e";

/// The SID server's issuer registry: one issuer with one key; Orders and
/// Wiki registered under it (Ghost is not). `unavailable` makes every resource
/// lookup fail as a down registry does.
struct MockIssuers {
    public_key: [u8; 32],
    unavailable: bool,
}

#[tonic::async_trait]
impl OidcIssuerService for MockIssuers {
    async fn get_oidc_issuer(
        &self,
        request: TonicRequest<GetOidcIssuerRequest>,
    ) -> Result<TonicResponse<OidcIssuer>, Status> {
        if request.into_inner().handle != HANDLE {
            return Err(Status::not_found("no issuer"));
        }
        Ok(TonicResponse::new(OidcIssuer {
            issuer: ISSUER.into(),
            keys: vec![IssuerPublicKey {
                key_id: "k1".into(),
                public_key: self.public_key.to_vec(),
            }],
        }))
    }

    async fn get_protected_resource(
        &self,
        request: TonicRequest<GetProtectedResourceRequest>,
    ) -> Result<TonicResponse<ProtectedResourceTarget>, Status> {
        if self.unavailable {
            return Err(Status::unavailable("registry down"));
        }
        let request = request.into_inner();
        match (request.issuer_handle.as_str(), request.resource.as_str()) {
            (HANDLE, ORDERS) | (HANDLE, WIKI) => Ok(TonicResponse::new(ProtectedResourceTarget {
                issuer: ISSUER.into(),
                resource: request.resource,
                active: true,
                id: Some(sid_core::models::ResourceId::generate().into()),
            })),
            _ => Err(Status::not_found("no resource")),
        }
    }
}

// ── Harness ──

/// The issuer's signing key and its public half.
fn issuer_key() -> (jsonwebtoken::EncodingKey, [u8; 32]) {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use rand::Rng;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let der = sk.to_pkcs8_der().unwrap();
    (
        jsonwebtoken::EncodingKey::from_ed_der(der.as_bytes()),
        sk.verifying_key().to_bytes(),
    )
}

/// Serve `routes` on a free local port.
async fn serve(routes: tonic::service::Routes) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    addr
}

/// A running decision service against a mock SID server.
struct Harness {
    key: jsonwebtoken::EncodingKey,
    grpc: SocketAddr,
    /// The HTTP form as the service serves it: the transcoder in front of
    /// the service's own gRPC services, called in process.
    http: structured_proxy::ProxyService<tonic::service::Routes>,
    cache: Arc<dyn sid_plugin::cache::CacheBackend>,
}

async fn harness_with(authz: MockAuthz, registry_down: bool) -> Harness {
    let (key, public_key) = issuer_key();
    let upstream = serve(
        tonic::service::Routes::new(AuthzServiceServer::new(authz)).add_service(
            OidcIssuerServiceServer::new(MockIssuers {
                public_key,
                unavailable: registry_down,
            }),
        ),
    )
    .await;
    let config: sid_auth::config::AuthConfig = serde_yaml::from_str(&format!(
        "upstream: http://{upstream}\n\
         issuer_url: https://sid.example.com\n\
         login_url: https://sid.example.com/auth/login\n\
         route_policy_path: {}/tests/fixtures/routes.yaml\n\
         http:\n  listen: {{ http: \"127.0.0.1:0\" }}\n",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let server = sid_auth::server::AuthServer::new(config, cache.clone()).unwrap();
    let grpc = serve(server.routes().await).await;
    let http = server
        .http_proxy()
        .unwrap()
        .expect("the http section gives a transcoder")
        .service(server.routes().await)
        .unwrap();
    Harness {
        key,
        grpc,
        http,
        cache,
    }
}

async fn harness() -> Harness {
    harness_with(MockAuthz::default(), false).await
}

/// An access token of the issuer for `aud`, with `extra` claims merged in.
fn access_token(key: &jsonwebtoken::EncodingKey, aud: &str, extra: serde_json::Value) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "sub": SUBJECT, "iss": ISSUER, "aud": [aud], "client_id": "orders-web",
        "exp": now + 3600, "iat": now, "auth_time": now,
        "acr": "urn:sid:acr:basic", "scope": "orders.read",
        "roles": "reader", "sid": "sess_01", "jti": "tok_01",
    });
    if let (Some(claims), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
        claims.extend(extra.clone());
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some("k1".into());
    header.typ = Some("at+jwt".into());
    jsonwebtoken::encode(&header, &claims, key).unwrap()
}

async fn http(
    router: &structured_proxy::ProxyService<tonic::service::Routes>,
    method: &str,
    application: &str,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/auth/verify/{application}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    use http_body_util::BodyExt;
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ═══════════════════════════════════════════════════════════════
// Reverse proxies over HTTP, through the embedded transcoder
// ═══════════════════════════════════════════════════════════════

/// A token for Orders opens Orders over HTTP: 200 with the identity header,
/// status and header carried from the RPC's response metadata.
#[tokio::test]
async fn http_allows_a_token_for_the_target() {
    let h = harness().await;
    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    let response = http(
        &h.http,
        "GET",
        "orders",
        &[("authorization", &bearer), ("x-original-uri", "/items")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-forwarded-user"], SUBJECT);
}

/// The sub-request arrives with the original request's method: the rule binds
/// every method, and the decision follows `x-original-method`.
#[tokio::test]
async fn http_answers_every_method() {
    let h = harness().await;
    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    for method in ["POST", "PUT", "DELETE", "PATCH", "HEAD"] {
        let response = http(
            &h.http,
            method,
            "orders",
            &[
                ("authorization", &bearer),
                ("x-original-uri", "/items"),
                ("x-original-method", method),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{method}");
    }
}

/// Refused over HTTP: 401 with the challenge and the login redirect, and a
/// token for another application is refused the same way.
#[tokio::test]
async fn http_refuses_without_a_token_for_the_target() {
    let h = harness().await;
    let response = http(&h.http, "GET", "orders", &[("x-original-uri", "/items")]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["www-authenticate"], "Bearer");
    assert_eq!(
        response.headers()["location"],
        "https://sid.example.com/auth/login?rd=/items"
    );

    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    let response = http(&h.http, "GET", "wiki", &[("authorization", &bearer)]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get("x-forwarded-user").is_none());
}

/// An application the configuration lacks is 404 with the canonical error
/// body; an unregistered target is 403.
#[tokio::test]
async fn http_unknown_application_and_target() {
    let h = harness().await;
    let response = http(&h.http, "GET", "nowhere", &[]).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_json(response).await;
    assert_eq!(
        body["details"][0]["reason"],
        "FORWARD_AUTH_APPLICATION_NOT_FOUND"
    );

    let ghost = format!(
        "Bearer {}",
        access_token(&h.key, "https://ghost.example.com/", serde_json::json!({}))
    );
    let response = http(&h.http, "GET", "ghost", &[("authorization", &ghost)]).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// A registry that cannot answer leaves no verdict: 503, never an allow.
#[tokio::test]
async fn http_registry_down_is_503() {
    let h = harness_with(MockAuthz::default(), true).await;
    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    let response = http(&h.http, "GET", "orders", &[("authorization", &bearer)]).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A session revoked by any SID process opens nothing.
#[tokio::test]
async fn http_revoked_session_is_refused() {
    let h = harness().await;
    sid_auth::revocation_view(h.cache.clone())
        .revoke_session("sess_01".into())
        .await
        .unwrap();
    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    let response = http(&h.http, "GET", "orders", &[("authorization", &bearer)]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A route that needs sid-authz's decision has no verdict while this
/// service holds no credential of its own for the authorization API: it
/// asks nothing, so the user's token goes nowhere, and the proxy denies.
#[tokio::test]
async fn http_checked_route_without_own_credential_asks_nothing() {
    let authz = MockAuthz::default();
    let asked = authz.asked.clone();
    let h = harness_with(authz, false).await;
    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    let response = http(
        &h.http,
        "GET",
        "orders",
        &[("authorization", &bearer), ("x-original-uri", "/checked/x")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 0);
}

// ── DPoP ──

/// RFC 7638 thumbprint of the ES256 fixture key the proofs below are signed with.
const FIXTURE_JKT: &str = "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA";
/// The protected request as the configured origin names it.
const PROTECTED: &str = "https://api.example.com/items";

fn bound_token(key: &jsonwebtoken::EncodingKey) -> String {
    access_token(
        key,
        ORDERS,
        serde_json::json!({ "jti": "tok_bound", "cnf": { "jkt": FIXTURE_JKT } }),
    )
}

/// A DPoP proof by the fixture key for `GET htu` naming `token`.
fn dpop_proof(htu: &str, token: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
        "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(jwk);
    let payload = serde_json::json!({
        "jti": format!("{:032x}", rand::random::<u128>()), "htm": "GET", "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "ath": sid_authn::dpop::access_token_hash(token),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../sid-authn/tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &payload, &key).unwrap()
}

/// A bound token under the DPoP scheme with a proof for the request at the
/// configured origin passes once; the same proof again is a replay; the
/// token as a bearer token is refused with the DPoP challenge.
#[tokio::test]
async fn http_dpop_bound_token() {
    let h = harness().await;
    let token = bound_token(&h.key);
    let proof = dpop_proof(PROTECTED, &token);
    let scheme = format!("DPoP {token}");
    let request = [
        ("authorization", scheme.as_str()),
        ("dpop", proof.as_str()),
        ("x-original-uri", "/items"),
        ("x-original-method", "GET"),
    ];
    assert_eq!(
        http(&h.http, "GET", "orders", &request).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        http(&h.http, "GET", "orders", &request).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let bearer = format!("Bearer {token}");
    let response = http(&h.http, "GET", "orders", &[("authorization", &bearer)]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("DPoP ")
    );
}

/// The URI a proof must name is the configured origin's: a proof for a host
/// the client put in `X-Forwarded-Host` is refused.
#[tokio::test]
async fn http_forwarded_host_does_not_choose_the_proof_uri() {
    let h = harness().await;
    let token = bound_token(&h.key);
    let forged = dpop_proof("https://evil.example.com/items", &token);
    let scheme = format!("DPoP {token}");
    let response = http(
        &h.http,
        "GET",
        "orders",
        &[
            ("authorization", &scheme),
            ("dpop", &forged),
            ("x-original-uri", "/items"),
            ("x-forwarded-host", "evil.example.com"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════
// Envoy over ext_authz, and the typed RPC over gRPC
// ═══════════════════════════════════════════════════════════════

fn envoy_check(application: &str, headers: &[(&str, &str)]) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(EnvoyAttributeRequest {
                http: Some(EnvoyHttpRequest {
                    method: "GET".into(),
                    path: "/items".into(),
                    headers: headers
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            context_extensions: [("application".to_owned(), application.to_owned())].into(),
            ..Default::default()
        }),
    }
}

/// Envoy gets the same decision over ext_authz: allowed with the identity
/// set, refused with its status.
#[tokio::test]
async fn ext_authz_over_grpc() {
    let h = harness().await;
    let mut client = AuthorizationClient::connect(format!("http://{}", h.grpc))
        .await
        .unwrap();
    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    let allowed = client
        .check(envoy_check("orders", &[("authorization", &bearer)]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(allowed.status.unwrap().code, 0);
    assert!(matches!(
        allowed.http_response,
        Some(EnvoyHttpResponse::OkResponse(_))
    ));

    let refused = client
        .check(envoy_check("wiki", &[("authorization", &bearer)]))
        .await
        .unwrap()
        .into_inner();
    let Some(EnvoyHttpResponse::DeniedResponse(denied)) = refused.http_response else {
        panic!("expected a denied response");
    };
    assert_eq!(denied.status.unwrap().code, 401);
}

/// A gRPC client calls Verify directly and reads the verdict from metadata.
#[tokio::test]
async fn verify_over_grpc() {
    let h = harness().await;
    let mut client =
        sid_proto::sid::v1::authz::forward_auth_service_client::ForwardAuthServiceClient::connect(
            format!("http://{}", h.grpc),
        )
        .await
        .unwrap();
    let bearer = format!(
        "Bearer {}",
        access_token(&h.key, ORDERS, serde_json::json!({}))
    );
    let mut request = tonic::Request::new(VerifyRequest {
        application: "orders".into(),
    });
    request
        .metadata_mut()
        .insert("authorization", bearer.parse().unwrap());
    let response = client.verify(request).await.unwrap();
    assert_eq!(response.metadata().get("x-http-code").unwrap(), "200");
    assert_eq!(
        response.metadata().get("x-forwarded-user").unwrap(),
        SUBJECT
    );
}

/// gRPC health reports both decision services serving.
#[tokio::test]
async fn health_reports_both_services() {
    let h = harness().await;
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", h.grpc))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = tonic_health::pb::health_client::HealthClient::new(channel);
    for service in [
        "sid.v1.authz.ForwardAuthService",
        "envoy.service.auth.v3.Authorization",
    ] {
        let status = client
            .check(tonic_health::pb::HealthCheckRequest {
                service: service.into(),
            })
            .await
            .unwrap()
            .into_inner()
            .status;
        assert_eq!(
            status,
            tonic_health::pb::health_check_response::ServingStatus::Serving as i32,
            "{service}"
        );
    }
}
