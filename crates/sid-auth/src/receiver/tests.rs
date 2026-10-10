// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::auth::decision::tests::{ISSUER, ORDERS, SUBJECT, access_token, keypair, sign};
use crate::issuers::{IssuerRecord, ResourceRecord};

const ORIGIN: &str = "https://ops.example.com";
const PATH: &str = "/sid.ops.v1.OrgAdminService/BanOrg";
/// RFC 7638 thumbprint of the fixture proof key.
const FIXTURE_JKT: &str = "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA";

/// A secret file, removed when dropped.
struct Secret(std::path::PathBuf);

impl Secret {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sid-auth-receiver-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, "receiver-secret").unwrap();
        Self(path)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

/// A receiver for Orders at [`ORIGIN`] whose authorization API cannot be
/// reached; Orders registered when `registered`.
struct Fixture {
    key: jsonwebtoken::EncodingKey,
    receiver: Receiver,
    _secret: Secret,
}

fn fixture_with(registered: bool) -> Fixture {
    let (key, public) = keypair();
    let resources = if registered {
        vec![ResourceRecord {
            issuer: ISSUER.into(),
            resource: ORDERS.into(),
            active: true,
            id: sid_core::models::ResourceId::generate(),
        }]
    } else {
        vec![]
    };
    let issuers = crate::test_issuers_with(
        vec![IssuerRecord {
            issuer: ISSUER.into(),
            keys: vec![("k1".into(), public)],
        }],
        resources,
    );
    let secret = Secret::new();
    let checker = ClientCredential::checker(
        &sid_authn::client_credential::ClientCredentialConfig {
            issuer: ISSUER.into(),
            client_id: "ops-receiver".into(),
            authentication: sid_authn::client_credential::ClientAuthentication::ClientSecretBasic {
                secret_file: secret.0.display().to_string(),
            },
        },
        "https://sid.example.com",
        crate::test_channel(),
    )
    .unwrap();
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let receiver = Receiver::new(
        "ops",
        issuers,
        Target {
            issuer: ISSUER.into(),
            resource: ORDERS.into(),
        },
        ORIGIN,
        Arc::new(sid_authn::dpop::DPopValidator::new(cache)),
        Arc::new(checker),
        crate::test_channel(),
    );
    Fixture {
        key,
        receiver,
        _secret: secret,
    }
}

fn fixture() -> Fixture {
    fixture_with(true)
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

/// An Orders token bound to the fixture proof key.
fn bound_token(key: &jsonwebtoken::EncodingKey) -> String {
    let now = chrono::Utc::now().timestamp();
    sign(
        key,
        "at+jwt",
        serde_json::json!({
            "sub": SUBJECT, "iss": ISSUER, "aud": [ORDERS], "client_id": "ops-console",
            "exp": now + 300, "iat": now, "auth_time": now,
            "acr": "urn:sid:acr:basic", "scope": "", "roles": "",
            "sid": "sess_ops", "jti": "tok_ops", "cnf": { "jkt": FIXTURE_JKT },
        }),
    )
}

/// A proof by the fixture key for `htm htu`, naming `token`.
fn proof(htm: &str, htu: &str, token: &str) -> String {
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
        "jti": uuid::Uuid::now_v7().to_string(), "htm": htm, "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "ath": sid_authn::dpop::access_token_hash(token),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../../sid-authn/tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &payload, &key).unwrap()
}

async fn admit(f: &Fixture, method: http::Method, headers: &HeaderMap) -> Result<Admitted, Status> {
    f.receiver
        .admit(&method, PATH, headers, "ops.orgs.ban")
        .await
}

/// The reason a refusal carries.
fn reason(status: &Status) -> String {
    use tonic_types::StatusExt;
    status
        .get_details_error_info()
        .map(|info| info.reason)
        .unwrap_or_default()
}

fn assert_unauthenticated(result: Result<Admitted, Status>) {
    let status = result.expect_err("refused");
    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}");
    assert_eq!(reason(&status), "TOKEN_INVALID");
}

/// A call without a token, or with a token that is not an access token of
/// the configured issuer for exactly this resource, is unauthenticated;
/// nothing about it reaches the authorization API.
#[tokio::test]
async fn a_call_without_a_token_for_this_resource_is_unauthenticated() {
    let f = fixture();
    let (stranger, _) = keypair();
    let bearer = |token: String| format!("Bearer {token}");
    assert_unauthenticated(admit(&f, http::Method::POST, &headers(&[])).await);
    for token in [
        // Another resource of the same issuer.
        access_token(&f.key, ISSUER, "https://wiki.example.com/", 300),
        // Expired.
        access_token(&f.key, ISSUER, ORDERS, -300),
        // Signed by a key the issuer does not publish.
        access_token(&stranger, ISSUER, ORDERS, 300),
        // Another issuer.
        access_token(&f.key, "https://other.example.com/i/x", ORDERS, 300),
    ] {
        assert_unauthenticated(
            admit(
                &f,
                http::Method::POST,
                &headers(&[("authorization", &bearer(token))]),
            )
            .await,
        );
    }
}

/// gRPC is POST: a call by any other method is no call of this service.
#[tokio::test]
async fn a_call_other_than_post_is_unauthenticated() {
    let f = fixture();
    let bearer = format!("Bearer {}", access_token(&f.key, ISSUER, ORDERS, 300));
    assert_unauthenticated(
        admit(
            &f,
            http::Method::GET,
            &headers(&[("authorization", &bearer)]),
        )
        .await,
    );
}

/// A key-bound token needs one proof for this call: POST to the configured
/// origin plus the RPC path. A proof for another method or path, a bound
/// token sent as a bearer token, or a proof used twice is refused.
#[tokio::test]
async fn a_bound_token_needs_a_proof_for_this_call() {
    let f = fixture();
    let token = bound_token(&f.key);
    let dpop = format!("DPoP {token}");
    let uri = format!("{ORIGIN}{PATH}");
    for wrong in [
        proof("GET", &uri, &token),
        proof(
            "POST",
            &format!("{ORIGIN}/sid.ops.v1.OrgAdminService/Other"),
            &token,
        ),
        proof(
            "POST",
            &format!("https://elsewhere.example.com{PATH}"),
            &token,
        ),
    ] {
        assert_unauthenticated(
            admit(
                &f,
                http::Method::POST,
                &headers(&[("authorization", &dpop), ("dpop", &wrong)]),
            )
            .await,
        );
    }
    let right = proof("POST", &uri, &token);
    let bearer = format!("Bearer {token}");
    assert_unauthenticated(
        admit(
            &f,
            http::Method::POST,
            &headers(&[("authorization", &bearer), ("dpop", &right)]),
        )
        .await,
    );
    // The right proof gets past the sender check (and fails only at the
    // unreachable authorization API); its replay does not.
    let call = headers(&[("authorization", &dpop), ("dpop", &right)]);
    let first = admit(&f, http::Method::POST, &call)
        .await
        .expect_err("no PDP");
    assert_eq!(first.code(), tonic::Code::Unavailable, "{first:?}");
    assert_unauthenticated(admit(&f, http::Method::POST, &call).await);
}

/// A valid token is admitted only on the authorization API's decision:
/// without an answer the call is unavailable, never served.
#[tokio::test]
async fn without_a_permission_decision_the_call_is_unavailable() {
    let f = fixture();
    let bearer = format!("Bearer {}", access_token(&f.key, ISSUER, ORDERS, 300));
    let status = admit(
        &f,
        http::Method::POST,
        &headers(&[("authorization", &bearer)]),
    )
    .await
    .expect_err("no PDP");
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
    assert_eq!(reason(&status), "DEPENDENCY_UNAVAILABLE");
}

/// A resource its issuer does not register opens nothing: every call is
/// unavailable, whatever token it carries.
#[tokio::test]
async fn an_unregistered_resource_opens_nothing() {
    let f = fixture_with(false);
    let bearer = format!("Bearer {}", access_token(&f.key, ISSUER, ORDERS, 300));
    let status = admit(
        &f,
        http::Method::POST,
        &headers(&[("authorization", &bearer)]),
    )
    .await
    .expect_err("no target");
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
}

/// The inner service, answering OK to whatever reaches it and counting
/// the calls.
#[derive(Clone, Default)]
struct Inner(Arc<std::sync::atomic::AtomicUsize>);

impl NamedService for Inner {
    const NAME: &'static str = "sid.ops.v1.OrgAdminService";
}

impl Service<http::Request<Body>> for Inner {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Infallible>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: http::Request<Body>) -> Self::Future {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(Ok(Status::ok("").into_http()))
    }
}

/// The grpc-status of a response.
fn grpc_status(response: &http::Response<Body>) -> Option<tonic::Code> {
    response
        .headers()
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i32>().ok())
        .map(tonic::Code::from)
}

/// A path the service names no action for, and a call the receiver
/// refuses, never reach the service.
#[tokio::test]
async fn only_admitted_calls_reach_the_service() {
    let f = fixture();
    let inner = Inner::default();
    let reached = inner.0.clone();
    let mut guarded = Guarded::new(
        inner,
        Arc::new(f.receiver),
        Arc::new(|path: &str| (path == PATH).then_some("ops.orgs.ban")),
    );
    let call = |path: &str| {
        http::Request::builder()
            .method(http::Method::POST)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    };
    let unknown = guarded
        .call(call("/sid.ops.v1.OrgAdminService/Unlisted"))
        .await
        .unwrap();
    assert_eq!(grpc_status(&unknown), Some(tonic::Code::Unimplemented));
    let refused = guarded.call(call(PATH)).await.unwrap();
    assert_eq!(grpc_status(&refused), Some(tonic::Code::Unauthenticated));
    assert_eq!(reached.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// A handler served without the guard has no admitted call and refuses.
#[test]
fn a_handler_without_the_guard_refuses() {
    let request = tonic::Request::new(());
    let status = admitted(&request).expect_err("no admitted call");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}
