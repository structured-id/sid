// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::issuers::{IssuerRecord, ResourceRecord};

pub(crate) const ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";
const OTHER_ISSUER: &str = "https://sid.example.com/i/fedcba9876543210fedcba9876543210";
pub(crate) const ORDERS: &str = "https://api.example.com/orders";
const WIKI: &str = "https://wiki.example.com/";
pub(crate) const SUBJECT: &str = "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e";

/// Two applications under one issuer, each with its own resource.
fn applications(orders_routes: &str) -> String {
    format!(
        r#"
applications:
  - name: orders
    origin: https://api.example.com
    issuer: {ISSUER}
    resource: {ORDERS}
    routes:
{orders_routes}
  - name: wiki
    origin: https://wiki.example.com
    issuer: {ISSUER}
    resource: {WIKI}
"#
    )
}

const DEFAULT_ROUTES: &str = r#"
      - match: { path: "/public/**" }
        policy: { auth: none }
      - match: { path: "/optional/**" }
        policy: { auth: optional }
      - match: { path: "/admin/**" }
        policy:
          auth: required
          require: { roles: ["super_admin"] }
      - match: { path: "/editor/**" }
        policy:
          auth: required
          require: { roles: ["admin", "editor"] }
      - match: { path: "/api/**", methods: ["GET"] }
        policy: { auth: none }
      - match: { path: "/api/**", methods: ["POST"] }
        policy: { auth: required }
      - match: { path: "/checked/**" }
        policy: { auth: required, check_authz: true, action: orders.read }
      - match: { path: "/**" }
        policy: { auth: required, headers: { inject: [user] } }
"#;

/// An Ed25519 key pair: the signing key and the raw public key.
pub(crate) fn keypair() -> (jsonwebtoken::EncodingKey, [u8; 32]) {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use rand::Rng;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let der = signing_key.to_pkcs8_der().unwrap();
    (
        jsonwebtoken::EncodingKey::from_ed_der(der.as_bytes()),
        signing_key.verifying_key().to_bytes(),
    )
}

/// The decision over two issuers of the installation; Orders registered in
/// the given state (`None` = not registered), Wiki registered and active.
pub(crate) struct Fixture {
    pub key: jsonwebtoken::EncodingKey,
    pub other_key: jsonwebtoken::EncodingKey,
    pub pdp: Pdp,
}

pub(crate) fn fixture_with(orders_routes: &str, orders: Option<bool>) -> Fixture {
    let (key, public) = keypair();
    let (other_key, other_public) = keypair();
    let mut resources = vec![ResourceRecord {
        issuer: ISSUER.into(),
        resource: WIKI.into(),
        active: true,
        id: sid_core::models::ResourceId::generate(),
    }];
    if let Some(active) = orders {
        resources.push(ResourceRecord {
            issuer: ISSUER.into(),
            resource: ORDERS.into(),
            active,
            id: sid_core::models::ResourceId::generate(),
        });
    }
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let pdp = Pdp {
        issuers: crate::test_issuers_with(
            vec![
                IssuerRecord {
                    issuer: ISSUER.into(),
                    keys: vec![("k1".into(), public)],
                },
                IssuerRecord {
                    issuer: OTHER_ISSUER.into(),
                    keys: vec![("k1".into(), other_public)],
                },
            ],
            resources,
        ),
        applications: Arc::new(PolicyEngine::from_yaml(&applications(orders_routes)).unwrap()),
        revocation: crate::revocation_view(cache.clone()),
        dpop: Arc::new(sid_authn::dpop::DPopValidator::new(cache)),
        authz: crate::test_channel(),
        checker: None,
        login_url: "https://sid.example.com/auth/login".into(),
    };
    Fixture {
        key,
        other_key,
        pdp,
    }
}

pub(crate) fn fixture() -> Fixture {
    fixture_with(DEFAULT_ROUTES, Some(true))
}

/// A JWT with `claims` and header `typ`, signed by `key` under `kid` k1.
pub(crate) fn sign(
    key: &jsonwebtoken::EncodingKey,
    typ: &str,
    claims: serde_json::Value,
) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some("k1".into());
    header.typ = Some(typ.into());
    jsonwebtoken::encode(&header, &claims, key).unwrap()
}

/// An access token as `iss` issues it to client `orders-web` for `aud`.
pub(crate) fn access_token(
    key: &jsonwebtoken::EncodingKey,
    iss: &str,
    aud: &str,
    exp_offset: i64,
) -> String {
    let now = chrono::Utc::now().timestamp();
    sign(
        key,
        "at+jwt",
        serde_json::json!({
            "sub": SUBJECT, "iss": iss, "aud": [aud], "client_id": "orders-web",
            "exp": now + exp_offset, "iat": now, "auth_time": now,
            "acr": "urn:sid:acr:basic", "scope": "orders.read",
            "roles": "admin reader", "sid": "sess_app", "jti": "tok_app",
        }),
    )
}

async fn decide(
    pdp: &Pdp,
    application: &str,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<Verdict, DecisionError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    pdp.decide(
        application,
        OriginalRequest {
            method: &method,
            path,
            headers: &map,
        },
    )
    .await
}

async fn with_bearer(pdp: &Pdp, application: &str, path: &str, token: &str) -> Verdict {
    let bearer = format!("Bearer {token}");
    decide(
        pdp,
        application,
        Method::GET,
        path,
        &[("authorization", &bearer)],
    )
    .await
    .unwrap()
}

/// An access token for Orders opens Orders and tells the upstream who it
/// is: the token's subject, nothing read from the request.
#[tokio::test]
async fn test_token_for_the_target_is_accepted() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "orders", "/dashboard", &token).await;
    assert_eq!(verdict.status, StatusCode::OK);
    assert_eq!(verdict.headers["x-forwarded-user"], SUBJECT);
}

/// The same valid token, same issuer and subject, does not open another
/// application: its audience is Orders, not Wiki (RFC 9068 §4).
#[tokio::test]
async fn test_token_for_another_resource_is_refused() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "wiki", "/page", &token).await;
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
    assert!(verdict.headers.get("x-forwarded-user").is_none());
}

/// A token of another issuer of the same installation is refused even when
/// it names the target's indicator and subject: the target is pinned to its
/// exact issuer.
#[tokio::test]
async fn test_token_of_another_issuer_is_refused() {
    let f = fixture();
    let token = access_token(&f.other_key, OTHER_ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "orders", "/dashboard", &token).await;
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
}

/// A forged token under the target issuer's `kid` but another key is refused.
#[tokio::test]
async fn test_token_signed_by_another_key_is_refused() {
    let f = fixture();
    let token = access_token(&f.other_key, ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "orders", "/dashboard", &token).await;
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
}

/// The installation's own sign-in token (its base URL as `iss`) and an ID
/// token of the target issuer are no application access tokens.
#[tokio::test]
async fn test_sign_in_and_id_tokens_are_refused() {
    let f = fixture();
    let now = chrono::Utc::now().timestamp();
    let sign_in = sign(
        &f.key,
        "JWT",
        serde_json::json!({
            "sub": SUBJECT, "pid": SUBJECT, "iss": "https://sid.example.com",
            "aud": ["https://sid.example.com"], "exp": now + 300, "iat": now,
            "auth_time": now, "acr": "urn:sid:acr:basic", "scope": "openid",
            "roles": "admin", "sid": "sess", "jti": "tok_session",
        }),
    );
    let id_token = sign(
        &f.key,
        "JWT",
        serde_json::json!({
            "sub": SUBJECT, "iss": ISSUER, "aud": ORDERS, "exp": now + 300,
            "iat": now, "auth_time": now, "acr": "urn:sid:acr:basic",
            "sid": "sess", "jti": "tok_id", "nonce": "n",
        }),
    );
    for token in [sign_in, id_token] {
        let verdict = with_bearer(&f.pdp, "orders", "/dashboard", &token).await;
        assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
    }
}

/// The IdP's `sid_session` cookie is not read: a browser signed in to SID
/// holds no credential for the application.
#[tokio::test]
async fn test_session_cookie_is_refused() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let cookie = format!("sid_session={token}");
    let verdict = decide(
        &f.pdp,
        "orders",
        Method::GET,
        "/dashboard",
        &[("cookie", &cookie)],
    )
    .await
    .unwrap();
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
}

/// An application the proxy names but this service does not know is an
/// error, never another application's decision.
#[tokio::test]
async fn test_unknown_application_is_an_error() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let bearer = format!("Bearer {token}");
    let result = decide(
        &f.pdp,
        "unknown",
        Method::GET,
        "/",
        &[("authorization", &bearer)],
    )
    .await;
    assert!(matches!(result, Err(DecisionError::UnknownApplication(name)) if name == "unknown"));
}

/// A target the registry does not know, or knows as inactive, opens nothing,
/// even for a token that names it.
#[tokio::test]
async fn test_unregistered_or_inactive_target_is_refused() {
    for orders in [None, Some(false)] {
        let f = fixture_with(DEFAULT_ROUTES, orders);
        let token = access_token(&f.key, ISSUER, ORDERS, 300);
        let verdict = with_bearer(&f.pdp, "orders", "/dashboard", &token).await;
        assert_eq!(verdict.status, StatusCode::FORBIDDEN, "{orders:?}");
        assert!(verdict.headers.get("x-forwarded-user").is_none());
    }
}

/// An optional route with a token for a target that is not registered does
/// not fall back to anonymous: the route's target itself is refused.
#[tokio::test]
async fn test_optional_route_with_unregistered_target_is_refused() {
    let f = fixture_with(DEFAULT_ROUTES, None);
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "orders", "/optional/page", &token).await;
    assert_eq!(verdict.status, StatusCode::FORBIDDEN);
    assert!(verdict.headers.get("x-forwarded-user").is_none());
}

/// A public route admits without a token and discloses no identity, even
/// with a valid one.
#[tokio::test]
async fn test_public_route_discloses_nobody() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "orders", "/public/logo.png", &token).await;
    assert_eq!(verdict.status, StatusCode::OK);
    assert!(verdict.headers.is_empty());
    let verdict = with_bearer(&f.pdp, "orders", "/public/page", "x.y.z").await;
    assert_eq!(verdict.status, StatusCode::OK);
}

/// A required route without a token is 401 with the bearer challenge
/// (RFC 6750 §3) and the login page to return from.
#[tokio::test]
async fn test_missing_token_returns_401() {
    let f = fixture();
    let verdict = decide(&f.pdp, "orders", Method::GET, "/dash?x=1&y=2", &[])
        .await
        .unwrap();
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
    assert_eq!(verdict.headers["www-authenticate"], "Bearer");
    assert_eq!(
        verdict.headers["location"],
        "https://sid.example.com/auth/login?rd=/dash%3Fx%3D1%26y%3D2"
    );
}

/// Without a login URL a 401 carries no redirect.
#[tokio::test]
async fn test_no_login_url_no_location() {
    let mut f = fixture();
    f.pdp.login_url = String::new();
    let verdict = decide(&f.pdp, "orders", Method::GET, "/dashboard", &[])
        .await
        .unwrap();
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
    assert!(verdict.headers.get("location").is_none());
}

/// An optional route admits without a token, or with an invalid one, as
/// anonymous.
#[tokio::test]
async fn test_optional_route_admits_anonymous() {
    let f = fixture();
    let verdict = decide(&f.pdp, "orders", Method::GET, "/optional/page", &[])
        .await
        .unwrap();
    assert_eq!(verdict.status, StatusCode::OK);
    let expired = access_token(&f.key, ISSUER, ORDERS, -3600);
    let verdict = with_bearer(&f.pdp, "orders", "/optional/page", &expired).await;
    assert_eq!(verdict.status, StatusCode::OK);
    assert!(verdict.headers.get("x-forwarded-user").is_none());
}

#[tokio::test]
async fn test_expired_token_returns_401() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, -3600);
    let verdict = with_bearer(&f.pdp, "orders", "/dashboard", &token).await;
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
}

/// Roles come from the verified token: a missing one is 403, one of the
/// listed ones admits.
#[tokio::test]
async fn test_required_roles() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "orders", "/admin/users", &token).await;
    assert_eq!(verdict.status, StatusCode::FORBIDDEN);
    let verdict = with_bearer(&f.pdp, "orders", "/editor/page", &token).await;
    assert_eq!(verdict.status, StatusCode::OK);
}

/// Identity headers the client sends are not decision output: the verdict
/// carries the verified subject only.
#[tokio::test]
async fn test_spoofed_identity_header_is_not_echoed() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let bearer = format!("Bearer {token}");
    let verdict = decide(
        &f.pdp,
        "orders",
        Method::GET,
        "/dashboard",
        &[
            ("authorization", &bearer),
            ("x-forwarded-user", "attacker"),
            ("x-auth-request-email", "attacker@example.com"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(verdict.status, StatusCode::OK);
    assert_eq!(verdict.headers["x-forwarded-user"], SUBJECT);
    assert!(verdict.headers.get("x-auth-request-email").is_none());
}

/// Method-specific routes: GET is public, POST needs a token.
#[tokio::test]
async fn test_method_based_policy() {
    let f = fixture();
    let verdict = decide(&f.pdp, "orders", Method::GET, "/api/data", &[])
        .await
        .unwrap();
    assert_eq!(verdict.status, StatusCode::OK);
    let verdict = decide(&f.pdp, "orders", Method::POST, "/api/data", &[])
        .await
        .unwrap();
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
}

/// When sid-authz cannot be asked, a route requiring its decision has no
/// verdict: the proxy denies.
#[tokio::test]
async fn test_check_authz_unreachable_is_unavailable() {
    let f = fixture();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let bearer = format!("Bearer {token}");
    let result = decide(
        &f.pdp,
        "orders",
        Method::GET,
        "/checked/resource",
        &[("authorization", &bearer)],
    )
    .await;
    assert!(matches!(result, Err(DecisionError::Unavailable(_))));
}

/// A revoked session opens nothing.
#[tokio::test]
async fn test_revoked_session_is_refused() {
    let f = fixture();
    f.pdp
        .revocation
        .revoke_session("sess_app".into())
        .await
        .unwrap();
    let token = access_token(&f.key, ISSUER, ORDERS, 300);
    let verdict = with_bearer(&f.pdp, "orders", "/dashboard", &token).await;
    assert_eq!(verdict.status, StatusCode::UNAUTHORIZED);
}

// ── Helpers ──

fn make_claims(roles: &str) -> ForwardAuthClaims {
    ForwardAuthClaims {
        sub: "user1".into(),
        iss: "test".into(),
        exp: 0,
        iat: 0,
        auth_time: 0,
        acr: "basic".into(),
        scope: "".into(),
        roles: roles.into(),
        sid: "s1".into(),
        jti: "j1".into(),
        email: None,
        name: None,
        preferred_username: None,
        groups: None,
        cnf: None,
    }
}

#[test]
fn test_has_any_role() {
    let claims = make_claims("editor viewer");
    assert!(has_any_role(&claims, &["admin".into(), "editor".into()]));
    assert!(!has_any_role(&claims, &["admin".into(), "super".into()]));
    assert!(!has_any_role(&make_claims(""), &["admin".into()]));
    assert!(!has_any_role(&make_claims("Admin"), &["admin".into()]));
    let spaced = make_claims("admin  editor\tviewer");
    assert!(has_any_role(&spaced, &["viewer".into()]));
}

/// `rd` keeps the whole original path: characters that would end or split
/// the parameter are encoded, `%` first so an encoded path stays itself.
#[test]
fn test_urlencoded() {
    assert_eq!(
        urlencoded("/app?page=1&sort=name"),
        "/app%3Fpage%3D1%26sort%3Dname"
    );
    assert_eq!(urlencoded("/a%26b"), "/a%2526b");
    assert_eq!(urlencoded("/x#frag y"), "/x%23frag%20y");
    assert_eq!(urlencoded(""), "");
}
