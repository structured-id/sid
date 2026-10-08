// SPDX-License-Identifier: AGPL-3.0-only
//! The account BFF end to end: sid-auth-proxy with its own client key learns
//! the account integration this server provisioned, signs a user in with
//! `private_key_jwt`, calls the account API over gRPC-Web as that user,
//! refreshes and signs out, all against this server's services on a local
//! port (auth/session-management.md, system account integration).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use common::TestServices;
use common::mock_storage::MockStorage;
use prost::Message;
use sid_auth_proxy::ProxyState;
use sid_auth_proxy::account::AccountLink;
use sid_auth_proxy::client_key::ClientKey;
use sid_auth_proxy::session::BffSessionStore;
use sid_authn::system_integration::{AccountSettings, ensure_account_integration};
use sid_core::models::{ClientKeySet, Profile};
use sid_proto::sid::v1::auth_service_server::{AuthService, AuthServiceServer};
use sid_proto::sid::v1::identity_service_server::IdentityServiceServer;
use sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerServiceServer;
use sid_proto::sid::v1::system_integration_service_server::SystemIntegrationServiceServer;
use sid_proto::sid::v1::{GetProfileResponse, OAuth2AuthorizeRequest};
use sid_server::grpc::system_integration_service::SystemIntegrationServiceImpl;
use tower::ServiceExt;

const ACCOUNT_URL: &str = "https://account.sid.example.com";
const COOKIE: &str = "__Host-sid-bff";

/// This server's services, and the BFF's view of them.
struct Deployment {
    svc: TestServices,
    profile: Profile,
    /// The installation URL, the base of its issuers.
    installation: String,
    /// Where this server's gRPC and gRPC-Web answer.
    addr: SocketAddr,
    /// The BFF's private key, PKCS#8 PEM.
    key_pem: String,
}

/// Provision the account integration for a freshly generated BFF key and
/// serve the services the BFF talks to on a local port, gRPC-Web included.
async fn deploy() -> Deployment {
    let profile = common::test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(profile.clone()),
    );
    let installation = svc
        .issuer
        .canonical_url
        .split("/i/")
        .next()
        .unwrap()
        .to_owned();
    let (key, key_pem) = ClientKey::generate().unwrap();
    let keys = ClientKeySet::try_from(key.public_jwks()).unwrap();
    let settings = AccountSettings::new(ACCOUNT_URL, keys).unwrap();
    ensure_account_integration(svc.storage.as_ref(), &svc.issuer, &installation, &settings)
        .await
        .unwrap();

    let integrations = SystemIntegrationServiceImpl::new(
        svc.storage.clone(),
        installation.clone(),
        svc.cache.clone(),
    );
    let registry = sid_server::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
        svc.issuers.clone(),
        svc.storage.clone(),
    );
    let identity = svc.identity.clone();
    let auth = svc.auth.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(tonic_web::GrpcWebLayer::new())
            .add_service(AuthServiceServer::from_arc(auth))
            .add_service(SystemIntegrationServiceServer::new(integrations))
            .add_service(OidcIssuerServiceServer::new(registry))
            .add_service(IdentityServiceServer::from_arc(identity))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    Deployment {
        svc,
        profile,
        installation,
        addr,
        key_pem,
    }
}

/// A BFF replica of `deployment`: its own process state, the deployment's
/// shared cache for sessions and revocations.
fn replica(deployment: &Deployment) -> axum::Router {
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", deployment.addr))
        .unwrap()
        .connect_lazy();
    let installation = deployment.installation.clone();
    let key = ClientKey::from_pem(deployment.key_pem.as_bytes()).unwrap();
    let state = ProxyState {
        issuer_url: installation.clone(),
        issuers: Arc::new(sid_auth::issuers::IssuerDirectory::new(
            &installation,
            Arc::new(sid_auth::issuers::GrpcIssuerSource::new(channel.clone())),
        )),
        grpc_channel: channel.clone(),
        revocation: sid_auth::revocation_view(deployment.svc.cache.clone()),
        bff_enabled: true,
        account: Some(Arc::new(AccountLink::new(key, installation, channel))),
        api_upstream: Some(url::Url::parse(&format!("http://{}", deployment.addr)).unwrap()),
        http: sid_auth_proxy::api_client(),
        bff_sessions: Arc::new(sessions(deployment)),
        bff_cookie_name: COOKIE.into(),
        bff_dev_mode: false,
    };
    sid_auth_proxy::bff::routes()
        .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 9], 50000))))
        .with_state(state)
}

/// The shared session store as any replica sees it.
fn sessions(deployment: &Deployment) -> BffSessionStore {
    BffSessionStore::new(
        deployment.svc.cache.clone(),
        std::time::Duration::from_secs(86400),
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(300),
    )
}

async fn send(router: &axum::Router, request: Request<Body>) -> axum::response::Response {
    router.clone().oneshot(request).await.unwrap()
}

fn query(url: &str) -> std::collections::HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// The cookie `name` among a response's `set-cookie` headers.
fn cookie(response: &axum::response::Response, name: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix(&format!("{name}=")))
        .and_then(|v| v.split(';').next())
        .unwrap_or_else(|| panic!("no {name} cookie"))
        .to_owned()
}

/// A signed-in browser: its session cookie and CSRF token.
struct Browser {
    session: String,
    csrf: String,
}

/// The browser's sign-in through the BFF: `/auth/login`, the IdP's
/// authorization with the user's live IdP session (as the sign-in surface
/// completes it), and the callback the IdP redirects back to.
async fn sign_in(deployment: &Deployment, router: &axum::Router) -> Browser {
    let login = send(
        router,
        Request::get("/auth/login?rd=/security")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(login.status(), StatusCode::FOUND);
    let asked = query(login.headers()["location"].to_str().unwrap());
    assert_eq!(
        asked["redirect_uri"],
        format!("{ACCOUNT_URL}/auth/callback")
    );
    assert_eq!(
        asked["resource"],
        format!("{}/account", deployment.installation)
    );

    let idp_session = common::fresh_token(&deployment.svc, &deployment.profile).await;
    let mut request = tonic::Request::new(OAuth2AuthorizeRequest {
        client_id: asked["client_id"].clone(),
        redirect_uri: asked["redirect_uri"].clone(),
        response_type: "code".into(),
        scope: Some(asked["scope"].clone()),
        state: Some(asked["state"].clone()),
        nonce: Some(asked["nonce"].clone()),
        code_challenge: Some(asked["code_challenge"].clone()),
        code_challenge_method: Some("S256".into()),
        issuer_handle: deployment.svc.issuer.handle.to_string(),
        resource: vec![asked["resource"].clone()],
        ..Default::default()
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {idp_session}").parse().unwrap(),
    );
    let code = match deployment
        .svc
        .auth
        .o_auth2_authorize(request)
        .await
        .unwrap()
        .into_inner()
        .result
    {
        Some(sid_proto::sid::v1::o_auth2_authorize_response::Result::AuthorizationCode(code)) => {
            code
        }
        other => panic!("expected a code, got {other:?}"),
    };

    let issuer: String =
        url::form_urlencoded::byte_serialize(deployment.svc.issuer.canonical_url.as_bytes())
            .collect();
    let callback = send(
        router,
        Request::get(format!(
            "/auth/callback?code={code}&state={}&iss={issuer}",
            asked["state"]
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::FOUND, "{callback:?}");
    assert_eq!(callback.headers()["location"], "/security");
    let session = cookie(&callback, COOKIE);

    // The session's CSRF token comes with the session check, where the page
    // takes it from; no cookie carries it.
    let userinfo = send(
        router,
        Request::get("/auth/userinfo")
            .header("cookie", format!("{COOKIE}={session}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(userinfo.status(), StatusCode::OK);
    let body = axum::body::to_bytes(userinfo.into_body(), 4096)
        .await
        .unwrap();
    let user: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let csrf = user["csrf_token"]
        .as_str()
        .expect("the session's CSRF token")
        .to_owned();
    Browser { session, csrf }
}

/// `GetCurrentProfile` as the page's gRPC-Web transport sends it through
/// `/api`, with or without the CSRF header.
fn current_profile(browser: &Browser, csrf: bool) -> Request<Body> {
    let path = format!(
        "/api/{}/GetCurrentProfile",
        sid_proto::sid::v1::identity_service_server::SERVICE_NAME
    );
    // An empty message in one gRPC-Web data frame: flag 0, length 0.
    let mut request = Request::post(path)
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .header("cookie", format!("{COOKIE}={}", browser.session));
    if csrf {
        request = request.header("x-csrf-token", &browser.csrf);
    }
    request.body(Body::from(vec![0u8, 0, 0, 0, 0])).unwrap()
}

/// The profile in a gRPC-Web answer's first data frame.
async fn answered_profile(response: axum::response::Response) -> String {
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(body[0], 0, "a data frame first: {body:?}");
    let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    let message = GetProfileResponse::decode(&body[5..5 + len]).unwrap();
    let trailers = String::from_utf8_lossy(&body[5 + len..]);
    assert!(trailers.contains("grpc-status:0"), "{trailers}");
    message.profile.unwrap().id
}

/// Sign-in through one replica, the account API through another: the user
/// sees their own profile, the page's request without the CSRF token is
/// refused, and the IdP session never reaches the account API.
#[tokio::test]
async fn a_user_signs_in_and_reads_their_account() {
    let deployment = deploy().await;
    let first = replica(&deployment);
    let second = replica(&deployment);
    let browser = sign_in(&deployment, &first).await;

    let userinfo = send(
        &second,
        Request::get("/auth/userinfo")
            .header("cookie", format!("{COOKIE}={}", browser.session))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(userinfo.status(), StatusCode::OK);
    let body = axum::body::to_bytes(userinfo.into_body(), 4096)
        .await
        .unwrap();
    let user: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(user["sub"], deployment.profile.id.to_string());

    let id = answered_profile(send(&second, current_profile(&browser, true)).await).await;
    assert_eq!(id, deployment.profile.id.to_string());

    let refused = send(&second, current_profile(&browser, false)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
}

/// An expired access token is refreshed with the key's assertion before the
/// call, the rotated refresh token replaces the old one, and the call goes
/// through as the same user.
#[tokio::test]
async fn an_expired_token_is_refreshed_before_the_call() {
    let deployment = deploy().await;
    let router = replica(&deployment);
    let browser = sign_in(&deployment, &router).await;
    let store = sessions(&deployment);
    let before = store.get_session(&browser.session).await.unwrap().unwrap();
    let mut expired = before.claims.clone();
    expired.exp = 0;
    assert!(
        store
            .replace_tokens(
                &browser.session,
                before.access_token.clone(),
                before.refresh_token.clone(),
                expired,
            )
            .await
            .unwrap()
    );

    let id = answered_profile(send(&router, current_profile(&browser, true)).await).await;
    assert_eq!(id, deployment.profile.id.to_string());
    let after = store.get_session(&browser.session).await.unwrap().unwrap();
    assert_ne!(after.access_token, before.access_token);
    assert_ne!(after.refresh_token, before.refresh_token);
    assert!(after.claims.exp > chrono::Utc::now().timestamp());
}

/// Sign-out ends the BFF session and revokes its grant at SID: the cookie no
/// longer opens anything, and the refresh token the session held is dead.
#[tokio::test]
async fn sign_out_revokes_the_grant() {
    let deployment = deploy().await;
    let router = replica(&deployment);
    let browser = sign_in(&deployment, &router).await;
    let held = sessions(&deployment)
        .get_session(&browser.session)
        .await
        .unwrap()
        .unwrap()
        .refresh_token
        .expect("the code flow grants a refresh token");

    let logout = send(
        &router,
        Request::post("/auth/logout")
            .header("cookie", format!("{COOKIE}={}", browser.session))
            .header("x-csrf-token", &browser.csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        send(&router, current_profile(&browser, true))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let link = AccountLink::new(
        ClientKey::from_pem(deployment.key_pem.as_bytes()).unwrap(),
        deployment.installation.clone(),
        tonic::transport::Channel::from_shared(format!("http://{}", deployment.addr))
            .unwrap()
            .connect_lazy(),
    );
    let connection = link.connection().await.unwrap();
    assert!(link.refresh(connection, held).await.is_err());
}
