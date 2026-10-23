// SPDX-License-Identifier: AGPL-3.0-only
//! The account application end to end: the UI host with its browser adapter
//! and its own client key learns the account integration this server
//! provisioned, signs a user in with `private_key_jwt`, calls the account API
//! over gRPC-Web as that user, refreshes and signs out, all against this
//! server's services, every replica on a local port of its own
//! (auth/session-management.md, system account integration).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::TestServices;
use common::mock_storage::MockStorage;
use prost::Message;
use secrecy::ExposeSecret;
use sid_authn::bff_session::BffSessionStore;
use sid_authn::client_key::ClientKey;
use sid_authn::issuer_directory::IssuerDirectory;
use sid_authn::system_integration::{AccountSettings, ensure_account_integration};
use sid_core::models::{ClientKeySet, Profile};
use sid_infra::issuer_client::RpClient;
use sid_infra::issuer_registry::GrpcIssuerSource;
use sid_proto::sid::v1::auth_service_server::{AuthService, AuthServiceServer};
use sid_proto::sid::v1::authn::{ApplicationSession, EndApplicationSessionResponse, GrantOutcome};
use sid_proto::sid::v1::identity_service_server::IdentityServiceServer;
use sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerServiceServer;
use sid_proto::sid::v1::system_integration_service_server::SystemIntegrationServiceServer;
use sid_proto::sid::v1::{GetProfileResponse, OAuth2AuthorizeRequest};
use sid_server::grpc::system_integration_service::SystemIntegrationServiceImpl;
use sid_ui_host::application_session::{ApplicationSessions, FORWARDED_HEADERS};
use sid_ui_host::host::{ADAPTER_PROTO, HostUpstream, asset_routes};

const ACCOUNT_URL: &str = "https://account.sid.example.com";
const COOKIE: &str = "__Host-sid-bff";
const ADAPTER: &str = "sid.v1.authn.ApplicationSessionService";

/// This server's services, and the adapter's view of them.
struct Deployment {
    svc: TestServices,
    profile: Profile,
    /// The installation URL, the base of its issuers.
    installation: String,
    /// Where this server's gRPC answers.
    addr: SocketAddr,
    /// The adapter's private key, PKCS#8 PEM.
    key_pem: String,
    /// The account application's compiled bundle.
    bundle: tempfile::TempDir,
}

/// Provision the account integration for a freshly generated client key and
/// serve the services the adapter talks to on a local port.
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
    let (key, key_pem) = ClientKey::generate_ed25519().unwrap();
    let key_pem = key_pem.expose_secret().to_owned();
    let keys = ClientKeySet::try_from(key.public_jwks().unwrap()).unwrap();
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
            .add_service(AuthServiceServer::from_arc(auth))
            .add_service(SystemIntegrationServiceServer::new(integrations))
            .add_service(OidcIssuerServiceServer::new(registry))
            .add_service(IdentityServiceServer::from_arc(identity))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let bundle = tempfile::tempdir().unwrap();
    std::fs::write(bundle.path().join("index.html"), "<!doctype html>").unwrap();
    Deployment {
        svc,
        profile,
        installation,
        addr,
        key_pem,
        bundle,
    }
}

/// A replica of the account application's UI host, serving on a local port
/// of its own: its own process state, the deployment's shared cache for
/// sessions and revocations. Its URL.
async fn replica(deployment: &Deployment) -> String {
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", deployment.addr))
        .unwrap()
        .connect_lazy();
    let installation = deployment.installation.clone();
    let key =
        ClientKey::ed25519_from_pem(&secrecy::SecretString::from(deployment.key_pem.as_str()))
            .unwrap();
    let revocation = sid_auth::revocation_view(deployment.svc.cache.clone());
    revocation.listen().await.unwrap();
    let adapter = ApplicationSessions::new(
        Arc::new(RpClient::new(key, installation.clone(), channel.clone()).unwrap()),
        Arc::new(IssuerDirectory::new(
            &installation,
            Arc::new(GrpcIssuerSource::new(channel.clone())),
        )),
        Arc::new(sessions(deployment)),
        revocation,
        COOKIE.into(),
    );
    let bundle = sid_ui_host::UiBundle::new(
        deployment.bundle.path(),
        "/",
        br#"{"environment":"test","release":"e2e"}"#,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let proxy = sid_infra::http::embedded_transcoder(
        &serde_json::json!({ "health": { "enabled": false } }),
        &FORWARDED_HEADERS,
        |file| file == ADAPTER_PROTO,
    )
    .unwrap()
    .with_grpc_web_translation(true)
    .with_extra_routes(asset_routes(sid_ui_host::standalone(bundle).unwrap()));
    let upstream = HostUpstream::new(Arc::new(adapter), Some(channel));
    tokio::spawn(async move {
        sid_infra::http::serve_on(
            &proxy,
            upstream,
            listener,
            std::future::pending(),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    });
    url
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

/// An HTTP client that follows no redirect: the test reads each one.
fn http() -> reqwest::Client {
    sid_plugin::http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn query(url: &str) -> std::collections::HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// The `name=value` of the cookie set under a name starting with `prefix`.
fn set_cookie(response: &reqwest::Response, prefix: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|v| v.starts_with(prefix) && !v.contains("Max-Age=0"))
        .find_map(|v| v.split(';').next())
        .unwrap_or_else(|| panic!("no {prefix} cookie"))
        .to_owned()
}

/// A signed-in browser: its session cookie and CSRF token.
struct Browser {
    cookie: String,
    csrf: String,
}

/// One gRPC-Web call of the page to `path` with `message`.
async fn grpc_web(
    replica: &str,
    path: &str,
    message: Vec<u8>,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> (Option<Vec<u8>>, String) {
    let mut frame = vec![0u8];
    frame.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&message);
    let mut request = http()
        .post(format!("{replica}{path}"))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(frame);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // A trailers-only answer carries its status in the headers.
    let header_status = response
        .headers()
        .get("grpc-status")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = response.bytes().await.unwrap();
    let mut message = None;
    let mut rest = &body[..];
    let mut status = header_status.unwrap_or_default();
    while rest.len() >= 5 {
        let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        let payload = &rest[5..5 + len];
        if rest[0] & 0x80 == 0 {
            message = Some(payload.to_vec());
        } else {
            let trailers = String::from_utf8_lossy(payload);
            if let Some(code) = trailers
                .lines()
                .find_map(|line| line.trim().strip_prefix("grpc-status:"))
            {
                status = code.trim().to_owned();
            }
        }
        rest = &rest[5 + len..];
    }
    (message, status)
}

/// The session the browser's cookie names, as the page reads it.
async fn read_session(replica: &str, cookie: &str) -> (Option<ApplicationSession>, String) {
    let (message, status) = grpc_web(
        replica,
        &format!("/{ADAPTER}/GetApplicationSession"),
        Vec::new(),
        Some(cookie),
        None,
    )
    .await;
    (
        message.map(|m| ApplicationSession::decode(&m[..]).unwrap()),
        status,
    )
}

/// The browser's sign-in: `/auth/login`, the IdP's authorization with the
/// user's live IdP session (as the sign-in surface completes it), and the
/// callback the IdP redirects back to, with the sign-in's correlation cookie.
async fn sign_in(deployment: &Deployment, replica: &str) -> Browser {
    let login = http()
        .get(format!("{replica}/auth/login?rd=/security"))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), reqwest::StatusCode::FOUND);
    let correlation = set_cookie(&login, &format!("{COOKIE}-signin-"));
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
    let callback = http()
        .get(format!(
            "{replica}/auth/callback?code={code}&state={}&iss={issuer}",
            asked["state"]
        ))
        .header("cookie", &correlation)
        .send()
        .await
        .unwrap();
    assert_eq!(
        callback.status(),
        reqwest::StatusCode::FOUND,
        "{callback:?}"
    );
    assert_eq!(callback.headers()["location"], "/security");
    let cookie = set_cookie(&callback, &format!("{COOKIE}="));

    // The session's CSRF token comes with the session read, where the page
    // takes it from; no cookie carries it.
    let (session, status) = read_session(replica, &cookie).await;
    assert_eq!(status, "0");
    let csrf = session.expect("the session").csrf_token;
    Browser { cookie, csrf }
}

/// `GetCurrentProfile` as the page's gRPC-Web transport sends it, with or
/// without the CSRF token: the profile id, and the gRPC status.
async fn current_profile(replica: &str, browser: &Browser, csrf: bool) -> (Option<String>, String) {
    let (message, status) = grpc_web(
        replica,
        &format!(
            "/{}/GetCurrentProfile",
            sid_proto::sid::v1::identity_service_server::SERVICE_NAME
        ),
        Vec::new(),
        Some(&browser.cookie),
        csrf.then_some(browser.csrf.as_str()),
    )
    .await;
    (
        message.map(|m| {
            GetProfileResponse::decode(&m[..])
                .unwrap()
                .profile
                .unwrap()
                .id
        }),
        status,
    )
}

/// Sign-in through one replica, the account API through another: the user
/// sees their own profile, the page's request without the CSRF token is
/// refused, and the bundle is served on the same listener.
#[tokio::test]
async fn a_user_signs_in_and_reads_their_account() {
    let deployment = deploy().await;
    let first = replica(&deployment).await;
    let second = replica(&deployment).await;
    let browser = sign_in(&deployment, &first).await;

    let (session, status) = read_session(&second, &browser.cookie).await;
    assert_eq!(status, "0");
    assert_eq!(session.unwrap().sub, deployment.profile.id.to_string());

    let (id, status) = current_profile(&second, &browser, true).await;
    assert_eq!(status, "0");
    assert_eq!(id.unwrap(), deployment.profile.id.to_string());

    // PERMISSION_DENIED: the CSRF token is missing.
    let (_, refused) = current_profile(&second, &browser, false).await;
    assert_eq!(refused, "7");

    let page = http()
        .get(format!("{second}/security"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    assert_eq!(page.text().await.unwrap(), "<!doctype html>");
}

/// Two first sign-ins of one browser at once each complete with a session of
/// their own: their correlation cookies never replace each other.
#[tokio::test]
async fn two_concurrent_sign_ins_both_complete() {
    let deployment = deploy().await;
    let replica = replica(&deployment).await;
    let (a, b) = tokio::join!(
        sign_in(&deployment, &replica),
        sign_in(&deployment, &replica)
    );
    assert_ne!(a.cookie, b.cookie);
    for browser in [&a, &b] {
        let (id, status) = current_profile(&replica, browser, true).await;
        assert_eq!(status, "0");
        assert_eq!(id.unwrap(), deployment.profile.id.to_string());
    }
}

/// An expired access token is refreshed with the key's assertion before the
/// call, the rotated refresh token replaces the old one, and the call goes
/// through as the same user.
#[tokio::test]
async fn an_expired_token_is_refreshed_before_the_call() {
    let deployment = deploy().await;
    let replica = replica(&deployment).await;
    let browser = sign_in(&deployment, &replica).await;
    let id = browser.cookie.split_once('=').unwrap().1.to_owned();
    let store = sessions(&deployment);
    let before = store.get_session(&id).await.unwrap().unwrap();
    let mut expired = before.claims.clone();
    expired.exp = 0;
    let held = before
        .refresh_token
        .clone()
        .expect("the sign-in granted a refresh token");
    assert!(matches!(
        store
            .replace_tokens(
                &id,
                &held,
                before.access_token.clone(),
                before.refresh_token.clone(),
                expired,
            )
            .await
            .unwrap(),
        sid_authn::bff_session::TokenReplacement::Replaced
    ));

    let (profile, status) = current_profile(&replica, &browser, true).await;
    assert_eq!(status, "0");
    assert_eq!(profile.unwrap(), deployment.profile.id.to_string());
    let after = store.get_session(&id).await.unwrap().unwrap();
    assert_ne!(after.bearer(), before.bearer());
    assert!(!after.holds_refresh_token(&held));
    assert!(after.claims.exp > chrono::Utc::now().timestamp());
}

/// Sign-out ends the application session and revokes its grant at SID: the
/// cookie no longer opens anything, and the refresh token the session held
/// is dead.
#[tokio::test]
async fn sign_out_revokes_the_grant() {
    let deployment = deploy().await;
    let replica = replica(&deployment).await;
    let browser = sign_in(&deployment, &replica).await;
    let id = browser.cookie.split_once('=').unwrap().1.to_owned();
    let held = sessions(&deployment)
        .get_session(&id)
        .await
        .unwrap()
        .unwrap()
        .refresh_token
        .expect("the code flow grants a refresh token");

    let (answer, status) = grpc_web(
        &replica,
        &format!("/{ADAPTER}/EndApplicationSession"),
        Vec::new(),
        Some(&browser.cookie),
        Some(&browser.csrf),
    )
    .await;
    assert_eq!(status, "0");
    let ended = EndApplicationSessionResponse::decode(&answer.unwrap()[..]).unwrap();
    assert_eq!(ended.grant, GrantOutcome::Revoked as i32);
    // UNAUTHENTICATED: the session is gone.
    let (_, after) = current_profile(&replica, &browser, true).await;
    assert_eq!(after, "16");

    let link = RpClient::new(
        ClientKey::ed25519_from_pem(&secrecy::SecretString::from(deployment.key_pem.as_str()))
            .unwrap(),
        deployment.installation.clone(),
        tonic::transport::Channel::from_shared(format!("http://{}", deployment.addr))
            .unwrap()
            .connect_lazy(),
    )
    .unwrap();
    let connection = link.connection().await.unwrap();
    assert!(
        link.refresh(connection, held.expose_secret().to_owned())
            .await
            .is_err()
    );
}
