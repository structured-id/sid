// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's own browser session as its pages use it through the
//! access guard: the session read with its CSRF token from an admitted
//! origin, and signing out of it.

mod common;

use std::sync::Arc;

use common::TestServices;
use common::mock_storage::MockStorage;
use sid_authn::browser_session::{BrowserCsrf, BrowserSecret};
use sid_core::models::{AuditEntry, ProfileId, Session};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authn::auth_service_client::AuthServiceClient;
use sid_proto::sid::v1::authn::auth_service_server::AuthServiceServer;
use tonic::Code;

const PAGE: &str = "https://sid.example.com";

/// The installation's own pages: its public origin only.
struct OwnPages;

#[async_trait::async_trait]
impl sid_infra::authn::access::AdmittedOrigins for OwnPages {
    async fn admits(&self, origin: &str) -> bool {
        origin == PAGE
    }
}

/// The auth service behind the guard as the server runs it, with browser
/// sessions admitted from the installation's own pages, and a client of it.
async fn served(svc: &TestServices) -> AuthServiceClient<tonic::transport::Channel> {
    use sid_infra::authn::access::{Access, AccessRules, BrowserSessions};
    let rules = AccessRules::from_descriptors(sid_proto::FILE_DESCRIPTOR_SET).unwrap();
    let access = Arc::new(
        Access::new(
            Arc::new(rules),
            svc.jwt.clone(),
            svc.revocation_cache.clone(),
            svc.storage.clone(),
            svc.revocation_cache.clone(),
        )
        .with_browser_sessions(BrowserSessions {
            cookie: svc.auth.browser_cookie().clone(),
            origins: Arc::new(OwnPages),
        }),
    );
    let guarded = access
        .guard(AuthServiceServer::from_arc(svc.auth.clone()))
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(guarded)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    AuthServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

/// A signed-in browser: its stored session, cookie secret and CSRF token.
async fn signed_in(storage: &dyn StorageBackend) -> (Session, BrowserSecret, String) {
    let secret = BrowserSecret::generate();
    let csrf = BrowserCsrf::generate();
    let mut session = Session::new(
        ProfileId::generate(),
        None,
        jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
    );
    session.browser_secret_hash = Some(secret.hash());
    session.browser_csrf = Some(csrf);
    storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    (session, secret, BrowserCsrf::encode(&csrf))
}

/// A call from the browser: its cookie, from `origin`, echoing `csrf`.
fn from_browser(
    svc: &TestServices,
    secret: &BrowserSecret,
    origin: Option<&str>,
    csrf: Option<&str>,
) -> tonic::Request<()> {
    let mut request = tonic::Request::new(());
    let cookie = format!(
        "{}={}",
        svc.auth.browser_cookie().name(),
        secret.encode().as_str()
    );
    let meta = request.metadata_mut();
    meta.insert("cookie", cookie.parse().unwrap());
    if let Some(origin) = origin {
        meta.insert("origin", origin.parse().unwrap());
    }
    if let Some(csrf) = csrf {
        meta.insert("x-csrf-token", csrf.parse().unwrap());
    }
    request
}

// The page reads its session with the cookie alone (a read changes nothing,
// so it needs no CSRF token yet) and gets the token its later calls echo; a
// page on another origin learns nothing. Bug prevented: a foreign page that
// reads the session's CSRF token and drives the console's API.
#[tokio::test]
async fn the_session_is_read_only_from_an_admitted_page() {
    let svc = TestServices::new(MockStorage::new());
    let (_, secret, csrf) = signed_in(svc.storage.as_ref()).await;
    let mut client = served(&svc).await;

    let read = client
        .get_browser_session(from_browser(&svc, &secret, Some(PAGE), None))
        .await
        .unwrap();
    assert_eq!(read.metadata().get("cache-control").unwrap(), "no-store");
    let session = read.into_inner();
    assert_eq!(session.csrf_token, csrf);
    assert!(!session.administrator);

    for origin in [Some("https://evil.example.net"), None] {
        let refused = client
            .get_browser_session(from_browser(&svc, &secret, origin, None))
            .await
            .unwrap_err();
        assert!(
            matches!(
                refused.code(),
                Code::Unauthenticated | Code::PermissionDenied
            ),
            "{origin:?}: {refused:?}"
        );
    }
}

// Signing out ends the session the cookie names and clears the cookie; the
// next read finds no session. Without the session's CSRF token the call is
// refused and the session stays. Bug prevented: a console whose Sign out
// leaves the session alive, or a foreign page that signs the user out.
#[tokio::test]
async fn signing_out_ends_the_session_and_clears_its_cookie() {
    let svc = TestServices::new(MockStorage::new());
    let (session, secret, csrf) = signed_in(svc.storage.as_ref()).await;
    let mut client = served(&svc).await;

    let refused = client
        .end_browser_session(from_browser(&svc, &secret, Some(PAGE), None))
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused.code(),
            Code::Unauthenticated | Code::PermissionDenied
        ),
        "{refused:?}"
    );
    assert!(svc.storage.get_session(session.id).await.unwrap().is_some());

    let ended = client
        .end_browser_session(from_browser(&svc, &secret, Some(PAGE), Some(&csrf)))
        .await
        .unwrap();
    assert_eq!(
        ended.metadata().get("set-cookie").unwrap(),
        svc.auth.browser_cookie().clear().as_str()
    );
    assert!(svc.storage.get_session(session.id).await.unwrap().is_none());

    let after = client
        .get_browser_session(from_browser(&svc, &secret, Some(PAGE), None))
        .await
        .unwrap_err();
    assert_eq!(after.code(), Code::Unauthenticated, "{after:?}");
}
