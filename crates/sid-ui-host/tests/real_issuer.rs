// SPDX-License-Identifier: AGPL-3.0-only
//! The browser adapter against a real issuer served over gRPC and the
//! application's shared PostgreSQL store, as two replicas of one
//! application run it: sign-in through the issuer's authorization endpoint,
//! code redemption with the client's `private_key_jwt`, refresh at the
//! token endpoint and the end of the issuer session.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use sid_authn::bff_session::BffSessionStore;
use sid_authn::client_connection::ClientConnection;
use sid_authn::client_key::ClientKey;
use sid_authn::issuer_directory::IssuerDirectory;
use sid_authn::relying_party::Connection;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::issuer_client::RpClient;
use sid_infra::issuer_registry::GrpcIssuerSource;
use sid_plugin::cache::{CacheBackend, InMemoryCacheBackend};
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1::OAuth2AuthorizeRequest;
use sid_proto::sid::v1::authn::application_session_service_server::ApplicationSessionService;
use sid_proto::sid::v1::authn::{
    ApplicationSession, CompleteSignInRequest, GetApplicationSessionRequest, StartSignInRequest,
};
use sid_test_issuer::{INSTALLATION, Setup, TestIssuer};
use sid_ui_host::application_session::ApplicationSessions;
use tonic::{Request, Response, Status};

/// The application's origin, its API and its registered callback.
const APP: &str = "https://app.sid.example.com";
const API: &str = "https://app.sid.example.com/api/";
const CALLBACK: &str = "https://app.sid.example.com/auth/callback";
const CLIENT: &str = "app-web";
const COOKIE: &str = "__Host-app-session";
const LONG: Duration = Duration::from_secs(3600);

/// The shared PostgreSQL the replicas keep their sessions in: the test
/// database unless `SID_TEST_DATABASE_URL` names another.
fn database() -> String {
    std::env::var("SID_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into())
}

/// The issuer, the application's two replicas over one store, and a user
/// signed in at the issuer in the browser: the bearer its pages present.
struct World {
    issuer: TestIssuer,
    replicas: [ApplicationSessions; 2],
    bearer: String,
    issuer_session: sid_core::models::Session,
    /// The store both replicas keep their sessions in.
    sessions: Arc<BffSessionStore>,
    /// The application's client at the issuer, as a replica holds it.
    client: Arc<RpClient>,
}

async fn world() -> World {
    let issuer = TestIssuer::start(Setup {
        resources: vec![API.into()],
        ..Default::default()
    })
    .await;
    let (key, pem) = ClientKey::generate_ed25519().unwrap();
    issuer
        .web_client(CLIENT, API, CALLBACK, key.public_jwks().unwrap())
        .await;
    let kid = key.kid().unwrap().to_owned();
    let store = sid_storage::application_store::ceremony_store(&database())
        .await
        .expect("the test database (docker compose -f docker-compose.test.yml up -d)");
    let sessions = Arc::new(BffSessionStore::new(store, LONG, LONG, LONG));
    // Revocations recorded anywhere reach both replicas.
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let channel = || {
        sid_infra::deadline::bounded_channel(&issuer.upstream(), Duration::from_secs(5)).unwrap()
    };
    let rp_client = |channel| {
        Arc::new(
            RpClient::delivered(
                ClientKey::ed25519_from_pem(&pem).unwrap(),
                INSTALLATION.into(),
                channel,
                connection(&issuer, &kid),
            )
            .unwrap(),
        )
    };
    let replica = || {
        let channel = channel();
        ApplicationSessions::new(
            rp_client(channel.clone()),
            Arc::new(IssuerDirectory::new(Arc::new(GrpcIssuerSource::new(
                channel,
            )))),
            sessions.clone(),
            Arc::new(RevocationCache::new(LONG, cache.clone())),
            COOKIE.into(),
        )
    };
    let replicas = [replica(), replica()];
    let client = rp_client(channel());
    drop(key);
    let profile = issuer.profile().await;
    let (issuer_session, bearer) = issuer.sign_in(&profile).await;
    World {
        issuer,
        replicas,
        bearer,
        issuer_session,
        sessions,
        client,
    }
}

/// The connection the installation delivers to the application.
fn connection(issuer: &TestIssuer, kid: &str) -> Connection {
    Connection::accept(ClientConnection {
        issuer: issuer.issuer.canonical_url.clone(),
        client_id: CLIENT.into(),
        resource: API.into(),
        scopes: vec!["openid".into()],
        redirect_uri: CALLBACK.into(),
        token_endpoint_auth_method: "private_key_jwt".into(),
        key_ids: vec![kid.to_owned()],
    })
    .unwrap()
}

fn status(response: &Response<HttpBody>) -> String {
    header(response, "x-http-code")
}

/// The response header `name` the transcoder turns into HTTP.
fn header(response: &Response<HttpBody>, name: &str) -> String {
    response
        .metadata()
        .get(name)
        .unwrap_or_else(|| panic!("no {name}"))
        .to_str()
        .unwrap()
        .to_owned()
}

/// A sign-in the browser starts at `replica`: the authorization request it
/// is sent to and the `name=value` of the correlation cookie it keeps.
async fn start(replica: &ApplicationSessions) -> (HashMap<String, String>, String) {
    let response = replica
        .start_sign_in(Request::new(StartSignInRequest { rd: "/".into() }))
        .await
        .unwrap();
    assert_eq!(status(&response), "302");
    let location: url::Url = header(&response, "location").parse().unwrap();
    let query = location.query_pairs().into_owned().collect();
    let pair = header(&response, "set-cookie")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (query, pair)
}

/// The code the issuer's authorization endpoint answers `query` with for
/// the signed-in browser.
async fn authorize(w: &World, query: &HashMap<String, String>) -> String {
    w.issuer
        .authorize(
            &w.bearer,
            OAuth2AuthorizeRequest {
                client_id: query["client_id"].clone(),
                redirect_uri: query["redirect_uri"].clone(),
                response_type: query["response_type"].clone(),
                scope: Some(query["scope"].clone()),
                state: Some(query["state"].clone()),
                code_challenge: Some(query["code_challenge"].clone()),
                code_challenge_method: Some(query["code_challenge_method"].clone()),
                nonce: Some(query["nonce"].clone()),
                resource: vec![query["resource"].clone()],
                ..Default::default()
            },
        )
        .await
}

/// A request of the application's page carrying `cookie`.
fn from_page<T>(message: T, cookie: &str, csrf: Option<&str>) -> Request<T> {
    let mut request = Request::new(message);
    let metadata = request.metadata_mut();
    metadata.insert("origin", APP.parse().unwrap());
    metadata.insert("cookie", cookie.parse().unwrap());
    if let Some(csrf) = csrf {
        metadata.insert("x-csrf-token", csrf.parse().unwrap());
    }
    request
}

/// The issuer's redirect back with `code` for `query`, arriving at `replica`
/// with the browser's `cookies`.
async fn callback(
    w: &World,
    replica: &ApplicationSessions,
    query: &HashMap<String, String>,
    code: &str,
    cookies: &str,
) -> Response<HttpBody> {
    replica
        .complete_sign_in(from_page(
            CompleteSignInRequest {
                state: query["state"].clone(),
                code: Some(code.to_owned()),
                error: None,
                iss: Some(w.issuer.issuer.canonical_url.clone()),
            },
            cookies,
            None,
        ))
        .await
        .unwrap()
}

/// The `name=value` of the session cookie `response` sets, if any.
fn session_cookie(response: &Response<HttpBody>) -> Option<String> {
    response
        .metadata()
        .get_all("set-cookie")
        .iter()
        .map(|set| set.to_str().unwrap().split(';').next().unwrap().to_owned())
        .find(|pair| pair.starts_with(&format!("{COOKIE}=")))
}

async fn read(replica: &ApplicationSessions, session: &str) -> Result<ApplicationSession, Status> {
    replica
        .get_application_session(from_page(GetApplicationSessionRequest {}, session, None))
        .await
        .map(Response::into_inner)
}

/// A complete sign-in started at one replica and finished at the other.
async fn signed_in(w: &World) -> (String, ApplicationSession) {
    let (query, pair) = start(&w.replicas[0]).await;
    let code = authorize(w, &query).await;
    let done = callback(w, &w.replicas[1], &query, &code, &pair).await;
    assert_eq!(status(&done), "302");
    let session = session_cookie(&done).expect("a session cookie");
    let read = read(&w.replicas[0], &session).await.unwrap();
    (session, read)
}

/// A sign-in started at one replica completes at the other against the
/// issuer: the code is redeemed with the client's key, the tokens are
/// verified against the issuer's published keys, and the session it makes
/// is read on both replicas. Its callback is used once.
#[tokio::test]
async fn a_sign_in_completes_at_the_issuer() {
    let w = world().await;
    let (query, pair) = start(&w.replicas[0]).await;
    let code = authorize(&w, &query).await;
    let done = callback(&w, &w.replicas[1], &query, &code, &pair).await;
    assert_eq!(status(&done), "302");
    let session = session_cookie(&done).expect("a session cookie");
    for replica in &w.replicas {
        let read = read(replica, &session).await.unwrap();
        assert!(!read.sub.is_empty());
        assert!(!read.csrf_token.is_empty());
    }

    let replay = callback(&w, &w.replicas[0], &query, &code, &pair).await;
    assert_eq!(status(&replay), "400", "the sign-in is taken once");
    assert!(session_cookie(&replay).is_none());
}

/// Two tabs start their first sign-ins before either has a cookie and the
/// issuer answers both; in either order of the callbacks, each completes
/// into a session of its own, and the later one leaves the earlier session
/// standing.
#[tokio::test]
async fn concurrent_first_sign_ins_both_become_sessions() {
    for a_first in [true, false] {
        let w = world().await;
        let ((a, cookie_a), (b, cookie_b)) =
            tokio::join!(start(&w.replicas[0]), start(&w.replicas[1]));
        let (code_a, code_b) = (authorize(&w, &a).await, authorize(&w, &b).await);
        let jar = format!("{cookie_a}; {cookie_b}");
        let order = if a_first {
            [(&a, &code_a), (&b, &code_b)]
        } else {
            [(&b, &code_b), (&a, &code_a)]
        };
        let mut sessions = Vec::new();
        for (i, (query, code)) in order.into_iter().enumerate() {
            let done = callback(&w, &w.replicas[i], query, code, &jar).await;
            assert_eq!(status(&done), "302", "a_first={a_first}");
            sessions.push(session_cookie(&done).expect("a session cookie"));
        }
        assert_ne!(sessions[0], sessions[1]);
        for session in &sessions {
            read(&w.replicas[0], session)
                .await
                .expect("each sign-in's session stands");
        }
    }
}

/// A callback carrying another browser's correlation cookie redeems
/// nothing; the code stays usable by the browser that started the sign-in.
#[tokio::test]
async fn another_browser_cannot_complete_a_sign_in() {
    let w = world().await;
    let (query, own) = start(&w.replicas[0]).await;
    let (_, other) = start(&w.replicas[0]).await;
    let code = authorize(&w, &query).await;
    let refused = callback(&w, &w.replicas[1], &query, &code, &other).await;
    assert_eq!(status(&refused), "400");
    assert!(session_cookie(&refused).is_none());

    let done = callback(&w, &w.replicas[1], &query, &code, &own).await;
    assert_eq!(status(&done), "302");
    assert!(session_cookie(&done).is_some());
}

/// A code issued to another client of the issuer is refused at redemption:
/// no session.
#[tokio::test]
async fn a_code_of_another_client_makes_no_session() {
    let w = world().await;
    let (other_key, _) = ClientKey::generate_ed25519().unwrap();
    w.issuer
        .web_client(
            "other-web",
            API,
            "https://other.sid.example.com/auth/callback",
            other_key.public_jwks().unwrap(),
        )
        .await;
    let (query, pair) = start(&w.replicas[0]).await;
    let mut foreign = query.clone();
    foreign.insert("client_id".into(), "other-web".into());
    foreign.insert(
        "redirect_uri".into(),
        "https://other.sid.example.com/auth/callback".into(),
    );
    let code = authorize(&w, &foreign).await;
    let done = callback(&w, &w.replicas[0], &query, &code, &pair).await;
    assert_eq!(status(&done), "502");
    assert!(session_cookie(&done).is_none());
}

/// A sign-in whose token endpoint cannot be reached is not completed: no
/// session, and the browser is told the issuer did not finish it.
#[tokio::test]
async fn an_unreachable_token_endpoint_completes_nothing() {
    let mut w = world().await;
    let (query, pair) = start(&w.replicas[0]).await;
    let code = authorize(&w, &query).await;
    w.issuer.stop().await;
    let done = callback(&w, &w.replicas[0], &query, &code, &pair).await;
    assert_eq!(status(&done), "502");
    assert!(session_cookie(&done).is_none());
}

/// The API refused the session's access token: the next call refreshes it
/// at the issuer's token endpoint, on whichever replica serves it, and the
/// session continues with the rotated token on both.
#[tokio::test]
async fn a_refused_token_is_refreshed_at_the_issuer() {
    let w = world().await;
    let (session, read) = signed_in(&w).await;
    let page = || from_page((), &session, Some(&read.csrf_token));
    let before = w.replicas[0].bearer(page().metadata()).await.unwrap();
    w.replicas[0].refused(&before).await.unwrap();
    let after = w.replicas[1].bearer(page().metadata()).await.unwrap();
    assert_ne!(
        after.token().expose_secret(),
        before.token().expose_secret(),
        "a new access token"
    );
    let held = w.replicas[0].bearer(page().metadata()).await.unwrap();
    assert_eq!(held.token().expose_secret(), after.token().expose_secret());
}

/// A replica claimed the session's refresh and the issuer committed the
/// rotation, but its answer was lost before the replica stored it: the
/// session still holds the replaced refresh token under that replica's
/// claim. Once the claim has lapsed, the next call on the other replica
/// takes the refresh over and presents the replaced token, and the issuer's
/// own retry contract decides: inside its grace window it rotates again, so
/// the session continues on both replicas with a new access token.
#[tokio::test]
async fn a_lost_refresh_is_taken_over_once_its_claim_lapses() {
    let w = world().await;
    let (session, read) = signed_in(&w).await;
    let id = session.split_once('=').expect("name=value").1.to_owned();
    let page = || from_page((), &session, Some(&read.csrf_token));
    let before = w.replicas[0].bearer(page().metadata()).await.unwrap();
    w.replicas[0].refused(&before).await.unwrap();
    let replaced = w
        .sessions
        .get_session(&id)
        .await
        .unwrap()
        .expect("the session")
        .refresh_token
        .expect("a refresh token");

    // The first replica's claim and its refresh at the issuer, whose answer
    // is lost: the rotation commits there, nothing is stored here.
    const HOLD: Duration = Duration::from_secs(1);
    let claimed = w
        .sessions
        .claim_refresh(&id, &replaced, HOLD, |_| true)
        .await
        .unwrap();
    assert!(
        matches!(claimed, sid_authn::bff_session::RefreshClaim::Claimed(_)),
        "the first replica holds the refresh"
    );
    let connection = w.client.connection().await.unwrap();
    w.client
        .refresh(connection, replaced.expose_secret().to_owned())
        .await
        .expect("the issuer commits the rotation");
    tokio::time::sleep(HOLD + Duration::from_millis(500)).await;
    let after = w.replicas[1]
        .bearer(page().metadata())
        .await
        .expect("inside the issuer's grace window the replaced token rotates again");
    assert_ne!(
        after.token().expose_secret(),
        before.token().expose_secret()
    );
    let stored = w
        .sessions
        .get_session(&id)
        .await
        .unwrap()
        .expect("the session");
    assert_ne!(
        stored
            .refresh_token
            .expect("a refresh token")
            .expose_secret(),
        replaced.expose_secret(),
        "the session holds the rotated refresh token"
    );
    let held = w.replicas[0].bearer(page().metadata()).await.unwrap();
    assert_eq!(held.token().expose_secret(), after.token().expose_secret());
}

/// Once the user's issuer session has ended, the application session made
/// from it ends at its next refresh: the issuer refuses the grant.
#[tokio::test]
async fn an_ended_issuer_session_ends_the_application_session() {
    let w = world().await;
    let (session, read) = signed_in(&w).await;
    let page = || from_page((), &session, Some(&read.csrf_token));
    let held = w.replicas[0].bearer(page().metadata()).await.unwrap();
    w.issuer.end(&w.issuer_session).await;
    w.replicas[0].refused(&held).await.unwrap();
    let ended = w.replicas[1]
        .bearer(page().metadata())
        .await
        .expect_err("the grant is gone");
    assert_eq!(ended.code(), tonic::Code::Unauthenticated, "{ended:?}");
    let gone = read_status(&w, &session).await;
    assert_eq!(gone, tonic::Code::Unauthenticated);
}

/// The user signed out and in again; the issuer's answer to an earlier
/// sign-in arrives late, after the new session exists. It opens nothing,
/// and the new session stands while the ended one stays ended.
#[tokio::test]
async fn a_late_answer_after_a_new_sign_in_changes_nothing() {
    use sid_proto::sid::v1::authn::EndApplicationSessionRequest;
    let w = world().await;
    let (earlier, pair) = start(&w.replicas[0]).await;
    let late_code = authorize(&w, &earlier).await;
    let first = callback(&w, &w.replicas[0], &earlier, &late_code, &pair).await;
    let first = session_cookie(&first).expect("a session cookie");
    let csrf = read(&w.replicas[0], &first).await.unwrap().csrf_token;
    w.replicas[1]
        .end_application_session(from_page(
            EndApplicationSessionRequest {},
            &first,
            Some(&csrf),
        ))
        .await
        .unwrap();
    let (second, _) = signed_in(&w).await;

    let late = callback(&w, &w.replicas[1], &earlier, &late_code, &pair).await;
    assert_eq!(status(&late), "400");
    assert!(session_cookie(&late).is_none());
    read(&w.replicas[0], &second)
        .await
        .expect("the new session stands");
    assert_eq!(read_status(&w, &first).await, tonic::Code::Unauthenticated);
}

async fn read_status(w: &World, session: &str) -> tonic::Code {
    read(&w.replicas[0], session)
        .await
        .expect_err("no session")
        .code()
}
