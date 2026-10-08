// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for OIDC Back-Channel Logout.
//!
//! An ended session owes its client a logout; the storage commits that work
//! with the deletion and the durable work runner delivers it over real HTTP to
//! a mock RP.

mod common;

use common::mock_storage::MockStorage;
use sid_authn::backchannel_logout::BackChannelLogoutHandler;
use sid_authn::issuer::{IssuerRegistry, IssuerVerifier};
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_authn::work_runner::{RunnerConfig, WorkHandler, WorkOutcome, WorkRunner};
use sid_core::models::{
    AuditEntry, ClaimedWork, LogoutDelivery, OAuth2Client, ProfileId, RevocationReason, Session,
    SubjectType, WorkState,
};
use sid_plugin::{StorageBackend, WorkStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ── Mock RP HTTP Server ──

/// A mock Relying Party HTTP server that receives back-channel logout POSTs.
struct MockRp {
    listener: TcpListener,
}

impl MockRp {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self { listener }
    }

    fn url(&self) -> String {
        let port = self.listener.local_addr().unwrap().port();
        format!("http://127.0.0.1:{}/backchannel-logout", port)
    }

    /// Accept one HTTP connection and respond with the given status code.
    /// Returns the raw HTTP request (including body with logout_token).
    async fn accept_and_respond(&self, status: u16) -> String {
        let (mut stream, _) = self.listener.accept().await.unwrap();
        let mut buf = vec![0u8; 16384];
        let n = stream.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();

        let status_text = match status {
            200 => "OK",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Error",
        };
        let response = format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        request
    }
}

// ── Helpers ──

fn profile_id() -> ProfileId {
    ProfileId::parse("0192b1e0-7c3a-7f4e-8a5d-3c2b1a0f9e8d").unwrap()
}

/// A relying party with a back-channel logout endpoint at `url`.
fn rp(url: Option<&str>, subject_type: SubjectType) -> OAuth2Client {
    let mut client = common::test_client();
    client.client_id = "client-456".to_string();
    client.backchannel_logout_uri = url.map(str::to_string);
    client.subject_type = subject_type;
    client
}

async fn storage_with(client: &OAuth2Client) -> Arc<MockStorage> {
    let mut profile = sid_core::models::Profile::new(Some("logout-holder"));
    profile.id = profile_id();
    let storage = Arc::new(MockStorage::new().with_profile(profile));
    common::store_client(&*storage, client).await.unwrap();
    storage
}

/// The handler over `storage`, whose installation issuer is provisioned as a
/// server start provisions it, and the verifier its relying parties use.
async fn handler(storage: Arc<MockStorage>) -> (BackChannelLogoutHandler, IssuerVerifier) {
    let keys = common::test_key_manager();
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        keys.as_ref(),
        &url::Url::parse("https://sid.example.com").unwrap(),
        common::test_org(),
    )
    .await
    .unwrap();
    let issuers = Arc::new(IssuerRegistry::new(storage.clone(), keys));
    let verifier = issuers.verifier(&issuer).await.unwrap();
    (BackChannelLogoutHandler::new(issuers, storage), verifier)
}

/// The logout owed for a session of `profile_id()` at client-456, as claimed.
fn claimed(delivery: &LogoutDelivery) -> ClaimedWork {
    let work = delivery.work();
    ClaimedWork {
        id: work.id,
        kind: work.kind,
        payload: work.payload,
        attempt: 1,
        max_attempts: work.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

fn delivery() -> LogoutDelivery {
    LogoutDelivery {
        client_id: "client-456".into(),
        profile_id: profile_id().to_string(),
        session_id: "0192b1e0-7c3a-7f4e-8a5d-3c2b1a0f9e8e".into(),
    }
}

/// The logout token the mock RP received, from its raw HTTP request.
fn logout_token(request: &str) -> String {
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let encoded = body
        .split('&')
        .find_map(|p| p.strip_prefix("logout_token="))
        .expect("logout_token not found in body");
    percent_decode(encoded)
}

// ── One delivery attempt ──

/// A delivered logout POSTs a logout token naming the ended session, signed
/// by the client's issuer, and the attempt is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delivery_posts_logout_token_for_the_session() {
    let mock = MockRp::start().await;
    let storage = storage_with(&rp(Some(&mock.url()), SubjectType::Public)).await;
    let server = tokio::spawn(async move { mock.accept_and_respond(200).await });

    let (handler, verifier) = handler(storage).await;
    let outcome = handler.handle(&claimed(&delivery())).await;
    assert!(
        matches!(&outcome, WorkOutcome::Done(Some(r)) if r == "HTTP 200"),
        "{outcome:?}"
    );

    let request = server.await.unwrap();
    assert!(request.starts_with("POST"), "should be POST");
    let claims = verifier
        .validate_logout_token(&logout_token(&request))
        .unwrap();
    assert_eq!(claims.iss, verifier.issuer());
    assert_eq!(claims.sub, profile_id().to_string());
    assert_eq!(claims.aud, "client-456");
    assert_eq!(claims.sid.as_deref(), Some(delivery().session_id.as_str()));
    assert!(
        claims
            .events
            .get("http://schemas.openid.net/event/backchannel-logout")
            .is_some(),
        "must contain backchannel-logout event claim"
    );
}

/// The logout names the subject the client's ID tokens carried under the same
/// hop, in an explicitly typed, expiring logout token (Back-Channel Logout
/// 1.0 §2.4). At an application of the installation's own organization that
/// is the local ProfileId even for a client stored with pairwise metadata,
/// and the logout allocates no binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_logout_subject_follows_the_hop_not_the_metadata() {
    let mock = MockRp::start().await;
    let client = rp(Some(&mock.url()), SubjectType::Pairwise);
    let storage = storage_with(&client).await;
    let server = tokio::spawn(async move { mock.accept_and_respond(200).await });

    let (handler, verifier) = handler(storage.clone()).await;
    handler.handle(&claimed(&delivery())).await;
    let token = logout_token(&server.await.unwrap());

    let claims = verifier.validate_logout_token(&token).unwrap();
    assert_eq!(claims.sub, profile_id().to_string());
    assert!(claims.exp > claims.iat, "logout token must expire");
    use base64::Engine;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').next().unwrap())
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
    assert_eq!(header["typ"], "logout+jwt");
    assert!(
        storage
            .find_service_binding(
                profile_id(),
                &sid_authn::subject::binding_scope(&client).unwrap()
            )
            .await
            .unwrap()
            .is_none(),
        "the logout allocated a binding"
    );
}

/// An RP answering with an error is retried: the logout is still owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rp_error_is_retried() {
    let mock = MockRp::start().await;
    let storage = storage_with(&rp(Some(&mock.url()), SubjectType::Public)).await;
    let server = tokio::spawn(async move { mock.accept_and_respond(503).await });

    let outcome = handler(storage).await.0.handle(&claimed(&delivery())).await;
    server.await.unwrap();
    assert!(
        matches!(&outcome, WorkOutcome::Retry(e) if e.contains("503")),
        "{outcome:?}"
    );
}

/// An unreachable RP is retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unreachable_rp_is_retried() {
    // Bound, then dropped: nothing listens on the port.
    let url = MockRp::start().await.url();
    let storage = storage_with(&rp(Some(&url), SubjectType::Public)).await;

    let outcome = handler(storage).await.0.handle(&claimed(&delivery())).await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
}

/// A client without a back-channel endpoint, or one removed since, is owed
/// nothing: the work ends without a request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_client_without_endpoint_or_removed_owes_nothing() {
    let storage = storage_with(&rp(None, SubjectType::Public)).await;
    let outcome = handler(storage).await.0.handle(&claimed(&delivery())).await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");

    let outcome = handler(Arc::new(MockStorage::new()))
        .await
        .0
        .handle(&claimed(&delivery()))
        .await;
    assert!(
        matches!(&outcome, WorkOutcome::Done(Some(r)) if r == "client removed"),
        "{outcome:?}"
    );
}

/// A client no issuer serves never received a token, so it is owed no
/// logout, and nothing is signed with another issuer's key for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_client_without_issuer_owes_nothing() {
    let mut client = rp(
        Some("http://127.0.0.1:9/backchannel-logout"),
        SubjectType::Public,
    );
    client.org_id = Some(sid_core::models::OrgId::generate());
    let storage = storage_with(&client).await;

    let outcome = handler(storage).await.0.handle(&claimed(&delivery())).await;
    assert!(
        matches!(&outcome, WorkOutcome::Done(Some(r)) if r == "client has no issuer"),
        "{outcome:?}"
    );
}

/// A payload that is not a logout delivery can never succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_malformed_delivery_is_permanent() {
    let mut work = claimed(&delivery());
    work.payload = b"not json".to_vec();
    let outcome = handler(Arc::new(MockStorage::new()))
        .await
        .0
        .handle(&work)
        .await;
    assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
}

// ── Revocation to delivery ──

/// Ending a profile's sessions owes one logout to the client of each session
/// issued to one, stored with the deletion; the runner delivers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_revoked_session_logout_is_owed_and_delivered() {
    let mock = MockRp::start().await;
    let storage = storage_with(&rp(Some(&mock.url()), SubjectType::Public)).await;

    let mut session = Session::new(
        profile_id(),
        "127.0.0.1".into(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.client_id = Some("client-456".into());
    let first_party = Session::new(
        profile_id(),
        "127.0.0.1".into(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    for s in [&session, &first_party] {
        storage
            .create_session(s, AuditEntry::system("test", "session").into())
            .await
            .unwrap();
    }

    let cascade = RevocationCascadeService::new(
        storage.clone(),
        Arc::new(RevocationCache::new(
            Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
    );
    cascade
        .revoke_sessions(
            profile_id(),
            RevocationReason::Admin,
            "admin",
            AuditEntry::system("test", "revoke all"),
        )
        .await
        .unwrap();

    // Owed before any delivery runs, and only for the client's session.
    let owed = LogoutDelivery::for_ended_session(&session).unwrap().work();
    let record = storage
        .get_work(owed.id)
        .await
        .unwrap()
        .expect("logout owed");
    assert_eq!(record.state, WorkState::Pending);
    assert_eq!(record.max_attempts, 6);
    assert!(LogoutDelivery::for_ended_session(&first_party).is_none());

    let server = tokio::spawn(async move { mock.accept_and_respond(200).await });
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let (handler, verifier) = handler(storage.clone()).await;
    let runner = WorkRunner::new(
        storage.clone(),
        "test-runner",
        vec![Arc::new(handler) as Arc<dyn WorkHandler>],
        RunnerConfig {
            concurrency: 2,
            lease: Duration::from_secs(30),
            scan_interval: Duration::from_millis(20),
        },
    )
    .unwrap();
    let running = tokio::spawn(runner.run(async move {
        stopped.await.unwrap_or(());
    }));

    let request = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the RP is sent the logout")
        .unwrap();
    let claims = verifier
        .validate_logout_token(&logout_token(&request))
        .unwrap();
    assert_eq!(claims.sid.as_deref(), Some(session.id.to_string().as_str()));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let record = storage.get_work(owed.id).await.unwrap().unwrap();
        if record.state == WorkState::Completed {
            assert_eq!(record.result.as_deref(), Some("HTTP 200"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "delivery not recorded: {record:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.send(()).unwrap();
    running.await.unwrap();
}

// ── Helpers ──

/// Simple percent-decoding for URL-encoded JWT tokens.
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}
