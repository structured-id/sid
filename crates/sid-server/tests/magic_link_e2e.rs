// SPDX-License-Identifier: AGPL-3.0-only
//! Magic link end-to-end tests with real PostgreSQL.
//!
//! Tests the full magic link lifecycle: generation → storage → redemption
//! → single-use enforcement → expiry → rate limiting → cleanup.
//!
//! Requires sid-test-postgres on port 54399.

mod common;

use sid_authn::magic_link::{MagicLinkService, MagicLinkVerifyResult};
use sid_core::models::{AuditEntry, MagicLinkSession};
use sid_plugin::StorageBackend;
use sid_storage::PostgresBackend;
use std::sync::Arc;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// An address no other run has used: the test database outlives a run, and an
/// unconsumed link from an earlier run counts against the per-address limit.
fn unique_email(tag: &str) -> String {
    format!("{tag}-{}@sid.example.com", uuid::Uuid::now_v7().simple())
}

/// A link for an account whose mailbox is spelled as its key.
trait RequestOwn {
    async fn request_own(
        &self,
        email: &str,
    ) -> Result<
        (sid_authn::magic_link::MagicLinkRequestResult, String),
        sid_authn::magic_link::MagicLinkError,
    >;
}

impl RequestOwn for MagicLinkService {
    async fn request_own(
        &self,
        email: &str,
    ) -> Result<
        (sid_authn::magic_link::MagicLinkRequestResult, String),
        sid_authn::magic_link::MagicLinkError,
    > {
        self.request_magic_link(email, email).await
    }
}

async fn setup() -> (MagicLinkService, Arc<dyn StorageBackend>) {
    let backend = PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");

    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");

    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let service = MagicLinkService::new(storage.clone(), common::test_key_manager());
    (service, storage)
}

#[tokio::test]
async fn test_magic_link_happy_path() {
    let (service, _storage) = setup().await;
    let email = unique_email("alice-ml-test");

    // Generate magic link.
    let (result, token) = service
        .request_own(&email)
        .await
        .expect("request_magic_link should succeed");

    assert!(!token.is_empty(), "token should be non-empty");
    assert!(
        result.expires_in_seconds > 0,
        "expires_in should be positive"
    );

    // Verify with correct token.
    let verify_result = service
        .verify_magic_link(result.session_id, &token)
        .await
        .unwrap();

    match verify_result {
        MagicLinkVerifyResult::Success { email: verified } => {
            assert_eq!(verified, email);
        }
        other => panic!("expected Success, got {:?}", other),
    }
}

#[tokio::test]
async fn test_magic_link_single_use_enforcement() {
    let (service, _storage) = setup().await;

    let (result, token) = service
        .request_own(&unique_email("bob-ml-single"))
        .await
        .unwrap();

    // First verify succeeds.
    let first = service
        .verify_magic_link(result.session_id, &token)
        .await
        .unwrap();
    assert!(
        matches!(first, MagicLinkVerifyResult::Success { .. }),
        "first verify should succeed"
    );

    // Second verify with same token → AlreadyConsumed.
    let second = service
        .verify_magic_link(result.session_id, &token)
        .await
        .unwrap();
    assert!(
        matches!(second, MagicLinkVerifyResult::AlreadyConsumed),
        "second verify should be AlreadyConsumed, got {:?}",
        second
    );
}

#[tokio::test]
async fn test_magic_link_invalid_token() {
    let (service, _storage) = setup().await;

    let (result, _token) = service
        .request_own(&unique_email("carol-ml-invalid"))
        .await
        .unwrap();

    // Verify with wrong token.
    let verify = service
        .verify_magic_link(result.session_id, "wrong-token-value")
        .await
        .unwrap();

    assert!(
        matches!(verify, MagicLinkVerifyResult::InvalidToken),
        "wrong token should be InvalidToken, got {:?}",
        verify
    );
}

#[tokio::test]
async fn test_magic_link_session_not_found() {
    let (service, _storage) = setup().await;

    let verify = service
        .verify_magic_link(uuid::Uuid::now_v7(), "any-token")
        .await
        .unwrap();

    assert!(
        matches!(verify, MagicLinkVerifyResult::SessionNotFound),
        "random UUID should be SessionNotFound, got {:?}",
        verify
    );
}

#[tokio::test]
async fn test_magic_link_expired() {
    let (_service, storage) = setup().await;

    // Create a session that's already expired (manually, bypassing service).
    let expired_session = MagicLinkSession {
        id: uuid::Uuid::now_v7(),
        email: "dave-ml-expired@sid.example.com".to_string(),
        destination: "dave-ml-expired@sid.example.com".to_string(),
        token_hash: "$argon2id$v=19$m=19456,t=2,p=1$fake$fakehash".to_string(),
        sealed_token: Vec::new(),
        consumed: false,
        created_at: chrono::Utc::now() - chrono::Duration::hours(1),
        expires_at: chrono::Utc::now() - chrono::Duration::minutes(1), // expired 1 min ago
    };

    storage
        .create_magic_link_session(&expired_session, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    // Create a fresh service and verify.
    let service = MagicLinkService::new(storage.clone(), common::test_key_manager());
    let verify = service
        .verify_magic_link(expired_session.id, "any-token")
        .await
        .unwrap();

    assert!(
        matches!(verify, MagicLinkVerifyResult::Expired),
        "expired session should be Expired, got {:?}",
        verify
    );
}

#[tokio::test]
async fn test_magic_link_rate_limiting() {
    let (service, _storage) = setup().await;
    // Use unique email per run to avoid leftover sessions from previous test runs
    // (test DB persists within container lifetime).
    let email = unique_email("eve-ml-rate");

    // Request 3 magic links (should succeed — rate limit is 3).
    for i in 0..3 {
        let result = service.request_own(&email).await;
        assert!(
            result.is_ok(),
            "request {} should succeed, got {:?}",
            i + 1,
            result.err()
        );
    }

    // 4th request should be rate-limited.
    let fourth = service.request_own(&email).await;
    assert!(
        fourth.is_err(),
        "4th request should be rate-limited, got Ok"
    );

    let err = fourth.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("rate") || err_str.contains("Rate") || err_str.contains("limit"),
        "error should mention rate limit, got: {}",
        err_str
    );
}

/// The cleanup deletes every expired link of the installation, so it runs in
/// a schema of its own: on the shared schema it would remove the expired link
/// `test_magic_link_expired` is verifying beside it.
#[tokio::test]
async fn test_magic_link_cleanup_removes_expired() {
    let schema = format!("magic_link_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("migrations in an isolated schema");
    let pool = backend.pool().clone();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let outcome = tokio::spawn(cleanup_removes_expired(storage)).await;
    // The migrations also create the schema's database-wide reader role.
    for statement in [
        format!("DROP SCHEMA \"{schema}\" CASCADE"),
        format!("DROP ROLE IF EXISTS \"{schema}_reader\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

async fn cleanup_removes_expired(storage: Arc<dyn StorageBackend>) {
    // Create an expired session.
    let expired = MagicLinkSession {
        id: uuid::Uuid::now_v7(),
        email: "frank-ml-cleanup@sid.example.com".to_string(),
        destination: "frank-ml-cleanup@sid.example.com".to_string(),
        token_hash: "hash".to_string(),
        sealed_token: Vec::new(),
        consumed: false,
        created_at: chrono::Utc::now() - chrono::Duration::hours(2),
        expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
    };
    storage
        .create_magic_link_session(&expired, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    // Verify it exists.
    let found = storage.get_magic_link_session(expired.id).await.unwrap();
    assert!(found.is_some(), "session should exist before cleanup");

    // Run cleanup.
    let service = MagicLinkService::new(storage.clone(), common::test_key_manager());
    let cleaned = service.cleanup().await.unwrap();
    assert!(cleaned >= 1, "should clean at least 1 expired session");

    // Verify it's gone.
    let after = storage.get_magic_link_session(expired.id).await.unwrap();
    assert!(
        after.is_none(),
        "expired session should be removed after cleanup"
    );
}

#[tokio::test]
async fn test_magic_link_token_uniqueness() {
    let (service, _storage) = setup().await;

    let (_, token1) = service
        .request_own(&unique_email("grace-ml-unique1"))
        .await
        .unwrap();
    let (_, token2) = service
        .request_own(&unique_email("grace-ml-unique2"))
        .await
        .unwrap();

    assert_ne!(token1, token2, "each magic link should have a unique token");
}

// ── Delivery of the link ────────────────────────────────────────────────────

use sid::auth_mail::{AuthMailDelivery, MagicLinkMail};
use sid_authn::work_runner::{WorkHandler, WorkOutcome};
use sid_core::models::{ClaimedWork, MAGIC_LINK_EMAIL_KIND, WorkKind};
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};
use sid_server::auth_mail::{MailTransport, TemplatedMail};

/// The server's templated mail over `transport`.
fn templated(transport: Transport) -> Arc<dyn AuthMailDelivery> {
    Arc::new(TemplatedMail::new(Arc::new(transport)))
}

/// The account UI page links open in these tests.
fn page() -> url::Url {
    url::Url::parse("https://id.sid.example.com/account/verify").unwrap()
}

/// Records every mail instead of sending it; `None` stands for an
/// installation with no usable email provider.
#[derive(Default)]
struct Recorded {
    sent: std::sync::Mutex<Vec<(String, RenderedMessage)>>,
}

#[async_trait::async_trait]
impl NotificationChannel for Recorded {
    fn channel_id(&self) -> &str {
        "email"
    }

    async fn deliver(
        &self,
        recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        self.sent
            .lock()
            .unwrap()
            .push((recipient.email.clone().unwrap(), message.clone()));
        Ok(DeliveryReceipt {
            message_id: uuid::Uuid::now_v7().to_string(),
            channel: "email".into(),
            timestamp: chrono::Utc::now(),
            provider: "recorded".into(),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        unreachable!("the mail handler never probes its channel")
    }
}

struct Transport(Option<Arc<Recorded>>);

#[async_trait::async_trait]
impl MailTransport for Transport {
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String> {
        match &self.0 {
            Some(recorded) => Ok(recorded.clone()),
            None => Err("no email provider is configured".into()),
        }
    }
}

/// The handler's attempt at the delivery work of session `id`.
fn delivery_of(id: uuid::Uuid) -> ClaimedWork {
    ClaimedWork {
        id: sid_core::models::WorkId::new(),
        kind: WorkKind::new(MAGIC_LINK_EMAIL_KIND).unwrap(),
        payload: id.as_bytes().to_vec(),
        attempt: 1,
        max_attempts: 8,
        generation: 1,
        expires_at: None,
    }
}

/// Requesting a link commits, with its session, one piece of work emailing
/// it: the work names only the session and expires with the link, and
/// neither it nor the stored session holds the token in the clear. Runs in
/// a schema of its own so the claim sees this request's work alone.
#[tokio::test]
async fn test_requested_link_owes_its_email() {
    let schema = format!("magic_link_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("migrations in an isolated schema");
    let pool = backend.pool().clone();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let outcome = tokio::spawn(requested_link_owes_its_email(storage)).await;
    for statement in [
        format!("DROP SCHEMA \"{schema}\" CASCADE"),
        format!("DROP ROLE IF EXISTS \"{schema}_reader\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

async fn requested_link_owes_its_email(storage: Arc<dyn StorageBackend>) {
    let service = MagicLinkService::new(storage.clone(), common::test_key_manager());
    let (result, token) = service
        .request_own(&unique_email("henry-ml-owed"))
        .await
        .unwrap();

    let kind = WorkKind::new(MAGIC_LINK_EMAIL_KIND).unwrap();
    let claimed = storage
        .claim_work(&[kind], "test", 10, std::time::Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "one email is owed per requested link");
    let session = storage
        .get_magic_link_session(result.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed[0].payload, result.session_id.as_bytes());
    assert_eq!(claimed[0].expires_at, Some(session.expires_at));
    assert!(!session.sealed_token.is_empty());
    let token = token.as_bytes();
    for stored in [&claimed[0].payload, &session.sealed_token] {
        assert!(
            !stored.windows(token.len()).any(|w| w == token),
            "the token is stored in the clear"
        );
    }
}

/// The mail goes to the mailbox bound at the request (here spelled unlike
/// its key), never to the key, with the link to the account UI page, and a
/// repeated attempt sends that same link again, so a lost send is retried
/// without a new token.
#[tokio::test]
async fn test_link_mail_sends_the_same_link_on_every_attempt() {
    let (service, _storage) = setup().await;
    let service = Arc::new(service);
    let key = unique_email("irismlmail");
    let email = key.replacen("irismlmail", "Iris.ML.Mail+login", 1);
    let (result, token) = service.request_magic_link(&key, &email).await.unwrap();
    let recorded = Arc::new(Recorded::default());
    let mail = MagicLinkMail::new(
        service.clone(),
        page(),
        templated(Transport(Some(recorded.clone()))),
    );

    for _ in 0..2 {
        let outcome = mail.handle(&delivery_of(result.session_id)).await;
        assert!(matches!(outcome, WorkOutcome::Done(Some(_))), "{outcome:?}");
    }

    let sent = recorded.sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    let mut expected = page();
    expected
        .query_pairs_mut()
        .append_pair("session", &result.session_id.to_string())
        .append_pair("token", &token);
    for (to, message) in sent.iter() {
        assert_eq!(to, &email);
        assert!(message.body.contains(expected.as_str()), "{}", message.body);
    }
    assert_eq!(sent[0].1.body, sent[1].1.body);
}

/// A consumed link sends nothing, and consuming it drops the sealed token
/// the delivery kept.
#[tokio::test]
async fn test_link_mail_sends_nothing_once_consumed() {
    let (service, storage) = setup().await;
    let service = Arc::new(service);
    let (result, token) = service
        .request_own(&unique_email("jack-ml-consumed"))
        .await
        .unwrap();
    assert!(matches!(
        service
            .verify_magic_link(result.session_id, &token)
            .await
            .unwrap(),
        MagicLinkVerifyResult::Success { .. }
    ));
    let recorded = Arc::new(Recorded::default());
    let mail = MagicLinkMail::new(
        service.clone(),
        page(),
        templated(Transport(Some(recorded.clone()))),
    );

    let outcome = mail.handle(&delivery_of(result.session_id)).await;

    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");
    assert!(recorded.sent.lock().unwrap().is_empty());
    let session = storage
        .get_magic_link_session(result.session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(session.sealed_token.is_empty());
}

/// An expired link sends nothing, even while its work is still claimed.
#[tokio::test]
async fn test_link_mail_sends_nothing_once_expired() {
    let (service, storage) = setup().await;
    let service = Arc::new(service);
    let keys = common::test_key_manager();
    let email = unique_email("kate-ml-expired");
    let mut expired = MagicLinkSession::new(email.clone(), email, "hash".into());
    expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    expired.sealed_token = sid_authn::sealed_secret::seal(
        keys.as_ref(),
        &sid_core::models::magic_link_sealing_context(expired.id),
        b"token",
    )
    .await
    .unwrap();
    storage
        .create_magic_link_session(&expired, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let recorded = Arc::new(Recorded::default());
    let mail = MagicLinkMail::new(
        service,
        page(),
        templated(Transport(Some(recorded.clone()))),
    );

    let outcome = mail.handle(&delivery_of(expired.id)).await;

    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");
    assert!(recorded.sent.lock().unwrap().is_empty());
}

/// Without a usable email provider the work waits and is tried again; the
/// link stays deliverable.
#[tokio::test]
async fn test_link_mail_waits_for_a_provider() {
    let (service, _storage) = setup().await;
    let service = Arc::new(service);
    let (result, _token) = service
        .request_own(&unique_email("liam-ml-provider"))
        .await
        .unwrap();
    let mail = MagicLinkMail::new(service.clone(), page(), templated(Transport(None)));

    let outcome = mail.handle(&delivery_of(result.session_id)).await;

    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
    assert!(
        service
            .pending_delivery(result.session_id, chrono::Utc::now())
            .await
            .unwrap()
            .is_some()
    );
}

/// A token sealed to another session is never sent as this one's: the work
/// fails for good instead of mailing a link that cannot be its own.
#[tokio::test]
async fn test_link_mail_refuses_a_token_sealed_to_another_session() {
    let (service, storage) = setup().await;
    let service = Arc::new(service);
    let keys = common::test_key_manager();
    let email = unique_email("mia-ml-foreign");
    let mut session = MagicLinkSession::new(email.clone(), email, "hash".into());
    session.sealed_token = sid_authn::sealed_secret::seal(
        keys.as_ref(),
        &sid_core::models::magic_link_sealing_context(uuid::Uuid::now_v7()),
        b"token",
    )
    .await
    .unwrap();
    storage
        .create_magic_link_session(&session, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let recorded = Arc::new(Recorded::default());
    let mail = MagicLinkMail::new(
        service,
        page(),
        templated(Transport(Some(recorded.clone()))),
    );

    let outcome = mail.handle(&delivery_of(session.id)).await;

    assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
    assert!(recorded.sent.lock().unwrap().is_empty());
}

/// Magic links without the account UI that opens them stop startup: a
/// requested link would be owed a mail that names no page.
#[tokio::test]
async fn test_magic_links_need_the_account_ui() {
    let (service, storage) = setup().await;
    let keys = common::test_key_manager();
    let links = Arc::new(service);

    let refused = sid_server::init::magic_link_mail(Some(&links), None, &storage, &keys);

    assert!(refused.is_err());
    assert!(
        sid_server::init::magic_link_mail(None, None, &storage, &keys)
            .unwrap()
            .is_none()
    );
}
