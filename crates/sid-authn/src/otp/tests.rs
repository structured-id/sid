// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_plugin::WorkStore;
use sid_storage::sqlite::SqliteBackend;

/// One installation's shared store: its ceremony state and its durable
/// work, as every replica sees them.
async fn store() -> Arc<SqliteBackend> {
    Arc::new(
        SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    )
}

/// A replica's OTP service over `store`.
fn replica(store: &Arc<SqliteBackend>) -> OtpService {
    OtpService::new(
        store.clone(),
        CodeDelivery {
            keys: crate::test_support::key_manager(),
        },
    )
}

async fn service() -> OtpService {
    replica(&store().await)
}

/// A code for an account at `target`, emailed there.
async fn request(
    service: &OtpService,
    target: &str,
) -> Result<(OtpRequestResult, String), OtpError> {
    service
        .request_otp(target, CodeDestination::Email(target))
        .await
}

fn email_kind() -> WorkKind {
    WorkKind::new(OTP_EMAIL_KIND).unwrap()
}

/// The code mails `store` owes now, claimed.
async fn owed_mails(store: &Arc<SqliteBackend>) -> Vec<sid_core::models::ClaimedWork> {
    store
        .claim_work(&[email_kind()], "test", 100, Duration::from_secs(60))
        .await
        .unwrap()
}

/// The issue a mail's payload names.
fn issue_of(work: &sid_core::models::ClaimedWork) -> Uuid {
    Uuid::from_slice(&work.payload[16..]).unwrap()
}

#[test]
fn test_generate_otp_code_length() {
    let code = generate_otp_code();
    assert_eq!(code.len(), OTP_CODE_LENGTH as usize);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn test_generate_otp_code_randomness() {
    let c1 = generate_otp_code();
    let c2 = generate_otp_code();
    // Extremely unlikely to be equal
    assert_ne!(c1, c2);
}

#[test]
fn test_hash_and_verify_code() {
    let code = "12345678";
    let hash = hash_code(code).unwrap();
    assert!(verify_code(code, &hash));
    assert!(!verify_code("87654321", &hash));
}

#[test]
fn test_otp_code_zero_padded() {
    // Verify that codes are always 8 digits even if numeric value is small
    for _ in 0..20 {
        let code = generate_otp_code();
        assert_eq!(code.len(), 8, "code '{}' is not 8 digits", code);
    }
}

#[tokio::test]
async fn test_request_otp_returns_code_and_session() {
    let service = service().await;
    let (result, code) = request(&service, "alice@example.com").await.unwrap();

    assert_eq!(code.len(), 8);
    assert_eq!(result.code_length, 8);
    assert_eq!(result.expires_in_seconds, 600);
    assert_eq!(result.resend_available_in, 120);
}

#[tokio::test]
async fn test_verify_otp_success_consumes_the_code() {
    let service = service().await;
    let (result, code) = request(&service, "alice@example.com").await.unwrap();

    match service.verify_otp(&result.session_id, &code).await.unwrap() {
        OtpVerifyResult::Success { target } => assert_eq!(target, "alice@example.com"),
        other => panic!("expected Success, got {other:?}"),
    }
    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

#[tokio::test]
async fn test_verify_otp_wrong_code_then_limit() {
    let service = service().await;
    let (result, code) = request(&service, "alice@example.com").await.unwrap();

    for expected in (1..=4).rev() {
        match service
            .verify_otp(&result.session_id, "00000000")
            .await
            .unwrap()
        {
            OtpVerifyResult::InvalidCode { remaining_attempts } => {
                assert_eq!(remaining_attempts, expected)
            }
            other => panic!("expected InvalidCode, got {other:?}"),
        }
    }
    assert!(matches!(
        service
            .verify_otp(&result.session_id, "00000000")
            .await
            .unwrap(),
        OtpVerifyResult::MaxAttempts
    ));
    // The session is gone: not even the right code works now.
    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

#[tokio::test]
async fn test_verify_otp_session_not_found() {
    assert!(matches!(
        service()
            .await
            .verify_otp(&Uuid::now_v7(), "12345678")
            .await
            .unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

/// Two replicas share one attempt count: guesses spread across them stop at
/// the limit, and a later right guess on the first replica is refused (each
/// replica once kept its own count, allowing five guesses per replica).
#[tokio::test]
async fn attempt_limit_holds_across_replicas() {
    let store = store().await;
    let (a, b) = (replica(&store), replica(&store));
    let (result, code) = request(&a, "x@example.com").await.unwrap();
    for _ in 0..4 {
        a.verify_otp(&result.session_id, "00000000").await.unwrap();
    }
    assert!(matches!(
        b.verify_otp(&result.session_id, "00000000").await.unwrap(),
        OtpVerifyResult::MaxAttempts
    ));
    assert!(
        !matches!(
            a.verify_otp(&result.session_id, &code).await.unwrap(),
            OtpVerifyResult::Success { .. }
        ),
        "a sixth guess was accepted after the limit"
    );
}

/// A code requested on one replica is verified on another.
#[tokio::test]
async fn code_verifies_on_another_replica() {
    let store = store().await;
    let (a, b) = (replica(&store), replica(&store));
    let (result, code) = request(&a, "y@example.com").await.unwrap();
    assert!(matches!(
        b.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::Success { .. }
    ));
}

/// Of concurrent verifications of the right code, exactly one signs in.
#[tokio::test]
async fn right_code_signs_in_once_under_concurrency() {
    let store = store().await;
    let (a, b) = (Arc::new(replica(&store)), Arc::new(replica(&store)));
    let (result, code) = request(&a, "z@example.com").await.unwrap();
    let (ra, rb) = tokio::join!(
        a.verify_otp(&result.session_id, &code),
        b.verify_otp(&result.session_id, &code)
    );
    let successes = [ra.unwrap(), rb.unwrap()]
        .iter()
        .filter(|r| matches!(r, OtpVerifyResult::Success { .. }))
        .count();
    assert_eq!(successes, 1);
}

/// Age `session_id`'s stored session past its expiry.
async fn expire(store: &Arc<SqliteBackend>, session_id: Uuid) {
    let key = session_id.to_string();
    let mut session: StoredOtpSession = serde_json::from_slice(
        &store
            .read_ceremony_state(SESSIONS, &key)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    session.expires_at = Utc::now() - chrono::Duration::seconds(1);
    store
        .put_ceremony_state(
            SESSIONS,
            &key,
            &serde_json::to_vec(&session).unwrap(),
            OTP_RETENTION,
        )
        .await
        .unwrap();
}

/// An expired code is reported as expired and ends its session.
#[tokio::test]
async fn expired_code_is_refused() {
    let store = store().await;
    let service = replica(&store);
    let (result, code) = request(&service, "old@example.com").await.unwrap();
    expire(&store, result.session_id).await;

    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::Expired
    ));
    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

/// Without the store nothing passes: requests and verifications are errors,
/// so neither the request limit nor the attempt limit can fail open.
#[tokio::test]
async fn unreachable_store_fails_closed() {
    let service = OtpService::new(
        Arc::new(crate::test_support::DownCeremonies),
        CodeDelivery {
            keys: crate::test_support::key_manager(),
        },
    );
    assert!(matches!(
        request(&service, "down@example.com").await,
        Err(OtpError::Internal(_))
    ));
    assert!(matches!(
        service.verify_otp(&Uuid::now_v7(), "12345678").await,
        Err(OtpError::Internal(_))
    ));
}

#[tokio::test]
async fn test_rate_limiting() {
    let service = service().await;
    let target = "ratelimit@example.com";
    for _ in 0..3 {
        assert!(request(&service, target).await.is_ok());
    }
    match request(&service, target).await {
        Err(OtpError::RateLimited { wait_seconds }) => {
            assert!(wait_seconds > 0);
            assert!(wait_seconds <= 900);
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

/// The request limit is shared too: requests spread over replicas count
/// together.
#[tokio::test]
async fn rate_limit_holds_across_replicas() {
    let store = store().await;
    let (a, b) = (replica(&store), replica(&store));
    let target = "spread@example.com";
    request(&a, target).await.unwrap();
    request(&b, target).await.unwrap();
    request(&a, target).await.unwrap();
    assert!(matches!(
        request(&b, target).await,
        Err(OtpError::RateLimited { .. })
    ));
}

#[tokio::test]
async fn test_different_targets_independent_rate_limits() {
    let service = service().await;
    for _ in 0..3 {
        assert!(request(&service, "a@example.com").await.is_ok());
    }
    assert!(request(&service, "b@example.com").await.is_ok());
}

/// A store that, while a verification counts its attempt (after it read the
/// session, before it ends it), resends the session's code through another
/// replica: the interleaving of a concurrent resend.
struct ResendDuringVerify {
    inner: Arc<SqliteBackend>,
    resend: tokio::sync::Mutex<Option<(OtpService, Uuid)>>,
    resent: tokio::sync::Mutex<Option<String>>,
}

#[async_trait::async_trait]
impl sid_plugin::SingleUseAdmissions for ResendDuringVerify {
    async fn admit_once(&self, n: &str, k: &str, ttl: Duration) -> sid_core::Result<bool> {
        self.inner.admit_once(n, k, ttl).await
    }
    async fn admit_for(&self, n: &str, k: &str, v: &[u8], ttl: Duration) -> sid_core::Result<bool> {
        self.inner.admit_for(n, k, v, ttl).await
    }
}

#[async_trait::async_trait]
impl CeremonyStateStore for ResendDuringVerify {
    async fn put_ceremony_state(
        &self,
        n: &str,
        k: &str,
        v: &[u8],
        ttl: Duration,
    ) -> sid_core::Result<()> {
        self.inner.put_ceremony_state(n, k, v, ttl).await
    }
    async fn take_ceremony_state(&self, n: &str, k: &str) -> sid_core::Result<Option<Vec<u8>>> {
        self.inner.take_ceremony_state(n, k).await
    }
    async fn read_ceremony_state(&self, n: &str, k: &str) -> sid_core::Result<Option<Vec<u8>>> {
        self.inner.read_ceremony_state(n, k).await
    }
    async fn replace_ceremony_state(
        &self,
        n: &str,
        k: &str,
        expected: &[u8],
        v: &[u8],
        ttl: Duration,
    ) -> sid_core::Result<bool> {
        self.inner
            .replace_ceremony_state(n, k, expected, v, ttl)
            .await
    }
    async fn put_ceremony_state_owing(
        &self,
        n: &str,
        k: &str,
        v: &[u8],
        ttl: Duration,
        owed: &NewWork,
    ) -> sid_core::Result<()> {
        self.inner
            .put_ceremony_state_owing(n, k, v, ttl, owed)
            .await
    }
    async fn replace_ceremony_state_owing(
        &self,
        n: &str,
        k: &str,
        expected: &[u8],
        v: &[u8],
        ttl: Duration,
        owed: &NewWork,
    ) -> sid_core::Result<bool> {
        self.inner
            .replace_ceremony_state_owing(n, k, expected, v, ttl, owed)
            .await
    }
    async fn count_in_window(&self, n: &str, k: &str, window: Duration) -> sid_core::Result<u64> {
        if n == ATTEMPTS
            && let Some((other, session)) = self.resend.lock().await.take()
        {
            let (_, code) = other.resend_otp(&session).await.unwrap().unwrap();
            *self.resent.lock().await = Some(code);
        }
        self.inner.count_in_window(n, k, window).await
    }
    async fn read_count(&self, n: &str, k: &str) -> sid_core::Result<u64> {
        self.inner.read_count(n, k).await
    }
    async fn clear_count(&self, n: &str, k: &str) -> sid_core::Result<()> {
        self.inner.clear_count(n, k).await
    }
    async fn purge_expired_ceremony_state(&self) -> sid_core::Result<u64> {
        self.inner.purge_expired_ceremony_state().await
    }
}

/// A code replaced by a resend while it was being verified does not sign
/// in, and the resent code still does. Verification once took whatever the
/// session held after checking the code it had read, so the replaced code
/// signed in and spent the new one.
#[tokio::test]
async fn code_replaced_during_its_verification_does_not_sign_in() {
    let inner = store().await;
    let racing = Arc::new(ResendDuringVerify {
        inner: inner.clone(),
        resend: tokio::sync::Mutex::new(None),
        resent: tokio::sync::Mutex::new(None),
    });
    let verifier = OtpService::new(
        racing.clone(),
        CodeDelivery {
            keys: crate::test_support::key_manager(),
        },
    );
    let (result, old) = request(&verifier, "race@example.com").await.unwrap();
    *racing.resend.lock().await = Some((replica(&inner), result.session_id));

    let outcome = verifier.verify_otp(&result.session_id, &old).await.unwrap();

    assert!(
        !matches!(outcome, OtpVerifyResult::Success { .. }),
        "the replaced code signed in: {outcome:?}"
    );
    let resent = racing.resent.lock().await.clone().expect("the resend ran");
    assert!(matches!(
        verifier
            .verify_otp(&result.session_id, &resent)
            .await
            .unwrap(),
        OtpVerifyResult::Success { .. }
    ));
}

// ── Delivery of the code ────────────────────────────────────────────────────

/// A requested code is owed one email naming its session and issue, which
/// expires with the code: neither the work nor the stored session holds the
/// code in the clear, and the mail's read gives the code and the mailbox
/// bound at the request.
#[tokio::test]
async fn requested_code_owes_its_email() {
    let store = store().await;
    let service = replica(&store);
    let (result, code) = request(&service, "mail@example.com").await.unwrap();

    let owed = owed_mails(&store).await;
    assert_eq!(owed.len(), 1, "one email is owed per requested code");
    assert_eq!(&owed[0].payload[..16], result.session_id.as_bytes());
    let stored = store
        .read_ceremony_state(SESSIONS, &result.session_id.to_string())
        .await
        .unwrap()
        .unwrap();
    for bytes in [&owed[0].payload, &stored] {
        assert!(
            !bytes.windows(code.len()).any(|w| w == code.as_bytes()),
            "the code is stored in the clear"
        );
    }
    let session: StoredOtpSession = serde_json::from_slice(&stored).unwrap();
    assert_eq!(owed[0].expires_at, Some(session.expires_at));

    let pending = service
        .pending_delivery(result.session_id, issue_of(&owed[0]), Utc::now())
        .await
        .unwrap()
        .expect("the code is waiting for its email");
    assert_eq!(pending.destination, "mail@example.com");
    assert_eq!(secrecy::ExposeSecret::expose_secret(&pending.code), code);
}

/// An address that routes to no account gets a session and a mail work like
/// any other, so neither tells the two apart, but the work sends nothing:
/// there is no mailbox to send it to.
#[tokio::test]
async fn code_for_no_account_sends_nothing() {
    let store = store().await;
    let service = replica(&store);
    let (result, _code) = service
        .request_otp("nobody@example.com", CodeDestination::None)
        .await
        .unwrap();

    let owed = owed_mails(&store).await;
    assert_eq!(owed.len(), 1, "an unknown address owes the same work");
    assert_eq!(owed[0].payload.len(), 32);
    assert!(
        service
            .pending_delivery(result.session_id, issue_of(&owed[0]), Utc::now())
            .await
            .unwrap()
            .is_none()
    );
}

/// A used or expired code has nothing left to send.
#[tokio::test]
async fn used_or_expired_code_sends_nothing() {
    let store = store().await;
    let service = replica(&store);
    let (used, code) = request(&service, "used@example.com").await.unwrap();
    let (old, _) = request(&service, "expired@example.com").await.unwrap();
    let owed = owed_mails(&store).await;
    let issue = |session: Uuid| {
        issue_of(
            owed.iter()
                .find(|w| w.payload[..16] == *session.as_bytes())
                .unwrap(),
        )
    };
    service.verify_otp(&used.session_id, &code).await.unwrap();
    expire(&store, old.session_id).await;

    for session in [used.session_id, old.session_id] {
        assert!(
            service
                .pending_delivery(session, issue(session), Utc::now())
                .await
                .unwrap()
                .is_none()
        );
    }
}

/// A resent code replaces the current one in the same session (the one the
/// client verifies against), to the same mailbox: the replaced code no
/// longer signs in and its email is superseded, the new one is owed its own
/// email, and the session keeps its attempt count. A resend once started a
/// new session the client never learned, so the resent code could not be
/// used.
#[tokio::test]
async fn resent_code_replaces_the_current_one() {
    let store = store().await;
    let service = replica(&store);
    let (result, first) = request(&service, "again@example.com").await.unwrap();
    let first_issue = issue_of(&owed_mails(&store).await[0]);
    service
        .verify_otp(&result.session_id, "00000000")
        .await
        .unwrap();

    let (resent, second) = service
        .resend_otp(&result.session_id)
        .await
        .unwrap()
        .expect("the session is live");

    assert_eq!(resent.session_id, result.session_id);
    let owed = owed_mails(&store).await;
    assert_eq!(owed.len(), 1, "the resent code is owed its email");
    let second_issue = issue_of(&owed[0]);
    assert_ne!(second_issue, first_issue);
    assert!(
        service
            .pending_delivery(result.session_id, first_issue, Utc::now())
            .await
            .unwrap()
            .is_none(),
        "the replaced code's email is superseded"
    );
    let pending = service
        .pending_delivery(result.session_id, second_issue, Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.destination, "again@example.com");
    if first != second {
        assert!(matches!(
            service
                .verify_otp(&result.session_id, &first)
                .await
                .unwrap(),
            OtpVerifyResult::InvalidCode {
                remaining_attempts: 3
            }
        ));
    }
    assert!(matches!(
        service
            .verify_otp(&result.session_id, &second)
            .await
            .unwrap(),
        OtpVerifyResult::Success { .. }
    ));
}

/// A resend counts as a request against its address's limit.
#[tokio::test]
async fn resend_counts_against_the_request_limit() {
    let service = service().await;
    let (result, _) = request(&service, "resend@example.com").await.unwrap();
    service.resend_otp(&result.session_id).await.unwrap();
    service.resend_otp(&result.session_id).await.unwrap();

    assert!(matches!(
        service.resend_otp(&result.session_id).await,
        Err(OtpError::RateLimited { .. })
    ));
}

/// A resend for a session that ended has nothing to replace.
#[tokio::test]
async fn resend_of_an_ended_session_is_none() {
    let service = service().await;
    assert!(service.resend_otp(&Uuid::now_v7()).await.unwrap().is_none());
}

/// A code sealed to another issue is never sent as this one: reading it
/// fails for good instead of yielding a code that is not its own.
#[tokio::test]
async fn code_sealed_to_another_issue_is_refused() {
    let store = store().await;
    let service = replica(&store);
    let (result, _) = request(&service, "foreign@example.com").await.unwrap();
    let issue = issue_of(&owed_mails(&store).await[0]);
    let key = result.session_id.to_string();
    let mut session: StoredOtpSession = serde_json::from_slice(
        &store
            .read_ceremony_state(SESSIONS, &key)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    session.sealed_code = crate::sealed_secret::seal(
        crate::test_support::key_manager().as_ref(),
        &sealing_context(result.session_id, Uuid::now_v7()),
        b"12345678",
    )
    .await
    .unwrap();
    store
        .put_ceremony_state(
            SESSIONS,
            &key,
            &serde_json::to_vec(&session).unwrap(),
            OTP_RETENTION,
        )
        .await
        .unwrap();

    assert!(matches!(
        service
            .pending_delivery(result.session_id, issue, Utc::now())
            .await,
        Err(OtpError::Sealed(_))
    ));
}
