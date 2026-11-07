use super::*;
use sid_authn::otp::{CodeDelivery, CodeDestination};
use sid_plugin::{StorageBackend, WorkStore};

/// What the host's delivery answers.
enum Answer {
    Sent,
    Unavailable,
    Unrenderable,
}

/// Records every mail the host is asked to send.
struct Recorded {
    answer: Answer,
    sent: std::sync::Mutex<Vec<(AuthMessage, String, String, i64)>>,
}

impl Recorded {
    fn answering(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer,
            sent: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<(AuthMessage, String, String, i64)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl AuthMailDelivery for Recorded {
    async fn deliver(&self, mail: &OwedMail) -> Result<String, MailError> {
        match self.answer {
            Answer::Unavailable => {
                return Err(MailError::Unavailable(
                    "no email provider is configured".into(),
                ));
            }
            Answer::Unrenderable => return Err(MailError::Render("no such template".into())),
            Answer::Sent => {}
        }
        self.sent.lock().unwrap().push((
            mail.message,
            mail.destination.clone(),
            mail.secret.expose_secret().to_owned(),
            mail.expires_minutes,
        ));
        Ok(uuid::Uuid::now_v7().to_string())
    }
}

fn keys() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

/// Codes over one in-memory installation, and the store holding their work.
async fn codes() -> (Arc<OtpService>, Arc<sid_storage::sqlite::SqliteBackend>) {
    let store = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let codes = Arc::new(OtpService::new(
        store.clone(),
        CodeDelivery {
            keys: keys(),
            work: store.clone(),
            capacity: 100,
        },
    ));
    (codes, store)
}

/// The mails of `kind` `store` owes now, claimed.
async fn owed(store: &sid_storage::sqlite::SqliteBackend, kind: &str) -> Vec<ClaimedWork> {
    store
        .claim_work(
            &[WorkKind::new(kind).unwrap()],
            "test",
            10,
            std::time::Duration::from_secs(60),
        )
        .await
        .unwrap()
}

/// The code mail goes to the mailbox bound at the request with the code,
/// the same on every attempt.
#[tokio::test]
async fn code_mail_sends_the_bound_code() {
    let (codes, store) = codes().await;
    let (_, code) = codes
        .request_otp(
            "key@sid.example.com",
            CodeDestination::Email("Key@sid.example.com"),
        )
        .await
        .unwrap();
    let work = owed(&store, OTP_EMAIL_KIND).await.remove(0);
    let recorded = Recorded::answering(Answer::Sent);
    let mail = CodeMail::new(codes, recorded.clone());

    for _ in 0..2 {
        let outcome = mail.handle(&work).await;
        assert!(matches!(outcome, WorkOutcome::Done(Some(_))), "{outcome:?}");
    }

    let sent = recorded.sent();
    assert_eq!(sent.len(), 2);
    for (message, to, secret, minutes) in sent {
        assert_eq!(message, AuthMessage::SignInCode);
        assert_eq!(to, "Key@sid.example.com");
        assert_eq!(secret, code);
        assert!(minutes >= 1);
    }
}

/// The mail of a replaced code sends nothing; the replacement's own mail
/// sends the new code.
#[tokio::test]
async fn replaced_code_mail_sends_nothing() {
    let (codes, store) = codes().await;
    let (pending, _) = codes
        .request_otp(
            "r@sid.example.com",
            CodeDestination::Email("r@sid.example.com"),
        )
        .await
        .unwrap();
    let first = owed(&store, OTP_EMAIL_KIND).await.remove(0);
    let (_, resent) = codes
        .resend_otp(&pending.session_id)
        .await
        .unwrap()
        .unwrap();
    let second = owed(&store, OTP_EMAIL_KIND).await.remove(0);
    let recorded = Recorded::answering(Answer::Sent);
    let mail = CodeMail::new(codes, recorded.clone());

    assert!(matches!(mail.handle(&first).await, WorkOutcome::Done(_)));
    assert!(recorded.sent().is_empty());
    assert!(matches!(
        mail.handle(&second).await,
        WorkOutcome::Done(Some(_))
    ));
    assert_eq!(recorded.sent()[0].2, resent);
}

/// Without a usable email provider the code's mail is tried again; a mail
/// the host cannot render fails for good.
#[tokio::test]
async fn code_mail_waits_for_a_provider_and_gives_up_on_rendering() {
    let (codes, store) = codes().await;
    codes
        .request_otp(
            "w@sid.example.com",
            CodeDestination::Email("w@sid.example.com"),
        )
        .await
        .unwrap();
    let work = owed(&store, OTP_EMAIL_KIND).await.remove(0);

    let waiting = CodeMail::new(codes.clone(), Recorded::answering(Answer::Unavailable));
    assert!(matches!(waiting.handle(&work).await, WorkOutcome::Retry(_)));
    let unrenderable = CodeMail::new(codes, Recorded::answering(Answer::Unrenderable));
    assert!(matches!(
        unrenderable.handle(&work).await,
        WorkOutcome::Permanent(_)
    ));
}

/// Ended mail records go after their retention; open mails and recent
/// records stay, and other kinds of work are untouched.
#[tokio::test]
async fn ended_mail_records_are_dropped_after_retention() {
    let (codes, store) = codes().await;
    codes
        .request_otp(
            "p@sid.example.com",
            CodeDestination::Email("p@sid.example.com"),
        )
        .await
        .unwrap();
    let ended = owed(&store, OTP_EMAIL_KIND).await.remove(0);
    store
        .complete_work(ended.id, ended.generation, None)
        .await
        .unwrap();
    codes
        .request_otp(
            "q@sid.example.com",
            CodeDestination::Email("q@sid.example.com"),
        )
        .await
        .unwrap();
    let other = NewWork::new(WorkKind::new("test.other").unwrap(), vec![]);
    store.enqueue_work(&other, 10).await.unwrap();

    assert_eq!(
        purge_ended_mail(store.as_ref(), Utc::now()).await.unwrap(),
        0
    );
    let later = Utc::now() + MAIL_RECORD_RETENTION + chrono::Duration::minutes(1);
    assert_eq!(purge_ended_mail(store.as_ref(), later).await.unwrap(), 1);

    assert!(store.get_work(ended.id).await.unwrap().is_none());
    assert_eq!(
        owed(&store, OTP_EMAIL_KIND).await.len(),
        1,
        "an open mail was dropped"
    );
    assert!(store.get_work(other.id).await.unwrap().is_some());
}

/// Work that does not name a code fails for good.
#[tokio::test]
async fn code_mail_refuses_malformed_work() {
    let (codes, _) = codes().await;
    let mail = CodeMail::new(codes, Recorded::answering(Answer::Sent));
    let work = ClaimedWork {
        id: sid_core::models::WorkId::new(),
        kind: WorkKind::new(OTP_EMAIL_KIND).unwrap(),
        payload: vec![1, 2, 3],
        attempt: 1,
        max_attempts: 8,
        generation: 1,
        expires_at: None,
    };

    assert!(matches!(
        mail.handle(&work).await,
        WorkOutcome::Permanent(_)
    ));
}

/// Resets over one in-memory installation with an account to reset, and
/// the store holding their work.
async fn resets() -> (
    Arc<PasswordResetService>,
    Arc<sid_storage::sqlite::SqliteBackend>,
    sid_core::models::ProfileId,
) {
    let store = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let profile = sid_core::models::Profile::new(Some("reset"));
    store
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("test", "profile").into(),
        )
        .await
        .unwrap();
    let resets = Arc::new(PasswordResetService::new(store.clone(), keys()));
    (resets, store, profile.id)
}

fn reset_page() -> url::Url {
    url::Url::parse("https://id.sid.example.com/account/reset/new").unwrap()
}

/// The token a reset link carries, on the configured page.
fn link_token(link: &str) -> String {
    let link = url::Url::parse(link).unwrap();
    assert_eq!(link.path(), "/account/reset/new");
    link.query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .into_owned()
}

/// A requested reset owes one mail whose work names only its session; the
/// mail goes to the mailbox bound at the request with a link that verifies
/// against the stored hash, the same link on every attempt.
#[tokio::test]
async fn reset_mail_sends_the_bound_link() {
    let (resets, store, profile) = resets().await;
    let session = resets
        .request(profile, "key@sid.example.com", "Key@sid.example.com")
        .await
        .unwrap();
    let work = owed(&store, PASSWORD_RESET_EMAIL_KIND).await.remove(0);
    assert_eq!(work.payload, session.0.as_bytes().to_vec());
    let recorded = Recorded::answering(Answer::Sent);
    let mail = ResetMail::new(resets, reset_page(), recorded.clone());

    for _ in 0..2 {
        let outcome = mail.handle(&work).await;
        assert!(matches!(outcome, WorkOutcome::Done(Some(_))), "{outcome:?}");
    }

    let stored = store.get_reset_session(session).await.unwrap().unwrap();
    let sent = recorded.sent();
    assert_eq!(sent.len(), 2);
    let tokens: Vec<String> = sent
        .iter()
        .map(|(_, _, link, _)| link_token(link))
        .collect();
    for (message, to, _, _) in &sent {
        assert_eq!(*message, AuthMessage::PasswordReset);
        assert_eq!(to, "Key@sid.example.com");
    }
    assert_eq!(tokens[0], tokens[1], "a retry sent another link");
    assert_eq!(
        sid_authn::password_reset::token_hash(&tokens[0]),
        stored.token_hash
    );
}

/// A verified reset's mail sends nothing: the link was already used.
#[tokio::test]
async fn verified_reset_mail_sends_nothing() {
    let (resets, store, profile) = resets().await;
    let session = resets
        .request(profile, "v@sid.example.com", "v@sid.example.com")
        .await
        .unwrap();
    let work = owed(&store, PASSWORD_RESET_EMAIL_KIND).await.remove(0);
    assert!(
        store
            .verify_reset_session(
                session,
                sid_core::models::AuditEntry::system("test", "verify").into()
            )
            .await
            .unwrap()
    );
    let recorded = Recorded::answering(Answer::Sent);
    let mail = ResetMail::new(resets, reset_page(), recorded.clone());

    assert!(matches!(mail.handle(&work).await, WorkOutcome::Done(_)));
    assert!(recorded.sent().is_empty());
}

/// An expired reset's link is never mailed.
#[tokio::test]
async fn expired_reset_is_not_delivered() {
    let (resets, store, profile) = resets().await;
    let session = resets
        .request(profile, "e@sid.example.com", "e@sid.example.com")
        .await
        .unwrap();
    let expires_at = store
        .get_reset_session(session)
        .await
        .unwrap()
        .unwrap()
        .expires_at;

    assert!(
        resets
            .pending_delivery(session, expires_at)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        resets
            .pending_delivery(session, expires_at - chrono::Duration::seconds(1))
            .await
            .unwrap()
            .is_some()
    );
}

/// The link names its session and carries the token as query parameters of
/// the configured page, keeping the page's own path.
#[test]
fn link_carries_session_and_token_on_the_page() {
    let page = url::Url::parse("https://id.sid.example.com/account/verify").unwrap();
    let id = uuid::Uuid::now_v7();
    let link = link(&page, id, "t+/=");

    assert_eq!(link.path(), "/account/verify");
    let query: std::collections::HashMap<_, _> = link.query_pairs().into_owned().collect();
    assert_eq!(query["session"], id.to_string());
    assert_eq!(query["token"], "t+/=");
}

/// A refusal is final, an unknown result is ambiguous, a transport failure
/// is tried again.
#[test]
fn delivery_errors_map_to_their_outcomes() {
    assert!(matches!(
        outcome_of(DeliveryError::Rejected("550".into())),
        WorkOutcome::Permanent(_)
    ));
    assert!(matches!(
        outcome_of(DeliveryError::InvalidRecipient("x".into())),
        WorkOutcome::Permanent(_)
    ));
    assert!(matches!(
        outcome_of(DeliveryError::Ambiguous("timeout".into())),
        WorkOutcome::Ambiguous(_)
    ));
    assert!(matches!(
        outcome_of(DeliveryError::Failed("refused".into())),
        WorkOutcome::Retry(_)
    ));
}
