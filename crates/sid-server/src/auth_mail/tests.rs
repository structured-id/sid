// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sid_authn::otp::{CodeDelivery, CodeDestination};
use sid_plugin::WorkStore;
use sid_plugin::notification::{ChannelHealth, DeliveryReceipt, RenderedMessage};

/// Records every mail instead of sending it.
#[derive(Default)]
struct Recorded {
    sent: std::sync::Mutex<Vec<(String, RenderedMessage)>>,
}

#[async_trait]
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
            timestamp: Utc::now(),
            provider: "recorded".into(),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        unreachable!("the mail handler never probes its channel")
    }
}

/// `None` stands for an installation with no usable email provider.
struct Transport(Option<Arc<Recorded>>);

#[async_trait]
impl MailTransport for Transport {
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String> {
        match &self.0 {
            Some(recorded) => Ok(recorded.clone()),
            None => Err("no email provider is configured".into()),
        }
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

/// The code mails `store` owes now, claimed.
async fn owed(store: &sid_storage::sqlite::SqliteBackend) -> Vec<ClaimedWork> {
    store
        .claim_work(
            &[WorkKind::new(OTP_EMAIL_KIND).unwrap()],
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
    let work = owed(&store).await.remove(0);
    let recorded = Arc::new(Recorded::default());
    let mail = CodeMail::new(codes, Arc::new(Transport(Some(recorded.clone()))));

    for _ in 0..2 {
        let outcome = mail.handle(&work).await;
        assert!(matches!(outcome, WorkOutcome::Done(Some(_))), "{outcome:?}");
    }

    let sent = recorded.sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    for (to, message) in sent.iter() {
        assert_eq!(to, "Key@sid.example.com");
        assert!(message.body.contains(&code), "{}", message.body);
        assert!(message.subject.as_deref().unwrap().contains(&code));
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
    let first = owed(&store).await.remove(0);
    let (_, resent) = codes
        .resend_otp(&pending.session_id)
        .await
        .unwrap()
        .unwrap();
    let second = owed(&store).await.remove(0);
    let recorded = Arc::new(Recorded::default());
    let mail = CodeMail::new(codes, Arc::new(Transport(Some(recorded.clone()))));

    assert!(matches!(mail.handle(&first).await, WorkOutcome::Done(_)));
    assert!(recorded.sent.lock().unwrap().is_empty());
    assert!(matches!(
        mail.handle(&second).await,
        WorkOutcome::Done(Some(_))
    ));
    assert!(recorded.sent.lock().unwrap()[0].1.body.contains(&resent));
}

/// Without a usable email provider the code's mail is tried again.
#[tokio::test]
async fn code_mail_waits_for_a_provider() {
    let (codes, store) = codes().await;
    codes
        .request_otp(
            "w@sid.example.com",
            CodeDestination::Email("w@sid.example.com"),
        )
        .await
        .unwrap();
    let work = owed(&store).await.remove(0);
    let mail = CodeMail::new(codes, Arc::new(Transport(None)));

    assert!(matches!(mail.handle(&work).await, WorkOutcome::Retry(_)));
}

/// Work that does not name a code fails for good.
#[tokio::test]
async fn code_mail_refuses_malformed_work() {
    let (codes, _) = codes().await;
    let mail = CodeMail::new(codes, Arc::new(Transport(None)));
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
