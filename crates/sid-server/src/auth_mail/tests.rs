// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use chrono::Utc;
use secrecy::SecretString;
use sid_plugin::notification::{ChannelHealth, DeliveryError, DeliveryReceipt, RenderedMessage};

/// Records every mail instead of sending it, or refuses each.
#[derive(Default)]
struct Recorded {
    refuse: Option<&'static str>,
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
        if let Some(reason) = self.refuse {
            return Err(DeliveryError::Rejected(reason.into()));
        }
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
        unreachable!("the mail delivery never probes its channel")
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

fn mail(message: AuthMessage, secret: &str) -> OwedMail {
    OwedMail {
        message,
        destination: "Key@sid.example.com".into(),
        secret: SecretString::from(secret.to_owned()),
        expires_minutes: 10,
    }
}

/// Each authentication message renders its secret into the mail sent to
/// the bound mailbox: the code also into its subject, a link into its body.
#[tokio::test]
async fn each_message_renders_its_secret() {
    let recorded = Arc::new(Recorded::default());
    let delivery = TemplatedMail::new(Arc::new(Transport(Some(recorded.clone()))));
    let link = "https://id.sid.example.com/account/verify?session=s&token=t";
    for (message, secret) in [
        (AuthMessage::SignInCode, "123456"),
        (AuthMessage::MagicLink, link),
        (AuthMessage::PasswordReset, link),
    ] {
        delivery.deliver(&mail(message, secret)).await.unwrap();
    }

    let sent = recorded.sent.lock().unwrap();
    assert_eq!(sent.len(), 3);
    for (to, _) in sent.iter() {
        assert_eq!(to, "Key@sid.example.com");
    }
    assert!(sent[0].1.body.contains("123456"), "{}", sent[0].1.body);
    assert!(sent[0].1.subject.as_deref().unwrap().contains("123456"));
    assert!(sent[1].1.body.contains(link), "{}", sent[1].1.body);
    assert!(sent[2].1.body.contains(link), "{}", sent[2].1.body);
}

/// Without a usable email provider the mail is unavailable, not failed; a
/// provider's refusal is passed on for the engine to settle.
#[tokio::test]
async fn provider_answers_are_passed_on() {
    let waiting = TemplatedMail::new(Arc::new(Transport(None)));
    assert!(matches!(
        waiting.deliver(&mail(AuthMessage::SignInCode, "1")).await,
        Err(MailError::Unavailable(_))
    ));
    let refusing = TemplatedMail::new(Arc::new(Transport(Some(Arc::new(Recorded {
        refuse: Some("550"),
        ..Recorded::default()
    })))));
    assert!(matches!(
        refusing.deliver(&mail(AuthMessage::SignInCode, "1")).await,
        Err(MailError::Delivery(DeliveryError::Rejected(_)))
    ));
}
