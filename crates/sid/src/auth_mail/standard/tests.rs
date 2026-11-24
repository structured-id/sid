// SPDX-License-Identifier: AGPL-3.0-only
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use secrecy::SecretString;
use sid_authn::work_runner::WorkOutcome;
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, NotificationPriority,
    Recipient, RenderedMessage,
};

use super::super::{AuthMessage, OwedMail, send};
use super::{MailTransport, StandardMail, render};

/// What the host's channel answers to a send.
#[derive(Clone, Copy)]
enum Answer {
    Accepted,
    Rejected,
    Ambiguous,
    RateLimited,
}

/// A host channel that records what it was handed.
struct Channel {
    answer: Answer,
    sent: Mutex<Vec<(Recipient, RenderedMessage)>>,
}

impl Channel {
    fn answering(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer,
            sent: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl NotificationChannel for Channel {
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
            .push((recipient.clone(), message.clone()));
        match self.answer {
            Answer::Accepted => Ok(DeliveryReceipt {
                message_id: "host-message-1".into(),
                channel: "email".into(),
                timestamp: jiff::Timestamp::now(),
                provider: "host".into(),
            }),
            Answer::Rejected => Err(DeliveryError::Rejected("mailbox refused".into())),
            Answer::Ambiguous => Err(DeliveryError::Ambiguous("reply lost".into())),
            Answer::RateLimited => Err(DeliveryError::RateLimited),
        }
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        Ok(ChannelHealth {
            healthy: true,
            message: None,
            last_success: None,
        })
    }
}

fn owed(message: AuthMessage, secret: &str) -> OwedMail {
    OwedMail {
        message,
        destination: "owner@sid.example.com".into(),
        secret: SecretString::from(secret.to_owned()),
        expires_minutes: 9,
    }
}

/// A sign-in code reaches the host's channel as the standard message, to the
/// mailbox bound at the request, and the work records the host's message id.
/// Bug prevented: an embedding host sending a mail without the code, to
/// another address, or as anything but transactional mail.
#[tokio::test]
async fn a_code_goes_out_on_the_hosts_channel() {
    let channel = Channel::answering(Answer::Accepted);
    let mail = StandardMail::over(channel.clone());
    let outcome = send(&mail, owed(AuthMessage::SignInCode, "482913")).await;
    assert!(matches!(outcome, WorkOutcome::Done(Some(ref id)) if id == "host-message-1"));
    let sent = channel.sent.lock().unwrap();
    let [(recipient, message)] = sent.as_slice() else {
        panic!("one mail was owed, {} sent", sent.len());
    };
    assert_eq!(recipient.email.as_deref(), Some("owner@sid.example.com"));
    assert_eq!(message.subject.as_deref(), Some("Your code: 482913"));
    assert!(message.body.contains("<strong>482913</strong>"));
    assert!(message.body.contains("Use this code to sign in:"));
    assert!(
        message
            .body_text
            .as_deref()
            .unwrap()
            .contains("expires in 9 minutes")
    );
    assert_eq!(message.priority, NotificationPriority::Transactional);
}

/// The host's answer settles the work as the server's mail does: a refusal
/// ends it, an unknown result is ambiguous, a rate limit is tried again.
/// Bug prevented: an embedding host resending a refused mail forever, or
/// sending a code twice after a lost reply as if it had failed.
#[tokio::test]
async fn the_hosts_answer_settles_the_work_like_the_servers() {
    for (answer, expected) in [
        (Answer::Rejected, "permanent"),
        (Answer::Ambiguous, "ambiguous"),
        (Answer::RateLimited, "retry"),
    ] {
        let mail = StandardMail::over(Channel::answering(answer));
        let outcome = send(&mail, owed(AuthMessage::SignInCode, "482913")).await;
        let got = match outcome {
            WorkOutcome::Permanent(_) => "permanent",
            WorkOutcome::Ambiguous(_) => "ambiguous",
            WorkOutcome::Retry(_) => "retry",
            WorkOutcome::Done(_) | WorkOutcome::DoneWith { .. } => "done",
        };
        assert_eq!(got, expected);
    }
}

/// No channel now keeps the mail waiting for one.
/// Bug prevented: a mail owed while the host's provider is down being
/// dropped instead of sent when it is back.
#[tokio::test]
async fn no_channel_now_keeps_the_mail_waiting() {
    struct Absent;
    #[async_trait]
    impl MailTransport for Absent {
        async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String> {
            Err("no email provider is configured".into())
        }
    }
    let mail = StandardMail::new(Arc::new(Absent));
    let outcome = send(
        &mail,
        owed(AuthMessage::PasswordReset, "https://sid.example.com/r"),
    )
    .await;
    assert!(matches!(outcome, WorkOutcome::Retry(ref why) if why.contains("no email provider")));
}

/// A link is placed in the message whole and as a valid HTML attribute: the
/// query's `&` is escaped in the HTML part and left as is in the text part.
/// Bug prevented: a mail client reading `&token` as a character reference
/// and opening a link without its token.
#[test]
fn a_link_survives_both_parts() {
    let link = "https://sid.example.com/reset?session=1&token=a\"b";
    for message in [AuthMessage::MagicLink, AuthMessage::PasswordReset] {
        let rendered = render(&owed(message, link));
        assert!(
            rendered
                .body
                .contains("href=\"https://sid.example.com/reset?session=1&amp;token=a&quot;b\"")
        );
        assert!(rendered.body_text.as_deref().unwrap().contains(link));
    }
}

/// A registration code names what it confirms.
/// Bug prevented: a new account's owner reading a sign-in mail and not
/// knowing the code finishes the registration.
#[test]
fn a_registration_code_names_its_purpose() {
    let rendered = render(&owed(AuthMessage::RegistrationCode, "120034"));
    assert!(
        rendered
            .body
            .contains("confirm your email address and finish creating your account")
    );
    assert!(!rendered.body.contains("sign in"), "{}", rendered.body);
}
