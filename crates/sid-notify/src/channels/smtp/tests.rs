use super::*;
use sid_plugin::notification::NotificationPriority;

fn test_recipient() -> Recipient {
    Recipient {
        profile_id: "prof_123".into(),
        email: Some("alice@sid.example.com".into()),
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    }
}

fn test_message() -> RenderedMessage {
    RenderedMessage {
        subject: Some("Test Subject".into()),
        body: "<p>Test body</p>".into(),
        body_text: Some("Test body".into()),
        priority: NotificationPriority::Transactional,
        event_type: "sid.test.v1".into(),
    }
}

/// Config pointing to a port that will always refuse connections.
fn unreachable_config() -> SmtpConfig {
    SmtpConfig {
        host: "127.0.0.1".into(),
        port: 1, // port 1 is privileged and never in use
        tls_mode: SmtpTlsMode::None,
        ..SmtpConfig::default()
    }
}

// ── Construction tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_smtp_new_default_config_ok() {
    // Default config (None auth, StartTls to localhost:587) must build successfully.
    // lettre's pool spawns tokio tasks — requires tokio runtime.
    let result = SmtpChannel::new(SmtpConfig::default());
    assert!(
        result.is_ok(),
        "default SmtpConfig must build: {:?}",
        result
    );
}

#[test]
fn test_smtp_new_plain_auth_requires_username() {
    let config = SmtpConfig {
        auth_method: EmailAuthMethod::Plain,
        username: None,
        password: Some("secret".into()),
        ..SmtpConfig::default()
    };
    let err = SmtpChannel::new(config).unwrap_err();
    assert!(matches!(err, SmtpBuildError::MissingCredentials(_)));
    assert!(err.to_string().contains("username"));
}

#[test]
fn test_smtp_new_plain_auth_requires_password() {
    let config = SmtpConfig {
        auth_method: EmailAuthMethod::Plain,
        username: Some("user@sid.example.com".into()),
        password: None,
        ..SmtpConfig::default()
    };
    let err = SmtpChannel::new(config).unwrap_err();
    assert!(matches!(err, SmtpBuildError::MissingCredentials(_)));
    assert!(err.to_string().contains("password"));
}

#[test]
fn test_smtp_new_xoauth2_not_yet_implemented() {
    let config = SmtpConfig {
        auth_method: EmailAuthMethod::XOAuth2,
        ..SmtpConfig::default()
    };
    let err = SmtpChannel::new(config).unwrap_err();
    assert!(matches!(err, SmtpBuildError::XOAuth2NotYetImplemented));
}

#[tokio::test]
async fn test_smtp_new_plain_with_credentials_ok() {
    let config = SmtpConfig {
        auth_method: EmailAuthMethod::Plain,
        username: Some("user@sid.example.com".into()),
        password: Some("correct-horse-battery".into()),
        tls_mode: SmtpTlsMode::StartTls,
        ..SmtpConfig::default()
    };
    let result = SmtpChannel::new(config);
    assert!(
        result.is_ok(),
        "plain auth with credentials must build: {:?}",
        result
    );
}

// ── channel_id ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_smtp_channel_id() {
    let channel = SmtpChannel::new(SmtpConfig::default()).unwrap();
    assert_eq!(channel.channel_id(), "email");
}

// ── SmtpConfig default values ─────────────────────────────────────────────

#[test]
fn test_smtp_config_default() {
    let config = SmtpConfig::default();
    assert_eq!(config.port, 587);
    assert_eq!(config.tls_mode, SmtpTlsMode::StartTls);
    assert_eq!(config.auth_method, EmailAuthMethod::None);
    assert!(config.username.is_none());
    assert!(config.password.is_none());
    assert_eq!(config.pool_size, 5);
}

// ── deliver: pre-network error paths ─────────────────────────────────────

#[tokio::test]
async fn test_smtp_deliver_no_email() {
    let channel = SmtpChannel::new(SmtpConfig::default()).unwrap();
    let recipient = Recipient {
        profile_id: "prof_123".into(),
        email: None,
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    };

    let err = channel
        .deliver(&recipient, &test_message())
        .await
        .unwrap_err();
    assert!(matches!(err, DeliveryError::NotReachable));
}

#[tokio::test]
async fn test_smtp_deliver_invalid_email() {
    let channel = SmtpChannel::new(SmtpConfig::default()).unwrap();
    let recipient = Recipient {
        profile_id: "prof_123".into(),
        email: Some("not-an-email".into()),
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    };

    let err = channel
        .deliver(&recipient, &test_message())
        .await
        .unwrap_err();
    assert!(matches!(err, DeliveryError::InvalidRecipient(_)));
}

// ── deliver: connection failure ───────────────────────────────────────────

#[tokio::test]
async fn test_smtp_deliver_no_server_returns_failed() {
    let channel = SmtpChannel::new(unreachable_config()).unwrap();
    let result = channel.deliver(&test_recipient(), &test_message()).await;
    assert!(result.is_err(), "deliver to unreachable host must fail");
    assert!(
        matches!(result.unwrap_err(), DeliveryError::Failed(_)),
        "expected DeliveryError::Failed for connection error"
    );
}

// ── deliver: an actual SMTP conversation ─────────────────────────────────

/// What the scripted server answers to RCPT, and what it does once it has
/// received the message data.
#[derive(Clone, Copy)]
enum Script {
    /// RCPT answered with this reply line.
    Rcpt(&'static str),
    /// The message accepted with 250.
    Accept,
    /// The data received, then the connection closed without a reply.
    CloseAfterData,
    /// The data received, then the connection reset without a reply.
    ResetAfterData,
}

/// A one-connection SMTP server on a loopback port playing `script`
/// (RFC 5321 §4.3.2 reply sequence); its port.
async fn scripted_server(script: Script) -> u16 {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        // A zero linger turns the close into a reset (RST).
        if matches!(script, Script::ResetAfterData) {
            socket.set_zero_linger().unwrap();
        }
        let (read, mut write) = socket.into_split();
        let mut lines = BufReader::new(read).lines();
        write.write_all(b"220 test ESMTP\r\n").await.unwrap();
        let mut in_data = false;
        while let Ok(Some(line)) = lines.next_line().await {
            if in_data {
                if line == "." {
                    match script {
                        Script::CloseAfterData | Script::ResetAfterData => return,
                        _ => write.write_all(b"250 2.0.0 queued\r\n").await.unwrap(),
                    }
                    in_data = false;
                }
                continue;
            }
            let verb = line.get(..4).unwrap_or("").to_ascii_uppercase();
            let reply: &str = match verb.as_str() {
                "EHLO" | "HELO" => "250 test\r\n",
                "MAIL" => "250 2.1.0 ok\r\n",
                "RCPT" => match script {
                    Script::Rcpt(reply) => reply,
                    _ => "250 2.1.5 ok\r\n",
                },
                "DATA" => {
                    in_data = true;
                    "354 go ahead\r\n"
                }
                "QUIT" => {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    return;
                }
                _ => "250 ok\r\n",
            };
            write.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    port
}

/// A channel delivering to the scripted server on `port`.
fn channel_to(port: u16) -> SmtpChannel {
    SmtpChannel::new(SmtpConfig {
        host: "127.0.0.1".into(),
        port,
        tls_mode: SmtpTlsMode::None,
        pool_size: 1,
        ..SmtpConfig::default()
    })
    .unwrap()
}

/// The server's reply decides the outcome (RFC 5321 §4.2.1): a 5xx refusal
/// is final, a 4xx refusal is transient, an accepted message is delivered.
#[tokio::test]
async fn test_smtp_reply_codes_decide_the_outcome() {
    let rejected = channel_to(scripted_server(Script::Rcpt("550 5.1.1 no such user\r\n")).await)
        .deliver(&test_recipient(), &test_message())
        .await;
    assert!(
        matches!(rejected, Err(DeliveryError::Rejected(_))),
        "{rejected:?}"
    );
    let busy = channel_to(scripted_server(Script::Rcpt("451 4.3.0 try later\r\n")).await)
        .deliver(&test_recipient(), &test_message())
        .await;
    assert!(matches!(busy, Err(DeliveryError::Failed(_))), "{busy:?}");
    let accepted = channel_to(scripted_server(Script::Accept).await)
        .deliver(&test_recipient(), &test_message())
        .await;
    assert!(accepted.is_ok(), "{accepted:?}");
}

/// Regression: a connection lost after the message data was sent, before
/// the server's reply, was reported as an ordinary transient failure,
/// although the server may already have accepted the message. Its outcome
/// is unknown, and is recorded as such.
#[tokio::test]
async fn test_smtp_connection_lost_after_data_is_ambiguous() {
    for script in [Script::CloseAfterData, Script::ResetAfterData] {
        let lost = channel_to(scripted_server(script).await)
            .deliver(&test_recipient(), &test_message())
            .await;
        assert!(matches!(lost, Err(DeliveryError::Ambiguous(_))), "{lost:?}");
    }
}

/// Captures everything logged while it is the default subscriber.
#[derive(Clone, Default)]
pub(crate) struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLog {
    /// Log at debug level into this capture while the guard lives.
    pub(crate) fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(move || writer.clone())
                .finish(),
        )
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// A subject can carry a sign-in code (the otp template puts it there),
/// so sending logs no subject at any level: a log reader never sees the
/// code. Sending once logged the whole subject at debug level.
#[tokio::test]
async fn test_smtp_deliver_logs_no_subject() {
    let log = CapturedLog::default();
    let _guard = log.install();
    let channel = SmtpChannel::new(unreachable_config()).unwrap();
    let message = RenderedMessage {
        subject: Some("Your code: 31415926".into()),
        ..test_message()
    };

    let _ = channel.deliver(&test_recipient(), &message).await;

    let text = log.text();
    assert!(text.contains("sending email via SMTP"), "{text}");
    assert!(!text.contains("31415926"), "the code was logged: {text}");
}

// ── health: unreachable server ────────────────────────────────────────────

#[tokio::test]
async fn test_smtp_health_unreachable_returns_unhealthy() {
    let channel = SmtpChannel::new(unreachable_config()).unwrap();
    let health = channel.health().await.unwrap();
    assert!(
        !health.healthy,
        "health must be false for unreachable server"
    );
    assert!(health.message.is_some());
    assert!(health.last_success.is_none());
}

// ── build_message ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_build_message_multipart() {
    let channel = SmtpChannel::new(SmtpConfig::default()).unwrap();
    let msg = RenderedMessage {
        subject: Some("Hello".into()),
        body: "<p>HTML body</p>".into(),
        body_text: Some("Plain body".into()),
        priority: NotificationPriority::Transactional,
        event_type: "sid.test.v1".into(),
    };
    let result = channel.build_message("bob@sid.example.com", &msg, "test-id-123");
    assert!(result.is_ok(), "multipart message must build: {:?}", result);
}

#[tokio::test]
async fn test_build_message_html_only() {
    let channel = SmtpChannel::new(SmtpConfig::default()).unwrap();
    let msg = RenderedMessage {
        subject: Some("Hello".into()),
        body: "<p>HTML only</p>".into(),
        body_text: None,
        priority: NotificationPriority::Transactional,
        event_type: "sid.test.v1".into(),
    };
    let result = channel.build_message("bob@sid.example.com", &msg, "test-id-456");
    assert!(result.is_ok(), "HTML-only message must build: {:?}", result);
}

#[tokio::test]
async fn test_build_message_invalid_recipient_address() {
    let channel = SmtpChannel::new(SmtpConfig::default()).unwrap();
    let msg = test_message();
    // "no-at-sign" will fail lettre's Mailbox parse.
    let result = channel.build_message("not-an-email", &msg, "test-id");
    assert!(matches!(result, Err(SmtpBuildError::InvalidAddress(_))));
}

// ── SmtpBuildError display ────────────────────────────────────────────────

#[test]
fn test_smtp_build_error_display() {
    let e = SmtpBuildError::MissingCredentials("username".into());
    assert!(e.to_string().contains("username"));

    let e = SmtpBuildError::XOAuth2NotYetImplemented;
    assert!(e.to_string().contains("XOAuth2SmtpChannel"));

    let e = SmtpBuildError::InvalidAddress("bad addr".into());
    assert!(e.to_string().contains("bad addr"));
}
