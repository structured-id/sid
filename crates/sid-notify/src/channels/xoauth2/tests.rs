use super::*;
use sid_plugin::notification::NotificationPriority;

// ── FetchedToken / error display ─────────────────────────────────────────

#[test]
fn test_xoauth2_error_display() {
    let e = XOAuth2Error::SmtpBuild("bad host".into());
    assert!(e.to_string().contains("bad host"));

    let e = XOAuth2Error::InvalidServiceAccountKey("missing field".into());
    assert!(e.to_string().contains("missing field"));

    let e = XOAuth2Error::TokenEndpoint {
        error: "invalid_client".into(),
        description: "wrong secret".into(),
    };
    assert!(e.to_string().contains("invalid_client"));
    assert!(e.to_string().contains("wrong secret"));
}

// ── Stub provider for unit tests ──────────────────────────────────────────

#[derive(Debug)]
struct StubProvider {
    token: String,
    expires_in: u64,
    fail: bool,
}

#[async_trait]
impl XOAuth2TokenProvider for StubProvider {
    async fn fetch_token(&self) -> Result<FetchedToken, XOAuth2Error> {
        if self.fail {
            return Err(XOAuth2Error::TokenEndpoint {
                error: "invalid_client".into(),
                description: "stub failure".into(),
            });
        }
        Ok(FetchedToken {
            access_token: self.token.clone(),
            expires_in: self.expires_in,
        })
    }
}

fn test_smtp_config() -> XOAuth2SmtpConfig {
    XOAuth2SmtpConfig {
        host: "127.0.0.1".into(),
        port: 1, // unreachable — only used for transport-level tests
        tls_mode: SmtpTlsMode::None,
        user_email: "smtp@sid.example.com".into(),
        from_address: "noreply@sid.example.com".into(),
        from_name: "StructuredID".into(),
        pool_size: 1,
    }
}

fn test_message() -> RenderedMessage {
    RenderedMessage {
        subject: Some("Test".into()),
        body: "<p>Hello</p>".into(),
        body_text: Some("Hello".into()),
        priority: NotificationPriority::Transactional,
        event_type: "sid.test.v1".into(),
    }
}

// ── Channel construction ─────────────────────────────────────────────────

#[test]
fn test_channel_id() {
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(),
        Arc::new(StubProvider {
            token: "tok".into(),
            expires_in: 3600,
            fail: false,
        }),
    );
    assert_eq!(channel.channel_id(), "email");
}

// ── deliver: missing email → NotReachable ────────────────────────────────

#[tokio::test]
async fn test_deliver_no_email_not_reachable() {
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(),
        Arc::new(StubProvider {
            token: "tok".into(),
            expires_in: 3600,
            fail: false,
        }),
    );
    let recipient = Recipient {
        profile_id: "p".into(),
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

// ── deliver: invalid email → InvalidRecipient ────────────────────────────

#[tokio::test]
async fn test_deliver_invalid_email() {
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(),
        Arc::new(StubProvider {
            token: "tok".into(),
            expires_in: 3600,
            fail: false,
        }),
    );
    let recipient = Recipient {
        profile_id: "p".into(),
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

// ── deliver: token fetch fails → DeliveryError::Failed ──────────────────

#[tokio::test]
async fn test_deliver_token_failure_is_failed() {
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(),
        Arc::new(StubProvider {
            token: String::new(),
            expires_in: 3600,
            fail: true,
        }),
    );
    let recipient = Recipient {
        profile_id: "p".into(),
        email: Some("alice@sid.example.com".into()),
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    };
    let err = channel
        .deliver(&recipient, &test_message())
        .await
        .unwrap_err();
    assert!(matches!(err, DeliveryError::Failed(_)));
}

// ── health: token fetch fails → unhealthy ────────────────────────────────

#[tokio::test]
async fn test_health_token_failure_unhealthy() {
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(),
        Arc::new(StubProvider {
            token: String::new(),
            expires_in: 3600,
            fail: true,
        }),
    );
    let health = channel.health().await.unwrap();
    assert!(!health.healthy);
    assert!(health.message.unwrap().contains("token fetch failed"));
}

// ── health: unreachable SMTP server after token OK → unhealthy ───────────

#[tokio::test]
async fn test_health_unreachable_server_after_token_ok() {
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(), // port 1 = unreachable
        Arc::new(StubProvider {
            token: "valid-token".into(),
            expires_in: 3600,
            fail: false,
        }),
    );
    let health = channel.health().await.unwrap();
    // Transport builds fine (lazy connect), but test_connection probes — should fail.
    assert!(!health.healthy);
    assert!(health.message.is_some());
    assert!(health.last_success.is_none());
}

// ── token cache: second call does not re-fetch ───────────────────────────

#[derive(Debug)]
struct CountingProvider {
    count: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl XOAuth2TokenProvider for CountingProvider {
    async fn fetch_token(&self) -> Result<FetchedToken, XOAuth2Error> {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(FetchedToken {
            access_token: "cached-token".into(),
            expires_in: 3600,
        })
    }
}

#[tokio::test]
async fn test_token_cached_on_second_call() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(),
        Arc::new(CountingProvider {
            count: Arc::clone(&count),
        }),
    );

    // Two calls to get_transport — token should be fetched only once.
    let _ = channel.get_transport().await.unwrap();
    let _ = channel.get_transport().await.unwrap();

    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "token must be fetched only once when still valid"
    );
}

// ── token cache: expired token triggers re-fetch ─────────────────────────

#[tokio::test]
async fn test_expired_token_triggers_refresh() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let channel = XOAuth2SmtpChannel::new(
        test_smtp_config(),
        Arc::new(CountingProvider {
            count: Arc::clone(&count),
        }),
    );

    // Force-populate cache with an already-expired token (expires_at = past).
    {
        let mut guard = channel.state.lock().await;
        let transport = channel.build_transport("tok").unwrap();
        *guard = Some(CachedState {
            expires_at: Instant::now() - Duration::from_secs(1),
            transport: Arc::new(transport),
        });
    }

    let _ = channel.get_transport().await.unwrap();
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "expired token must trigger exactly one refresh"
    );
}

// ── channel_from_email_config: non-XOAUTH2 returns None ─────────────────

#[test]
fn test_channel_from_email_config_non_xoauth2_none() {
    use secrecy::SecretBox;
    use sid_core::models::{EmailProviderConfig, SmtpAuthMethod, SmtpEncryption};

    let cfg = EmailProviderConfig {
        smtp_host: "localhost".into(),
        smtp_port: 587,
        from_address: "a@sid.example.com".into(),
        from_display_name: "SID".into(),
        reply_to: String::new(),
        encryption: SmtpEncryption::Starttls,
        auth_type: SmtpAuthMethod::None,
        username: String::new(),
        password: SecretBox::new(Box::new(String::new())),
        xoauth2: None,
    };

    assert!(channel_from_email_config(&cfg).unwrap().is_none());
}

// ── Google service account key JSON parse error ───────────────────────────

#[tokio::test]
async fn test_google_invalid_key_json_error() {
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .unwrap();
    let provider = GoogleTokenProvider {
        user_email: "smtp@sid.example.com".into(),
        service_account_key: secrecy::SecretBox::new(Box::new("not valid json".into())),
        token_endpoint: None,
        http: sid_plugin::client_builder().unwrap().build().unwrap(),
    };
    let err = provider.fetch_token().await.unwrap_err();
    assert!(matches!(err, XOAuth2Error::InvalidServiceAccountKey(_)));
}
