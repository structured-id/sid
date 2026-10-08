// SPDX-License-Identifier: AGPL-3.0-only
//! SMTP email channel backed by lettre async transport.
//!
//! Supports PLAIN/LOGIN auth for standard SMTP (port 587 STARTTLS, port 465 TLS)
//! and open relay (no TLS, no auth) for development.
//!
//! XOAUTH2 for Microsoft 365 / Google Workspace is served by `XOAuth2SmtpChannel`
//! (`XOAuth2TokenProvider`). Configuring `auth_method: XOAuth2` in this struct
//! returns [`SmtpBuildError::XOAuth2NotYetImplemented`] at construction time.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::{
        PoolConfig,
        authentication::{Credentials, Mechanism},
    },
};
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};

/// TLS mode for SMTP connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpTlsMode {
    /// Implicit TLS — connects on port 465. Transport is encrypted from the first byte.
    Tls,
    /// STARTTLS — connects plaintext on port 587 and negotiates TLS upgrade.
    StartTls,
    /// No TLS — plaintext throughout. For internal relay or dev-only. Forbidden in production.
    None,
}

/// Authentication method for SMTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailAuthMethod {
    /// SMTP PLAIN or LOGIN with username + password credentials.
    Plain,
    /// OAuth2 bearer token via XOAUTH2 SASL mechanism.
    /// Served by `XOAuth2SmtpChannel`; this channel refuses it at construction.
    XOAuth2,
    /// No authentication — open relay (dev or internal only).
    None,
}

/// SMTP email configuration.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port. Canonical defaults: 587 (StartTls), 465 (Tls), 25 (None).
    pub port: u16,
    /// Sender email address.
    pub from_address: String,
    /// Sender display name shown in email clients.
    pub from_name: String,
    /// TLS mode for the connection.
    pub tls_mode: SmtpTlsMode,
    /// Authentication method.
    pub auth_method: EmailAuthMethod,
    /// SMTP username. Required when `auth_method` is `Plain`.
    pub username: Option<String>,
    /// SMTP password. Required when `auth_method` is `Plain`.
    pub password: Option<String>,
    /// Maximum connections in the lettre connection pool.
    pub pool_size: u32,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 587,
            from_address: "noreply@sid.example.com".into(),
            from_name: "StructuredID".into(),
            tls_mode: SmtpTlsMode::StartTls,
            auth_method: EmailAuthMethod::None,
            username: None,
            password: None,
            pool_size: 5,
        }
    }
}

/// Errors during SMTP transport construction.
#[derive(Debug, thiserror::Error)]
pub enum SmtpBuildError {
    #[error("invalid SMTP configuration: {0}")]
    InvalidConfig(String),

    #[error("missing credential field for Plain auth: {0}")]
    MissingCredentials(String),

    #[error("XOAUTH2 requires XOAuth2TokenProvider — use XOAuth2SmtpChannel")]
    XOAuth2NotYetImplemented,

    #[error("invalid email address: {0}")]
    InvalidAddress(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),
}

/// SMTP email delivery channel backed by lettre async transport with connection pooling.
///
/// The transport connects lazily — construction succeeds even if the SMTP server is
/// unreachable. Connection errors surface at delivery time.
pub struct SmtpChannel {
    config: SmtpConfig,
    transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
}

impl std::fmt::Debug for SmtpChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpChannel")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .finish_non_exhaustive()
    }
}

impl SmtpChannel {
    /// Build an SMTP channel from configuration.
    ///
    /// Validates the configuration and constructs the lettre transport.
    /// Does NOT attempt a network connection — the transport connects on first use.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the hostname is invalid, required auth credentials are missing,
    /// or `auth_method` is `XOAuth2` (served by `XOAuth2SmtpChannel`).
    pub fn new(config: SmtpConfig) -> Result<Self, SmtpBuildError> {
        let transport = Self::build_transport(&config)?;
        Ok(Self {
            config,
            transport: Arc::new(transport),
        })
    }

    /// Returns the channel configuration.
    pub fn config(&self) -> &SmtpConfig {
        &self.config
    }

    fn build_transport(
        cfg: &SmtpConfig,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, SmtpBuildError> {
        // Validate auth configuration FIRST — before spawning any tokio pool tasks.
        let credentials = Self::make_credentials(cfg)?;

        let pool = PoolConfig::new()
            .max_size(cfg.pool_size)
            .idle_timeout(Duration::from_secs(600));

        let auth_mechanisms = vec![Mechanism::Plain, Mechanism::Login];

        match &cfg.tls_mode {
            SmtpTlsMode::StartTls => {
                let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                    .map_err(|e| SmtpBuildError::InvalidConfig(e.to_string()))?
                    .port(cfg.port)
                    .pool_config(pool);

                if let Some(creds) = credentials {
                    builder = builder.credentials(creds).authentication(auth_mechanisms);
                }

                Ok(builder.build())
            }
            SmtpTlsMode::Tls => {
                let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
                    .map_err(|e| SmtpBuildError::InvalidConfig(e.to_string()))?
                    .port(cfg.port)
                    .pool_config(pool);

                if let Some(creds) = credentials {
                    builder = builder.credentials(creds).authentication(auth_mechanisms);
                }

                Ok(builder.build())
            }
            SmtpTlsMode::None => {
                let mut builder =
                    AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
                        .port(cfg.port)
                        .pool_config(pool);

                if let Some(creds) = credentials {
                    builder = builder.credentials(creds).authentication(auth_mechanisms);
                }

                Ok(builder.build())
            }
        }
    }

    fn make_credentials(cfg: &SmtpConfig) -> Result<Option<Credentials>, SmtpBuildError> {
        match &cfg.auth_method {
            EmailAuthMethod::None => Ok(None),
            EmailAuthMethod::Plain => {
                let username = cfg
                    .username
                    .clone()
                    .ok_or_else(|| SmtpBuildError::MissingCredentials("username".into()))?;
                let password = cfg
                    .password
                    .clone()
                    .ok_or_else(|| SmtpBuildError::MissingCredentials("password".into()))?;
                Ok(Some(Credentials::new(username, password)))
            }
            EmailAuthMethod::XOAuth2 => Err(SmtpBuildError::XOAuth2NotYetImplemented),
        }
    }

    /// Build a lettre `Message` from delivery parameters.
    fn build_message(
        &self,
        to_address: &str,
        message: &RenderedMessage,
        message_id: &str,
    ) -> Result<Message, SmtpBuildError> {
        let from_mailbox: Mailbox =
            format!("{} <{}>", self.config.from_name, self.config.from_address)
                .parse()
                .map_err(|e: lettre::address::AddressError| {
                    SmtpBuildError::InvalidAddress(e.to_string())
                })?;

        let to_mailbox: Mailbox =
            to_address
                .parse()
                .map_err(|e: lettre::address::AddressError| {
                    SmtpBuildError::InvalidAddress(e.to_string())
                })?;

        let subject = message.subject.as_deref().unwrap_or("Notification");

        let email = match message.body_text.as_deref() {
            Some(plain) if !plain.is_empty() => {
                // Multipart alternative: plain text + HTML.
                Message::builder()
                    .from(from_mailbox)
                    .to(to_mailbox)
                    .subject(subject)
                    .message_id(Some(format!("<{message_id}@sid>")))
                    .multipart(
                        MultiPart::alternative()
                            .singlepart(
                                SinglePart::builder()
                                    .header(ContentType::TEXT_PLAIN)
                                    .body(plain.to_owned()),
                            )
                            .singlepart(
                                SinglePart::builder()
                                    .header(ContentType::TEXT_HTML)
                                    .body(message.body.clone()),
                            ),
                    )
                    .map_err(|e: lettre::error::Error| {
                        SmtpBuildError::InvalidMessage(e.to_string())
                    })?
            }
            _ => {
                // HTML only.
                Message::builder()
                    .from(from_mailbox)
                    .to(to_mailbox)
                    .subject(subject)
                    .message_id(Some(format!("<{message_id}@sid>")))
                    .header(ContentType::TEXT_HTML)
                    .body(message.body.clone())
                    .map_err(|e: lettre::error::Error| {
                        SmtpBuildError::InvalidMessage(e.to_string())
                    })?
            }
        };

        Ok(email)
    }

    /// Map a lettre SMTP error to a `DeliveryError`: a 5xx reply is a
    /// permanent rejection (RFC 5321 4.2.1), a timeout may have followed an
    /// accepted DATA so its outcome is unknown, anything else is transient.
    pub(crate) fn map_smtp_error(e: &lettre::transport::smtp::Error) -> DeliveryError {
        let msg = e.to_string();
        if e.is_permanent() {
            DeliveryError::Rejected(msg)
        } else if e.is_timeout() {
            DeliveryError::Ambiguous(msg)
        } else {
            DeliveryError::Failed(msg)
        }
    }
}

#[async_trait]
impl NotificationChannel for SmtpChannel {
    fn channel_id(&self) -> &str {
        "email"
    }

    async fn deliver(
        &self,
        recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let email_addr = recipient
            .email
            .as_deref()
            .ok_or(DeliveryError::NotReachable)?;

        // Basic structural check before touching the network.
        if !email_addr.contains('@') {
            return Err(DeliveryError::InvalidRecipient(format!(
                "invalid email address: {email_addr}"
            )));
        }

        let message_id = uuid::Uuid::now_v7().to_string();

        let email = self
            .build_message(email_addr, message, &message_id)
            .map_err(|e| DeliveryError::InvalidRecipient(e.to_string()))?;

        tracing::debug!(
            channel = "email",
            to = email_addr,
            subject = message.subject.as_deref().unwrap_or("(no subject)"),
            from = %self.config.from_address,
            host = %self.config.host,
            message_id,
            "sending email via SMTP"
        );

        self.transport.send(email).await.map_err(|e| {
            tracing::warn!(
                channel = "email",
                to = email_addr,
                error = %e,
                "SMTP delivery failed"
            );
            Self::map_smtp_error(&e)
        })?;

        tracing::info!(
            channel = "email",
            to = email_addr,
            message_id,
            "email delivered successfully"
        );

        Ok(DeliveryReceipt {
            message_id,
            channel: "email".into(),
            timestamp: Utc::now(),
            provider: format!("smtp:{}", self.config.host),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        match self.transport.test_connection().await {
            Ok(true) => Ok(ChannelHealth {
                healthy: true,
                message: Some(format!(
                    "SMTP {}:{} reachable",
                    self.config.host, self.config.port
                )),
                last_success: Some(Utc::now()),
            }),
            Ok(false) => Ok(ChannelHealth {
                healthy: false,
                message: Some(format!(
                    "SMTP {}:{} EHLO probe returned false",
                    self.config.host, self.config.port
                )),
                last_success: None,
            }),
            Err(e) => Ok(ChannelHealth {
                healthy: false,
                message: Some(format!(
                    "SMTP {}:{} unreachable: {e}",
                    self.config.host, self.config.port
                )),
                last_success: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
