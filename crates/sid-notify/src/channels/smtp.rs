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

    /// Map a lettre SMTP error to a `DeliveryError`. A reply decides it: 5xx
    /// is a permanent rejection, 4xx transient (RFC 5321 4.2.1). Failing to
    /// connect sent nothing, so it is transient too. A broken or unreadable
    /// exchange (network, malformed or missing reply, timeout) may have
    /// followed the end of the message data, which the server may already
    /// have accepted (RFC 5321 4.5.4.1, 6.1): its outcome is unknown.
    pub(crate) fn map_smtp_error(e: &lettre::transport::smtp::Error) -> DeliveryError {
        let msg = e.to_string();
        if e.is_permanent() {
            DeliveryError::Rejected(msg)
        } else if e.is_transient() {
            DeliveryError::Failed(msg)
        } else if e.is_response() || e.is_timeout() || Self::is_exchange_broken(e) {
            DeliveryError::Ambiguous(msg)
        } else {
            DeliveryError::Failed(msg)
        }
    }

    /// The connection failed during the exchange, not while it was being
    /// established: lettre reports the latter as a connection error.
    fn is_exchange_broken(e: &lettre::transport::smtp::Error) -> bool {
        e.to_string().starts_with("network error")
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

        // No subject: rendered content (a sign-in code in the otp subject)
        // never reaches the logs.
        tracing::debug!(
            channel = "email",
            to = email_addr,
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
mod tests;
