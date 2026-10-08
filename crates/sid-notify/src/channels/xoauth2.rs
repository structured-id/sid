// SPDX-License-Identifier: AGPL-3.0-only
//! XOAUTH2 SMTP authentication provider.
//!
//! Implements token acquisition for Microsoft 365 (Azure AD client credentials)
//! and Google Workspace (service account JWT bearer exchange).
//!
//! The `XOAuth2SmtpChannel` wraps an `XOAuth2TokenProvider` and maintains a
//! cached access token.  When the token is within 60 seconds of expiry the
//! channel fetches a new one and rebuilds the lettre transport atomically so
//! in-flight deliveries are not affected.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::{
        PoolConfig,
        authentication::{Credentials, Mechanism},
    },
};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::channels::smtp::SmtpTlsMode;

// ── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by XOAUTH2 token providers.
#[derive(Debug, thiserror::Error)]
pub enum XOAuth2Error {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("token endpoint returned error: {error} — {description}")]
    TokenEndpoint { error: String, description: String },

    #[error("service account key JSON is invalid: {0}")]
    InvalidServiceAccountKey(String),

    #[error("JWT signing failed: {0}")]
    JwtSign(#[from] jsonwebtoken::errors::Error),

    #[error("SMTP transport build failed: {0}")]
    SmtpBuild(String),

    #[error("SMTP connection test failed: {0}")]
    SmtpTest(String),
}

// ── Token provider trait ─────────────────────────────────────────────────────

/// Fetches an OAuth2 access token suitable for XOAUTH2 SASL over SMTP.
#[async_trait]
pub trait XOAuth2TokenProvider: Send + Sync + std::fmt::Debug {
    /// Acquire a fresh access token.  Implementations MUST NOT cache tokens
    /// internally — caching is handled by `XOAuth2SmtpChannel`.
    async fn fetch_token(&self) -> Result<FetchedToken, XOAuth2Error>;
}

/// A freshly fetched OAuth2 access token together with its expiry.
#[derive(Debug)]
pub struct FetchedToken {
    /// Bearer access token value.
    pub access_token: String,
    /// Seconds until the token expires (from fetch time).
    pub expires_in: u64,
}

// ── Shared HTTP response types ────────────────────────────────────────────────

/// OAuth2 token endpoint success response (RFC 6749 §5.1).
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// OAuth2 token endpoint error response (RFC 6749 §5.2).
#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

// ── Microsoft 365 provider ────────────────────────────────────────────────────

/// Token provider for Microsoft 365 using Azure AD client credentials flow.
///
/// Fetches a token from `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
/// with `grant_type=client_credentials` and scope
/// `https://outlook.office365.com/.default`.
///
/// Requires the Azure AD application to have the `SMTP.SendMail` (or
/// `Mail.Send`) application permission granted by a tenant administrator.
#[derive(Debug)]
pub struct M365TokenProvider {
    /// Azure AD tenant ID (GUID or domain, e.g. `contoso.onmicrosoft.com`).
    pub tenant_id: String,
    /// Azure AD application (client) ID.
    pub client_id: String,
    /// Azure AD client secret.
    pub client_secret: SecretBox<String>,
    /// Optional override for the token endpoint URL.
    /// Defaults to the Microsoft identity platform endpoint.
    pub token_endpoint: Option<String>,
    /// Reqwest HTTP client shared across token fetches.
    pub http: Client,
}

#[async_trait]
impl XOAuth2TokenProvider for M365TokenProvider {
    async fn fetch_token(&self) -> Result<FetchedToken, XOAuth2Error> {
        let endpoint = self.token_endpoint.as_deref().unwrap_or_else(|| {
            // Allocated on the stack — format! used below instead.
            ""
        });
        let url = if endpoint.is_empty() {
            format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                self.tenant_id
            )
        } else {
            endpoint.to_owned()
        };

        debug!(tenant = %self.tenant_id, client_id = %self.client_id, "M365: fetching SMTP OAuth2 token");

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose_secret()),
            ("scope", "https://outlook.office365.com/.default"),
        ];

        let resp = self.http.post(&url).form(&params).send().await?;

        if resp.status().is_success() {
            let t: TokenResponse = resp.json().await?;
            info!(tenant = %self.tenant_id, expires_in = t.expires_in, "M365: SMTP token acquired");
            Ok(FetchedToken {
                access_token: t.access_token,
                expires_in: t.expires_in,
            })
        } else {
            let err: TokenErrorResponse = resp.json().await.unwrap_or(TokenErrorResponse {
                error: "unknown".into(),
                error_description: "no response body".into(),
            });
            Err(XOAuth2Error::TokenEndpoint {
                error: err.error,
                description: err.error_description,
            })
        }
    }
}

// ── Google Workspace provider ─────────────────────────────────────────────────

/// Minimal fields extracted from a Google service account key JSON file.
#[derive(Deserialize)]
struct ServiceAccountKey {
    /// Service account email (`*@*.iam.gserviceaccount.com`).
    client_email: String,
    /// PEM-encoded RSA private key.
    private_key: String,
}

/// JWT claims for the Google service account JWT bearer grant (RFC 7523).
#[derive(Serialize)]
struct GoogleJwtClaims {
    /// Issuer — service account email.
    iss: String,
    /// OAuth2 scope — Gmail SMTP access.
    scope: String,
    /// Audience — Google token endpoint.
    aud: String,
    /// Expiry (Unix timestamp).
    exp: i64,
    /// Issued at (Unix timestamp).
    iat: i64,
    /// Subject — the Gmail address to authenticate as.
    sub: String,
}

/// Token provider for Google Workspace using service account JWT bearer exchange.
///
/// Signs a JWT with the service account private key and exchanges it at
/// `https://oauth2.googleapis.com/token` for a Gmail-scoped access token.
///
/// Requires the service account to have domain-wide delegation enabled and
/// the `https://mail.google.com/` scope granted in the Google Admin console.
#[derive(Debug)]
pub struct GoogleTokenProvider {
    /// SMTP user email (the Google Workspace mailbox to send as).
    pub user_email: String,
    /// Service account key JSON content (full file).
    pub service_account_key: SecretBox<String>,
    /// Optional override for the token endpoint URL.
    pub token_endpoint: Option<String>,
    /// Reqwest HTTP client.
    pub http: Client,
}

#[async_trait]
impl XOAuth2TokenProvider for GoogleTokenProvider {
    async fn fetch_token(&self) -> Result<FetchedToken, XOAuth2Error> {
        let key: ServiceAccountKey = serde_json::from_str(self.service_account_key.expose_secret())
            .map_err(|e| XOAuth2Error::InvalidServiceAccountKey(e.to_string()))?;

        let endpoint = self
            .token_endpoint
            .as_deref()
            .unwrap_or("https://oauth2.googleapis.com/token");

        let now = Utc::now().timestamp();
        let claims = GoogleJwtClaims {
            iss: key.client_email.clone(),
            scope: "https://mail.google.com/".into(),
            aud: endpoint.to_owned(),
            exp: now + 3600,
            iat: now,
            sub: self.user_email.clone(),
        };

        // The only RSA private-key operation in the workspace. Google requires
        // RS256 here, and the pure-Rust `rsa` backend has no constant-time
        // private-key path (RUSTSEC-2023-0071). Safe as written because the
        // claims are ours and nobody outside can drive or time this signature;
        // it stops being safe if an RSA key is ever signed with on request.
        let encoding_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes())?;
        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)?;

        debug!(user = %self.user_email, issuer = %key.client_email, "Google: exchanging service account JWT for SMTP token");

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ];

        let resp = self.http.post(endpoint).form(&params).send().await?;

        if resp.status().is_success() {
            let t: TokenResponse = resp.json().await?;
            info!(user = %self.user_email, expires_in = t.expires_in, "Google: SMTP token acquired");
            Ok(FetchedToken {
                access_token: t.access_token,
                expires_in: t.expires_in,
            })
        } else {
            let err: TokenErrorResponse = resp.json().await.unwrap_or(TokenErrorResponse {
                error: "unknown".into(),
                error_description: "no response body".into(),
            });
            Err(XOAuth2Error::TokenEndpoint {
                error: err.error,
                description: err.error_description,
            })
        }
    }
}

// ── Token cache ───────────────────────────────────────────────────────────────

/// Number of seconds before expiry at which the token is proactively refreshed.
const REFRESH_BEFORE_EXPIRY_SECS: u64 = 60;

/// Cached access token and the SMTP transport built from it.
struct CachedState {
    expires_at: Instant,
    transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
}

// ── XOAuth2SmtpChannel ────────────────────────────────────────────────────────

/// Configuration for the SMTP connection used by the XOAUTH2 channel.
#[derive(Debug, Clone)]
pub struct XOAuth2SmtpConfig {
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    /// SMTP username — the email address to authenticate as (same as `user_email`
    /// in the token provider).
    pub user_email: String,
    pub from_address: String,
    pub from_name: String,
    pub pool_size: u32,
}

/// SMTP email delivery channel using XOAUTH2 SASL authentication.
///
/// Maintains a cached OAuth2 access token and rebuilds the lettre transport
/// when the token is within `REFRESH_BEFORE_EXPIRY_SECS` seconds of expiry.
/// Token refresh and transport rebuild are protected by a `Mutex` so only one
/// task refreshes at a time; other tasks wait and then share the new transport.
pub struct XOAuth2SmtpChannel {
    config: XOAuth2SmtpConfig,
    provider: Arc<dyn XOAuth2TokenProvider>,
    state: Mutex<Option<CachedState>>,
}

impl std::fmt::Debug for XOAuth2SmtpChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XOAuth2SmtpChannel")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("user_email", &self.config.user_email)
            .finish_non_exhaustive()
    }
}

impl XOAuth2SmtpChannel {
    /// Create an XOAUTH2 SMTP channel.
    ///
    /// The channel does NOT fetch a token or open a connection at construction
    /// time.  The first `deliver` or `health` call triggers the initial token
    /// fetch.
    pub fn new(config: XOAuth2SmtpConfig, provider: Arc<dyn XOAuth2TokenProvider>) -> Self {
        Self {
            config,
            provider,
            state: Mutex::new(None),
        }
    }

    /// Return a valid SMTP transport, refreshing the token if needed.
    async fn get_transport(&self) -> Result<Arc<AsyncSmtpTransport<Tokio1Executor>>, XOAuth2Error> {
        let mut guard = self.state.lock().await;

        let needs_refresh = match &*guard {
            None => true,
            Some(s) => {
                let remaining = s.expires_at.saturating_duration_since(Instant::now());
                remaining < Duration::from_secs(REFRESH_BEFORE_EXPIRY_SECS)
            }
        };

        if needs_refresh {
            debug!(
                host = %self.config.host,
                user = %self.config.user_email,
                "XOAUTH2: refreshing SMTP token"
            );
            let fetched = self.provider.fetch_token().await?;
            let transport = self
                .build_transport(&fetched.access_token)
                .map_err(|e| XOAuth2Error::SmtpBuild(e.to_string()))?;
            let expires_at = Instant::now() + Duration::from_secs(fetched.expires_in);
            *guard = Some(CachedState {
                expires_at,
                transport: Arc::new(transport),
            });
        }

        Ok(Arc::clone(&guard.as_ref().unwrap().transport))
    }

    fn build_transport(
        &self,
        access_token: &str,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
        let creds = Credentials::new(self.config.user_email.clone(), access_token.to_owned());
        let pool = PoolConfig::new()
            .max_size(self.config.pool_size)
            .idle_timeout(Duration::from_secs(600));

        let transport = match &self.config.tls_mode {
            SmtpTlsMode::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.host)
                    .map_err(|e| e.to_string())?
                    .port(self.config.port)
                    .credentials(creds)
                    .authentication(vec![Mechanism::Xoauth2])
                    .pool_config(pool)
                    .build()
            }
            SmtpTlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.host)
                .map_err(|e| e.to_string())?
                .port(self.config.port)
                .credentials(creds)
                .authentication(vec![Mechanism::Xoauth2])
                .pool_config(pool)
                .build(),
            SmtpTlsMode::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.host)
                    .port(self.config.port)
                    .credentials(creds)
                    .authentication(vec![Mechanism::Xoauth2])
                    .pool_config(pool)
                    .build()
            }
        };

        Ok(transport)
    }

    fn build_message(
        &self,
        to_address: &str,
        message: &RenderedMessage,
        message_id: &str,
    ) -> Result<Message, String> {
        let from_mailbox: Mailbox =
            format!("{} <{}>", self.config.from_name, self.config.from_address)
                .parse()
                .map_err(|e: lettre::address::AddressError| e.to_string())?;

        let to_mailbox: Mailbox = to_address
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;

        let subject = message.subject.as_deref().unwrap_or("Notification");

        let email = match message.body_text.as_deref() {
            Some(plain) if !plain.is_empty() => Message::builder()
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
                .map_err(|e: lettre::error::Error| e.to_string())?,
            _ => Message::builder()
                .from(from_mailbox)
                .to(to_mailbox)
                .subject(subject)
                .message_id(Some(format!("<{message_id}@sid>")))
                .header(ContentType::TEXT_HTML)
                .body(message.body.clone())
                .map_err(|e: lettre::error::Error| e.to_string())?,
        };

        Ok(email)
    }
}

#[async_trait]
impl NotificationChannel for XOAuth2SmtpChannel {
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

        if !email_addr.contains('@') {
            return Err(DeliveryError::InvalidRecipient(format!(
                "invalid email address: {email_addr}"
            )));
        }

        let transport = self.get_transport().await.map_err(|e| {
            warn!(error = %e, channel = "email:xoauth2", "token refresh failed");
            DeliveryError::Failed(format!("XOAUTH2 token refresh failed: {e}"))
        })?;

        let message_id = uuid::Uuid::now_v7().to_string();

        let email = self
            .build_message(email_addr, message, &message_id)
            .map_err(DeliveryError::InvalidRecipient)?;

        debug!(
            channel = "email:xoauth2",
            to = email_addr,
            subject = message.subject.as_deref().unwrap_or("(no subject)"),
            from = %self.config.from_address,
            host = %self.config.host,
            message_id,
            "sending email via SMTP XOAUTH2"
        );

        transport.send(email).await.map_err(|e| {
            warn!(channel = "email:xoauth2", to = email_addr, error = %e, "SMTP XOAUTH2 delivery failed");
            super::smtp::SmtpChannel::map_smtp_error(&e)
        })?;

        info!(
            channel = "email:xoauth2",
            to = email_addr,
            message_id,
            "email delivered successfully via XOAUTH2"
        );

        Ok(DeliveryReceipt {
            message_id,
            channel: "email".into(),
            timestamp: Utc::now(),
            provider: format!("smtp-xoauth2:{}", self.config.host),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        match self.get_transport().await {
            Err(e) => Ok(ChannelHealth {
                healthy: false,
                message: Some(format!("XOAUTH2 token fetch failed: {e}")),
                last_success: None,
            }),
            Ok(transport) => match transport.test_connection().await {
                Ok(true) => Ok(ChannelHealth {
                    healthy: true,
                    message: Some(format!(
                        "SMTP {}:{} reachable (XOAUTH2)",
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
            },
        }
    }
}

// ── Builder helpers ───────────────────────────────────────────────────────────

/// Build an `XOAuth2SmtpChannel` from a domain `EmailProviderConfig`.
///
/// Returns `None` when `auth_type` is not XOAUTH2 or `xoauth2` config is absent.
pub fn channel_from_email_config(
    cfg: &sid_core::models::EmailProviderConfig,
) -> Option<XOAuth2SmtpChannel> {
    use sid_core::models::{SmtpAuthMethod, SmtpEncryption, XOAuth2Provider};

    if cfg.auth_type != SmtpAuthMethod::XOAuth2 {
        return None;
    }
    let x = cfg.xoauth2.as_ref()?;

    let http = sid_plugin::client_builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client build cannot fail with valid config");

    let provider: Arc<dyn XOAuth2TokenProvider> = match x.provider {
        XOAuth2Provider::M365 => Arc::new(M365TokenProvider {
            tenant_id: x.tenant_id.clone().unwrap_or_default(),
            client_id: x.client_id.clone(),
            client_secret: SecretBox::new(Box::new(x.client_secret.expose_secret().clone())),
            token_endpoint: x.token_endpoint.clone(),
            http,
        }),
        XOAuth2Provider::Google => Arc::new(GoogleTokenProvider {
            user_email: x.user_email.clone(),
            service_account_key: x
                .service_account_key
                .as_ref()
                .map(|k| SecretBox::new(Box::new(k.expose_secret().clone())))
                .unwrap_or_else(|| SecretBox::new(Box::new(String::new()))),
            token_endpoint: x.token_endpoint.clone(),
            http,
        }),
    };

    let tls_mode = match cfg.encryption {
        SmtpEncryption::SslTls => SmtpTlsMode::Tls,
        SmtpEncryption::None => SmtpTlsMode::None,
        SmtpEncryption::Starttls => SmtpTlsMode::StartTls,
    };

    Some(XOAuth2SmtpChannel::new(
        XOAuth2SmtpConfig {
            host: cfg.smtp_host.clone(),
            port: cfg.smtp_port,
            tls_mode,
            user_email: x.user_email.clone(),
            from_address: cfg.from_address.clone(),
            from_name: cfg.from_display_name.clone(),
            pool_size: 5,
        },
        provider,
    ))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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

        assert!(channel_from_email_config(&cfg).is_none());
    }

    // ── Google service account key JSON parse error ───────────────────────────

    #[tokio::test]
    async fn test_google_invalid_key_json_error() {
        let provider = GoogleTokenProvider {
            user_email: "smtp@sid.example.com".into(),
            service_account_key: secrecy::SecretBox::new(Box::new("not valid json".into())),
            token_endpoint: None,
            http: sid_plugin::client_builder().build().unwrap(),
        };
        let err = provider.fetch_token().await.unwrap_err();
        assert!(matches!(err, XOAuth2Error::InvalidServiceAccountKey(_)));
    }
}
