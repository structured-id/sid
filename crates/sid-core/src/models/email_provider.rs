// SPDX-License-Identifier: AGPL-3.0-only
//! Email provider configuration domain model.
//!
//! Instance-level singleton managed via `AdminService.UpdateEmailSettings` (gRPC).
//! `sid-notify` reads this table on startup and falls back to env-var config
//! if the table row is absent.

use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

/// SMTP TLS/encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SmtpEncryption {
    /// Plain SMTP — no TLS (dev relays, port 25).
    None,
    /// Implicit TLS from first byte (port 465).
    SslTls,
    /// STARTTLS upgrade (port 587, default).
    #[default]
    Starttls,
}

impl SmtpEncryption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SslTls => "ssl_tls",
            Self::Starttls => "starttls",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "none" => Self::None,
            "ssl_tls" => Self::SslTls,
            _ => Self::Starttls,
        }
    }
}

/// SMTP authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SmtpAuthMethod {
    /// No authentication (open relay / dev relay).
    #[default]
    None,
    /// PLAIN / LOGIN with username + password.
    UsernamePassword,
    /// XOAUTH2 SASL mechanism via OAuth2 client credentials (M365) or
    /// service account JWT exchange (Google Workspace).
    XOAuth2,
}

impl SmtpAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::UsernamePassword => "username_password",
            Self::XOAuth2 => "xoauth2",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "username_password" => Self::UsernamePassword,
            "xoauth2" => Self::XOAuth2,
            _ => Self::None,
        }
    }
}

/// OAuth2 provider type for XOAUTH2 SMTP authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XOAuth2Provider {
    /// Microsoft 365 via Azure AD client credentials flow.
    M365,
    /// Google Workspace via service account JWT bearer exchange.
    Google,
}

impl XOAuth2Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::M365 => "m365",
            Self::Google => "google",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "m365" => Some(Self::M365),
            "google" => Some(Self::Google),
            _ => None,
        }
    }
}

/// XOAUTH2-specific configuration stored alongside `EmailProviderConfig`.
///
/// Credentials are stored in plaintext.
///
/// `Clone` is implemented manually because `SecretBox<String>` requires
/// exposing the secret to create a new box — `String` does not implement
/// `CloneableSecret` in secrecy 0.10.
pub struct XOAuth2Config {
    /// OAuth2 provider (M365 or Google).
    pub provider: XOAuth2Provider,
    /// Azure AD tenant ID (GUID or domain). Required for M365.
    pub tenant_id: Option<String>,
    /// OAuth2 client ID (Azure app reg client ID, or Google service account email).
    pub client_id: String,
    /// OAuth2 client secret (Azure client secret). Not used for Google.
    pub client_secret: SecretBox<String>,
    /// Google Workspace service account key JSON (full JSON content).
    pub service_account_key: Option<SecretBox<String>>,
    /// Optional override for the token endpoint URL.
    pub token_endpoint: Option<String>,
    /// SMTP username — the email address to authenticate as.
    pub user_email: String,
}

impl Clone for XOAuth2Config {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider,
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            client_secret: SecretBox::new(Box::new(self.client_secret.expose_secret().clone())),
            service_account_key: self
                .service_account_key
                .as_ref()
                .map(|k| SecretBox::new(Box::new(k.expose_secret().clone()))),
            token_endpoint: self.token_endpoint.clone(),
            user_email: self.user_email.clone(),
        }
    }
}

/// Instance-level SMTP email provider configuration (CE singleton).
///
/// Written by `AdminService.UpdateEmailSettings`, read by `sid-notify` on startup.
/// The credentials are stored sealed under the field-encryption key manager
/// in every edition; the service seals them before writing and opens them
/// after reading.
///
/// `Clone` is implemented manually — see `XOAuth2Config` for rationale.
pub struct EmailProviderConfig {
    /// SMTP server hostname or IP.
    pub smtp_host: String,
    /// SMTP server port (default 587 for STARTTLS, 465 for SSL/TLS).
    pub smtp_port: u16,
    /// Envelope From / From header address.
    pub from_address: String,
    /// Display name in From header (e.g. "StructuredID").
    pub from_display_name: String,
    /// Optional Reply-To address (empty = none).
    pub reply_to: String,
    /// TLS/encryption mode.
    pub encryption: SmtpEncryption,
    /// Authentication method.
    pub auth_type: SmtpAuthMethod,
    /// SMTP username (empty if auth_type == None/XOAuth2).
    pub username: String,
    /// SMTP password. Empty when auth_type != UsernamePassword.
    pub password: SecretBox<String>,
    /// XOAUTH2 configuration. Set when auth_type == XOAuth2.
    pub xoauth2: Option<XOAuth2Config>,
}

impl Clone for EmailProviderConfig {
    fn clone(&self) -> Self {
        Self {
            smtp_host: self.smtp_host.clone(),
            smtp_port: self.smtp_port,
            from_address: self.from_address.clone(),
            from_display_name: self.from_display_name.clone(),
            reply_to: self.reply_to.clone(),
            encryption: self.encryption,
            auth_type: self.auth_type,
            username: self.username.clone(),
            password: SecretBox::new(Box::new(self.password.expose_secret().clone())),
            xoauth2: self.xoauth2.clone(),
        }
    }
}
