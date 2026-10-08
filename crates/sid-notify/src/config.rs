// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration for sid-notify standalone binary.
//!
//! Reads from environment variables:
//! - `SID_NATS_URL` — NATS server URL (required, e.g., `nats://127.0.0.1:4222`)
//! - `SID_NOTIFY_BIND` — gRPC bind address (default: `0.0.0.0:9040`)
//! - `SID_NOTIFY_QUEUE_GROUP` — NATS queue group name (default: `sid-notify`)
//! - `SID_NOTIFY_DATABASE_URL` — PostgreSQL URL for delivery jobs and templates (required)
//! - `SID_NOTIFY_JOB_CAPACITY` — open jobs per kind before events stay with the broker (default: 100000)
//! - `SID_IDENTITY_GRPC_ADDRESS` — sid-identity gRPC address for recipient resolution (optional, e.g., `http://127.0.0.1:9000`)
//! - `SID_JWT_PUBLIC_KEY_PATH` — Ed25519 public key PEM that verifies administrators' tokens (required)
//! - `SID_ISSUER` — token issuer URL (required)
//! - `SID_SMTP_HOST` — SMTP server hostname (default: `localhost`)
//! - `SID_SMTP_PORT` — SMTP server port (default: `587`)
//! - `SID_SMTP_FROM` — Sender email address (default: `noreply@sid.example.com`)
//! - `SID_SMTP_FROM_NAME` — Sender display name (default: `StructuredID`)
//! - `SID_SMTP_TLS_MODE` — TLS mode: `starttls` (default), `tls`, `none`
//! - `SID_SMTP_AUTH_METHOD` — Auth method: `none` (default), `plain`
//! - `SID_SMTP_USERNAME` — SMTP username (required for `plain` auth)
//! - `SID_SMTP_PASSWORD` — SMTP password (required for `plain` auth)
//! - `SID_VAPID_SUBJECT` — VAPID subject (mailto: or https:)
//! - `SID_VAPID_PUBLIC_KEY` — VAPID public key (base64url)
//! - `SID_VAPID_PRIVATE_KEY` — VAPID private key (base64url)

use std::net::SocketAddr;

use crate::channels::smtp::{EmailAuthMethod, SmtpConfig, SmtpTlsMode};
use crate::channels::web_push::VapidConfig;

/// sid-notify configuration.
#[derive(Debug, Clone)]
pub struct NotifyConfig {
    /// NATS server URL.
    pub nats_url: String,

    /// gRPC server bind address.
    pub grpc_bind: SocketAddr,

    /// NATS queue group name for load-balanced consumption.
    pub queue_group: String,

    /// SMTP channel configuration.
    pub smtp: SmtpConfig,

    /// Whether SMTP channel is enabled.
    pub smtp_enabled: bool,

    /// Whether webhook channel is enabled.
    pub webhook_enabled: bool,

    /// VAPID configuration for Web Push.
    pub vapid: Option<VapidConfig>,

    /// PostgreSQL connection URL: delivery jobs, their outcomes and template
    /// customizations live there. Required: without it no delivery can be
    /// owned durably.
    pub database_url: String,

    /// Open jobs per kind before new events are refused (and left with the
    /// broker) instead of accepted.
    pub job_capacity: u64,

    /// sid-identity gRPC address for recipient resolution (optional).
    /// When None, recipient info extracted from event data only.
    /// Example: `http://127.0.0.1:9000`
    pub identity_grpc_address: Option<String>,

    /// Ed25519 public key PEM path that verifies administrators' tokens; the
    /// server does not start without it. The signing key is never loaded here.
    pub jwt_public_key_path: Option<String>,

    /// JWT issuer URL for token validation.
    pub jwt_issuer: String,
}

impl NotifyConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let nats_url =
            std::env::var("SID_NATS_URL").map_err(|_| ConfigError::Missing("SID_NATS_URL"))?;

        let grpc_bind: SocketAddr = std::env::var("SID_NOTIFY_BIND")
            .unwrap_or_else(|_| "0.0.0.0:9040".into())
            .parse()
            .map_err(|e| ConfigError::Invalid("SID_NOTIFY_BIND", format!("{e}")))?;

        let queue_group =
            std::env::var("SID_NOTIFY_QUEUE_GROUP").unwrap_or_else(|_| "sid-notify".into());

        let smtp_host = std::env::var("SID_SMTP_HOST").unwrap_or_else(|_| "localhost".into());
        let smtp_port: u16 = std::env::var("SID_SMTP_PORT")
            .unwrap_or_else(|_| "587".into())
            .parse()
            .map_err(|e| ConfigError::Invalid("SID_SMTP_PORT", format!("{e}")))?;
        let smtp_from =
            std::env::var("SID_SMTP_FROM").unwrap_or_else(|_| "noreply@sid.example.com".into());
        let smtp_from_name =
            std::env::var("SID_SMTP_FROM_NAME").unwrap_or_else(|_| "StructuredID".into());

        let smtp_tls_mode = match std::env::var("SID_SMTP_TLS_MODE")
            .unwrap_or_else(|_| "starttls".into())
            .to_lowercase()
            .as_str()
        {
            "tls" => SmtpTlsMode::Tls,
            "none" => SmtpTlsMode::None,
            _ => SmtpTlsMode::StartTls,
        };

        let smtp_auth_method = match std::env::var("SID_SMTP_AUTH_METHOD")
            .unwrap_or_else(|_| "none".into())
            .to_lowercase()
            .as_str()
        {
            "plain" => EmailAuthMethod::Plain,
            "xoauth2" => EmailAuthMethod::XOAuth2,
            _ => EmailAuthMethod::None,
        };

        let smtp_username = std::env::var("SID_SMTP_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let smtp_password = std::env::var("SID_SMTP_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());

        let smtp = SmtpConfig {
            host: smtp_host,
            port: smtp_port,
            from_address: smtp_from,
            from_name: smtp_from_name,
            tls_mode: smtp_tls_mode,
            auth_method: smtp_auth_method,
            username: smtp_username,
            password: smtp_password,
            pool_size: 5,
        };

        // SMTP is enabled by default — real delivery via lettre (task #741).
        let smtp_enabled = std::env::var("SID_SMTP_ENABLED")
            .unwrap_or_else(|_| "true".into())
            .parse::<bool>()
            .unwrap_or(true);

        let webhook_enabled = std::env::var("SID_WEBHOOK_ENABLED")
            .unwrap_or_else(|_| "true".into())
            .parse::<bool>()
            .unwrap_or(true);

        // VAPID is optional — only enabled when all 3 keys are set.
        let vapid = match (
            std::env::var("SID_VAPID_SUBJECT").ok(),
            std::env::var("SID_VAPID_PUBLIC_KEY").ok(),
            std::env::var("SID_VAPID_PRIVATE_KEY").ok(),
        ) {
            (Some(subject), Some(public_key), Some(private_key))
                if !subject.is_empty() && !public_key.is_empty() && !private_key.is_empty() =>
            {
                Some(VapidConfig {
                    subject,
                    public_key,
                    private_key,
                })
            }
            _ => None,
        };

        let database_url = std::env::var("SID_NOTIFY_DATABASE_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or(ConfigError::Missing("SID_NOTIFY_DATABASE_URL"))?;

        let job_capacity = match std::env::var("SID_NOTIFY_JOB_CAPACITY") {
            Ok(value) => value
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    ConfigError::Invalid("SID_NOTIFY_JOB_CAPACITY", format!("{value:?}"))
                })?,
            Err(_) => DEFAULT_JOB_CAPACITY,
        };

        let identity_grpc_address = std::env::var("SID_IDENTITY_GRPC_ADDRESS")
            .ok()
            .filter(|s| !s.is_empty());

        let jwt_public_key_path = std::env::var("SID_JWT_PUBLIC_KEY_PATH")
            .ok()
            .filter(|s| !s.is_empty());

        let jwt_issuer = std::env::var("SID_ISSUER")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or(ConfigError::Missing("SID_ISSUER"))?;

        Ok(Self {
            nats_url,
            grpc_bind,
            queue_group,
            smtp,
            smtp_enabled,
            webhook_enabled,
            vapid,
            database_url,
            job_capacity,
            identity_grpc_address,
            jwt_public_key_path,
            jwt_issuer,
        })
    }
}

/// Open jobs per kind when `SID_NOTIFY_JOB_CAPACITY` is unset.
pub const DEFAULT_JOB_CAPACITY: u64 = 100_000;

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),

    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Config tests construct NotifyConfig directly to avoid env var race conditions
    // (env vars are process-global, tests run in parallel).

    #[test]
    fn test_config_struct_defaults() {
        let config = NotifyConfig {
            nats_url: "nats://127.0.0.1:4222".into(),
            grpc_bind: "0.0.0.0:9040".parse().unwrap(),
            queue_group: "sid-notify".into(),
            smtp: SmtpConfig::default(),
            smtp_enabled: true,
            webhook_enabled: true,
            vapid: None,
            database_url: "postgres://sid:sid_dev@localhost:54399/sid".into(),
            job_capacity: DEFAULT_JOB_CAPACITY,
            identity_grpc_address: None,
            jwt_public_key_path: None,
            jwt_issuer: "https://sid.example.com".into(),
        };

        assert_eq!(config.nats_url, "nats://127.0.0.1:4222");
        assert_eq!(config.grpc_bind.port(), 9040);
        assert_eq!(config.queue_group, "sid-notify");
        assert_eq!(config.smtp.host, "localhost");
        assert_eq!(config.smtp.port, 587);
        assert!(config.smtp_enabled);
        assert!(config.webhook_enabled);
        assert!(config.vapid.is_none());
    }

    #[test]
    fn test_config_with_vapid() {
        let config = NotifyConfig {
            nats_url: "nats://127.0.0.1:4222".into(),
            grpc_bind: "0.0.0.0:9040".parse().unwrap(),
            queue_group: "sid-notify".into(),
            smtp: SmtpConfig::default(),
            smtp_enabled: true,
            webhook_enabled: true,
            vapid: Some(VapidConfig {
                subject: "mailto:admin@sid.example.com".into(),
                public_key: "BEl62iUYgUivxIkv69yViEuiBIa".into(),
                private_key: "Dt1CLgQlkiaA-tmCkATyKZeoF1".into(),
            }),
            database_url: "postgres://sid:sid_dev@localhost:54399/sid".into(),
            job_capacity: DEFAULT_JOB_CAPACITY,
            identity_grpc_address: None,
            jwt_public_key_path: None,
            jwt_issuer: "https://sid.example.com".into(),
        };

        assert!(config.vapid.is_some());
        let vapid = config.vapid.unwrap();
        assert_eq!(vapid.subject, "mailto:admin@sid.example.com");
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::Missing("SID_NATS_URL");
        assert!(err.to_string().contains("SID_NATS_URL"));

        let err = ConfigError::Invalid("SID_NOTIFY_BIND", "bad address".into());
        assert!(err.to_string().contains("SID_NOTIFY_BIND"));
        assert!(err.to_string().contains("bad address"));
    }

    #[test]
    fn test_config_disabled_channels() {
        let config = NotifyConfig {
            nats_url: "nats://127.0.0.1:4222".into(),
            grpc_bind: "0.0.0.0:9040".parse().unwrap(),
            queue_group: "sid-notify".into(),
            smtp: SmtpConfig::default(),
            smtp_enabled: false,
            webhook_enabled: false,
            vapid: None,
            database_url: "postgres://sid:sid_dev@localhost:54399/sid".into(),
            job_capacity: DEFAULT_JOB_CAPACITY,
            identity_grpc_address: None,
            jwt_public_key_path: None,
            jwt_issuer: "https://sid.example.com".into(),
        };

        assert!(!config.smtp_enabled);
        assert!(!config.webhook_enabled);
        assert!(config.vapid.is_none());
    }

    #[test]
    fn test_smtp_config_default() {
        let smtp = SmtpConfig::default();
        assert_eq!(smtp.host, "localhost");
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.from_address, "noreply@sid.example.com");
        assert_eq!(smtp.from_name, "StructuredID");
        assert_eq!(smtp.tls_mode, SmtpTlsMode::StartTls);
        assert_eq!(smtp.auth_method, EmailAuthMethod::None);
    }
}
