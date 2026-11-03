// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration for sid-notify standalone binary.
//!
//! Reads from environment variables:
//! - `SID_NATS_URL` — NATS server URL (required, e.g., `nats://127.0.0.1:4222`)
//! - `SID_NOTIFY_BIND` — gRPC bind address (default: `0.0.0.0:9040`)
//! - `SID_NOTIFY_RECEIVER` — the receiver facts are owed to; replicas share it (default: `sid-notify`)
//! - `SID_EVENT_RECEIVERS` — the deployment's required receivers, as producers list them (required; `none` for none); this service owes its own facts to all but itself
//! - `SID_NATS_TOPOLOGY` and the `SID_NATS_*` bounds — the event topology, as for every SID service
//! - `SID_NOTIFY_DATABASE_URL` — PostgreSQL URL for delivery jobs and templates (required)
//! - `SID_NOTIFY_JOB_CAPACITY` — open jobs per kind before events stay with the broker (default: 100000)
//! - `SID_IDENTITY_GRPC_ADDRESS` — sid-identity gRPC address for recipient resolution (optional, e.g., `http://127.0.0.1:9000`)
//! - `SID_GRPC_UPSTREAM`, `SID_ISSUER_URL`, `SID_RECEIVER_RESOURCE`,
//!   `SID_RECEIVER_ORIGIN`, `SID_AUTHZ_CHECKER_*` — the template API's
//!   receiver: the issuer it asks, the installation's account API resource it
//!   serves, its external origin and its own checker credential (required)
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

use sid_core::models::{RequiredReceiver, WorkRecipient};

use crate::channels::smtp::{EmailAuthMethod, SmtpConfig, SmtpTlsMode};
use crate::channels::web_push::VapidConfig;

/// sid-notify configuration.
#[derive(Debug, Clone)]
pub struct NotifyConfig {
    /// NATS server URL.
    pub nats_url: String,

    /// gRPC server bind address.
    pub grpc_bind: SocketAddr,

    /// The receiver every fact is owed to as addressed work: producers name
    /// the same one in `SID_EVENT_RECEIVERS`, and replicas share its work.
    pub receiver: WorkRecipient,

    /// The receivers the facts this service raises (dead-letter alerts) are
    /// owed to: the deployment's required receivers other than itself.
    pub event_receivers: Vec<RequiredReceiver>,

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

    /// Where the template API's calls are admitted: the installation's
    /// account API resource, decided by its issuer (`crate::access`).
    pub api: sid_auth::config::ReceiverConfig,
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

        let receiver = WorkRecipient::new(
            std::env::var("SID_NOTIFY_RECEIVER").unwrap_or_else(|_| DEFAULT_RECEIVER.into()),
        )
        .map_err(|e| ConfigError::Invalid("SID_NOTIFY_RECEIVER", e.to_string()))?;
        let event_receivers = other_receivers(
            &receiver,
            &std::env::var("SID_EVENT_RECEIVERS")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .ok_or(ConfigError::Missing("SID_EVENT_RECEIVERS"))?,
        )?;

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

        // SMTP is enabled by default — real delivery via lettre.
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

        let api = sid_auth::config::ReceiverConfig::from_env()
            .map_err(|e| ConfigError::Invalid("template API receiver", e.to_string()))?;

        Ok(Self {
            nats_url,
            grpc_bind,
            receiver,
            event_receivers,
            smtp,
            smtp_enabled,
            webhook_enabled,
            vapid,
            database_url,
            job_capacity,
            identity_grpc_address,
            api,
        })
    }
}

/// Open jobs per kind when `SID_NOTIFY_JOB_CAPACITY` is unset.
pub const DEFAULT_JOB_CAPACITY: u64 = 100_000;

/// The receiver when `SID_NOTIFY_RECEIVER` is unset.
pub const DEFAULT_RECEIVER: &str = "sid-notify";

/// The receivers `list` names other than `own`: this service does not route
/// its own facts, so owing them to itself would only fill its queue.
pub fn other_receivers(
    own: &WorkRecipient,
    list: &str,
) -> Result<Vec<RequiredReceiver>, ConfigError> {
    Ok(RequiredReceiver::parse_list(list)
        .map_err(|e| ConfigError::Invalid("SID_EVENT_RECEIVERS", e.to_string()))?
        .into_iter()
        .filter(|r| r.recipient != *own)
        .collect())
}

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),

    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

#[cfg(test)]
mod tests;
