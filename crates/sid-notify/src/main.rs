// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Notification Service — standalone binary.
//!
//! Consumes events from NATS JetStream and delivers notifications
//! through configured channels (email, webhook, web push).
//!
//! ## Usage
//!
//! ```bash
//! # Required: NATS URL
//! SID_NATS_URL=nats://127.0.0.1:4222 sid-notify
//!
//! # With SMTP config:
//! SID_NATS_URL=nats://127.0.0.1:4222 \
//! SID_SMTP_HOST=mail.example.com \
//! SID_SMTP_FROM=noreply@example.com \
//! sid-notify
//! ```

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting sid-notify v{}", env!("CARGO_PKG_VERSION"));

    let config = sid_notify::config::NotifyConfig::from_env()?;
    tracing::info!(
        nats = %config.nats_url,
        bind = %config.grpc_bind,
        group = %config.queue_group,
        smtp = config.smtp_enabled,
        webhook = config.webhook_enabled,
        vapid = config.vapid.is_some(),
        identity = config.identity_grpc_address.is_some(),
        "Configuration loaded"
    );

    let server = sid_notify::server::NotifyServer::new(config).await?;
    server.serve().await
}
