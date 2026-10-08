// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Device Attestation Service — standalone binary.
//!
//! Manages device key registration, attestation storage, key rotation,
//! and revocation. CE stores attestation without verification.

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting sid-attestation v{}", env!("CARGO_PKG_VERSION"));

    let config = sid_attestation::config::AttestationConfig::from_env()?;
    tracing::info!(
        bind = %config.grpc_bind,
        db = %config.database_url_display(),
        "Configuration loaded"
    );

    let server = sid_attestation::server::AttestationServer::new(config).await?;
    server.serve().await
}
