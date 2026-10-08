// SPDX-License-Identifier: AGPL-3.0-only
//! sid-attestation gRPC server setup.

use crate::config::AttestationConfig;
use crate::handler::AttestationServiceImpl;
use sid_authn::jwt::TokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_proto::sid::v1::attestation::attestation_service_server::AttestationServiceServer;
use sid_storage::PostgresBackend;
use std::sync::Arc;
use tracing::info;

/// Attestation gRPC server.
pub struct AttestationServer {
    config: AttestationConfig,
    storage: Arc<PostgresBackend>,
    verifier: Arc<TokenVerifier>,
}

impl AttestationServer {
    /// Create server with PostgreSQL storage and the token verifier. Only the
    /// public key is loaded: this service accepts tokens, it never issues them.
    pub async fn new(config: AttestationConfig) -> anyhow::Result<Self> {
        let storage = Arc::new(
            PostgresBackend::new(&config.database_url, None)
                .await
                .map_err(|e| anyhow::anyhow!("database connection failed: {e}"))?,
        );
        let pub_pem = std::fs::read(&config.jwt_public_key_path)
            .map_err(|e| anyhow::anyhow!("failed to read JWT public key: {e}"))?;
        let verifier = Arc::new(
            TokenVerifier::new(&pub_pem, config.jwt_issuer.clone())
                .map_err(|e| anyhow::anyhow!("token verifier init failed: {e}"))?,
        );
        Ok(Self {
            config,
            storage,
            verifier,
        })
    }

    /// Run the gRPC server until shutdown signal, then stop as every SID
    /// service does ([`sid_serve::run`]).
    pub async fn serve(self) -> anyhow::Result<()> {
        let reflection_svc = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(sid_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        // Revocations made by any SID service apply here too.
        let shared_cache =
            sid_infra::shared_cache(sid_infra::cache_url_from_env().as_deref()).await?;
        let revocation = Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            shared_cache,
        ));
        // Runs until the cache connection closes with the process.
        let _revocation_listener = revocation.listen().await?;

        let attestation_svc = AttestationServiceImpl::new(self.storage, self.verifier, revocation);

        let drain = sid_serve::shutdown::drain_interval_from_env()?;
        let mut services = sid_serve::Services::new();
        services
            .route(reflection_svc)
            .add(AttestationServiceServer::new(attestation_svc))
            .await;
        let listener = tokio::net::TcpListener::bind(self.config.grpc_bind).await?;
        info!(bind = %self.config.grpc_bind, "gRPC server starting");
        sid_serve::serve(listener, services, sid_serve::shutdown::signal(), drain).await?;

        info!("sid-attestation shutdown complete");
        Ok(())
    }
}
