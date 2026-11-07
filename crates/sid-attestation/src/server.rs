// SPDX-License-Identifier: AGPL-3.0-only
//! sid-attestation gRPC server setup.

use crate::config::AttestationConfig;
use crate::handler::AttestationServiceImpl;
use sid_auth::receiver::Receiver;
use sid_proto::sid::v1::attestation::attestation_service_server::AttestationServiceServer;
use sid_storage::PostgresBackend;
use std::sync::Arc;
use tracing::info;

/// Attestation gRPC server.
pub struct AttestationServer {
    config: AttestationConfig,
    storage: Arc<PostgresBackend>,
    /// Admits every call (`crate::access`).
    receiver: Arc<Receiver>,
}

impl AttestationServer {
    /// Create server with PostgreSQL storage and the receiver. The receiver
    /// holds public trust material and its own checker credential only; one
    /// that cannot authenticate at its issuer stops the start.
    pub async fn new(config: AttestationConfig) -> anyhow::Result<Self> {
        let storage = Arc::new(
            PostgresBackend::new(&config.database_url, None)
                .await
                .map_err(|e| anyhow::anyhow!("database connection failed: {e}"))?,
        );
        let receiver = Arc::new(Receiver::connect("sid-attestation", &config.api).await?);
        Ok(Self {
            config,
            storage,
            receiver,
        })
    }

    /// Run the gRPC server until shutdown signal, then stop as every SID
    /// service does ([`sid_serve::run`]).
    pub async fn serve(self) -> anyhow::Result<()> {
        let reflection_svc = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(sid_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        let storage: Arc<dyn sid_plugin::StorageBackend> = self.storage;
        let keys = sid_authn::field_keys::field_key_manager(
            storage.as_ref(),
            &self.config.master_key_file,
            Arc::new(sid_crypto::AwsLcPrimitives::new()),
        )
        .await
        .map_err(|e| anyhow::anyhow!("field keys: {e}"))?;
        let attestation_svc = AttestationServiceImpl::new(storage, keys);

        let drain = sid_serve::shutdown::drain_interval_from_env()?;
        let mut services = sid_serve::Services::new();
        services
            .route(reflection_svc)
            .add(crate::access::guarded(
                AttestationServiceServer::new(attestation_svc),
                &self.receiver,
            ))
            .await;
        let listener = tokio::net::TcpListener::bind(self.config.grpc_bind).await?;
        info!(bind = %self.config.grpc_bind, "gRPC server starting");
        sid_serve::serve(listener, services, sid_serve::shutdown::signal(), drain).await?;

        info!("sid-attestation shutdown complete");
        Ok(())
    }
}
