// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Authorization Service — standalone binary.
//!
//! gRPC authorization server: RBAC + Cedar ABAC.
//! CE standalone deployment: one of 4 containers (sid-identity + sid-authz + sid-proxy + sid-notify).
//!
//! Can also be used as a library (embedded mode) in sid-server monolith.

#![allow(unused_imports, unused_variables)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sid_proto::sid::v1::authz_service_server::AuthzServiceServer;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = sid_authz::config::AuthzConfig::from_env();
    info!(
        bind = %config.bind_addr,
        "Starting sid-authz v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Storage backend — initialized by the deployer (sid-server in embedded mode,
    // or directly here in standalone mode). For now, standalone requires an external
    // storage setup. The binary connects to the same database as sid-identity.
    //
    // TODO: Initialize storage backend from DATABASE_URL when sid-storage
    // exposes a public constructor. Currently sid-storage is tightly coupled
    // to sid-server's initialization. This will be resolved when sid-storage
    // gets a standalone init API.
    //
    // For now, this binary serves as the entry point structure.
    // Integration with sid-storage will be added in the next iteration.

    let maintenance_mode = Arc::new(AtomicBool::new(config.maintenance_mode));

    info!(
        maintenance = config.maintenance_mode,
        db = %config.database_url.split('@').next_back().unwrap_or("***"),
        "Configuration loaded"
    );

    // Placeholder: storage init will go here once sid-storage exposes standalone init.
    // For embedded mode (sid-server), CeAuthzEngine is created with the shared storage.
    //
    // Standalone mode pattern:
    //   let storage = sid_storage::connect(&config.database_url).await?;
    //   let engine = Arc::new(sid_authz::CeAuthzEngine::new(storage.clone()));
    //   let cedar = sid_authz::cedar::CedarService::new();
    //   let svc = sid_authz::grpc::AuthzServiceImpl::new(engine, storage, cedar, maintenance_mode);
    //   Server::builder().add_service(AuthzServiceServer::new(svc)).serve(addr).await?;

    info!("sid-authz standalone binary structure ready");
    info!("Standalone storage init pending — use embedded mode (sid-server) for now");

    // When storage is available, serve:
    // Server::builder()
    //     .add_service(AuthzServiceServer::new(svc))
    //     .serve(config.bind_addr)
    //     .await?;

    Ok(())
}
