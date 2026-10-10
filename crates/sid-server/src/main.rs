// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Server
//!
//! Main entry point for the StructuredID CE identity provider: its gRPC
//! services, and their HTTP form through the embedded transcoder.

use tracing::info;

use sid_serve::shutdown;
use sid_server::init::{init_ce, spawn_ce_background_tasks};
use sid_server::serve::{CeServices, serve};

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run());
    // Blocking work still running once the server has stopped (the ZKPP
    // verifying keys being prepared, say) serves nothing any more; waiting
    // for it would hold the exit past the drain interval.
    runtime.shutdown_background();
    result
}

async fn run() -> anyhow::Result<()> {
    let _telemetry_guard =
        sid_server::telemetry::init_telemetry().expect("Failed to initialize telemetry");

    info!("Starting StructuredID v{}", env!("CARGO_PKG_VERSION"));

    let c = init_ce().await?;
    spawn_ce_background_tasks(&c);
    let services = CeServices::new(&c).await?;
    serve(c, services, shutdown::signal()).await?;

    info!("Server shutdown complete");
    Ok(())
}
