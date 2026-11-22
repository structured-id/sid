// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Server
//!
//! Main entry point for the StructuredID CE identity provider: its gRPC
//! services, and their HTTP form through the embedded transcoder.

use tracing::info;

use sid_serve::shutdown;
use sid_server::serve::{CeServices, serve};

fn main() -> anyhow::Result<()> {
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("another TLS crypto provider is already installed"))?;
    sid_crypto::jwt::install_jwt_provider()?;
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

    // The installation's own web UI, when the image carries its bundles: it
    // brings the account settings its pages sign in with.
    #[cfg(feature = "ui")]
    let ui = match sid_server::init::env_setting("SID_ISSUER")? {
        Some(issuer) => {
            let data = sid_server::init::env_setting("SID_DATA_DIR")?
                .unwrap_or_else(|| "/var/lib/sid".to_owned());
            sid_server::ui::prepare(&issuer, std::path::Path::new(&data))?
        }
        None => None,
    };
    #[cfg(feature = "ui")]
    let (ui, account) = match ui {
        Some((prepared, account)) => (Some(prepared), Some(account)),
        None => (None, None),
    };
    #[cfg(not(feature = "ui"))]
    let account = None;

    let c = sid_server::init::init_ce_with(sid_server::init::CeHost {
        account,
        ..Default::default()
    })
    .await?;
    #[allow(unused_mut)]
    let mut services = CeServices::new(&c, Default::default()).await?;
    #[cfg(feature = "ui")]
    if let Some(prepared) = ui {
        let started = sid_server::ui::start(&c, prepared).await?;
        services
            .add(sid_proto::sid::v1::authn::application_session_service_server::ApplicationSessionServiceServer::from_arc(started.adapter))
            .await;
        services.add_routes(started.routes);
        services.add_mount("/account", started.account_api);
        info!("web UI served: account pages and administration console");
    }
    serve(c, services, shutdown::signal()).await?;

    info!("Server shutdown complete");
    Ok(())
}
