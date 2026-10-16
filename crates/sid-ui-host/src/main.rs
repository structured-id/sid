// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID UI host as a standalone service: serves one compiled UI
//! bundle and its public configuration.
//!
//! - `SID_UI_BUNDLE`: the bundle directory (the SPA build output);
//! - `SID_UI_MOUNT`: where it is served, such as `/account/` (default `/`);
//! - `SID_UI_CONFIG`: the deployment's public configuration file (JSON);
//! - `SID_UI_BIND`: listen address (default `0.0.0.0:8080`).
//!
//! `GET /health` answers once the bundle and configuration were accepted.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use axum::Router;
use axum::routing::get;
use sid_ui_host::{UiBundle, router};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let dir = PathBuf::from(required("SID_UI_BUNDLE")?);
    let mount = std::env::var("SID_UI_MOUNT").unwrap_or_else(|_| "/".to_owned());
    let config_path = required("SID_UI_CONFIG")?;
    let config = std::fs::read(&config_path)
        .with_context(|| format!("public configuration {config_path:?} cannot be read"))?;
    // A bundle or configuration that cannot be served stops the service:
    // there is no other environment's configuration to fall back to.
    let bundle = UiBundle::new(&dir, &mount, &config)?;

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(router(bundle));

    let bind = std::env::var("SID_UI_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("SID_UI_BIND {bind:?}"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, bundle = %dir.display(), %mount, "sid-ui-host listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

/// Resolves on SIGTERM (a pod stopping) or Ctrl-C.
async fn shutdown() {
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::warn!("no SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
}
