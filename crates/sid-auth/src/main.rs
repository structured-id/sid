// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID forward-auth decision service: standalone binary.
//!
//! ```bash
//! sid-auth --config sid-auth.yaml   # YAML config
//! sid-auth                          # SID_* environment variables
//! ```

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = load_config()?;
    tracing::info!(
        grpc = %config.grpc_listen,
        upstream = %config.upstream,
        issuer = %config.issuer_url,
        "starting sid-auth"
    );
    let cache = sid_auth::shared_cache(config.cache_url.as_deref()).await?;
    sid_auth::server::AuthServer::new(config, cache)?
        .serve(sid_serve::shutdown::signal())
        .await
}

/// The config file named by `--config`, else the environment.
fn load_config() -> anyhow::Result<sid_auth::config::AuthConfig> {
    let args: Vec<String> = std::env::args().collect();
    match args.iter().position(|a| a == "--config") {
        Some(pos) => {
            let path = args
                .get(pos + 1)
                .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?;
            sid_auth::config::AuthConfig::from_yaml(path)
        }
        None => sid_auth::config::AuthConfig::from_env(),
    }
}
