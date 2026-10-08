// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID application proxy (PEP): standalone binary.
//!
//! BFF sessions and auth translation; access decisions come from sid-auth.
//!
//! ```bash
//! sid-auth-proxy --config sid-auth-proxy.yaml
//! sid-auth-proxy keygen <private-key.pem> <public-jwks.json>
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use sid_auth_proxy::account::AccountLink;
use sid_auth_proxy::client_key::ClientKey;
use sid_auth_proxy::config::ProxyConfig;
use sid_auth_proxy::session::BffSessionStore;
use sid_auth_proxy::shield::Shield;
use sid_auth_proxy::{ProxyState, api_client, bff, health, metrics};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("keygen") {
        return keygen(&args[2..]);
    }

    let config = load_config();

    tracing::info!(
        bind = %config.bind_addr(),
        upstream = %config.grpc_upstream(),
        issuer = %config.issuer_url(),
        "Starting sid-auth-proxy"
    );

    let grpc_channel = tonic::transport::Channel::from_shared(config.grpc_upstream().to_string())
        .expect("invalid gRPC upstream URL")
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(5))
        .connect_lazy();

    // One cache for both things replicas must agree on: the sessions below
    // and the rate-limit counters inside Shield.
    let cache = sid_auth::shared_cache(config.cache_url()).await?;
    // Revocations made anywhere reach this process before it answers.
    let revocation = sid_auth::revocation_view(cache.clone());
    revocation.listen().await?;

    let issuers = Arc::new(sid_auth::issuers::IssuerDirectory::new(
        config.issuer_url(),
        Arc::new(sid_auth::issuers::GrpcIssuerSource::new(
            grpc_channel.clone(),
        )),
    ));
    // A configured key that cannot be read is a broken deployment, not a
    // BFF quietly switched off.
    let account = match config.bff_client_key() {
        Some(path) => {
            let pem = std::fs::read(path)
                .with_context(|| format!("BFF client key {path:?} cannot be read"))?;
            let key =
                ClientKey::from_pem(&pem).with_context(|| format!("BFF client key {path:?}"))?;
            tracing::info!(kid = %key.kid(), "BFF client key loaded");
            Some(Arc::new(AccountLink::new(
                key,
                config.issuer_url().to_string(),
                grpc_channel.clone(),
            )))
        }
        None => None,
    };
    if config.bff_enabled() && account.is_none() {
        tracing::warn!("BFF enabled without a client key: its endpoints stay off");
    }
    let api_upstream = config
        .bff_api_upstream()
        .map(|url| url::Url::parse(url).with_context(|| format!("BFF API upstream {url:?}")))
        .transpose()?;

    let state = ProxyState {
        issuer_url: config.issuer_url().to_string(),
        issuers,
        grpc_channel,
        revocation,
        bff_enabled: config.bff_enabled(),
        account,
        api_upstream,
        http: api_client(),
        bff_sessions: Arc::new(BffSessionStore::new(
            cache.clone(),
            std::time::Duration::from_secs(config.bff_max_age()),
            std::time::Duration::from_secs(config.bff_idle_timeout()),
            std::time::Duration::from_secs(config.bff_pending_ttl()),
        )),
        bff_cookie_name: config.bff_cookie_name().to_string(),
        bff_dev_mode: config.bff_dev_mode(),
    };

    let cors = if config.cors_origins().is_empty() {
        tracing::info!("no CORS origins: same-origin mode (no CORS headers)");
        CorsLayer::new()
    } else {
        let origins: Vec<_> = config
            .cors_origins()
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
            .allow_credentials(true)
    };

    let shield = Shield::new(config.shield.to_shield_config(), cache);

    let router = Router::new()
        .merge(bff::routes())
        .merge(health::routes())
        .layer(cors)
        .layer(axum::middleware::from_fn(
            sid_auth_proxy::shield::shield_middleware,
        ))
        .layer(axum::Extension(shield.clone()))
        .layer(axum::middleware::from_fn(metrics::metrics_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = config.bind_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Background: shield cleanup every 5 minutes.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            shield.cleanup();
        }
    });

    tracing::info!("sid-auth-proxy listening on {}", addr);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// `keygen <private-key.pem> <public-jwks.json>`: a new client key. The
/// private key is written readable by its owner only and never printed; the
/// public JWK Set is what SID registers (`SID_ACCOUNT_CLIENT_JWKS`). An
/// existing file is never overwritten: replacing a registered key would lock
/// the BFF out.
fn keygen(args: &[String]) -> anyhow::Result<()> {
    let [private_path, public_path] = args else {
        anyhow::bail!("usage: sid-auth-proxy keygen <private-key.pem> <public-jwks.json>");
    };
    let (key, pem) = ClientKey::generate()?;
    write_new(private_path, pem.as_bytes(), 0o600)?;
    let jwks = serde_json::to_vec_pretty(&key.public_jwks())?;
    write_new(public_path, &jwks, 0o644)?;
    println!(
        "client key {} written: private {private_path}, public {public_path}",
        key.kid()
    );
    Ok(())
}

/// Create `path` with `contents`, refusing an existing file.
fn write_new(path: &str, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("{path:?} cannot be created (it must not exist yet)"))?;
    file.write_all(contents)
        .with_context(|| format!("writing {path:?}"))
}

/// Load config from --config flag or fall back to env vars.
fn load_config() -> ProxyConfig {
    let args: Vec<String> = std::env::args().collect();

    if let Some(pos) = args.iter().position(|a| a == "--config") {
        if let Some(path) = args.get(pos + 1) {
            match ProxyConfig::from_yaml(path) {
                Ok(config) => return config,
                Err(e) => {
                    eprintln!("Error loading config from {}: {}", path, e);
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("--config requires a path argument");
            std::process::exit(1);
        }
    }

    ProxyConfig::from_env()
}
