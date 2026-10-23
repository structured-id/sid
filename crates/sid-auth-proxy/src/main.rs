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

use secrecy::SecretString;
use sid_auth_proxy::config::ProxyConfig;
use sid_auth_proxy::shield::Shield;
use sid_auth_proxy::{ProxyState, api_client, bff, health, metrics};
use sid_authn::bff_session::BffSessionStore;
use sid_authn::client_key::ClientKey;
use sid_infra::issuer_client::RpClient;

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

    // Issuer calls end within a bound, their whole answer included.
    let issuer_channel = sid_infra::deadline::issuer(grpc_channel.clone());
    let issuers = Arc::new(sid_authn::issuer_directory::IssuerDirectory::new(
        config.issuer_url(),
        Arc::new(sid_infra::issuer_registry::GrpcIssuerSource::new(
            issuer_channel.clone(),
        )),
    ));
    // A configured key that cannot be read is a broken deployment, not a
    // BFF quietly switched off.
    let account = match config.bff_client_key() {
        Some(path) => {
            let pem = SecretString::from(
                std::fs::read_to_string(path)
                    .with_context(|| format!("BFF client key {path:?} cannot be read"))?,
            );
            let key = ClientKey::ed25519_from_pem(&pem)
                .with_context(|| format!("BFF client key {path:?}"))?;
            let installation_url = config.issuer_url().to_string();
            // A delivered bundle that cannot be read or validated stops the
            // BFF here, never falls back to discovering another connection.
            let link = match config.bff_connection() {
                Some(path) => {
                    let kid = key
                        .kid()
                        .ok_or_else(|| anyhow::anyhow!("the BFF client key names no key id"))?
                        .to_owned();
                    let connection = sid_infra::issuer_client::load_connection(
                        std::path::Path::new(path),
                        &installation_url,
                        &kid,
                    )?;
                    tracing::info!(
                        issuer = %connection.issuer,
                        client_id = %connection.client_id,
                        resource = %connection.resource,
                        "BFF connection delivered"
                    );
                    RpClient::delivered(key, installation_url, issuer_channel.clone(), connection)?
                }
                None => RpClient::new(key, installation_url, issuer_channel.clone())?,
            };
            tracing::info!(kid = %link.kid(), "BFF client key loaded");
            Some(Arc::new(link))
        }
        None => None,
    };
    if config.bff_connection().is_some() && account.is_none() {
        anyhow::bail!("a BFF connection is configured without the client key that signs for it");
    }
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
    let (key, pem) = ClientKey::generate_ed25519()?;
    write_new(
        private_path,
        secrecy::ExposeSecret::expose_secret(&pem).as_bytes(),
        0o600,
    )?;
    let jwks = serde_json::to_vec_pretty(&key.public_jwks())?;
    write_new(public_path, &jwks, 0o644)?;
    println!(
        "client key {} written: private {private_path}, public {public_path}",
        key.kid().unwrap_or("?")
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
