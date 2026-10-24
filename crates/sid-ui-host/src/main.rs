// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID UI host as a standalone service: serves one compiled UI
//! bundle and its public configuration and, for an application with a
//! browser adapter, signs its users in and calls its API as them.
//!
//! - `SID_UI_BUNDLE`: the bundle directory (the SPA build output);
//! - `SID_UI_MOUNT`: where it is served, such as `/account/` (default `/`);
//! - `SID_UI_CONFIG`: the deployment's public configuration file (JSON);
//! - `SID_UI_SETTINGS_SOURCE`: the gRPC address of the installation whose
//!   public UI settings the configuration carries, followed live; unset, the
//!   deployment's configuration is served alone;
//! - `SID_UI_BIND`: listen address (default `0.0.0.0:8080`).
//!
//! The browser adapter is on when `SID_UI_CLIENT_KEY_FILE` names the
//! application client's private key (PKCS#8 PEM, Ed25519):
//! - `SID_UI_INSTALLATION_URL`: the installation's public URL, under which
//!   the client's issuer lives;
//! - `SID_UI_ISSUER_GRPC`: the installation's gRPC address (registry, token
//!   endpoint, account connection);
//! - `SID_UI_CONNECTION_FILE`: the connection bundle the installation
//!   delivered; unset, the connection is asked of the account API;
//! - `SID_UI_SESSION_COOKIE`: the session cookie's `__Host-` name;
//! - `SID_UI_API_UPSTREAM`: the gRPC address of the application's API; unset,
//!   the page calls only the adapter;
//! - `SID_CACHE_URL`: the cache the replicas share sessions through;
//!   required, as a host behind a load balancer completes sign-ins another
//!   replica started.
//!
//! `GET /health` answers once the bundle and configuration were accepted and,
//! with a settings source, once its first projection arrived.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use secrecy::SecretString;
use sid_authn::bff_session::BffSessionStore;
use sid_authn::client_key::ClientKey;
use sid_authn::issuer_directory::IssuerDirectory;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::issuer_client::{RpClient, load_connection};
use sid_infra::issuer_registry::GrpcIssuerSource;
use sid_ui_host::application_session::{ApplicationSessions, FORWARDED_HEADERS};
use sid_ui_host::host::{
    ADAPTER_PROTO, HostUpstream, asset_routes, issuer_channel, required_shared_cache,
};
use sid_ui_host::{GrpcSettingsSource, Retry, UiBundle, follow, standalone};
use tracing_subscriber::EnvFilter;

/// A session lasts at most this long, however active.
const SESSION_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// A session ends after this long unused.
const SESSION_IDLE: Duration = Duration::from_secs(3600);
/// A started sign-in waits this long for its callback.
const SIGN_IN_TTL: Duration = Duration::from_secs(300);
/// Calls in flight at shutdown get this long to finish.
const DRAIN: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    sid_crypto::jwt::install_jwt_provider()?;

    let dir = PathBuf::from(required("SID_UI_BUNDLE")?);
    let mount = std::env::var("SID_UI_MOUNT").unwrap_or_else(|_| "/".to_owned());
    let config_path = required("SID_UI_CONFIG")?;
    let config = std::fs::read(&config_path)
        .with_context(|| format!("public configuration {config_path:?} cannot be read"))?;
    // A bundle or configuration that cannot be served stops the service:
    // there is no other environment's configuration to fall back to.
    let bundle = match std::env::var("SID_UI_SETTINGS_SOURCE") {
        Ok(source) => {
            let endpoint = tonic::transport::Endpoint::from_shared(source.clone())
                .with_context(|| format!("SID_UI_SETTINGS_SOURCE {source:?}"))?;
            let (bundle, sink) = UiBundle::live(&dir, &mount, &config)?;
            tokio::spawn(follow(
                sink,
                GrpcSettingsSource::new(endpoint),
                Retry::default(),
            ));
            tracing::info!(%source, "following the public UI settings");
            bundle
        }
        Err(_) => UiBundle::new(&dir, &mount, &config)?,
    };
    let app = standalone(bundle)?;

    let bind = std::env::var("SID_UI_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("SID_UI_BIND {bind:?}"))?;

    let Ok(key_file) = std::env::var("SID_UI_CLIENT_KEY_FILE") else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, bundle = %dir.display(), %mount, "sid-ui-host listening");
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown())
            .await?;
        return Ok(());
    };

    let sessions = Arc::new(adapter(&key_file).await?);
    let api = match std::env::var("SID_UI_API_UPSTREAM") {
        Ok(api) => Some(
            tonic::transport::Endpoint::from_shared(api.clone())
                .with_context(|| format!("SID_UI_API_UPSTREAM {api:?}"))?
                .connect_lazy(),
        ),
        Err(_) => None,
    };
    let transcoder_config = serde_json::json!({
        "listen": { "http": bind },
        // The bundle's router answers `/health`; the transcoder's probes would
        // ask the in-process services for a gRPC health they do not serve.
        "health": { "enabled": false },
    });
    let proxy =
        sid_infra::http::embedded_transcoder(&transcoder_config, &FORWARDED_HEADERS, |file| {
            file == ADAPTER_PROTO
        })?
        // The hosted API speaks gRPC; the page calls it over gRPC-Web.
        .with_grpc_web_translation(true)
        .with_extra_routes(asset_routes(app));
    tracing::info!(%addr, bundle = %dir.display(), %mount, "sid-ui-host listening with its browser adapter");
    sid_infra::http::serve(&proxy, HostUpstream::new(sessions, api), shutdown(), DRAIN).await
}

/// The browser adapter the environment configures, with the client key at
/// `key_file`.
async fn adapter(key_file: &str) -> anyhow::Result<ApplicationSessions> {
    let installation = required("SID_UI_INSTALLATION_URL")?;
    let issuer_grpc = required("SID_UI_ISSUER_GRPC")?;
    let cookie = required("SID_UI_SESSION_COOKIE")?;
    // The session and correlation cookies are host-only (RFC 6265bis §4.1.3.2).
    anyhow::ensure!(
        cookie.starts_with("__Host-"),
        "SID_UI_SESSION_COOKIE {cookie:?} must be a __Host- cookie"
    );
    let pem = SecretString::from(
        std::fs::read_to_string(key_file)
            .with_context(|| format!("SID_UI_CLIENT_KEY_FILE {key_file:?} cannot be read"))?,
    );
    let key = ClientKey::ed25519_from_pem(&pem).context("SID_UI_CLIENT_KEY_FILE")?;
    let channel = issuer_channel(&issuer_grpc)
        .with_context(|| format!("SID_UI_ISSUER_GRPC {issuer_grpc:?}"))?;
    let client = match std::env::var("SID_UI_CONNECTION_FILE") {
        Ok(path) => {
            let kid = key
                .kid()
                .context("the client key names no key id")?
                .to_owned();
            let connection = load_connection(std::path::Path::new(&path), &installation, &kid)?;
            tracing::info!(
                issuer = %connection.issuer,
                client_id = %connection.client_id,
                resource = %connection.resource,
                "connection delivered"
            );
            RpClient::delivered(key, installation.clone(), channel.clone(), connection)?
        }
        Err(_) => RpClient::new(key, installation.clone(), channel.clone())?,
    };

    let cache_url = required_shared_cache(sid_infra::cache_url_from_env())?;
    let cache = sid_infra::shared_cache(Some(&cache_url)).await?;
    let lifetime = sid_authn::jwt::AccessTokenTtl::MAX
        .duration()
        .to_std()
        .context("the longest access-token lifetime is positive")?;
    let revocation = Arc::new(RevocationCache::new(lifetime, cache.clone()));
    // Revocations made anywhere reach this process before it answers.
    revocation.listen().await?;
    Ok(ApplicationSessions::new(
        Arc::new(client),
        Arc::new(IssuerDirectory::new(
            &installation,
            Arc::new(GrpcIssuerSource::new(channel)),
        )),
        Arc::new(BffSessionStore::new(
            cache,
            SESSION_MAX_AGE,
            SESSION_IDLE,
            SIGN_IN_TTL,
        )),
        revocation,
        cookie,
    ))
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
