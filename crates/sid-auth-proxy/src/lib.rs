// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID application proxy (PEP): BFF sign-in for SPAs with
//! server-side sessions, auth translation for legacy upstreams. Access
//! decisions come from the decision service (sid-auth).

pub mod account;
pub mod api;
pub mod bff;
pub mod client_key;
pub mod config;
pub mod health;
pub mod metrics;
pub mod registry;
pub mod session;
pub mod shield;
pub mod translation;

use std::sync::Arc;

use session::BffSessionStore;
use sid_auth::issuers::IssuerDirectory;

/// Shared state of the proxy's handlers.
#[derive(Clone, Debug)]
pub struct ProxyState {
    /// The installation's public URL, the base of its issuers' URLs.
    pub issuer_url: String,
    /// The installation's OIDC issuers, whose tokens the BFF verifies.
    pub issuers: Arc<IssuerDirectory>,
    /// Lazy gRPC channel to the SID server (token endpoint, health).
    pub grpc_channel: tonic::transport::Channel,
    /// Revoked tokens and sessions, as every SID process records them.
    pub revocation: Arc<sid_authn::revocation_cache::RevocationCache>,
    /// Whether the BFF endpoints answer. Read through [`ProxyState::bff`],
    /// which also requires the client key.
    pub bff_enabled: bool,
    /// The BFF as the account integration's client; absent without a
    /// configured client key.
    pub account: Option<Arc<account::AccountLink>>,
    /// Where `/api/*` goes: the account API's gRPC-Web endpoint.
    pub api_upstream: Option<url::Url>,
    /// HTTP client for the account API. Follows no redirect: the API's
    /// answer goes back to the browser as it is.
    pub http: reqwest::Client,
    /// BFF session store, shared across replicas.
    pub bff_sessions: Arc<BffSessionStore>,
    /// BFF session cookie name (e.g., "__Host-sid-bff").
    pub bff_cookie_name: String,
    /// Dev mode: skip the Secure flag on cookies (localhost without HTTPS).
    pub bff_dev_mode: bool,
}

/// The HTTP client the BFF forwards API calls with.
pub fn api_client() -> reqwest::Client {
    sid_plugin::http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("an HTTP client with default TLS roots")
}

/// A lazy channel to nowhere, for tests.
#[cfg(test)]
pub(crate) fn test_channel() -> tonic::transport::Channel {
    tonic::transport::Channel::from_static("http://127.0.0.1:1")
        .connect_timeout(std::time::Duration::from_millis(100))
        .connect_lazy()
}

/// An issuer directory under `https://sid.example.com` that knows no issuer.
#[cfg(test)]
pub(crate) fn test_issuers() -> Arc<IssuerDirectory> {
    struct NoIssuers;
    #[async_trait::async_trait]
    impl sid_auth::issuers::IssuerSource for NoIssuers {
        async fn issuer(
            &self,
            _handle: &str,
        ) -> Result<Option<sid_auth::issuers::IssuerRecord>, tonic::Status> {
            Ok(None)
        }
        async fn resource(
            &self,
            _handle: &str,
            _resource: &str,
        ) -> Result<Option<sid_auth::issuers::ResourceRecord>, tonic::Status> {
            Ok(None)
        }
    }
    Arc::new(IssuerDirectory::new(
        "https://sid.example.com",
        Arc::new(NoIssuers),
    ))
}

/// A proxy state for tests: BFF switched on but without a client key, so its
/// endpoints are off unless a test gives it one.
#[cfg(test)]
pub(crate) fn test_state() -> ProxyState {
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    ProxyState {
        issuer_url: "https://sid.example.com".into(),
        issuers: test_issuers(),
        grpc_channel: test_channel(),
        revocation: sid_auth::revocation_view(cache.clone()),
        bff_enabled: true,
        account: None,
        api_upstream: None,
        http: api_client(),
        bff_sessions: Arc::new(BffSessionStore::new(
            cache,
            std::time::Duration::from_secs(86400),
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(300),
        )),
        bff_cookie_name: "__Host-sid-bff".into(),
        bff_dev_mode: false,
    }
}
