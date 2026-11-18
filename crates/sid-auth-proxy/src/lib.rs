// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID application proxy (PEP): BFF sign-in for SPAs with
//! server-side sessions, auth translation for legacy upstreams. Access
//! decisions come from the decision service (sid-auth).

pub mod api;
pub mod bff;
pub mod config;
pub mod health;
pub mod metrics;
pub mod registry;
pub mod shield;
pub mod translation;

use std::sync::Arc;

use sid_authn::application_session::BrowserSessions;
#[cfg(test)]
use sid_authn::issuer_directory::IssuerDirectory;
use sid_infra::issuer_client::RpClient;

#[cfg(test)]
#[path = "../../../tests/support/crypto.rs"]
mod test_crypto;

/// Shared state of the proxy's handlers.
#[derive(Clone, Debug)]
pub struct ProxyState {
    /// Lazy gRPC channel to the SID server (health).
    pub grpc_channel: tonic::transport::Channel,
    /// The BFF's browser sessions as the account integration's client; absent
    /// when the BFF is off or has no client key, and its endpoints then answer
    /// 404.
    pub bff: Option<Arc<BrowserSessions<RpClient>>>,
    /// Where `/api/*` goes: the account API's gRPC-Web endpoint.
    pub api_upstream: Option<url::Url>,
    /// HTTP client for the account API. Follows no redirect: the API's
    /// answer goes back to the browser as it is.
    pub http: reqwest::Client,
    /// Dev mode: skip the Secure flag on cookies (localhost without HTTPS).
    pub bff_dev_mode: bool,
}

/// The HTTP client the BFF forwards API calls with.
pub fn api_client() -> Result<reqwest::Client, sid_plugin::http::HttpClientError> {
    Ok(sid_plugin::http::client_builder()?
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?)
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
    use sid_authn::issuer_directory::{
        IssuerRecord, IssuerSource, RegistryUnavailable, ResourceRecord,
    };
    struct NoIssuers;
    #[async_trait::async_trait]
    impl IssuerSource for NoIssuers {
        async fn issuer(&self, _handle: &str) -> Result<Option<IssuerRecord>, RegistryUnavailable> {
            Ok(None)
        }
        async fn resource(
            &self,
            _handle: &str,
            _resource: &str,
        ) -> Result<Option<ResourceRecord>, RegistryUnavailable> {
            Ok(None)
        }
    }
    Arc::new(IssuerDirectory::new(
        "https://sid.example.com",
        Arc::new(NoIssuers),
    ))
}

/// A proxy state for tests: the BFF off unless a test gives it its sessions.
#[cfg(test)]
pub(crate) fn test_state() -> ProxyState {
    ProxyState {
        grpc_channel: test_channel(),
        bff: None,
        api_upstream: None,
        http: test_crypto::with_tls(api_client),
        bff_dev_mode: false,
    }
}
