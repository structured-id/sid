// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID forward-auth decision service (PDP).
//!
//! Decides whether a request may reach a protected application, for reverse
//! proxies and Envoy:
//! - `sid.v1.authz.ForwardAuthService/Verify`, served over HTTP as
//!   `/auth/verify/{application}` by the embedded transcoder (`http` feature);
//! - `envoy.service.auth.v3.Authorization/Check` (ext_authz);
//! - gRPC health.
//!
//! No browser sessions, redirects or proxying: those belong to the
//! application proxy (sid-auth-proxy).

pub mod auth;
pub mod config;
pub mod issuers;
pub mod receiver;
pub mod server;

use std::sync::Arc;

/// The shared cache at `url`, or one kept in this process when unset.
pub async fn shared_cache(
    url: Option<&str>,
) -> anyhow::Result<Arc<dyn sid_plugin::cache::CacheBackend>> {
    Ok(sid_infra::shared_cache(url).await?)
}

/// A revocation view over `cache` for a verifier that does not know the
/// issuer's access-token lifetime: it assumes the longest allowed one.
pub fn revocation_view(
    cache: Arc<dyn sid_plugin::cache::CacheBackend>,
) -> Arc<sid_authn::revocation_cache::RevocationCache> {
    let lifetime = sid_authn::jwt::AccessTokenTtl::MAX
        .duration()
        .to_std()
        .expect("the longest access-token lifetime is positive");
    Arc::new(sid_authn::revocation_cache::RevocationCache::new(
        lifetime, cache,
    ))
}

/// Issuers and resources the tests know: fixed sets of records.
#[cfg(test)]
pub(crate) struct TestIssuers {
    pub issuers: Vec<issuers::IssuerRecord>,
    pub resources: Vec<issuers::ResourceRecord>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl issuers::IssuerSource for TestIssuers {
    async fn issuer(&self, handle: &str) -> Result<Option<issuers::IssuerRecord>, tonic::Status> {
        Ok(self
            .issuers
            .iter()
            .find(|record| record.issuer.ends_with(&format!("/i/{handle}")))
            .cloned())
    }

    async fn resource(
        &self,
        handle: &str,
        resource: &str,
    ) -> Result<Option<issuers::ResourceRecord>, tonic::Status> {
        Ok(self
            .resources
            .iter()
            .find(|record| {
                record.issuer.ends_with(&format!("/i/{handle}")) && record.resource == resource
            })
            .cloned())
    }
}

/// An issuer directory under `https://sid.example.com` knowing `issuers` and
/// `resources`.
#[cfg(test)]
pub(crate) fn test_issuers_with(
    issuers: Vec<issuers::IssuerRecord>,
    resources: Vec<issuers::ResourceRecord>,
) -> Arc<issuers::IssuerDirectory> {
    Arc::new(issuers::IssuerDirectory::new(
        "https://sid.example.com",
        Arc::new(TestIssuers { issuers, resources }),
    ))
}

/// A lazy channel to nowhere, for tests.
#[cfg(test)]
pub(crate) fn test_channel() -> tonic::transport::Channel {
    tonic::transport::Channel::from_static("http://127.0.0.1:1")
        .connect_timeout(std::time::Duration::from_millis(100))
        .connect_lazy()
}
