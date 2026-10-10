// SPDX-License-Identifier: AGPL-3.0-only
//! The decision service: its gRPC services and, with the `http` feature, the
//! embedded transcoder that serves `ForwardAuthService.Verify` over HTTP.

use std::future::Future;
use std::sync::Arc;

use envoy_types::pb::envoy::service::auth::v3::authorization_server::AuthorizationServer;
use sid_proto::sid::v1::authz::forward_auth_service_server::ForwardAuthServiceServer;
use tonic::service::Routes;

use crate::auth::decision::Pdp;
use crate::auth::ext_authz::ExtAuthzImpl;
use crate::auth::forward_auth_grpc::ForwardAuthServiceImpl;
use crate::auth::policy::PolicyEngine;
use crate::config::AuthConfig;
use crate::issuers::{GrpcIssuerSource, IssuerDirectory};

/// Request headers the transcoder hands to `Verify` as metadata: the
/// original request as the reverse proxy forwards it. Forwarding them is
/// part of the contract, not a deployment choice.
#[cfg(feature = "http")]
pub const FORWARDED_HEADERS: [&str; 6] = [
    "authorization",
    "dpop",
    "x-original-uri",
    "x-original-method",
    "x-forwarded-uri",
    "x-forwarded-method",
];

pub struct AuthServer {
    config: AuthConfig,
    pdp: Arc<Pdp>,
}

impl AuthServer {
    /// Build the service. A route file that does not load stops start-up: a
    /// typo must not leave every protected application refused, or worse,
    /// silently configured differently than written.
    pub fn new(
        config: AuthConfig,
        cache: Arc<dyn sid_plugin::cache::CacheBackend>,
    ) -> anyhow::Result<Self> {
        let applications = match &config.route_policy_path {
            Some(path) => PolicyEngine::load(path)
                .map_err(|e| anyhow::anyhow!("route policies {path}: {e}"))?,
            None => {
                tracing::warn!("no route policy file: every forward-auth request is refused");
                PolicyEngine::empty()
            }
        };
        let upstream = tonic::transport::Channel::from_shared(config.upstream.clone())
            .map_err(|e| anyhow::anyhow!("upstream {}: {e}", config.upstream))?
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(5))
            .connect_lazy();
        let checker = config
            .authz_checker
            .as_ref()
            .map(|checker| {
                sid_authn::client_credential::ClientCredential::checker(
                    checker,
                    &config.issuer_url,
                    upstream.clone(),
                )
                .map(Arc::new)
            })
            .transpose()?;
        let pdp = Arc::new(Pdp {
            issuers: Arc::new(IssuerDirectory::new(
                &config.issuer_url,
                Arc::new(GrpcIssuerSource::new(upstream.clone())),
            )),
            applications: Arc::new(applications),
            revocation: crate::revocation_view(cache.clone()),
            dpop: Arc::new(sid_authn::dpop::DPopValidator::new(cache)),
            authz: upstream,
            checker,
            login_url: config.login_url.clone(),
        });
        Ok(Self { config, pdp })
    }

    /// The decision this service gives.
    pub fn pdp(&self) -> &Arc<Pdp> {
        &self.pdp
    }

    /// The gRPC services, with gRPC health reporting each serving.
    pub async fn routes(&self) -> Routes {
        self.services().await.into_parts().0
    }

    /// The gRPC services of this process, each reported on gRPC health.
    async fn services(&self) -> sid_serve::Services {
        let mut services = sid_serve::Services::new();
        services
            .add(ForwardAuthServiceServer::new(ForwardAuthServiceImpl::new(
                self.pdp.clone(),
            )))
            .await
            .add(AuthorizationServer::new(ExtAuthzImpl::new(
                self.pdp.clone(),
            )))
            .await;
        services
    }

    /// The embedded transcoder for the HTTP form of `Verify`; `None` when no
    /// HTTP form is configured. It calls this service's own gRPC services in
    /// process ([`Self::routes`]).
    #[cfg(feature = "http")]
    pub fn http_proxy(&self) -> anyhow::Result<Option<structured_proxy::ProxyServer>> {
        self.config
            .http
            .as_ref()
            .map(|http| {
                sid_infra::http::embedded_transcoder(http, &FORWARDED_HEADERS, |name| {
                    name == sid_proto::FORWARD_AUTH_PROTO
                })
            })
            .transpose()
    }

    /// Serve until the listeners fail or `shutdown` resolves. On shutdown the
    /// health service reports not serving, so load balancers stop routing
    /// here, and both listeners stop accepting while calls in flight get the
    /// process's drain interval.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
        // Revocations made anywhere reach this process before it answers.
        self.pdp.revocation.listen().await?;
        let drain = sid_serve::shutdown::drain_interval_from_env()?;
        let listener = tokio::net::TcpListener::bind(&self.config.grpc_listen).await?;
        let grpc_addr = listener.local_addr()?;
        let (routes, health) = self.services().await.into_parts();
        tracing::info!(%grpc_addr, "sid-auth gRPC listening");
        let (stopper, stopped) = sid_serve::stop_signal();
        // The forward-auth sub-request of every protected request reaches the
        // decision in process, with no hop to the gRPC listener.
        #[cfg(feature = "http")]
        let http = self.http_proxy()?.map(|proxy| (proxy, routes.clone()));
        let grpc = tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                stopped.clone().wait(),
            );
        let serving = async move {
            let grpc = async { grpc.await.map_err(anyhow::Error::from) };
            #[cfg(feature = "http")]
            if let Some((proxy, routes)) = http {
                tracing::info!(bind = %proxy.config().listen.http, "sid-auth HTTP listening");
                let http = sid_infra::http::serve(&proxy, routes, stopped.wait(), drain);
                return tokio::try_join!(grpc, http).map(|_| ());
            }
            grpc.await
        };
        sid_serve::run(serving, shutdown, &health, &stopper, drain).await
    }
}

#[cfg(test)]
mod tests;
