// SPDX-License-Identifier: AGPL-3.0-only
//! The CE gRPC service set and the serving loop.
//!
//! Every binary that serves SID composes its
//! services from [`CeServices::new`] and runs them through [`serve`], so none of
//! them drops a CE service, leaves one out of the health report or runs without
//! the background work its services owe.

use std::convert::Infallible;
use std::future::Future;

use tonic::body::Body;
use tonic::codegen::{Service, http};
use tonic::server::NamedService;
use tonic::transport::Server as TonicServer;
use tracing::info;

use sid_proto::sid::v1::account::account_service_server::AccountServiceServer;
use sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentServiceServer;
#[cfg(feature = "scim")]
use sid_proto::sid::v1::admin::provisioning_service_server::ProvisioningServiceServer;
use sid_proto::sid::v1::admin::realm_service_server::RealmServiceServer;
use sid_proto::sid::v1::admin::security_service_server::SecurityServiceServer;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorServiceServer;
use sid_proto::sid::v1::authz::governance_service_server::GovernanceServiceServer;
use sid_proto::sid::v1::events::event_stream_service_server::EventStreamServiceServer;
#[cfg(feature = "scim")]
use sid_proto::sid::v1::scim_protocol_service_server::ScimProtocolServiceServer;
#[cfg(feature = "scim")]
use sid_proto::sid::v1::scim_service_server::ScimServiceServer;
#[cfg(feature = "dev-perf-test")]
use sid_proto::sid::v1::test_service_server::TestServiceServer;
use sid_proto::sid::v1::{
    admin_service_server::AdminServiceServer, auth_service_server::AuthServiceServer,
    authz_service_server::AuthzServiceServer, branding_service_server::BrandingServiceServer,
    flow_action_service_server::FlowActionServiceServer,
    flow_config_service_server::FlowConfigServiceServer,
    identity_service_server::IdentityServiceServer,
    oidc_issuer_service_server::OidcIssuerServiceServer,
    oidc_provider_service_server::OidcProviderServiceServer,
    project_service_server::ProjectServiceServer,
    system_integration_service_server::SystemIntegrationServiceServer,
};

use crate::init::{CeComponents, spawn_work_runner};

/// The services one server exposes: routed and reported on the gRPC health
/// service together.
pub struct CeServices {
    services: sid_serve::Services,
    #[cfg(feature = "dev-perf-test")]
    test_svc: std::sync::Arc<crate::grpc::test_service::TestServiceImpl>,
}

impl CeServices {
    /// Every CE service over `c`, with the SCIM outbound worker when targets
    /// are configured.
    pub async fn new(c: &CeComponents) -> anyhow::Result<Self> {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(sid_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;
        let mut served = sid_serve::Services::new();
        served.route(reflection);

        #[cfg(feature = "dev-perf-test")]
        let test_svc = spawn_test_service();

        let mut services = Self {
            services: served,
            #[cfg(feature = "dev-perf-test")]
            test_svc: test_svc.clone(),
        };
        services
            .add(IdentityServiceServer::from_arc(c.identity_svc.clone()))
            .await
            .add(AuthServiceServer::from_arc(c.auth_svc.clone()))
            .await
            .add(ProjectServiceServer::from_arc(c.project_svc.clone()))
            .await
            .add(OidcIssuerServiceServer::new(
                crate::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
                    c.issuers.clone(),
                    c.storage.clone(),
                ),
            ))
            .await
            .add(OidcProviderServiceServer::new(
                crate::grpc::oidc_provider_service::OidcProviderServiceImpl::new(
                    c.issuers.clone(),
                    c.storage.clone(),
                    c.revocation_cache.clone(),
                    c.cache_backend.clone(),
                    c.auth_svc.clone(),
                    c.project_svc.clone(),
                    c.login_url.clone(),
                ),
            ))
            .await
            .add(AuthzServiceServer::from_arc(c.authz_svc.clone()))
            .await
            .add(AdminServiceServer::from_arc(c.admin_svc.clone()))
            .await
            .add(BrandingServiceServer::from_arc(c.branding_svc.clone()))
            .await
            .add(FlowConfigServiceServer::from_arc(c.flow_config_svc.clone()))
            .await
            .add(FlowActionServiceServer::from_arc(c.flow_action_svc.clone()))
            .await
            .add(EnrollmentServiceServer::from_arc(c.enrollment_svc.clone()))
            .await
            .add(SecurityServiceServer::from_arc(c.security_svc.clone()))
            .await
            .add(GovernanceServiceServer::new(
                sid_authz::governance_grpc::GovernanceServiceImpl::new(
                    c.storage.clone(),
                    c.jwt.clone(),
                    c.revocation_cache.clone(),
                ),
            ))
            .await
            .add(EventStreamServiceServer::new(
                crate::grpc::event_stream_service::EventStreamServiceImpl::new(
                    c.event_bus.clone(),
                    c.jwt.clone(),
                    c.revocation_cache.clone(),
                ),
            ))
            .await
            .add(AccountServiceServer::from_arc(c.account_svc.clone()))
            .await
            .add(SystemIntegrationServiceServer::new(
                crate::grpc::system_integration_service::SystemIntegrationServiceImpl::new(
                    c.storage.clone(),
                    c.issuer.clone(),
                    c.cache_backend.clone(),
                ),
            ))
            .await
            .add(RealmServiceServer::new(
                crate::grpc::realm_service::RealmServiceImpl::new(
                    c.storage.clone(),
                    c.jwt.clone(),
                    c.revocation_cache.clone(),
                    c.key_manager.clone(),
                ),
            ))
            .await;

        // The VOPRF evaluator of password history, when it runs in this
        // process; a split deployment serves it from its own.
        if let Some(evaluator) = c.auth_svc.history_evaluator() {
            services
                .add(PasswordHistoryEvaluatorServiceServer::new(evaluator))
                .await;
        }

        #[cfg(feature = "scim")]
        {
            // One SCIM service: typed for gRPC callers, and behind the RFC 7644
            // HTTP endpoint SCIM clients use.
            let scim = std::sync::Arc::new(scim_service(c).await?);
            services
                .add(ScimProtocolServiceServer::new(
                    sid_scim::protocol::ScimProtocolServiceImpl::new(scim.clone()),
                ))
                .await;
            services.add(ScimServiceServer::from_arc(scim)).await;
            services
                .add(ProvisioningServiceServer::new(
                    crate::grpc::provisioning_service::ProvisioningServiceImpl::new(
                        c.storage.clone(),
                        c.jwt.clone(),
                        c.revocation_cache.clone(),
                        c.scim_issuer.clone(),
                        c.scim_resource.clone(),
                        format!("{}/scim/v2", scim_server_url(c)),
                    ),
                ))
                .await;
            start_scim_outbound(c).await?;
            info!("SCIM 2.0 inbound provisioning enabled");
        }

        #[cfg(feature = "dev-perf-test")]
        services.add(TestServiceServer::from_arc(test_svc)).await;

        Ok(services)
    }

    /// Serves `svc` beside the CE services and reports it serving.
    pub async fn add<S>(&mut self, svc: S) -> &mut Self
    where
        S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        self.services.add(svc).await;
        self
    }
}

/// The URL the SCIM endpoint is served under (its `/scim/v2` paths follow).
#[cfg(feature = "scim")]
fn scim_server_url(c: &CeComponents) -> String {
    std::env::var("SID_SCIM_BASE_URL").unwrap_or_else(|_| c.issuer.clone())
}

/// The SCIM endpoint: a connector authenticates by its SCIM bearer or by an
/// access token of the SCIM resource from its issuer.
#[cfg(feature = "scim")]
async fn scim_service(c: &CeComponents) -> anyhow::Result<sid_scim::grpc::ScimServiceImpl> {
    let tokens = sid_authn::resource_token::ResourceTokenVerifier::new(
        c.issuers.clone(),
        c.scim_issuer.clone(),
        c.scim_resource.indicator.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("SCIM resource token keys: {e}"))?;
    let base_url = scim_server_url(c);
    Ok(sid_scim::grpc::ScimServiceImpl::new(
        c.storage.clone(),
        sid_scim::mapping::ScimOrgContext::installation(&c.organization),
        base_url,
        c.scim_directory,
        c.authz_engine.clone(),
        c.revocation_cache.clone(),
    )
    .with_access_tokens(std::sync::Arc::new(tokens)))
}

/// Configured targets that cannot be loaded or served stop startup: running
/// without them would silently stop provisioning.
#[cfg(feature = "scim")]
async fn start_scim_outbound(c: &CeComponents) -> anyhow::Result<()> {
    let targets = c
        .storage
        .list_scim_outbound_targets(sid_core::models::ProjectId::system())
        .await
        .map_err(|e| anyhow::anyhow!("loading SCIM outbound targets: {e}"))?;
    if targets.is_empty() {
        return Ok(());
    }
    let worker = std::sync::Arc::new(sid_scim::outbound::worker::ScimOutboundWorker::new(
        c.storage.clone(),
        c.event_bus.clone(),
        targets,
    ));
    worker
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("SCIM outbound worker: {e}"))?;
    info!("SCIM outbound worker started");
    Ok(())
}

#[cfg(feature = "dev-perf-test")]
fn spawn_test_service() -> std::sync::Arc<crate::grpc::test_service::TestServiceImpl> {
    let svc = std::sync::Arc::new(crate::grpc::test_service::TestServiceImpl::new());
    let cleanup_svc = svc.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_svc.cleanup();
        }
    });
    info!("TestService enabled (dev-perf-test feature)");
    svc
}

/// Serves `services` on `c.grpc_addr` with the durable work runner until
/// `shutdown` (typically [`sid_serve::shutdown::signal`]) resolves, then
/// lets attempts in flight record their outcome.
pub async fn serve(
    c: CeComponents,
    services: CeServices,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let drain = sid_serve::shutdown::drain_interval_from_env()?;
    let (stopper, stopped) = sid_serve::stop_signal();

    #[cfg(feature = "webtransport")]
    let mut webtransport = {
        let wt_config = sid_webtransport::config::Config::from_env()?;
        let dispatcher = crate::webtransport_dispatch::register_all(&c.identity_svc, &c.auth_svc);
        #[cfg(feature = "dev-perf-test")]
        let dispatcher = {
            let mut dispatcher = dispatcher;
            crate::webtransport_dispatch::register_test_service(
                &mut dispatcher,
                &services.test_svc,
            );
            dispatcher
        };
        let mut wt_server = sid_webtransport::WebTransportServer::new(wt_config, dispatcher);
        // A configured transport that cannot start stops startup.
        wt_server.resolve_cert_hash().await?;
        let wt_shutdown = stopped.clone().wait();
        Some(tokio::spawn(async move {
            wt_server
                .serve(wt_shutdown, drain)
                .await
                .map_err(anyhow::Error::from)
        }))
    };
    #[cfg(not(feature = "webtransport"))]
    let mut webtransport: Option<tokio::task::JoinHandle<anyhow::Result<()>>> = None;

    // The HTTP form of the annotated RPCs; a configured one that cannot be
    // built stops startup.
    #[cfg(feature = "http")]
    let http_proxy = http_transcoder(
        std::env::var("SID_BIND").ok().as_deref(),
        std::env::var("SID_HTTP_CONFIG").ok().as_deref(),
        c.login_url.as_ref(),
    )?;

    let work_runner = spawn_work_runner(&c, stopped.clone().wait())?;

    let (routes, health) = services.services.into_parts();

    // The transcoder calls these same services in process: REST, native gRPC
    // and gRPC-Web on its port reach them with no hop to the gRPC listener.
    // It stops with the gRPC listener and drains in the same interval.
    #[cfg(feature = "http")]
    let mut http = http_proxy.map(|proxy| {
        info!(bind = %proxy.config().listen.http, "HTTP transcoder listening");
        let upstream = transcoder_upstream(routes.clone());
        let http_stopped = stopped.clone().wait();
        tokio::spawn(
            async move { sid_infra::http::serve(&proxy, upstream, http_stopped, drain).await },
        )
    });
    #[cfg(not(feature = "http"))]
    let mut http: Option<tokio::task::JoinHandle<anyhow::Result<()>>> = None;

    // Browser gRPC-web is answered here; CORS for it comes from the fronting
    // proxy, and for the HTTP form from the transcoder's configuration.
    let server = TonicServer::builder()
        .accept_http1(true)
        .layer(tonic_web::GrpcWebLayer::new())
        .add_routes(routes)
        .serve_with_shutdown(c.grpc_addr, stopped.wait());
    info!("gRPC listening on {}", c.grpc_addr);

    let mut http_ended = None;
    // A transcoder that stopped leaves the HTTP form down while gRPC runs
    // on: the process stops the same way as on a signal, so it is restarted
    // whole.
    let transcoder_ended = async {
        http_ended = Some(finished(&mut http).await);
    };
    let shutdown = async {
        tokio::select! {
            () = shutdown => {}
            () = transcoder_ended => {}
        }
    };
    let served = sid_serve::run(server, shutdown, &health, &stopper, drain).await;
    // Calls still open after the drain interval end with their connections;
    // every other listener stops too.
    stopper.stop();

    // The HTTP listener and WebTransport drain within the same interval.
    let http_drained = match http.as_mut() {
        Some(_) => finished(&mut http).await,
        None => Ok(()),
    };
    let transport = match webtransport.as_mut() {
        Some(_) => finished(&mut webtransport).await,
        None => Ok(()),
    };
    // Attempts in flight record their outcome before the process ends.
    let drained = work_runner.await;
    served?;
    http_drained?;
    transport?;
    drained?;
    if let Some(ended) = http_ended {
        ended?;
        anyhow::bail!("the HTTP transcoder stopped");
    }
    Ok(())
}

/// The services the embedded transcoder calls in process: gRPC-Web answered
/// here, and every transcoded call carrying the HTTP request it was made
/// from (see [`transcoded_request`]).
#[cfg(feature = "http")]
pub fn transcoder_upstream(
    routes: tonic::service::Routes,
) -> impl structured_proxy::upstream::Upstream {
    tower::ServiceBuilder::new()
        .layer(tonic_web::GrpcWebLayer::new())
        .map_request(transcoded_request)
        .service(routes)
}

/// `request` with the HTTP request the transcoder made it from, as the
/// services read it for sender proofs (RFC 9449 §4.3): the method and path
/// it received. The transcoder records them and checks nothing; a call that
/// did not come through it carries none.
#[cfg(feature = "http")]
fn transcoded_request<B>(mut request: http::Request<B>) -> http::Request<B> {
    if let Some(received) = request
        .extensions()
        .get::<structured_proxy::ReceivedRequest>()
    {
        let transcoded = sid_authn::resource::TranscodedRequest::new(
            received.method().as_str(),
            received.path_and_query().path(),
        );
        request.extensions_mut().insert(transcoded);
    }
    request
}

/// Request headers the annotated RPCs read as metadata: credentials, DPoP
/// proofs, idempotency keys, client address and locale.
#[cfg(feature = "http")]
pub const HTTP_FORWARDED_HEADERS: [&str; 11] = [
    "authorization",
    // The IdP session cookie, read by the authorization and end-session
    // endpoints, and the origin a ceremony that sets it must come from.
    "cookie",
    "origin",
    "dpop",
    "x-request-id",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
    "accept-language",
    "user-agent",
    "idempotency-key",
];

/// The embedded transcoder serving this server's annotated RPCs over HTTP:
/// `config_file` is a structured-proxy configuration, else `bind` alone is
/// the listen address; neither means no HTTP form. The forward-auth decision
/// belongs to sid-auth and is not mounted here. With a sign-in page, its
/// origin is among the CORS origins (see [`allow_sign_in_origin`]).
#[cfg(feature = "http")]
pub fn http_transcoder(
    bind: Option<&str>,
    config_file: Option<&str>,
    sign_in: Option<&url::Url>,
) -> anyhow::Result<Option<structured_proxy::ProxyServer>> {
    let mut config = match (config_file, bind) {
        (Some(path), _) => serde_yaml::from_str(
            &std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("SID_HTTP_CONFIG {path}: {e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("SID_HTTP_CONFIG {path}: {e}"))?,
        (None, Some(bind)) => sid_infra::http::listening_on(bind),
        (None, None) => return Ok(None),
    };
    if let Some(sign_in) = sign_in {
        allow_sign_in_origin(&mut config, &sign_in.origin())?;
    }
    sid_infra::http::embedded_transcoder(&config, &HTTP_FORWARDED_HEADERS, |name| {
        name != sid_proto::FORWARD_AUTH_PROTO
    })
    .map(Some)
}

/// `config` with the sign-in page's `origin` among its CORS origins. The
/// page calls the sign-in ceremonies cross-origin with credentials, which a
/// browser allows only for an exact allowed origin (Fetch standard §3.2.5):
/// an explicit list is also what makes the transcoder allow credentials. A
/// wildcard or `null` origin in the list stops startup.
#[cfg(feature = "http")]
pub fn allow_sign_in_origin(
    config: &mut serde_yaml::Value,
    origin: &url::Origin,
) -> anyhow::Result<()> {
    let map = config
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("the HTTP configuration must be a mapping"))?;
    let cors = map
        .entry("cors".into())
        .or_insert_with(|| serde_yaml::Mapping::new().into());
    let cors = cors
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("the HTTP configuration's cors must be a mapping"))?;
    let origins = cors
        .entry("origins".into())
        .or_insert_with(|| serde_yaml::Sequence::new().into());
    let origins = origins
        .as_sequence_mut()
        .ok_or_else(|| anyhow::anyhow!("cors.origins must be a list"))?;
    if let Some(any) = origins
        .iter()
        .filter_map(|o| o.as_str())
        .find(|o| matches!(o.trim(), "*" | "null"))
    {
        anyhow::bail!(
            "cors.origins holds {any:?}: credentialed calls of the sign-in page need exact origins"
        );
    }
    let serialized = origin.ascii_serialization();
    if !origins
        .iter()
        .any(|o| o.as_str() == Some(serialized.as_str()))
    {
        origins.push(serialized.into());
    }
    Ok(())
}

/// Resolves when the task ends and clears it; never, when there is none.
async fn finished(
    task: &mut Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
) -> anyhow::Result<()> {
    let Some(handle) = task.as_mut() else {
        return std::future::pending().await;
    };
    let ended = handle.await;
    *task = None;
    ended?
}

#[cfg(test)]
mod tests;
