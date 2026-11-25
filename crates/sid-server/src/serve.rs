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
    entry_connection_service_server::EntryConnectionServiceServer,
    federated_entry_service_server::FederatedEntryServiceServer,
    federation_site_service_server::FederationSiteServiceServer,
    flow_action_service_server::FlowActionServiceServer,
    flow_config_service_server::FlowConfigServiceServer,
    identity_service_server::IdentityServiceServer,
    oidc_issuer_service_server::OidcIssuerServiceServer,
    oidc_provider_service_server::OidcProviderServiceServer,
    operation_service_server::OperationServiceServer, project_service_server::ProjectServiceServer,
    system_integration_service_server::SystemIntegrationServiceServer,
    upstream_service_server::UpstreamServiceServer,
};

use crate::init::CeComponents;

#[cfg(feature = "http")]
pub mod browser_route;

/// What a host serving its own services beside SID's gives the access
/// guard: their schemas' encoded descriptor sets, and the verifier of a
/// service's own tokens for each API that admits them, by the gRPC service
/// serving it.
#[derive(Default)]
pub struct HostServices<'a> {
    pub schemas: &'a [&'a [u8]],
    pub service_tokens: Vec<(
        &'static str,
        std::sync::Arc<sid_authn::resource_token::ResourceTokenVerifier>,
    )>,
}

/// The origins of the installation's own pages, as its settings place them
/// now: the public URL's and the console's.
struct InstallationPages(std::sync::Arc<sid::web_settings::WebSettingsAdmin>);

#[async_trait::async_trait]
impl sid_infra::authn::access::AdmittedOrigins for InstallationPages {
    async fn admits(&self, origin: &str) -> bool {
        match self.0.recent().await {
            Ok(placed) => [&placed.public_url, &placed.console_url]
                .iter()
                .any(|url| url.origin().ascii_serialization() == origin),
            // Settings that cannot be read admit no page.
            Err(e) => {
                tracing::warn!(error = %e, "web settings unavailable; browser session refused");
                false
            }
        }
    }
}

/// The console's origin as credentialed CORS admits it, when the settings
/// place the console on a sibling host: its calls of the installation's API
/// are cross-origin. Read from the settings held in this process, refreshed
/// every second by the server; the guard still checks every call's origin
/// against the stored settings and admits nothing on CORS alone.
#[cfg(feature = "http")]
pub struct ConsoleOrigin(pub std::sync::Arc<sid::web_settings::WebSettingsAdmin>);

#[cfg(feature = "http")]
impl structured_proxy::hooks::CorsOrigins for ConsoleOrigin {
    fn admits(&self, origin: &str) -> bool {
        self.0.last().is_some_and(|placed| {
            let console = placed.console_url.origin();
            console != placed.public_url.origin() && console.ascii_serialization() == origin
        })
    }
}

/// The services one server exposes: routed and reported on the gRPC health
/// service together, each behind the access guard of the rules its schema
/// declares.
pub struct CeServices {
    services: sid_serve::Services,
    access: std::sync::Arc<sid_infra::authn::access::Access>,
    /// Receivers this server runs that facts are owed to (SCIM outbound
    /// provisioning while targets are configured).
    receivers: Vec<sid_core::models::RequiredReceiver>,
    /// The encoded file descriptor sets of added services whose annotated
    /// RPCs the HTTP form serves beside SID's.
    #[cfg(feature = "http")]
    transcoded: Vec<&'static [u8]>,
    /// Routes the HTTP port serves beside the annotated RPCs (the
    /// installation's own web UI).
    #[cfg(feature = "http")]
    extra_routes: Vec<structured_proxy::hooks::ExtraRoute>,
    /// Services served under path prefixes of their own on the HTTP port.
    #[cfg(feature = "http")]
    mounts: Vec<(String, MountFactory)>,
}

impl CeServices {
    /// Every CE service over `c`, with the SCIM outbound worker when targets
    /// are configured, and the guard enforcing also the access rules of the
    /// host's own services `host` names.
    pub async fn new(c: &CeComponents, host: HostServices<'_>) -> anyhow::Result<Self> {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(sid_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;
        let mut served = sid_serve::Services::new();
        served.route(reflection);

        #[cfg(feature = "dev-perf-test")]
        let test_svc = spawn_test_service();

        let mut rules =
            sid_infra::authn::access::AccessRules::from_descriptors(sid_proto::FILE_DESCRIPTOR_SET)
                .map_err(|e| anyhow::anyhow!("SID's access rules: {e}"))?;
        for schema in host.schemas {
            rules
                .add(schema)
                .map_err(|e| anyhow::anyhow!("the host's access rules: {e}"))?;
        }
        let mut access = sid_infra::authn::access::Access::new(
            std::sync::Arc::new(rules),
            c.jwt.clone(),
            c.revocation_cache.clone(),
            c.storage.clone(),
            c.revocation_cache.clone(),
        );
        if let Some(tokens) = c.authz_svc.service_tokens() {
            access = access.with_service_tokens(
                <AuthzServiceServer<crate::grpc::authz_service::AuthzServiceImpl> as NamedService>::NAME,
                tokens,
            );
        }
        if let Some(tokens) = c.enrollment_svc.invite_tokens() {
            access = access.with_service_tokens(
                <EnrollmentServiceServer<crate::grpc::enrollment_service::EnrollmentServiceImpl> as NamedService>::NAME,
                tokens,
            );
        }
        for (service, tokens) in host.service_tokens {
            access = access.with_service_tokens(service, tokens);
        }
        // The installation's own pages (account, console) call its API with
        // its browser session.
        access = access.with_browser_sessions(sid_infra::authn::access::BrowserSessions {
            cookie: c.auth_svc.browser_cookie().clone(),
            origins: std::sync::Arc::new(InstallationPages(c.web_settings.clone())),
        });

        let mut services = Self {
            services: served,
            access: std::sync::Arc::new(access),
            receivers: Vec::new(),
            #[cfg(feature = "http")]
            transcoded: Vec::new(),
            // The session on a selected subdomain: hosts the scope selects
            // establish their own cookie through these steps.
            #[cfg(feature = "http")]
            extra_routes: crate::session_establish::routes(
                c.web_settings.clone(),
                c.storage.clone(),
                c.key_manager.clone(),
                c.auth_svc.browser_cookie().clone(),
            ),
            #[cfg(feature = "http")]
            mounts: Vec::new(),
        };
        services
            .add(IdentityServiceServer::from_arc(c.identity_svc.clone()))
            .await
            .add(AuthServiceServer::from_arc(c.auth_svc.clone()))
            .await
            .add(
                sid_proto::sid::v1::authn::auth_flow_service_server::AuthFlowServiceServer::new(
                    crate::grpc::auth_flow_service::AuthFlowServiceImpl::new(c.auth_svc.clone()),
                ),
            )
            .await
            .add(ProjectServiceServer::from_arc(c.project_svc.clone()))
            .await
            .add(OidcIssuerServiceServer::new(
                crate::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
                    c.issuers.clone(),
                    c.storage.clone(),
                    c.authz_svc.clone(),
                ),
            ))
            .await
            .add(OidcProviderServiceServer::new(
                crate::grpc::oidc_provider_service::OidcProviderServiceImpl::new(
                    c.auth_svc.clone(),
                    c.project_svc.clone(),
                    c.sign_in_page.clone(),
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
            .add(
                sid_proto::sid::v1::ui::public_ui_settings_service_server::PublicUiSettingsServiceServer::new(
                    crate::grpc::public_ui_settings_service::PublicUiSettingsServiceImpl::new(
                        c.public_settings.clone(),
                    ),
                ),
            )
            .await
            .add(SecurityServiceServer::from_arc(c.security_svc.clone()))
            .await
            .add(GovernanceServiceServer::new(
                crate::grpc::governance_service::GovernanceServiceImpl::new(
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
            .add(UpstreamServiceServer::from_arc(c.upstream_svc.clone()))
            .await
            .add(EntryConnectionServiceServer::new(
                crate::grpc::entry_connection_service::EntryConnectionServiceImpl::new(
                    c.entry_connections.clone(),
                    c.jwt.clone(),
                    c.revocation_cache.clone(),
                ),
            ))
            .await
            .add(FederatedEntryServiceServer::new(federated_entry(c)?))
            .await
            // Built here, after a host has set the recipient side its
            // composition verifies with.
            .add(FederationSiteServiceServer::new(
                crate::grpc::federation_site_service::FederationSiteServiceImpl::new(
                    std::sync::Arc::new(sid::federation_site::FederationSite::new(
                        c.storage.clone(),
                        c.key_manager.clone(),
                        c.identities.clone(),
                        c.organization.id,
                    )),
                    c.jwt.clone(),
                    c.revocation_cache.clone(),
                ),
            ))
            .await
            .add(SystemIntegrationServiceServer::new(
                crate::grpc::system_integration_service::SystemIntegrationServiceImpl::new(
                    c.storage.clone(),
                    c.issuer.clone(),
                ),
            ))
            .await
            .add(RealmServiceServer::new(
                crate::grpc::realm_service::RealmServiceImpl::new(
                    c.storage.clone(),
                    c.jwt.clone(),
                    c.revocation_cache.clone(),
                    c.key_manager.clone(),
                    c.web_settings.clone(),
                ),
            ))
            .await
            .add(OperationServiceServer::new(
                sid_infra::authn::operation::OperationPeriods::new(c.storage.clone()),
            ))
            .await;

        // Password operations are served once the ZKPP keys are ready; a
        // deployment's readiness names them when it serves them.
        services
            .services
            .report_ready(
                sid_authn::opaque_zkpp::setup::PASSWORD_OPERATIONS_HEALTH,
                c.zkpp_ready.clone().wait(),
            )
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
                        format!("{}/scim/v2", scim_server_url(c)?),
                    ),
                ))
                .await;
            services.receivers.extend(start_scim_outbound(c).await?);
            info!("SCIM 2.0 inbound provisioning enabled");
        }

        #[cfg(feature = "dev-perf-test")]
        services.add(TestServiceServer::from_arc(test_svc)).await;

        Ok(services)
    }

    /// Serves `svc` behind its access guard beside the CE services and
    /// reports it serving.
    ///
    /// # Panics
    /// When no schema given to [`Self::new`] declares `svc`'s rules: a
    /// service is never served without them.
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
        let guarded = self
            .access
            .guard(svc)
            .expect("every served service's schema is given to CeServices::new");
        self.services.add(guarded).await;
        self
    }

    /// Serves `svc` as [`Self::add`] does, and its annotated RPCs over the
    /// HTTP form: `descriptors` is the encoded file descriptor set its
    /// `google.api.http` annotations live in. A build without the HTTP form
    /// serves it over gRPC alone.
    pub async fn add_transcoded<S>(&mut self, svc: S, descriptors: &'static [u8]) -> &mut Self
    where
        S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        #[cfg(feature = "http")]
        self.transcoded.push(descriptors);
        #[cfg(not(feature = "http"))]
        let _ = descriptors;
        self.add(svc).await
    }

    /// Serve the service `build` makes from the server's own services on the
    /// HTTP port for calls under `prefix` (without a trailing `/`), which it
    /// receives with the prefix removed.
    #[cfg(feature = "http")]
    pub fn add_mount(&mut self, prefix: &str, build: MountFactory) -> &mut Self {
        self.mounts.push((prefix.to_owned(), build));
        self
    }

    /// Serve `routes` on the HTTP port beside the annotated RPCs.
    #[cfg(feature = "http")]
    pub fn add_routes(
        &mut self,
        routes: impl IntoIterator<Item = structured_proxy::hooks::ExtraRoute>,
    ) -> &mut Self {
        self.extra_routes.extend(routes);
        self
    }
}

/// The federated entry over `c`: every entry reads its connection from the
/// store, and its pending state is held there too, so an entry started on
/// one replica finishes on another with or without the cache. It accepts a
/// presented identity with `c.identities`, which a host may have replaced,
/// and also returns to the host's pages `c.entry_continuations`.
pub fn federated_entry(
    c: &CeComponents,
) -> anyhow::Result<crate::grpc::federated_entry_service::FederatedEntryServiceImpl> {
    use sid_authn::federated_entry::FederatedEntry;
    let http = sid_plugin::client_builder()
        .map_err(|e| anyhow::anyhow!("entry connection issuer client: {e}"))?
        .build()
        .map_err(|e| anyhow::anyhow!("entry connection issuer client: {e}"))?;
    let ceremonies: std::sync::Arc<dyn sid_plugin::CeremonyStateStore> = c.storage.clone();
    let (keys, cookie) = (c.key_manager.clone(), c.auth_svc.browser_cookie().clone());
    let entries: crate::grpc::federated_entry_service::Entries =
        std::sync::Arc::new(move |trusted| {
            FederatedEntry::new(
                trusted,
                http.clone(),
                ceremonies.clone(),
                keys.clone(),
                cookie.clone(),
            )
        });
    Ok(
        crate::grpc::federated_entry_service::FederatedEntryServiceImpl::new(
            entries,
            c.entry_connections.clone(),
            c.storage.clone(),
            c.auth_svc.clone(),
            c.identities.clone(),
        )
        .with_host_continuations(c.entry_continuations.clone()),
    )
}

/// The URL the SCIM endpoint is served under (its `/scim/v2` paths follow).
#[cfg(feature = "scim")]
fn scim_server_url(c: &CeComponents) -> anyhow::Result<String> {
    Ok(crate::init::env_setting("SID_SCIM_BASE_URL")?.unwrap_or_else(|| c.issuer.clone()))
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
    let base_url = scim_server_url(c)?;
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
/// without them would silently stop provisioning. With targets, outbound
/// provisioning is a receiver every SCIM fact is owed to; without, it still
/// settles the work owed before the last target was removed.
#[cfg(feature = "scim")]
async fn start_scim_outbound(
    c: &CeComponents,
) -> anyhow::Result<Option<sid_core::models::RequiredReceiver>> {
    let targets = c
        .storage
        .list_scim_outbound_targets(sid_core::models::ProjectId::SYSTEM)
        .await
        .map_err(|e| anyhow::anyhow!("loading SCIM outbound targets: {e}"))?;
    let worker = std::sync::Arc::new(sid_scim::outbound::worker::ScimOutboundWorker::new(
        c.storage.clone(),
        c.event_bus.clone(),
        targets,
    ));
    let owed = worker
        .start_owed()
        .await
        .map_err(|e| anyhow::anyhow!("SCIM outbound worker: {e}"))?;
    info!("SCIM outbound worker started");
    Ok(owed)
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
    let listener = tokio::net::TcpListener::bind(c.grpc_addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind gRPC on {}: {e}", c.grpc_addr))?;
    serve_on(listener, c, services, shutdown).await
}

/// [`serve`] on a listener the caller already holds, so the port it chose
/// stays reserved from the moment it was opened; `c.grpc_addr` should name
/// the same address.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    c: CeComponents,
    services: CeServices,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let grpc_addr = listener.local_addr()?;
    #[cfg(feature = "http")]
    let assembled = assemble(
        c,
        services,
        http_config(
            crate::init::env_setting("SID_BIND")?.as_deref(),
            crate::init::env_setting("SID_HTTP_CONFIG")?.as_deref(),
        )?,
    )?;
    #[cfg(not(feature = "http"))]
    let assembled = assemble(c, services)?;
    let Assembled {
        routes,
        http,
        background,
        stopped,
        drain,
    } = assembled;

    // The HTTP form stops with the gRPC listener and drains in the same
    // interval.
    #[cfg(feature = "http")]
    let mut http = http.map(|form| {
        info!(bind = %form.proxy.config().listen.http, "HTTP transcoder listening");
        let http_stopped = stopped.clone().wait();
        tokio::spawn(async move {
            sid_infra::http::serve(&form.proxy, form.upstream, http_stopped, drain).await
        })
    });
    #[cfg(not(feature = "http"))]
    let mut http: Option<tokio::task::JoinHandle<anyhow::Result<()>>> =
        http.map(|never| match never {});

    // The gRPC port is a direct path unless a proxy in front of it is named:
    // its own trust, since other callers than the HTTP port's reach it.
    #[cfg(feature = "http")]
    let grpc_edge = crate::init::env_setting("SID_GRPC_TRUSTED_PROXIES")?
        .map(|proxies| sid_infra::http::edge_layer(&proxies))
        .transpose()
        .map_err(|e| anyhow::anyhow!("SID_GRPC_TRUSTED_PROXIES: {e}"))?;
    #[cfg(not(feature = "http"))]
    let grpc_edge: Option<tower::layer::util::Identity> = None;

    // Browser gRPC-web is answered here; CORS for it comes from the fronting
    // proxy, and for the HTTP form from the transcoder's configuration.
    let server = TonicServer::builder()
        .accept_http1(true)
        .layer(tower::util::option_layer(grpc_edge))
        .layer(tonic_web::GrpcWebLayer::new())
        .layer(sid_infra::authn::operation::OperationContextLayer)
        .add_routes(routes)
        // tonic's own bind sets only TCP_NODELAY (on by default).
        .serve_with_incoming_shutdown(
            tonic::transport::server::TcpIncoming::from(listener).with_nodelay(Some(true)),
            stopped.wait(),
        );
    info!("gRPC listening on {grpc_addr}");

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
    let served = sid_serve::run(
        server,
        shutdown,
        &background.health,
        &background.stopper,
        drain,
    )
    .await;
    // Calls still open after the drain interval end with their connections;
    // every other listener stops too.
    background.stopper.stop();

    // The HTTP listener drains within the same interval.
    let http_drained = match http.as_mut() {
        Some(_) => finished(&mut http).await,
        None => Ok(()),
    };
    let finished = background.finish().await;
    served?;
    http_drained?;
    finished?;
    if let Some(ended) = http_ended {
        ended?;
        anyhow::bail!("the HTTP transcoder stopped");
    }
    Ok(())
}

/// The installation assembled with no listener: its services, the HTTP form
/// over them where one is configured, and the background work they owe,
/// already running.
struct Assembled<H> {
    routes: tonic::service::Routes,
    http: Option<H>,
    background: Background,
    stopped: sid_serve::Stopped,
    drain: std::time::Duration,
}

/// The HTTP form of an assembled installation: the transcoder and the
/// services it calls in process, so REST, native gRPC and gRPC-Web reach
/// them with no hop to a gRPC listener.
#[cfg(feature = "http")]
struct HttpForm<U> {
    proxy: structured_proxy::ProxyServer,
    upstream: U,
}

/// The work an assembled installation runs beside its calls: the durable
/// work runner with its maintenance, the cleanup settlements and the settings
/// refresh. It runs until the server stops.
struct Background {
    /// Held until the work ends: the services and the work share its parts.
    _components: CeComponents,
    health: sid_serve::Health,
    engine: sid::Running,
    settlements: Option<tokio::task::JoinHandle<()>>,
    stopper: sid_serve::Stopper,
}

impl Background {
    /// Attempts and maintenance runs in flight record their outcome before
    /// the process ends; a settlement being recorded finishes, and an
    /// unacknowledged one is delivered again.
    async fn finish(self) -> anyhow::Result<()> {
        let drained = self.engine.drain().await;
        if let Some(settlements) = self.settlements {
            settlements.await?;
        }
        drained?;
        Ok(())
    }
}

/// Starts the background work of `c` owed to `receivers`.
fn start_background(
    c: CeComponents,
    receivers: &[sid_core::models::RequiredReceiver],
    health: sid_serve::Health,
    stopper: sid_serve::Stopper,
    stopped: &sid_serve::Stopped,
) -> anyhow::Result<Background> {
    let engine = crate::init::engine(&c, receivers)?.start();
    let settlements = crate::init::spawn_cleanup_settlements(&c, stopped.clone().wait());
    Ok(Background {
        _components: c,
        health,
        engine,
        settlements,
        stopper,
    })
}

/// `services` over `c` with their background work started and, with a
/// `config` (a structured-proxy configuration tree), their HTTP form. A
/// configured HTTP form that cannot be built stops startup.
#[cfg(feature = "http")]
fn assemble(
    c: CeComponents,
    services: CeServices,
    config: Option<serde_json::Value>,
) -> anyhow::Result<Assembled<HttpForm<impl structured_proxy::upstream::Upstream>>> {
    let drain = sid_serve::shutdown::drain_interval_from_env()?;
    let (stopper, stopped) = sid_serve::stop_signal();
    let CeServices {
        services,
        receivers,
        transcoded,
        extra_routes,
        mounts,
        ..
    } = services;

    let proxy = config
        .map(|config| {
            // The ceremonies' page, not the authorization endpoint's target a
            // host may have replaced: the auth service admits ceremonies
            // from it.
            transcoder_over(config, c.ceremony_page.as_ref(), &transcoded)
        })
        .transpose()?
        .map(|proxy| {
            let proxy = proxy.with_extra_routes(extra_routes);
            // The console's origin joins credentialed CORS only where that
            // policy is in force (origins are listed): with none listed the
            // transcoder answers every origin without credentials, which
            // browser relying parties fetching discovery and keys depend on,
            // and the hook would replace that with the credentialed policy.
            if proxy.config().cors.origins.is_empty() {
                proxy
            } else {
                proxy.with_cors_origins(std::sync::Arc::new(ConsoleOrigin(c.web_settings.clone())))
            }
        });
    // The settings CORS reads synchronously follow the store within a
    // second, whatever the traffic; the task ends with the work.
    {
        let web = c.web_settings.clone();
        let stop = stopped.clone().wait();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(sid::web_settings::RECENT_FOR);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tokio::pin!(stop);
            loop {
                tokio::select! {
                    () = &mut stop => break,
                    _ = every.tick() => {
                        if let Err(e) = web.recent().await {
                            tracing::warn!(error = %e, "web settings unavailable");
                        }
                    }
                }
            }
        });
    }

    let (issuers, web_settings, cookie) = (
        c.issuers.clone(),
        c.web_settings.clone(),
        c.auth_svc.browser_cookie().clone(),
    );
    let (routes, health) = services.into_parts();
    let background = start_background(c, &receivers, health, stopper, &stopped)?;

    let http = proxy.map(|proxy| {
        let mounts = mounts
            .into_iter()
            .map(|(prefix, build)| (prefix, build(routes.clone())))
            .collect();
        // The installation cookie reaches as far as its scope setting says.
        let upstream = crate::cookie_scope::CookieScopeEdge::new(
            transcoder_upstream(routes.clone(), issuers, mounts),
            web_settings,
            cookie,
        );
        HttpForm { proxy, upstream }
    });
    Ok(Assembled {
        routes,
        http,
        background,
        stopped,
        drain,
    })
}

/// `services` over `c` with their background work started.
#[cfg(not(feature = "http"))]
fn assemble(c: CeComponents, services: CeServices) -> anyhow::Result<Assembled<Infallible>> {
    let drain = sid_serve::shutdown::drain_interval_from_env()?;
    let (stopper, stopped) = sid_serve::stop_signal();
    let (routes, health) = services.services.into_parts();
    let background = start_background(c, &services.receivers, health, stopper, &stopped)?;
    Ok(Assembled {
        routes,
        http: None,
        background,
        stopped,
        drain,
    })
}

/// A service the HTTP port serves under a path prefix of its own, ahead of
/// the installation's API (an application hosted in process).
#[cfg(feature = "http")]
pub type MountedService = tower::util::BoxCloneSyncService<
    http::Request<Body>,
    http::Response<Body>,
    std::convert::Infallible,
>;

/// What builds a mounted service once the server's own services exist: it
/// receives them, behind their access guards, to call in process.
#[cfg(feature = "http")]
pub type MountFactory = Box<dyn FnOnce(tonic::service::Routes) -> MountedService + Send>;

/// Calls under a mount's prefix go to its service with the prefix removed;
/// every other call goes to `inner`.
#[cfg(feature = "http")]
#[derive(Clone)]
pub struct Mounts<S> {
    inner: S,
    mounts: std::sync::Arc<[(String, MountedService)]>,
}

#[cfg(feature = "http")]
impl<S> Service<http::Request<Body>> for Mounts<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        use tower::ServiceExt as _;
        let path = request.uri().path().to_owned();
        for (prefix, service) in self.mounts.iter() {
            let Some(rest) = path.strip_prefix(prefix.as_str()) else {
                continue;
            };
            if !rest.starts_with('/') {
                continue;
            }
            let mut parts = request.uri().clone().into_parts();
            let query = request
                .uri()
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            match http::uri::PathAndQuery::try_from(format!("{rest}{query}")) {
                Ok(rewritten) => parts.path_and_query = Some(rewritten),
                Err(e) => {
                    let refused = sid_infra::grpc_error::refuse::internal("route the mount", e);
                    return Box::pin(async move { Ok(refused.into_http()) });
                }
            }
            match http::Uri::from_parts(parts) {
                Ok(uri) => *request.uri_mut() = uri,
                Err(e) => {
                    let refused = sid_infra::grpc_error::refuse::internal("route the mount", e);
                    return Box::pin(async move { Ok(refused.into_http()) });
                }
            }
            let service = service.clone();
            return Box::pin(service.oneshot(request));
        }
        // The service polled ready serves this call; its clone the next one.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        Box::pin(inner.call(request))
    }
}

/// The services the embedded transcoder calls in process: the mounted
/// applications' calls under their prefixes, gRPC-Web answered here under
/// the API mount, browser sign-in calls addressed to an issuer of `issuers`
/// (see [`browser_route`]), and every transcoded call carrying the HTTP
/// request it was made from (see [`transcoded_request`]).
#[cfg(feature = "http")]
pub fn transcoder_upstream(
    routes: tonic::service::Routes,
    issuers: std::sync::Arc<sid_authn::issuer::IssuerRegistry>,
    mounts: Vec<(String, MountedService)>,
) -> impl structured_proxy::upstream::Upstream {
    let mounts: std::sync::Arc<[(String, MountedService)]> = mounts.into();
    tower::ServiceBuilder::new()
        .layer(tower::layer::layer_fn(move |inner| Mounts {
            inner,
            mounts: mounts.clone(),
        }))
        .map_request(browser_route::mark_browser_call)
        .layer(tonic_web::GrpcWebLayer::new())
        .layer(tower::layer::layer_fn(move |inner| {
            browser_route::BrowserRoute::new(inner, issuers.clone())
        }))
        .map_request(transcoded_request)
        .layer(sid_infra::authn::operation::OperationContextLayer)
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
        let transcoded = sid_infra::authn::resource::TranscodedRequest::new(
            received.method().as_str(),
            received.path_and_query().path(),
        );
        request.extensions_mut().insert(transcoded);
    }
    request
}

/// Request headers the annotated RPCs read as metadata: credentials, DPoP
/// proofs, operation contexts, client address and locale.
#[cfg(feature = "http")]
pub const HTTP_FORWARDED_HEADERS: [&str; 15] = [
    "authorization",
    // The IdP session cookie, read by the authorization and end-session
    // endpoints, and the origin a ceremony that sets it must come from.
    "cookie",
    "origin",
    // The CSRF token a browser step echoes with its cookie.
    sid_authn::browser_session::CSRF_HEADER,
    "dpop",
    "x-request-id",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
    "accept-language",
    "user-agent",
    sid_infra::authn::operation::OPERATION_KEY_HEADER,
    sid_infra::authn::operation::OPERATION_PERIOD_HEADER,
    // A native client's proof of its application key and the refresh
    // credential it presents (native_session.proto).
    sid_authn::native_session::PROOF_METADATA,
    sid_authn::native_session::REFRESH_METADATA,
];

/// The embedded transcoder serving this server's annotated RPCs over HTTP:
/// `config_file` is a structured-proxy configuration, else `bind` alone is
/// the listen address; neither means no HTTP form. The forward-auth decision
/// belongs to sid-auth and the platform CA publication to the platform:
/// neither is mounted here. With a sign-in page, its origin is among the CORS
/// origins (see [`allow_sign_in_origin`]).
#[cfg(feature = "http")]
pub fn http_transcoder(
    bind: Option<&str>,
    config_file: Option<&str>,
    sign_in: Option<&url::Url>,
) -> anyhow::Result<Option<structured_proxy::ProxyServer>> {
    http_transcoder_with(bind, config_file, sign_in, &[])
}

/// [`http_transcoder`] also serving the annotated RPCs of the added services
/// whose encoded file descriptor sets `added` holds.
#[cfg(feature = "http")]
pub fn http_transcoder_with(
    bind: Option<&str>,
    config_file: Option<&str>,
    sign_in: Option<&url::Url>,
    added: &[&[u8]],
) -> anyhow::Result<Option<structured_proxy::ProxyServer>> {
    http_config(bind, config_file)?
        .map(|config| transcoder_over(config, sign_in, added))
        .transpose()
}

/// The HTTP form's configuration: the structured-proxy configuration in
/// `config_file`, else one listening on `bind` and nothing else; neither
/// means no HTTP form.
#[cfg(feature = "http")]
fn http_config(
    bind: Option<&str>,
    config_file: Option<&str>,
) -> anyhow::Result<Option<serde_json::Value>> {
    Ok(Some(match (config_file, bind) {
        (Some(path), _) => serde_saphyr::from_str(
            &std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("SID_HTTP_CONFIG {path}: {e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("SID_HTTP_CONFIG {path}: {e}"))?,
        (None, Some(bind)) => sid_infra::http::listening_on(bind),
        (None, None) => return Ok(None),
    }))
}

/// The transcoder `config` describes, as [`http_transcoder_with`] makes it.
#[cfg(feature = "http")]
fn transcoder_over(
    mut config: serde_json::Value,
    sign_in: Option<&url::Url>,
    added: &[&[u8]],
) -> anyhow::Result<structured_proxy::ProxyServer> {
    if let Some(sign_in) = sign_in {
        allow_sign_in_origin(&mut config, &sign_in.origin())?;
    }
    // The proxies in front of this port, whose report names the client, and
    // what they report it in; unset means clients connect directly.
    if let Some(proxies) = crate::init::env_setting("SID_EDGE_TRUSTED_PROXIES")? {
        let report = match crate::init::env_setting("SID_EDGE_CLIENT_HEADER")? {
            Some(header) => sid_infra::http::EdgeReport::parse(&header)
                .map_err(|e| anyhow::anyhow!("SID_EDGE_CLIENT_HEADER: {e}"))?,
            None => sid_infra::http::EdgeReport::Chain,
        };
        sid_infra::http::with_edge_trust(&mut config, &proxies, report)?;
    }
    sid_infra::http::embedded_transcoder_with_sets(
        &config,
        &HTTP_FORWARDED_HEADERS,
        // Neither is served here: no route of theirs is mounted.
        |name| name != sid_proto::FORWARD_AUTH_PROTO && name != sid_proto::PLATFORM_CA_PROTO,
        added,
    )
}

/// `config` with the sign-in page's `origin` among its CORS origins and the
/// CSRF header among the headers its script may read. The
/// page calls the sign-in ceremonies cross-origin with credentials, which a
/// browser allows only for an exact allowed origin (Fetch standard §3.2.5):
/// an explicit list is also what makes the transcoder allow credentials. A
/// wildcard or `null` origin in the list stops startup.
#[cfg(feature = "http")]
pub fn allow_sign_in_origin(
    config: &mut serde_json::Value,
    origin: &url::Origin,
) -> anyhow::Result<()> {
    let map = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("the HTTP configuration must be a mapping"))?;
    let cors = map
        .entry("cors")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let cors = cors
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("the HTTP configuration's cors must be a mapping"))?;
    let origins = cors
        .entry("origins")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    let origins = origins
        .as_array_mut()
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
    // A ceremony answers the page with its CSRF token in a response header,
    // which a cross-origin script reads only when it is exposed (Fetch
    // standard §3.2.6, CORS-exposed header-name list).
    let exposed = cors
        .entry("expose_headers")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("cors.expose_headers must be a list"))?;
    let csrf = sid_authn::browser_session::CSRF_HEADER;
    if !exposed
        .iter()
        .any(|h| h.as_str().is_some_and(|h| h.eq_ignore_ascii_case(csrf)))
    {
        exposed.push(csrf.into());
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
