// SPDX-License-Identifier: AGPL-3.0-only
//! sid-notify server: durable work consumer + gRPC API.
//!
//! Consumes the facts owed to this service from its addressed work, routes
//! them through NotificationDispatcher, and exposes gRPC API for
//! template/webhook/DLQ management.

use crate::channels::smtp::SmtpChannel;
use crate::channels::web_push::WebPushChannel;
use crate::channels::webhook::WebhookChannel;
use crate::config::NotifyConfig;
use crate::delivery;
use crate::dispatcher::NotificationDispatcher;
use crate::recipient_resolver::{RecipientResolver, ResolveError};
use crate::routing::RoutingTable;
use crate::template::TemplateEngine;
use crate::template_store::TemplateStore;

use sid_auth::receiver::Receiver;
use sid_authn::event_relay::{EventDeliveryHandler, EventFanoutHandler, EventRelayHandler};
use sid_authn::work_runner::{RunnerConfig, WorkHandler, WorkRunner};
use sid_core::grpc_error::ErrorReason;
use sid_core::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, missing_field, not_configured, not_found,
    storage_failure,
};
use sid_plugin::WorkStore;
use sid_plugin::notification::NotificationChannel;
use sid_storage::PgWorkStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server as TonicServer;
use tracing::{info, warn};

/// Notification server combining NATS consumer and gRPC API.
pub struct NotifyServer {
    config: NotifyConfig,
    dispatcher: Arc<NotificationDispatcher>,
    routing: RoutingTable,
    /// Delivery jobs: routing, per-channel deliveries, dead-letter alerts.
    jobs: Arc<dyn WorkStore>,
    store: Arc<TemplateStore>,
    resolver: Arc<RecipientResolver>,
    /// Admits the template API's calls (`crate::access`).
    receiver: Arc<Receiver>,
}

impl NotifyServer {
    /// Initialize the notification server from config.
    ///
    /// Sets up dispatcher with CE channels based on config.
    /// Connects to PostgreSQL if `database_url` is configured.
    pub async fn new(config: NotifyConfig) -> anyhow::Result<Self> {
        let routing = RoutingTable::default_ce_rules();
        // One engine: the template API customizes it and delivery renders from it.
        let engine = Arc::new(RwLock::new(TemplateEngine::with_default_ce_templates()));
        let mut dispatcher = NotificationDispatcher::new(Arc::clone(&engine));

        // Register enabled channels.
        if config.smtp_enabled {
            match SmtpChannel::new(config.smtp.clone()) {
                Ok(channel) => {
                    dispatcher.register_channel(Arc::new(channel) as Arc<dyn NotificationChannel>);
                    info!(
                        host = %config.smtp.host,
                        port = config.smtp.port,
                        "SMTP channel registered"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "SMTP channel disabled — invalid configuration"
                    );
                }
            }
        }

        if config.webhook_enabled {
            dispatcher.register_channel(
                Arc::new(WebhookChannel::new(vec![])?) as Arc<dyn NotificationChannel>
            );
            info!("Webhook channel registered (no endpoints configured yet)");
        }

        if let Some(ref vapid) = config.vapid {
            dispatcher.register_channel(
                Arc::new(WebPushChannel::new(vapid.clone())) as Arc<dyn NotificationChannel>
            );
            warn!(
                "Web Push (VAPID) channel registered, but delivery is unavailable: recipients carry no subscription keys"
            );
        }

        // Delivery jobs and template customizations live in this service's database.
        let pool = sqlx::PgPool::connect(&config.database_url).await?;
        let jobs = PgWorkStore::new(pool.clone());
        jobs.ensure_schema()
            .await
            .map_err(|e| anyhow::anyhow!("delivery job store init failed: {e}"))?;
        let jobs: Arc<dyn WorkStore> = Arc::new(jobs);

        let store = Arc::new(
            TemplateStore::new(&routing, engine, Some(pool))
                .await
                .map_err(|e| anyhow::anyhow!("template store init failed: {e}"))?,
        );

        // Create recipient resolver (optional gRPC client to sid-identity).
        // A configured but unusable address is a configuration error, not a
        // reason to deliver from event data instead.
        let resolver = if let Some(ref addr) = config.identity_grpc_address {
            let resolver = RecipientResolver::with_identity(addr).await?;
            info!(address = %addr, "Recipient resolver connected to sid-identity");
            Arc::new(resolver)
        } else {
            info!("No SID_IDENTITY_GRPC_ADDRESS — recipient resolution from event data only");
            Arc::new(RecipientResolver::without_identity())
        };

        // Every template call is decided by the issuer for its caller; a
        // receiver that cannot authenticate there stops the start rather than
        // leaving every call without a decision. It holds public trust
        // material and its own checker credential only.
        let receiver = Arc::new(Receiver::connect("sid-notify", &config.api).await?);

        Ok(Self {
            config,
            dispatcher: Arc::new(dispatcher),
            routing,
            jobs,
            store,
            resolver,
            receiver,
        })
    }

    /// Run the notification server (NATS consumer + gRPC).
    ///
    /// Blocks until shutdown signal (SIGINT/SIGTERM).
    pub async fn serve(self) -> anyhow::Result<()> {
        let drain = sid_serve::shutdown::drain_interval_from_env()?;
        let (stopper, stopped) = sid_serve::stop_signal();

        // The deployment prepares the event topology; this service requires
        // it as defined unless it is named the owner.
        let bus: Arc<dyn sid_plugin::EventBus> = Arc::new(
            sid_infra::NatsEventBus::connect(
                &self.config.nats_url,
                sid_infra::Topology::from_env()?,
                sid_infra::TopologyRole::from_env(sid_infra::TopologyRole::Verify)?,
            )
            .await
            .map_err(|e| anyhow::anyhow!("NATS event bus: {e}"))?,
        );
        info!(url = %self.config.nats_url, receiver = %self.config.receiver, "Connected to NATS");
        // A consumer that cannot be opened stops startup: serving without it
        // would look healthy while owed work piles up. The same holds for
        // each bound source.
        let mut sources = vec![
            delivery::open_work(bus.as_ref(), self.config.receiver.clone())
                .await
                .map_err(|e| anyhow::anyhow!("notification work consumer: {e}"))?,
        ];
        // The platform source, bound only where the composition permits it:
        // its own streams, prepared by the platform deployment.
        let platform = match &self.config.platform_nats_url {
            Some(url) => {
                let platform = sid_infra::NatsEventBus::connect(
                    url,
                    sid_infra::Topology::from_env()?
                        .for_family(sid_core::models::event::EventFamily::Platform),
                    sid_infra::TopologyRole::Verify,
                )
                .await
                .map_err(|e| anyhow::anyhow!("platform event source: {e}"))?;
                sources.push(
                    delivery::open_work(&platform, self.config.receiver.clone())
                        .await
                        .map_err(|e| anyhow::anyhow!("platform work consumer: {e}"))?,
                );
                info!(url = %url, "Bound to the platform event source");
                Some(platform)
            }
            None => None,
        };

        // Delivery jobs run in this process under leases shared with every replica.
        let handlers: Vec<Arc<dyn WorkHandler>> = vec![
            Arc::new(delivery::RouteHandler::new(
                self.routing.clone(),
                self.resolver.clone(),
                Arc::clone(&self.jobs),
                self.config.job_capacity,
            )),
            Arc::new(delivery::PlanHandler::new(
                Arc::clone(&self.jobs),
                self.config.job_capacity,
            )),
            Arc::new(delivery::DeliverHandler::new(self.dispatcher.clone())),
            // This service's own facts (dead-letter alerts) are relayed as
            // every fact is: owed to the other required receivers, then
            // published to history. They replace the `notify.dlq_alert` work
            // of builds before any release, which no release carries, so no
            // installation has such work to drain.
            Arc::new(EventRelayHandler::new(
                Arc::clone(&self.jobs),
                self.config.event_receivers.clone(),
                self.config.job_capacity,
            )),
            Arc::new(EventFanoutHandler::new(
                Arc::clone(&bus),
                Arc::clone(&self.jobs),
                self.config.job_capacity,
            )),
            Arc::new(EventDeliveryHandler::new(Arc::clone(&bus))),
        ];
        let worker = format!("sid-notify-{}-{}", std::process::id(), uuid::Uuid::now_v7());
        let runner = WorkRunner::new(
            Arc::clone(&self.jobs),
            worker,
            handlers,
            RunnerConfig::default(),
        )
        .map_err(|e| anyhow::anyhow!("delivery runner: {e}"))?;
        let waker = runner.waker();
        let runner_handle = tokio::spawn(runner.run(stopped.clone().wait()));

        // Every fact is owed to this service as addressed work, kept by the
        // bus until settled; an event is settled only once its routing job is
        // stored, and stays with the bus otherwise.
        let consumer_handles: Vec<_> = sources
            .into_iter()
            .map(|deliveries| {
                let jobs = Arc::clone(&self.jobs);
                let capacity = self.config.job_capacity;
                let consumer_stopped = stopped.clone().wait();
                let waker = waker.clone();
                tokio::spawn(async move {
                    delivery::accept_work(
                        deliveries,
                        jobs.as_ref(),
                        capacity,
                        || waker.wake(),
                        consumer_stopped,
                    )
                    .await;
                    info!("notification work consumer stopped");
                })
            })
            .collect();

        // gRPC reflection service.
        let reflection_svc = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(sid_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        // Build gRPC server.
        let template_svc = NotificationTemplateServiceImpl::new(
            self.dispatcher.clone(),
            self.store.clone(),
            self.resolver.clone(),
        );
        let mut services = sid_serve::Services::new();
        services
            .route(reflection_svc)
            .add(crate::access::guarded(
                sid_proto::sid::v1::admin::notification_template_service_server::NotificationTemplateServiceServer::new(template_svc),
                &self.receiver,
            ))
            .await;
        let (routes, health) = services.into_parts();
        let grpc_server = TonicServer::builder()
            .accept_http1(true)
            .add_routes(routes)
            .serve_with_shutdown(self.config.grpc_bind, stopped.wait());

        info!(bind = %self.config.grpc_bind, "gRPC server starting");
        let served = sid_serve::run(
            grpc_server,
            sid_serve::shutdown::signal(),
            &health,
            &stopper,
            drain,
        )
        .await;
        // A failed server stops the consumer and the runner as well.
        stopper.stop();

        // Stop accepting, then let delivery attempts in flight record their outcome.
        let mut consumed = Vec::with_capacity(consumer_handles.len());
        for handle in consumer_handles {
            consumed.push(handle.await);
        }
        let ran = runner_handle.await;
        // The platform source's connection lives until its consumer stopped.
        drop(platform);
        served?;
        for result in consumed {
            result.map_err(|e| anyhow::anyhow!("NATS consumer task failed: {e}"))?;
        }
        ran.map_err(|e| anyhow::anyhow!("delivery runner task failed: {e}"))?;

        info!("sid-notify shutdown complete");
        Ok(())
    }

    /// Get a reference to the dispatcher (for testing).
    pub fn dispatcher(&self) -> &Arc<NotificationDispatcher> {
        &self.dispatcher
    }
}

/// gRPC implementation of NotificationTemplateService. It is served only
/// behind its receiver (`crate::access`), which admits each call for its
/// method's action before it reaches a handler.
///
/// Provides template listing, preview, update, reset, and test send.
pub struct NotificationTemplateServiceImpl {
    dispatcher: Arc<NotificationDispatcher>,
    store: Arc<crate::template_store::TemplateStore>,
    /// The caller's own address for a test send.
    resolver: Arc<RecipientResolver>,
}

impl NotificationTemplateServiceImpl {
    pub(crate) fn new(
        dispatcher: Arc<NotificationDispatcher>,
        store: Arc<crate::template_store::TemplateStore>,
        resolver: Arc<RecipientResolver>,
    ) -> Self {
        Self {
            dispatcher,
            store,
            resolver,
        }
    }

    /// The Profile and own address on `channel` of the caller whose token is
    /// `authorization`, the default recipient of a test send. Without one
    /// (no identity service, no such address, or a sender-bound token that
    /// only its holder can present) the request names a recipient.
    async fn own_address(
        &self,
        authorization: Option<&tonic::metadata::AsciiMetadataValue>,
        channel: Channel,
    ) -> Result<(String, String), tonic::Status> {
        // A DPoP-bound token is presented with its holder's proof for this
        // call only; it cannot be presented again to another service.
        let Some(bearer) = authorization.filter(|value| {
            value.to_str().is_ok_and(|v| {
                v.get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("bearer "))
            })
        }) else {
            return Err(missing_field("recipient"));
        };
        let contact = self
            .resolver
            .current_contact(bearer)
            .await
            .map_err(|e| match e {
                ResolveError::ProfileGone(id) => {
                    not_found(ErrorReason::ProfileNotFound, "Profile", id)
                }
                ResolveError::Unavailable(cause) => {
                    dependency_unavailable("identity service", cause)
                }
            })?;
        contact
            .and_then(|(profile, c)| {
                match channel {
                    Channel::Email => c.email,
                    Channel::Sms => c.phone,
                    Channel::Push => None,
                }
                .map(|address| (profile, address))
            })
            .ok_or_else(|| missing_field("recipient"))
    }
}

use crate::template_store::{Channel, StoredContent, TemplateStoreError};

/// Convert proto NotificationChannel enum to internal Channel.
#[allow(clippy::result_large_err)]
fn proto_channel_to_internal(v: i32) -> Result<Channel, tonic::Status> {
    Channel::from_i32(v).ok_or_else(|| invalid_field("channel", "not a notification channel"))
}

/// TEMPLATE_NOT_FOUND for `template_id`.
fn template_not_found(template_id: &str) -> tonic::Status {
    not_found(
        ErrorReason::TemplateNotFound,
        "NotificationTemplate",
        template_id,
    )
}

/// A template store failure: an unknown template, or a storage failure whose
/// cause stays in the log.
fn store_refusal(e: TemplateStoreError) -> tonic::Status {
    match e {
        TemplateStoreError::NotFound(id) => template_not_found(&id),
        TemplateStoreError::Database(cause) => storage_failure(sid_core::Error::Storage(cause)),
    }
}

/// Convert internal Channel to proto i32 value.
fn channel_to_proto(ch: &Channel) -> i32 {
    *ch as i32
}

/// Build proto NotificationTemplate from store data.
fn build_proto_template(
    content: &StoredContent,
    customized: bool,
    meta: &crate::template_store::TemplateMeta,
    channel: Channel,
    locale: &str,
    available_locales: Vec<String>,
) -> sid_proto::sid::v1::admin::NotificationTemplate {
    use sid_proto::sid::v1::admin;

    admin::NotificationTemplate {
        template_id: meta.template_id.clone(),
        name: meta.name.clone(),
        description: meta.description.clone(),
        channels: meta.channels.iter().map(channel_to_proto).collect(),
        trigger: meta.trigger.clone(),
        customized,
        updated_at: Some(prost_types::Timestamp {
            seconds: content.updated_at.timestamp(),
            nanos: content.updated_at.timestamp_subsec_nanos() as i32,
        }),
        content: Some(admin::TemplateContent {
            channel: channel as i32,
            locale: locale.to_string(),
            subject: content.subject.clone(),
            html_body: content.html_body.clone(),
            text_body: content.text_body.clone(),
            sms_body: content.sms_body.clone(),
            push_title: content.push_title.clone(),
            push_body: content.push_body.clone(),
            push_action_url: content.push_action_url.clone(),
        }),
        available_locales,
        variables: meta
            .variables
            .iter()
            .map(|v| admin::TemplateVariable {
                name: v.name.clone(),
                description: v.description.clone(),
                example: v.example.clone(),
            })
            .collect(),
    }
}

#[tonic::async_trait]
impl sid_proto::sid::v1::admin::notification_template_service_server::NotificationTemplateService
    for NotificationTemplateServiceImpl
{
    async fn list_templates(
        &self,
        request: tonic::Request<sid_proto::sid::v1::admin::ListTemplatesRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::admin::ListTemplatesResponse>, tonic::Status>
    {
        let req = request.into_inner();
        let channel_filter = if req.channel == 0 {
            None
        } else {
            Some(proto_channel_to_internal(req.channel)?)
        };

        let summaries = self
            .store
            .list_templates(channel_filter, req.customized_only)
            .await;

        let templates = summaries
            .into_iter()
            .map(|s| sid_proto::sid::v1::admin::TemplateSummary {
                template_id: s.template_id,
                name: s.name,
                description: s.description,
                channels: s.channels.iter().map(channel_to_proto).collect(),
                trigger: s.trigger,
                customized: s.customized,
                updated_at: s.updated_at.map(|t| prost_types::Timestamp {
                    seconds: t.timestamp(),
                    nanos: t.timestamp_subsec_nanos() as i32,
                }),
            })
            .collect();

        Ok(tonic::Response::new(
            sid_proto::sid::v1::admin::ListTemplatesResponse { templates },
        ))
    }

    async fn get_template(
        &self,
        request: tonic::Request<sid_proto::sid::v1::admin::GetTemplateRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::admin::NotificationTemplate>, tonic::Status>
    {
        let req = request.into_inner();
        let channel = if req.channel == 0 {
            Channel::Email
        } else {
            proto_channel_to_internal(req.channel)?
        };
        let locale = if req.locale.is_empty() {
            "en"
        } else {
            &req.locale
        };

        let (content, customized, meta) = self
            .store
            .get_template(&req.template_id, channel, locale)
            .await
            .ok_or_else(|| template_not_found(&req.template_id))?;

        let available_locales = self.store.available_locales(&req.template_id).await;

        Ok(tonic::Response::new(build_proto_template(
            &content,
            customized,
            meta,
            channel,
            locale,
            available_locales,
        )))
    }

    async fn update_template(
        &self,
        request: tonic::Request<sid_proto::sid::v1::admin::UpdateTemplateRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::admin::NotificationTemplate>, tonic::Status>
    {
        let req = request.into_inner();
        let proto_content = req.content.ok_or_else(|| missing_field("content"))?;

        let channel = proto_channel_to_internal(proto_content.channel)?;
        let locale = if proto_content.locale.is_empty() {
            "en"
        } else {
            &proto_content.locale
        };

        let stored = StoredContent {
            subject: proto_content.subject,
            html_body: proto_content.html_body,
            text_body: proto_content.text_body,
            sms_body: proto_content.sms_body,
            push_title: proto_content.push_title,
            push_body: proto_content.push_body,
            push_action_url: proto_content.push_action_url,
            updated_at: chrono::Utc::now(),
        };

        self.store
            .update_template(&req.template_id, channel, locale, stored)
            .await
            .map_err(store_refusal)?;

        // Return the updated template.
        let (content, customized, meta) = self
            .store
            .get_template(&req.template_id, channel, locale)
            .await
            .ok_or_else(|| internal("update_template", "template missing after update"))?;

        let available_locales = self.store.available_locales(&req.template_id).await;

        Ok(tonic::Response::new(build_proto_template(
            &content,
            customized,
            meta,
            channel,
            locale,
            available_locales,
        )))
    }

    async fn reset_template(
        &self,
        request: tonic::Request<sid_proto::sid::v1::admin::ResetTemplateRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::admin::NotificationTemplate>, tonic::Status>
    {
        let req = request.into_inner();
        let channel = if req.channel == 0 {
            Channel::Email
        } else {
            proto_channel_to_internal(req.channel)?
        };
        let locale = if req.locale.is_empty() {
            "en"
        } else {
            &req.locale
        };

        self.store
            .reset_template(&req.template_id, channel, locale)
            .await
            .map_err(store_refusal)?;

        // Return the default template.
        let (content, customized, meta) = self
            .store
            .get_template(&req.template_id, channel, locale)
            .await
            .ok_or_else(|| internal("reset_template", "template missing after reset"))?;

        let available_locales = self.store.available_locales(&req.template_id).await;

        Ok(tonic::Response::new(build_proto_template(
            &content,
            customized,
            meta,
            channel,
            locale,
            available_locales,
        )))
    }

    async fn preview_template(
        &self,
        request: tonic::Request<sid_proto::sid::v1::admin::PreviewTemplateRequest>,
    ) -> Result<tonic::Response<sid_proto::sid::v1::admin::PreviewTemplateResponse>, tonic::Status>
    {
        let req = request.into_inner();
        let channel = if req.channel == 0 {
            Channel::Email
        } else {
            proto_channel_to_internal(req.channel)?
        };
        let locale = if req.locale.is_empty() {
            "en"
        } else {
            &req.locale
        };

        let (content, _, meta) = self
            .store
            .get_template(&req.template_id, channel, locale)
            .await
            .ok_or_else(|| template_not_found(&req.template_id))?;

        // Build variables: merge defaults from meta with user-provided sample_data.
        let mut vars: std::collections::HashMap<String, String> = meta
            .variables
            .iter()
            .map(|v| (v.name.clone(), v.example.clone()))
            .collect();
        for (k, v) in req.sample_data {
            vars.insert(k, v);
        }

        let (rendered_subject, rendered_body, rendered_text) =
            TemplateStore::render_preview(&content, channel, &vars);

        Ok(tonic::Response::new(
            sid_proto::sid::v1::admin::PreviewTemplateResponse {
                rendered_subject,
                rendered_body,
                rendered_text,
            },
        ))
    }

    async fn send_test_notification(
        &self,
        request: tonic::Request<sid_proto::sid::v1::admin::SendTestNotificationRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        // The call is admitted: its verified subject names the test's
        // recipient when no Profile can be learned for it.
        let subject = sid_auth::receiver::admitted(&request)?.claims.sub.clone();
        let authorization = request.metadata().get("authorization").cloned();
        let req = request.into_inner();
        let channel = if req.channel == 0 {
            Channel::Email
        } else {
            proto_channel_to_internal(req.channel)?
        };
        let locale = if req.locale.is_empty() {
            "en"
        } else {
            &req.locale
        };

        let (content, _, meta) = self
            .store
            .get_template(&req.template_id, channel, locale)
            .await
            .ok_or_else(|| template_not_found(&req.template_id))?;

        // Build sample variables for rendering.
        let vars: std::collections::HashMap<String, String> = meta
            .variables
            .iter()
            .map(|v| (v.name.clone(), v.example.clone()))
            .collect();

        let (rendered_subject, rendered_body, rendered_text) =
            TemplateStore::render_preview(&content, channel, &vars);

        // Determine channel ID for dispatch.
        let channel_id = match channel {
            Channel::Email => "email",
            Channel::Sms => "sms",
            Channel::Push => "web_push",
        };

        if !self
            .dispatcher
            .channel_ids()
            .iter()
            .any(|id| id == channel_id)
        {
            return Err(not_configured(channel_id));
        }

        // The named recipient, or the caller's own address.
        let (profile_id, address) = if req.recipient.is_empty() {
            self.own_address(authorization.as_ref(), channel).await?
        } else {
            (subject, req.recipient)
        };
        let recipient = sid_plugin::notification::Recipient {
            profile_id,
            email: (channel == Channel::Email).then(|| address.clone()),
            phone: (channel == Channel::Sms).then(|| address.clone()),
            push_endpoint: (channel == Channel::Push).then_some(address),
            device_token: None,
            locale: locale.to_string(),
        };

        // Build rendered message.
        let message = sid_plugin::notification::RenderedMessage {
            subject: Some(rendered_subject),
            body: rendered_body,
            body_text: Some(rendered_text),
            priority: sid_plugin::notification::NotificationPriority::Transactional,
            event_type: format!("sid.admin.test_notification.{}", req.template_id),
        };

        self.dispatcher
            .deliver_to_channel(channel_id, &recipient, &message)
            .await
            .map_err(|e| dependency_unavailable(channel_id, e))?;
        Ok(tonic::Response::new(()))
    }
}

#[cfg(test)]
mod tests;
