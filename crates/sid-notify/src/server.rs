// SPDX-License-Identifier: AGPL-3.0-only
//! sid-notify server: NATS consumer + gRPC API.
//!
//! Subscribes to NATS JetStream events via durable consumer with queue group,
//! routes events through NotificationDispatcher, and exposes gRPC API for
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

use async_nats::jetstream::{self, consumer, stream};
use futures::StreamExt;
use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::TokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::work_runner::{RunnerConfig, WorkHandler, WorkRunner};
use sid_core::grpc_error::ErrorReason;
use sid_core::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, missing_field, not_configured, not_found,
    storage_failure,
};
use sid_core::models::ProfileId;
use sid_plugin::WorkStore;
use sid_plugin::notification::NotificationChannel;
use sid_storage::PgWorkStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server as TonicServer;
use tracing::{error, info, warn};

/// NATS JetStream stream name for SID events.
const STREAM_NAME: &str = "SID_EVENTS";

/// NATS subject filter — all SID events.
const SUBJECT_FILTER: &str = "sid.>";

/// Notification server combining NATS consumer and gRPC API.
pub struct NotifyServer {
    config: NotifyConfig,
    dispatcher: Arc<NotificationDispatcher>,
    routing: RoutingTable,
    /// Delivery jobs: routing, per-channel deliveries, dead-letter alerts.
    jobs: Arc<dyn WorkStore>,
    store: Arc<TemplateStore>,
    resolver: Arc<RecipientResolver>,
    verifier: Arc<TokenVerifier>,
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

        // The template API serves administrators only, so a token verifier is
        // required: without one the server does not start. Only the public key
        // is loaded; this service never issues tokens.
        let Some(pub_path) = &config.jwt_public_key_path else {
            anyhow::bail!(
                "SID_JWT_PUBLIC_KEY_PATH is required: the template API authenticates administrators"
            );
        };
        let pub_pem = std::fs::read(pub_path)
            .map_err(|e| anyhow::anyhow!("failed to read JWT public key {pub_path}: {e}"))?;
        let verifier = Arc::new(
            TokenVerifier::new(&pub_pem, config.jwt_issuer.clone())
                .map_err(|e| anyhow::anyhow!("token verifier init failed: {e}"))?,
        );

        Ok(Self {
            config,
            dispatcher: Arc::new(dispatcher),
            routing,
            jobs,
            store,
            resolver,
            verifier,
        })
    }

    /// Run the notification server (NATS consumer + gRPC).
    ///
    /// Blocks until shutdown signal (SIGINT/SIGTERM).
    pub async fn serve(self) -> anyhow::Result<()> {
        let drain = sid_serve::shutdown::drain_interval_from_env()?;
        let (stopper, stopped) = sid_serve::stop_signal();

        // Connect to NATS.
        let nats_client = async_nats::connect(&self.config.nats_url).await?;
        let jetstream = jetstream::new(nats_client);
        info!(url = %self.config.nats_url, "Connected to NATS");

        // Ensure the SID_EVENTS stream exists.
        jetstream
            .get_or_create_stream(stream::Config {
                name: STREAM_NAME.to_string(),
                subjects: vec![SUBJECT_FILTER.to_string()],
                max_age: std::time::Duration::from_secs(7 * 24 * 60 * 60),
                storage: stream::StorageType::File,
                retention: stream::RetentionPolicy::Limits,
                ..Default::default()
            })
            .await?;

        // Create durable consumer with queue group for load-balanced processing.
        let stream = jetstream.get_stream(STREAM_NAME).await?;
        let durable_name = format!(
            "{}-{}",
            self.config.queue_group,
            SUBJECT_FILTER.replace('.', "-")
        );
        let deliver_subject = format!("_INBOX.sid-notify.{}", std::process::id());

        // A new durable consumer starts from the stream's first event: events
        // published before this service first ran are owed to it too.
        let nats_consumer = stream
            .create_consumer(consumer::push::Config {
                filter_subject: SUBJECT_FILTER.to_string(),
                deliver_policy: consumer::DeliverPolicy::All,
                ack_policy: consumer::AckPolicy::Explicit,
                deliver_subject,
                durable_name: Some(durable_name.clone()),
                deliver_group: Some(self.config.queue_group.clone()),
                ..Default::default()
            })
            .await?;

        info!(
            durable = %durable_name,
            group = %self.config.queue_group,
            "NATS JetStream consumer created"
        );

        // Delivery jobs run in this process under leases shared with every replica.
        let bus: Arc<dyn sid_plugin::EventBus> = Arc::new(
            sid_infra::NatsEventBus::connect(&self.config.nats_url)
                .await
                .map_err(|e| anyhow::anyhow!("NATS event bus: {e}"))?,
        );
        let handlers: Vec<Arc<dyn WorkHandler>> = vec![
            Arc::new(delivery::RouteHandler::new(
                self.routing.clone(),
                self.resolver.clone(),
                Arc::clone(&self.jobs),
                self.config.job_capacity,
            )),
            Arc::new(delivery::DeliverHandler::new(self.dispatcher.clone())),
            Arc::new(delivery::DlqAlertHandler::new(bus)),
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

        // An event is acknowledged only once its routing job is stored; until
        // then the broker keeps it and redelivers.
        let jobs = Arc::clone(&self.jobs);
        let capacity = self.config.job_capacity;
        let consumer_stopped = stopped.clone().wait();
        let consumer_handle = tokio::spawn(async move {
            tokio::pin!(consumer_stopped);
            let messages = match nats_consumer.messages().await {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to start NATS message stream: {e}");
                    return;
                }
            };

            let mut messages = messages;
            loop {
                tokio::select! {
                    msg = messages.next() => {
                        match msg {
                            Some(Ok(msg)) => {
                                delivery::accept_message(jobs.as_ref(), capacity, &msg).await;
                                waker.wake();
                            }
                            Some(Err(e)) => {
                                warn!("NATS message error: {e}");
                            }
                            None => {
                                info!("NATS message stream ended");
                                break;
                            }
                        }
                    }
                    () = &mut consumer_stopped => {
                        info!("NATS consumer shutting down");
                        break;
                    }
                }
            }
        });

        // gRPC reflection service.
        let reflection_svc = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(sid_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        // Revocations made by any SID service apply here too.
        let shared_cache =
            sid_infra::shared_cache(sid_infra::cache_url_from_env().as_deref()).await?;
        let revocation = Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            shared_cache,
        ));
        // Runs until the cache connection closes with the process.
        let _revocation_listener = revocation.listen().await?;

        // Build gRPC server.
        let template_svc = NotificationTemplateServiceImpl::new(
            self.dispatcher.clone(),
            self.store.clone(),
            self.resolver.clone(),
            self.verifier.clone(),
            revocation,
        );
        let mut services = sid_serve::Services::new();
        services
            .route(reflection_svc)
            .add(
                sid_proto::sid::v1::admin::notification_template_service_server::NotificationTemplateServiceServer::new(template_svc),
            )
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
        let consumed = consumer_handle.await;
        let ran = runner_handle.await;
        served?;
        consumed.map_err(|e| anyhow::anyhow!("NATS consumer task failed: {e}"))?;
        ran.map_err(|e| anyhow::anyhow!("delivery runner task failed: {e}"))?;

        info!("sid-notify shutdown complete");
        Ok(())
    }

    /// Get a reference to the dispatcher (for testing).
    pub fn dispatcher(&self) -> &Arc<NotificationDispatcher> {
        &self.dispatcher
    }
}

/// gRPC implementation of NotificationTemplateService.
///
/// Provides template listing, preview, update, reset, and test send.
pub struct NotificationTemplateServiceImpl {
    dispatcher: Arc<NotificationDispatcher>,
    store: Arc<crate::template_store::TemplateStore>,
    /// The requesting administrator's own address for a test send.
    resolver: Arc<RecipientResolver>,
    verifier: Arc<TokenVerifier>,
    /// Revocations made anywhere in the deployment (see [`RevocationCache::listen`]).
    revocation: Arc<RevocationCache>,
}

impl NotificationTemplateServiceImpl {
    pub(crate) fn new(
        dispatcher: Arc<NotificationDispatcher>,
        store: Arc<crate::template_store::TemplateStore>,
        resolver: Arc<RecipientResolver>,
        verifier: Arc<TokenVerifier>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            dispatcher,
            store,
            resolver,
            verifier,
            revocation,
        }
    }

    /// Authenticate the caller and require the administrator role.
    #[allow(clippy::result_large_err)]
    async fn require_admin<T>(&self, req: &tonic::Request<T>) -> Result<Caller, tonic::Status> {
        let caller = authenticate(req, &self.verifier, &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    /// The administrator's own address on `channel`, the default recipient
    /// of a test send. Without one the request names a recipient.
    async fn own_address(
        &self,
        profile_id: ProfileId,
        channel: Channel,
    ) -> Result<String, tonic::Status> {
        let contact = self
            .resolver
            .contact(&profile_id.to_string())
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
            .and_then(|c| match channel {
                Channel::Email => c.email,
                Channel::Sms => c.phone,
                Channel::Push => None,
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
        TemplateStoreError::Database(cause) => storage_failure(cause),
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
        self.require_admin(&request).await?;
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
        self.require_admin(&request).await?;
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
        self.require_admin(&request).await?;
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
        self.require_admin(&request).await?;
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
        self.require_admin(&request).await?;
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
        let caller = self.require_admin(&request).await?;
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

        // The named recipient, or the administrator's own address.
        let address = if req.recipient.is_empty() {
            self.own_address(caller.profile_id, channel).await?
        } else {
            req.recipient
        };
        let recipient = sid_plugin::notification::Recipient {
            profile_id: caller.profile_id.to_string(),
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
