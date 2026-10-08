use super::*;
use crate::channels::smtp::SmtpConfig;

fn test_config() -> NotifyConfig {
    NotifyConfig {
        nats_url: "nats://127.0.0.1:4222".into(),
        grpc_bind: "127.0.0.1:0".parse().unwrap(),
        queue_group: "sid-notify".into(),
        smtp: SmtpConfig::default(),
        smtp_enabled: true,
        webhook_enabled: true,
        vapid: None,
        database_url: test_database_url(),
        job_capacity: crate::config::DEFAULT_JOB_CAPACITY,
        identity_grpc_address: None,
        jwt_public_key_path: Some(fixture_key("test_ed25519_public.pem")),
        jwt_issuer: "https://sid.example.com".into(),
    }
}

/// The service's own test database; an unreachable one fails the test.
fn test_database_url() -> String {
    std::env::var("SID_NOTIFY_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_notify_test".into())
}

/// A template an administrator customizes through the API is the one
/// delivery renders: both use one engine.
#[tokio::test]
async fn test_customized_template_reaches_delivery() {
    use crate::template_store::{Channel, StoredContent};
    let server = NotifyServer::new(test_config()).await.unwrap();
    let subject = format!("Custom alert {}", uuid::Uuid::now_v7());
    server
        .store
        .update_template(
            "security_alert",
            Channel::Email,
            "en",
            StoredContent {
                subject: subject.clone(),
                html_body: "<p>custom</p>".into(),
                text_body: "custom".into(),
                sms_body: String::new(),
                push_title: String::new(),
                push_body: String::new(),
                push_action_url: String::new(),
                updated_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
    let event = sid_core::models::event::Event::new(
        "src",
        sid_core::models::event::event_types::SECURITY_BRUTE_FORCE,
    );
    let message = server
        .dispatcher
        .render(
            "security_alert",
            &event,
            sid_plugin::notification::NotificationPriority::Critical,
        )
        .await
        .unwrap();
    assert_eq!(
        message.subject.as_deref(),
        Some(subject.as_str()),
        "delivery rendered a template other than the customized one"
    );
}

/// Without its database the service does not start: delivery could not
/// be owned durably.
#[tokio::test]
async fn test_server_without_a_reachable_database_does_not_start() {
    let config = NotifyConfig {
        database_url: "postgres://sid:sid_dev@127.0.0.1:1/none".into(),
        ..test_config()
    };
    assert!(NotifyServer::new(config).await.is_err());
}

fn fixture_key(name: &str) -> String {
    format!(
        "{}/../sid-authn/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// The notification service only verifies administrators' tokens, so it
/// starts with the public key alone and never needs the signing key (with
/// it, a compromised notification service could mint admin tokens).
#[tokio::test]
async fn test_server_starts_with_the_public_key_alone() {
    NotifyServer::new(test_config())
        .await
        .expect("a verify-only service needs no private key");
}

#[tokio::test]
async fn test_server_init_registers_channels() {
    let server = NotifyServer::new(test_config()).await.unwrap();
    let channels = server.dispatcher.channel_ids();
    assert!(channels.contains(&"email".to_string()));
    assert!(channels.contains(&"webhook".to_string()));
}

#[tokio::test]
async fn test_server_init_no_smtp() {
    let mut config = test_config();
    config.smtp_enabled = false;
    let server = NotifyServer::new(config).await.unwrap();
    let channels = server.dispatcher.channel_ids();
    assert!(!channels.contains(&"email".to_string()));
    assert!(channels.contains(&"webhook".to_string()));
}

#[tokio::test]
async fn test_server_init_with_vapid() {
    let mut config = test_config();
    config.vapid = Some(crate::channels::web_push::VapidConfig {
        subject: "mailto:admin@sid.example.com".into(),
        public_key: "test-key".into(),
        private_key: "test-private".into(),
    });
    let server = NotifyServer::new(config).await.unwrap();
    let channels = server.dispatcher.channel_ids();
    assert!(channels.contains(&"web_push".to_string()));
}

#[tokio::test]
async fn test_resolver_no_data() {
    let resolver = RecipientResolver::without_identity();
    let event = sid_core::models::event::Event::new("sid-server", "sid.session.created.v1");

    let recipient = resolver.resolve(&event).await.unwrap();
    assert_eq!(recipient.profile_id, "unknown");
    assert!(recipient.email.is_none());
    assert!(recipient.phone.is_none());
}

// ── gRPC Handler Tests ──

use sid_proto::sid::v1::admin::notification_template_service_server::NotificationTemplateService;

/// The template service with the given channels registered and no identity
/// service.
async fn grpc_service_with(
    channels: Vec<Arc<dyn NotificationChannel>>,
) -> NotificationTemplateServiceImpl {
    let routing = RoutingTable::default_ce_rules();
    let engine = Arc::new(RwLock::new(TemplateEngine::with_default_ce_templates()));
    let mut dispatcher = NotificationDispatcher::new(Arc::clone(&engine));
    for channel in channels {
        dispatcher.register_channel(channel);
    }
    let store = Arc::new(
        crate::template_store::TemplateStore::new(&routing, engine, None)
            .await
            .unwrap(),
    );
    NotificationTemplateServiceImpl::new(
        Arc::new(dispatcher),
        store,
        Arc::new(RecipientResolver::without_identity()),
        test_verifier(),
        Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
    )
}

/// An SMTP channel whose server cannot be reached: every delivery fails.
fn unreachable_smtp() -> Arc<dyn NotificationChannel> {
    Arc::new(
        SmtpChannel::new(SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1,
            ..SmtpConfig::default()
        })
        .expect("SMTP config is valid"),
    )
}

async fn test_grpc_service() -> NotificationTemplateServiceImpl {
    grpc_service_with(vec![unreachable_smtp()]).await
}

/// A request carrying an administrator's token: the template API serves
/// administrators only.
fn admin<T>(inner: T) -> tonic::Request<T> {
    request_with_token(inner, &issue_admin_token(&test_jwt_service()))
}

/// `ErrorInfo.reason` of a refusal.
fn reason(status: &tonic::Status) -> Option<String> {
    sid_core::grpc_error::extract_error_info(status).map(|(reason, _, _)| reason)
}

/// Every refusal of the template API, without a token and as an
/// administrator, carries ErrorInfo in the structured.id domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_every_refusal_carries_error_info() {
    let mut services = sid_serve::Services::new();
    services
        .add(
            sid_proto::sid::v1::admin::notification_template_service_server::NotificationTemplateServiceServer::new(
                test_grpc_service().await,
            ),
        )
        .await;
    let (routes, health) = services.into_parts();
    let token = issue_admin_token(&test_jwt_service());
    let report = sid_serve::error_contract::probe(
        routes,
        health.names(),
        &[sid_proto::FILE_DESCRIPTOR_SET],
        &[sid_core::grpc_error::DOMAIN_SID],
        &[
            sid_serve::error_contract::Caller {
                name: "anonymous",
                token: None,
            },
            sid_serve::error_contract::Caller {
                name: "admin",
                token: Some(&token),
            },
        ],
    )
    .await;
    assert!(report.methods >= 5, "only {} methods", report.methods);
    // Every anonymous call is refused at least.
    assert!(report.refusals >= report.methods, "{report:?}");
    assert!(
        report.violations.is_empty(),
        "{}",
        report.violations.join("\n")
    );
}

#[tokio::test]
async fn test_grpc_list_templates_returns_all_defaults() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 0,
        customized_only: false,
    });
    let resp = svc.list_templates(req).await.unwrap();
    let templates = resp.into_inner().templates;
    assert_eq!(templates.len(), 8);
    assert!(templates.iter().all(|t| !t.customized));
    assert!(templates.iter().all(|t| !t.template_id.is_empty()));
    assert!(templates.iter().all(|t| !t.trigger.is_empty()));
}

#[tokio::test]
async fn test_grpc_list_templates_filter_email() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 1, // EMAIL
        customized_only: false,
    });
    let resp = svc.list_templates(req).await.unwrap();
    assert_eq!(resp.into_inner().templates.len(), 8);
}

#[tokio::test]
async fn test_grpc_list_templates_filter_sms_empty() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 2, // SMS
        customized_only: false,
    });
    let resp = svc.list_templates(req).await.unwrap();
    assert!(resp.into_inner().templates.is_empty());
}

#[tokio::test]
async fn test_grpc_get_template_default() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::GetTemplateRequest {
        template_id: "security_alert".into(),
        channel: 1, // EMAIL
        locale: "en".into(),
    });
    let resp = svc.get_template(req).await.unwrap();
    let tmpl = resp.into_inner();
    assert_eq!(tmpl.template_id, "security_alert");
    assert!(!tmpl.customized);
    assert!(tmpl.content.is_some());
    let content = tmpl.content.unwrap();
    assert!(content.subject.contains("Security Alert"));
    assert!(!content.html_body.is_empty());
    assert!(tmpl.variables.len() >= 3);
    assert!(tmpl.available_locales.contains(&"en".to_string()));
}

#[tokio::test]
async fn test_grpc_get_template_not_found() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::GetTemplateRequest {
        template_id: "nonexistent".into(),
        channel: 1,
        locale: "en".into(),
    });
    let err = svc.get_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(reason(&err).as_deref(), Some("TEMPLATE_NOT_FOUND"));
}

#[tokio::test]
async fn test_grpc_update_and_get() {
    let svc = test_grpc_service().await;

    // Update security_alert email template.
    let update_req = admin(sid_proto::sid::v1::admin::UpdateTemplateRequest {
        template_id: "security_alert".into(),
        content: Some(sid_proto::sid::v1::admin::TemplateContent {
            channel: 1,
            locale: "en".into(),
            subject: "CUSTOM: Security Alert".into(),
            html_body: "<p>Custom body</p>".into(),
            text_body: "Custom body".into(),
            sms_body: String::new(),
            push_title: String::new(),
            push_body: String::new(),
            push_action_url: String::new(),
        }),
    });
    let resp = svc.update_template(update_req).await.unwrap();
    let tmpl = resp.into_inner();
    assert!(tmpl.customized);
    assert_eq!(tmpl.content.unwrap().subject, "CUSTOM: Security Alert");

    // Get should return the custom version.
    let get_req = admin(sid_proto::sid::v1::admin::GetTemplateRequest {
        template_id: "security_alert".into(),
        channel: 1,
        locale: "en".into(),
    });
    let got = svc.get_template(get_req).await.unwrap().into_inner();
    assert!(got.customized);
    assert_eq!(got.content.unwrap().subject, "CUSTOM: Security Alert");
}

#[tokio::test]
async fn test_grpc_update_nonexistent_fails() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::UpdateTemplateRequest {
        template_id: "nonexistent".into(),
        content: Some(sid_proto::sid::v1::admin::TemplateContent {
            channel: 1,
            locale: "en".into(),
            subject: "x".into(),
            html_body: String::new(),
            text_body: String::new(),
            sms_body: String::new(),
            push_title: String::new(),
            push_body: String::new(),
            push_action_url: String::new(),
        }),
    });
    let err = svc.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(reason(&err).as_deref(), Some("TEMPLATE_NOT_FOUND"));
}

#[tokio::test]
async fn test_grpc_update_missing_content_fails() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::UpdateTemplateRequest {
        template_id: "security_alert".into(),
        content: None,
    });
    let err = svc.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&err).as_deref(), Some("REQUIRED_FIELD_MISSING"));
}

#[tokio::test]
async fn test_grpc_reset_reverts_to_default() {
    let svc = test_grpc_service().await;

    // First customize.
    let update_req = admin(sid_proto::sid::v1::admin::UpdateTemplateRequest {
        template_id: "new_session".into(),
        content: Some(sid_proto::sid::v1::admin::TemplateContent {
            channel: 1,
            locale: "en".into(),
            subject: "Temporary".into(),
            html_body: "<p>Temp</p>".into(),
            text_body: "Temp".into(),
            sms_body: String::new(),
            push_title: String::new(),
            push_body: String::new(),
            push_action_url: String::new(),
        }),
    });
    svc.update_template(update_req).await.unwrap();

    // Reset.
    let reset_req = admin(sid_proto::sid::v1::admin::ResetTemplateRequest {
        template_id: "new_session".into(),
        channel: 1,
        locale: "en".into(),
    });
    let resp = svc.reset_template(reset_req).await.unwrap();
    let tmpl = resp.into_inner();
    assert!(!tmpl.customized);
    assert!(tmpl.content.unwrap().subject.contains("New login"));
}

#[tokio::test]
async fn test_grpc_reset_nonexistent_fails() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::ResetTemplateRequest {
        template_id: "nonexistent".into(),
        channel: 1,
        locale: "en".into(),
    });
    let err = svc.reset_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_grpc_preview_with_sample_data() {
    let svc = test_grpc_service().await;
    let mut sample_data = std::collections::HashMap::new();
    sample_data.insert(
        "event_type".to_string(),
        "sid.security.brute_force.v1".to_string(),
    );
    sample_data.insert("source".to_string(), "sid-server".to_string());

    let req = admin(sid_proto::sid::v1::admin::PreviewTemplateRequest {
        template_id: "security_alert".into(),
        channel: 1,
        locale: "en".into(),
        sample_data,
    });
    let resp = svc.preview_template(req).await.unwrap();
    let preview = resp.into_inner();
    assert!(
        preview
            .rendered_subject
            .contains("sid.security.brute_force.v1"),
        "subject should contain event_type: {}",
        preview.rendered_subject
    );
    assert!(
        preview.rendered_body.contains("sid-server"),
        "body should contain source: {}",
        preview.rendered_body
    );
}

#[tokio::test]
async fn test_grpc_preview_not_found() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::PreviewTemplateRequest {
        template_id: "nonexistent".into(),
        channel: 1,
        locale: "en".into(),
        sample_data: Default::default(),
    });
    let err = svc.preview_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_grpc_send_test_no_template_for_channel() {
    let svc = test_grpc_service().await;
    // security_alert has no SMS template (email-only default).
    let req = admin(sid_proto::sid::v1::admin::SendTestNotificationRequest {
        template_id: "security_alert".into(),
        channel: 2, // SMS — no template content exists for this channel
        locale: "en".into(),
        recipient: "+1234567890".into(),
    });
    let err = svc.send_test_notification(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(reason(&err).as_deref(), Some("TEMPLATE_NOT_FOUND"));
}

fn send_test_email(recipient: &str) -> sid_proto::sid::v1::admin::SendTestNotificationRequest {
    sid_proto::sid::v1::admin::SendTestNotificationRequest {
        template_id: "security_alert".into(),
        channel: 1, // EMAIL
        locale: "en".into(),
        recipient: recipient.into(),
    }
}

/// Regression: a channel that did not accept the message was answered OK
/// with `success: false` and the provider's error text. It is
/// DEPENDENCY_UNAVAILABLE with a retry delay, and the provider's text stays
/// in the log.
#[tokio::test]
async fn test_grpc_send_test_delivery_failure_is_unavailable() {
    let svc = test_grpc_service().await;
    let err = svc
        .send_test_notification(admin(send_test_email("test@sid.example.com")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert_eq!(reason(&err).as_deref(), Some("DEPENDENCY_UNAVAILABLE"));
    assert!(sid_core::grpc_error::extract_retry_delay(&err).is_some());
}

/// Regression: a channel that is not enabled was answered OK with
/// `success: false`. It is FEATURE_NOT_CONFIGURED naming the channel.
#[tokio::test]
async fn test_grpc_send_test_unconfigured_channel() {
    let svc = grpc_service_with(vec![]).await;
    let err = svc
        .send_test_notification(admin(send_test_email("test@sid.example.com")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(reason(&err).as_deref(), Some("FEATURE_NOT_CONFIGURED"));
    let (_, _, metadata) = sid_core::grpc_error::extract_error_info(&err).unwrap();
    assert_eq!(metadata.get("feature").map(String::as_str), Some("email"));
}

/// Regression: without a recipient the test went to a placeholder address.
/// It goes to the administrator's own address, and when the server cannot
/// learn one (no identity service) the request names a recipient.
#[tokio::test]
async fn test_grpc_send_test_without_recipient_or_own_address() {
    let svc = test_grpc_service().await;
    let err = svc
        .send_test_notification(admin(send_test_email("")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&err).as_deref(), Some("REQUIRED_FIELD_MISSING"));
}

#[tokio::test]
async fn test_grpc_invalid_channel() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::GetTemplateRequest {
        template_id: "security_alert".into(),
        channel: 99, // Invalid
        locale: "en".into(),
    });
    let err = svc.get_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&err).as_deref(), Some("INVALID_FIELD_VALUE"));
}

#[tokio::test]
async fn test_grpc_list_customized_only_after_update() {
    let svc = test_grpc_service().await;

    // Before update: no customized templates.
    let req = admin(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 0,
        customized_only: true,
    });
    let resp = svc.list_templates(req).await.unwrap();
    assert!(resp.into_inner().templates.is_empty());

    // Customize one template.
    let update_req = admin(sid_proto::sid::v1::admin::UpdateTemplateRequest {
        template_id: "cert_expiry".into(),
        content: Some(sid_proto::sid::v1::admin::TemplateContent {
            channel: 1,
            locale: "en".into(),
            subject: "Custom cert".into(),
            html_body: String::new(),
            text_body: String::new(),
            sms_body: String::new(),
            push_title: String::new(),
            push_body: String::new(),
            push_action_url: String::new(),
        }),
    });
    svc.update_template(update_req).await.unwrap();

    // After update: exactly 1 customized.
    let req2 = admin(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 0,
        customized_only: true,
    });
    let resp2 = svc.list_templates(req2).await.unwrap();
    let list = resp2.into_inner().templates;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].template_id, "cert_expiry");
    assert!(list[0].customized);
}

#[tokio::test]
async fn test_grpc_get_locale_fallback_to_en() {
    let svc = test_grpc_service().await;
    // Request French locale — no French override exists, should fallback to "en".
    let req = admin(sid_proto::sid::v1::admin::GetTemplateRequest {
        template_id: "security_alert".into(),
        channel: 1,
        locale: "fr".into(),
    });
    let resp = svc.get_template(req).await.unwrap();
    let tmpl = resp.into_inner();
    // Should return the English default (fallback).
    assert!(!tmpl.customized);
    assert!(tmpl.content.is_some());
    assert!(tmpl.content.unwrap().subject.contains("Security Alert"));
}

#[tokio::test]
async fn test_grpc_preview_uses_default_examples_without_sample_data() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::PreviewTemplateRequest {
        template_id: "security_alert".into(),
        channel: 1,
        locale: "en".into(),
        sample_data: Default::default(), // No overrides — use variable examples.
    });
    let resp = svc.preview_template(req).await.unwrap();
    let preview = resp.into_inner();
    // Default example for event_type is "sid.security.brute_force.v1".
    assert!(
        preview
            .rendered_subject
            .contains("sid.security.brute_force.v1"),
        "default example should be used: {}",
        preview.rendered_subject
    );
}

#[tokio::test]
async fn test_grpc_update_unspecified_channel_fails() {
    let svc = test_grpc_service().await;
    let req = admin(sid_proto::sid::v1::admin::UpdateTemplateRequest {
        template_id: "security_alert".into(),
        content: Some(sid_proto::sid::v1::admin::TemplateContent {
            channel: 0, // UNSPECIFIED
            locale: "en".into(),
            subject: "x".into(),
            html_body: String::new(),
            text_body: String::new(),
            sms_body: String::new(),
            push_title: String::new(),
            push_body: String::new(),
            push_action_url: String::new(),
        }),
    });
    let err = svc.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ── Admin Auth Enforcement Tests ──

/// The service's verifier: the public key only, as in production.
fn test_verifier() -> Arc<TokenVerifier> {
    Arc::new(
        TokenVerifier::new(
            include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
            "https://sid.example.com".to_string(),
        )
        .expect("token verifier"),
    )
}

fn test_jwt_service() -> Arc<sid_authn::jwt::JwtService> {
    let private_pem = include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_private.pem");
    let public_pem = include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_public.pem");
    Arc::new(
        sid_authn::jwt::JwtService::new(
            private_pem,
            public_pem,
            "https://sid.example.com".to_string(),
        )
        .expect("JWT creation failed"),
    )
}

fn issue_admin_token(jwt: &sid_authn::jwt::JwtService) -> String {
    use chrono::{Duration, Utc};
    use sid_core::models::{Profile, Session};

    let mut profile = Profile::new(Some("admin-user"));
    profile.roles = vec!["admin".into()];

    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    );

    jwt.issue_access_token(
        &profile.id.to_string(),
        Some(&profile.id.to_string()),
        &profile,
        &session,
        &[],
        None,
        None,
    )
    .unwrap()
}

fn issue_user_token(jwt: &sid_authn::jwt::JwtService) -> String {
    use chrono::{Duration, Utc};
    use sid_core::models::{Profile, Session};

    let profile = Profile::new(Some("regular-user"));
    // No admin role

    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    );

    jwt.issue_access_token(
        &profile.id.to_string(),
        Some(&profile.id.to_string()),
        &profile,
        &session,
        &[],
        None,
        None,
    )
    .unwrap()
}

async fn test_grpc_service_with_auth() -> NotificationTemplateServiceImpl {
    test_grpc_service().await
}

fn request_with_token<T>(inner: T, token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(inner);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

#[tokio::test]
async fn test_auth_no_token_rejected() {
    use sid_proto::sid::v1::admin::ListTemplatesRequest;
    let svc = test_grpc_service_with_auth().await;
    let req = tonic::Request::new(ListTemplatesRequest::default());
    let err = svc.list_templates(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_auth_invalid_token_rejected() {
    let svc = test_grpc_service_with_auth().await;
    let req = request_with_token(
        sid_proto::sid::v1::admin::ListTemplatesRequest::default(),
        "invalid.jwt.token",
    );
    let err = svc.list_templates(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_auth_non_admin_denied() {
    let svc = test_grpc_service_with_auth().await;
    let jwt = test_jwt_service();
    let token = issue_user_token(&jwt);
    let req = request_with_token(
        sid_proto::sid::v1::admin::ListTemplatesRequest::default(),
        &token,
    );
    let err = svc.list_templates(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_auth_admin_allowed() {
    let svc = test_grpc_service_with_auth().await;
    let jwt = test_jwt_service();
    let token = issue_admin_token(&jwt);
    let req = request_with_token(
        sid_proto::sid::v1::admin::ListTemplatesRequest::default(),
        &token,
    );
    let resp = svc.list_templates(req).await.unwrap();
    assert!(!resp.into_inner().templates.is_empty());
}

#[tokio::test]
async fn test_auth_admin_can_update() {
    let svc = test_grpc_service_with_auth().await;
    let jwt = test_jwt_service();
    let token = issue_admin_token(&jwt);
    let req = request_with_token(
        sid_proto::sid::v1::admin::UpdateTemplateRequest {
            template_id: "security_alert".into(),
            content: Some(sid_proto::sid::v1::admin::TemplateContent {
                channel: 1,
                locale: "en".into(),
                subject: "Custom Alert".into(),
                html_body: "<p>Custom</p>".into(),
                text_body: "Custom".into(),
                sms_body: String::new(),
                push_title: String::new(),
                push_body: String::new(),
                push_action_url: String::new(),
            }),
        },
        &token,
    );
    let resp = svc.update_template(req).await.unwrap();
    assert!(!resp.into_inner().template_id.is_empty());
}

#[tokio::test]
async fn test_auth_non_admin_cannot_update() {
    let svc = test_grpc_service_with_auth().await;
    let jwt = test_jwt_service();
    let token = issue_user_token(&jwt);
    let req = request_with_token(
        sid_proto::sid::v1::admin::UpdateTemplateRequest {
            template_id: "security_alert".into(),
            content: Some(sid_proto::sid::v1::admin::TemplateContent {
                channel: 1,
                locale: "en".into(),
                subject: "Hacked".into(),
                html_body: "<p>Hacked</p>".into(),
                text_body: "Hacked".into(),
                sms_body: String::new(),
                push_title: String::new(),
                push_body: String::new(),
                push_action_url: String::new(),
            }),
        },
        &token,
    );
    let err = svc.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

/// A server without a token verifier does not start; it never serves the
/// template API to everyone.
#[tokio::test]
async fn test_server_without_a_verifier_does_not_start() {
    let config = NotifyConfig {
        jwt_public_key_path: None,
        ..test_config()
    };
    let err = NotifyServer::new(config)
        .await
        .err()
        .expect("a missing verifier stops startup");
    assert!(err.to_string().contains("SID_JWT_PUBLIC_KEY_PATH"));
}
