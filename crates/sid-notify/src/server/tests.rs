use super::*;
use crate::channels::smtp::SmtpConfig;
use sid_proto::sid::v1::admin::notification_template_service_client::NotificationTemplateServiceClient;
use sid_proto::sid::v1::admin::notification_template_service_server::{
    NotificationTemplateService, NotificationTemplateServiceServer,
};
use sid_test_issuer::{Checker, Setup, TestIssuer};

/// The installation's account API resource the template API serves.
const API: &str = "https://sid.example.com/api";
/// A resource of another application at the same issuer.
const OTHER: &str = "https://orders.sid.example.com/api";
/// The origin callers address the service at.
const ORIGIN: &str = "https://sid.example.com";
/// This service's own checker client at the issuer.
const CHECKER: &str = "sid-notify";
const CHECKER_SECRET: &str = "notify-checker-secret";

/// The checker's secret in a file of its own, removed with it.
struct SecretFile(std::path::PathBuf);

impl Drop for SecretFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

/// A running issuer of the installation, with the account API resource and
/// this service registered as its checker, and the receiver configuration
/// that reaches it.
struct Installation {
    issuer: TestIssuer,
    api: sid_auth::config::ReceiverConfig,
    _secret: SecretFile,
}

async fn installation() -> Installation {
    crate::test_crypto::install_tls();
    let issuer = TestIssuer::start(Setup {
        resources: vec![API.into(), OTHER.into()],
        checkers: vec![Checker {
            client_id: CHECKER.into(),
            secret: CHECKER_SECRET.into(),
            confirms_proofs: false,
        }],
    })
    .await;
    let secret = SecretFile(
        std::env::temp_dir().join(format!("sid-notify-checker-{}", uuid::Uuid::now_v7())),
    );
    std::fs::write(&secret.0, CHECKER_SECRET).expect("checker secret file");
    let api = issuer.receiver_config(API, ORIGIN, CHECKER, &secret.0);
    Installation {
        issuer,
        api,
        _secret: secret,
    }
}

/// The configuration of a test server, built after the test application has
/// selected its TLS backend, as the binary does before building its server.
fn test_config(api: sid_auth::config::ReceiverConfig) -> NotifyConfig {
    crate::test_crypto::install_tls();
    NotifyConfig {
        nats_url: "nats://127.0.0.1:4222".into(),
        platform_nats_url: None,
        grpc_bind: "127.0.0.1:0".parse().unwrap(),
        receiver: sid_core::models::WorkRecipient::new(crate::config::DEFAULT_RECEIVER).unwrap(),
        event_receivers: Vec::new(),
        smtp: SmtpConfig::default(),
        smtp_enabled: true,
        webhook_enabled: true,
        vapid: None,
        database_url: test_database_url(),
        job_capacity: crate::config::DEFAULT_JOB_CAPACITY,
        identity_grpc_address: None,
        api,
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
    let installation = installation().await;
    let server = NotifyServer::new(test_config(installation.api.clone()))
        .await
        .unwrap();
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
            |_, _| ((), None),
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
    let installation = installation().await;
    let config = NotifyConfig {
        database_url: "postgres://sid:sid_dev@127.0.0.1:1/none".into(),
        ..test_config(installation.api.clone())
    };
    assert!(NotifyServer::new(config).await.is_err());
}

/// A receiver that cannot authenticate at its issuer stops the start: the
/// template API is never served without a decision for its calls.
#[tokio::test]
async fn test_server_without_its_checker_credential_does_not_start() {
    let installation = installation().await;
    let mut api = installation.api.clone();
    api.checker.authentication =
        sid_infra::client_credential::ClientAuthentication::ClientSecretBasic {
            secret_file: "/nonexistent/sid-notify-secret".into(),
        };
    assert!(NotifyServer::new(test_config(api)).await.is_err());
}

#[tokio::test]
async fn test_server_init_registers_channels() {
    let installation = installation().await;
    let server = NotifyServer::new(test_config(installation.api.clone()))
        .await
        .unwrap();
    let channels = server.dispatcher.channel_ids();
    assert!(channels.contains(&"email".to_string()));
    assert!(channels.contains(&"webhook".to_string()));
}

#[tokio::test]
async fn test_server_init_no_smtp() {
    let installation = installation().await;
    let mut config = test_config(installation.api.clone());
    config.smtp_enabled = false;
    let server = NotifyServer::new(config).await.unwrap();
    let channels = server.dispatcher.channel_ids();
    assert!(!channels.contains(&"email".to_string()));
    assert!(channels.contains(&"webhook".to_string()));
}

#[tokio::test]
async fn test_server_init_with_vapid() {
    let installation = installation().await;
    let mut config = test_config(installation.api.clone());
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

/// Every template method has an action, and nothing else is served.
#[test]
fn test_every_template_method_has_an_action() {
    use crate::access::{TEMPLATE_CHANGE, TEMPLATE_READ, TEMPLATE_TEST, action};
    use sid_auth::receiver::Action::OnResource;
    let path = |m: &str| format!("/sid.v1.admin.NotificationTemplateService/{m}");
    for (method, expected) in [
        ("ListTemplates", TEMPLATE_READ),
        ("GetTemplate", TEMPLATE_READ),
        ("PreviewTemplate", TEMPLATE_READ),
        ("UpdateTemplate", TEMPLATE_CHANGE),
        ("ResetTemplate", TEMPLATE_CHANGE),
        ("SendTestNotification", TEMPLATE_TEST),
    ] {
        assert_eq!(
            action(&path(method)),
            Some(OnResource(expected)),
            "{method}"
        );
    }
    assert_eq!(action(&path("DeleteEverything")), None);
    assert_eq!(action("/sid.v1.identity.IdentityService/GetProfile"), None);
}

// ── Handlers ──

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
    let pool = crate::test_db::pool().await;
    let operations = crate::test_db::operations(&pool).await;
    let store = Arc::new(
        crate::template_store::TemplateStore::new(&routing, engine, pool)
            .await
            .unwrap(),
    );
    NotificationTemplateServiceImpl::new(
        Arc::new(dispatcher),
        store,
        operations,
        Arc::new(RecipientResolver::without_identity()),
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

/// A call as the handler receives it: admission is the receiver's, checked
/// below through the served service.
fn call<T>(inner: T) -> tonic::Request<T> {
    tonic::Request::new(inner)
}

/// `ErrorInfo.reason` of a refusal.
fn reason(status: &tonic::Status) -> Option<String> {
    sid_infra::grpc_error::extract_error_info(status).map(|(reason, _, _)| reason)
}

#[tokio::test]
async fn test_grpc_list_templates_returns_all_defaults() {
    let svc = test_grpc_service().await;
    let req = call(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 0,
        customized_only: false,
    });
    let resp = svc.list_templates(req).await.unwrap();
    let templates = resp.into_inner().templates;
    assert_eq!(templates.len(), 10);
    assert!(templates.iter().all(|t| !t.customized));
    assert!(templates.iter().all(|t| !t.template_id.is_empty()));
    assert!(templates.iter().all(|t| !t.trigger.is_empty()));
}

#[tokio::test]
async fn test_grpc_list_templates_filter_email() {
    let svc = test_grpc_service().await;
    let req = call(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 1, // EMAIL
        customized_only: false,
    });
    let resp = svc.list_templates(req).await.unwrap();
    assert_eq!(resp.into_inner().templates.len(), 10);
}

#[tokio::test]
async fn test_grpc_list_templates_filter_sms_empty() {
    let svc = test_grpc_service().await;
    let req = call(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 2, // SMS
        customized_only: false,
    });
    let resp = svc.list_templates(req).await.unwrap();
    assert!(resp.into_inner().templates.is_empty());
}

#[tokio::test]
async fn test_grpc_get_template_default() {
    let svc = test_grpc_service().await;
    let req = call(sid_proto::sid::v1::admin::GetTemplateRequest {
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
    let req = call(sid_proto::sid::v1::admin::GetTemplateRequest {
        template_id: "nonexistent".into(),
        channel: 1,
        locale: "en".into(),
    });
    let err = svc.get_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(reason(&err).as_deref(), Some("TEMPLATE_NOT_FOUND"));
}

#[tokio::test]
async fn test_grpc_preview_with_sample_data() {
    let svc = test_grpc_service().await;
    let mut sample_data = std::collections::BTreeMap::new();
    sample_data.insert(
        "event_type".to_string(),
        "sid.security.brute_force.v1".to_string(),
    );
    sample_data.insert("source".to_string(), "sid-server".to_string());

    let req = call(sid_proto::sid::v1::admin::PreviewTemplateRequest {
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
    let req = call(sid_proto::sid::v1::admin::PreviewTemplateRequest {
        template_id: "nonexistent".into(),
        channel: 1,
        locale: "en".into(),
        sample_data: Default::default(),
    });
    let err = svc.preview_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_grpc_invalid_channel() {
    let svc = test_grpc_service().await;
    let req = call(sid_proto::sid::v1::admin::GetTemplateRequest {
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
    let req = call(sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 0,
        customized_only: true,
    });
    let resp = svc.list_templates(req).await.unwrap();
    assert!(resp.into_inner().templates.is_empty());

    // Customize one template.
    svc.store
        .update_template(
            "cert_expiry",
            Channel::Email,
            "en",
            StoredContent {
                subject: "Custom cert".into(),
                html_body: String::new(),
                text_body: String::new(),
                sms_body: String::new(),
                push_title: String::new(),
                push_body: String::new(),
                push_action_url: String::new(),
                updated_at: chrono::Utc::now(),
            },
            |_, _| ((), None),
        )
        .await
        .unwrap();

    // After update: exactly 1 customized.
    let req2 = call(sid_proto::sid::v1::admin::ListTemplatesRequest {
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
    let req = call(sid_proto::sid::v1::admin::GetTemplateRequest {
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
    let req = call(sid_proto::sid::v1::admin::PreviewTemplateRequest {
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

/// A handler reached without its receiver has no admitted call: a test send
/// is refused rather than sent for nobody.
#[tokio::test]
async fn test_grpc_send_test_without_the_receiver_is_refused() {
    let svc = test_grpc_service().await;
    let err = svc
        .send_test_notification(call(send_test_email("test@sid.example.com")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ── Served behind the receiver, with tokens of a real issuer ──

/// A template service served as the server serves it, on a loopback port.
struct Served {
    client: NotificationTemplateServiceClient<tonic::transport::Channel>,
    /// The connection the client uses, for the other services served beside.
    channel: tonic::transport::Channel,
    /// Its operation results and periods.
    operations: Arc<PgOperationStore>,
    _serving: tokio::task::JoinHandle<()>,
}

/// `svc` served behind a receiver of `api`, beside the operation service of
/// its store and behind the operation context check, as the server serves
/// it.
async fn served(
    svc: NotificationTemplateServiceImpl,
    api: &sid_auth::config::ReceiverConfig,
) -> Served {
    let receiver = Arc::new(
        Receiver::connect("sid-notify", api)
            .await
            .expect("receiver"),
    );
    let operations = svc.operations.clone();
    let routes = tonic::service::Routes::new(crate::access::guarded(
        NotificationTemplateServiceServer::new(svc),
        &receiver,
    ))
    .add_service(
        sid_proto::sid::v1::operation_service_server::OperationServiceServer::new(
            OperationPeriods::new(operations.clone()),
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let serving = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .layer(OperationContextLayer)
            .add_routes(routes)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Channel::from_shared(address)
        .unwrap()
        .connect_lazy();
    Served {
        client: NotificationTemplateServiceClient::new(channel.clone()),
        channel,
        operations,
        _serving: serving,
    }
}

impl Served {
    /// `inner` from the bearer of `token`, named as the command `key` under
    /// the period this service's store issues: the same key names a retry.
    async fn named<T>(&self, inner: T, token: &str, key: &str) -> tonic::Request<T> {
        let period = self
            .operations
            .current_operation_period(chrono::Utc::now(), chrono::Duration::hours(1))
            .await
            .unwrap()
            .period;
        let mut req = bearer(inner, token);
        sid_infra::authn::operation::insert_context(
            req.metadata_mut(),
            &sid_core::models::OperationContext::new(
                sid_core::models::OperationKey::parse(key).unwrap(),
                period,
            ),
        );
        req
    }

    /// `inner` from the bearer of `token`, named as a new command.
    async fn new_command<T>(&self, inner: T, token: &str) -> tonic::Request<T> {
        self.named(inner, token, &uuid::Uuid::now_v7().to_string())
            .await
    }
}

/// `inner` carrying `token` as its bearer.
fn bearer<T>(inner: T, token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(inner);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn customize(subject: &str) -> sid_proto::sid::v1::admin::UpdateTemplateRequest {
    sid_proto::sid::v1::admin::UpdateTemplateRequest {
        template_id: "security_alert".into(),
        content: Some(sid_proto::sid::v1::admin::TemplateContent {
            channel: 1,
            locale: "en".into(),
            subject: subject.into(),
            html_body: "<p>x</p>".into(),
            text_body: "x".into(),
            sms_body: String::new(),
            push_title: String::new(),
            push_body: String::new(),
            push_action_url: String::new(),
        }),
    }
}

fn customized_only() -> sid_proto::sid::v1::admin::ListTemplatesRequest {
    sid_proto::sid::v1::admin::ListTemplatesRequest {
        channel: 0,
        customized_only: true,
    }
}

fn send_test_email(recipient: &str) -> sid_proto::sid::v1::admin::SendTestNotificationRequest {
    sid_proto::sid::v1::admin::SendTestNotificationRequest {
        template_id: "security_alert".into(),
        channel: 1, // EMAIL
        locale: "en".into(),
        recipient: recipient.into(),
    }
}

/// The installation's administrator, by its current assignment, reads and
/// customizes templates with a token for the account API; no roles claim is
/// involved.
#[tokio::test]
async fn test_the_installation_administrator_manages_templates() {
    let i = installation().await;
    let mut s = served(test_grpc_service().await, &i.api).await;
    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;
    let token = i.issuer.token(&admin, API, None).await.token;

    let listed = s
        .client
        .list_templates(bearer(Default::default(), &token))
        .await
        .expect("an administrator lists templates")
        .into_inner();
    assert_eq!(listed.templates.len(), 10);
    let req = s.new_command(customize("Admin's alert"), &token).await;
    let updated = s
        .client
        .update_template(req)
        .await
        .expect("an administrator customizes a template")
        .into_inner();
    assert!(updated.customized);
}

/// A signed-in user without an assignment is denied every method, and a
/// denied change leaves the template as it was.
#[tokio::test]
async fn test_a_user_without_the_action_is_denied_and_changes_nothing() {
    let i = installation().await;
    let mut s = served(test_grpc_service().await, &i.api).await;
    let user = i.issuer.profile().await;
    let token = i.issuer.token(&user, API, None).await.token;

    let err = s
        .client
        .list_templates(bearer(Default::default(), &token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let req = s.new_command(customize("Hacked"), &token).await;
    let err = s.client.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;
    let admin_token = i.issuer.token(&admin, API, None).await.token;
    let customized = s
        .client
        .list_templates(bearer(customized_only(), &admin_token))
        .await
        .unwrap()
        .into_inner();
    assert!(
        customized.templates.is_empty(),
        "a denied change took effect"
    );
}

/// The actions are separate: a reader on the account API reads templates
/// but neither changes nor sends one.
#[tokio::test]
async fn test_a_reader_reads_but_does_not_change_or_send() {
    let i = installation().await;
    let mut s = served(test_grpc_service().await, &i.api).await;
    let reader = i.issuer.profile().await;
    let role = i
        .issuer
        .role("template-reader", &[crate::access::TEMPLATE_READ])
        .await;
    i.issuer.grant(&reader, &role, API).await;
    let token = i.issuer.token(&reader, API, None).await.token;

    s.client
        .list_templates(bearer(Default::default(), &token))
        .await
        .expect("a reader lists templates");
    let req = s
        .new_command(
            sid_proto::sid::v1::admin::ResetTemplateRequest {
                template_id: "security_alert".into(),
                channel: 1,
                locale: "en".into(),
            },
            &token,
        )
        .await;
    let err = s.client.reset_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let req = s
        .new_command(send_test_email("test@sid.example.com"), &token)
        .await;
    let err = s.client.send_test_notification(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

/// Only an access token for the account API is admitted: a token for
/// another application's resource and the installation's internal session
/// token are refused, even for its administrator.
#[tokio::test]
async fn test_a_token_of_another_purpose_is_unauthenticated() {
    let i = installation().await;
    let Served {
        mut client,
        _serving,
        ..
    } = served(test_grpc_service().await, &i.api).await;
    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;

    let other = i.issuer.token(&admin, OTHER, None).await.token;
    let err = client
        .list_templates(bearer(Default::default(), &other))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let jwt = sid_authn::jwt::JwtService::new(
        include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
        include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
        sid_test_issuer::INSTALLATION.to_string(),
    )
    .unwrap();
    let session = sid_core::models::Session::new(
        admin.id,
        None,
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let internal = jwt
        .issue_access_token(
            &admin.id.to_string(),
            Some(&admin.id.to_string()),
            &["admin".to_string()],
            &session,
            &[],
            None,
            None,
        )
        .unwrap();
    let err = client
        .list_templates(bearer(Default::default(), &internal))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    let err = client
        .list_templates(tonic::Request::new(Default::default()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// An ended sign-in's token is refused at once: by the warm receiver and by
/// one started after the sign-out (it learned of no revocation event), with
/// no cache in the deployment at all; the issuer decides every call.
#[tokio::test]
async fn test_an_ended_session_is_refused_warm_and_cold() {
    let i = installation().await;
    let mut warm = served(test_grpc_service().await, &i.api).await;
    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;
    let issued = i.issuer.token(&admin, API, None).await;
    warm.client
        .list_templates(bearer(Default::default(), &issued.token))
        .await
        .expect("admitted before the sign-out");

    i.issuer.end(&issued.session).await;
    let err = warm
        .client
        .list_templates(bearer(Default::default(), &issued.token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let mut cold = served(test_grpc_service().await, &i.api).await;
    let req = cold
        .new_command(customize("After sign-out"), &issued.token)
        .await;
    let err = cold.client.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// Without its issuer no call has a decision: refused as unavailable, and a
/// change attempted meanwhile does not take effect.
#[tokio::test]
async fn test_without_the_issuer_calls_are_unavailable_and_change_nothing() {
    let mut i = installation().await;
    let svc = test_grpc_service().await;
    let store = svc.store.clone();
    let mut s = served(svc, &i.api).await;
    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;
    let token = i.issuer.token(&admin, API, None).await.token;

    i.issuer.stop().await;
    let req = s
        .new_command(customize("While the issuer is down"), &token)
        .await;
    let err = s.client.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert!(
        store.list_templates(None, true).await.unwrap().is_empty(),
        "a change without a decision took effect"
    );
}

/// A test send for the caller: without a recipient and no identity service
/// to learn the caller's address, the request must name one; a channel that
/// is not enabled, one that does not accept the message and a template
/// without content for the channel are refused with their reasons.
#[tokio::test]
async fn test_test_sends_are_refused_with_their_reasons() {
    let i = installation().await;
    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;
    let token = i.issuer.token(&admin, API, None).await.token;

    let mut unreachable = served(test_grpc_service().await, &i.api).await;
    // Regression: without a recipient the test went to a placeholder address.
    let req = unreachable.new_command(send_test_email(""), &token).await;
    let err = unreachable
        .client
        .send_test_notification(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&err).as_deref(), Some("REQUIRED_FIELD_MISSING"));
    // Regression: a channel that did not accept the message was answered OK.
    let req = unreachable
        .new_command(send_test_email("test@sid.example.com"), &token)
        .await;
    let err = unreachable
        .client
        .send_test_notification(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert_eq!(reason(&err).as_deref(), Some("DEPENDENCY_UNAVAILABLE"));
    assert!(sid_infra::grpc_error::extract_retry_delay(&err).is_some());
    // security_alert has no SMS template (email-only default).
    let req = unreachable
        .new_command(
            sid_proto::sid::v1::admin::SendTestNotificationRequest {
                template_id: "security_alert".into(),
                channel: 2,
                locale: "en".into(),
                recipient: "+1234567890".into(),
            },
            &token,
        )
        .await;
    let err = unreachable
        .client
        .send_test_notification(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(reason(&err).as_deref(), Some("TEMPLATE_NOT_FOUND"));

    // Regression: a channel that is not enabled was answered OK.
    let mut none = served(grpc_service_with(vec![]).await, &i.api).await;
    let req = none
        .new_command(send_test_email("test@sid.example.com"), &token)
        .await;
    let err = none.client.send_test_notification(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(reason(&err).as_deref(), Some("FEATURE_NOT_CONFIGURED"));
    let (_, _, metadata) = sid_infra::grpc_error::extract_error_info(&err).unwrap();
    assert_eq!(metadata.get("feature").map(String::as_str), Some("email"));
}

/// An email channel that counts what it is asked to send and answers each
/// delivery as `accepts` says.
struct Counting {
    sent: std::sync::atomic::AtomicUsize,
    accepts: bool,
}

#[tonic::async_trait]
impl NotificationChannel for Counting {
    fn channel_id(&self) -> &str {
        "email"
    }

    async fn deliver(
        &self,
        _: &sid_plugin::notification::Recipient,
        _: &sid_plugin::notification::RenderedMessage,
    ) -> Result<sid_plugin::notification::DeliveryReceipt, sid_plugin::notification::DeliveryError>
    {
        self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.accepts {
            Ok(sid_plugin::notification::DeliveryReceipt {
                message_id: "m-1".into(),
                channel: "email".into(),
                timestamp: chrono::Utc::now(),
                provider: "test".into(),
            })
        } else {
            Err(sid_plugin::notification::DeliveryError::Ambiguous(
                "no reply".into(),
            ))
        }
    }

    async fn health(
        &self,
    ) -> Result<sid_plugin::notification::ChannelHealth, sid_plugin::notification::DeliveryError>
    {
        Ok(sid_plugin::notification::ChannelHealth {
            healthy: true,
            message: None,
            last_success: None,
        })
    }
}

fn counting(accepts: bool) -> Arc<Counting> {
    Arc::new(Counting {
        sent: std::sync::atomic::AtomicUsize::new(0),
        accepts,
    })
}

/// An installation's administrator and its token for the account API.
async fn administrator(i: &Installation) -> String {
    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;
    i.issuer.token(&admin, API, None).await.token
}

fn reset(template_id: &str) -> sid_proto::sid::v1::admin::ResetTemplateRequest {
    sid_proto::sid::v1::admin::ResetTemplateRequest {
        template_id: template_id.into(),
        channel: 1,
        locale: "en".into(),
    }
}

fn get_alert() -> sid_proto::sid::v1::admin::GetTemplateRequest {
    sid_proto::sid::v1::admin::GetTemplateRequest {
        template_id: "security_alert".into(),
        channel: 1,
        locale: "en".into(),
    }
}

/// A change answers with the template it left, reads answer with it, a reset
/// answers with the default again; an unknown template, a change without
/// content and one on no channel are refused with their reasons.
#[tokio::test]
async fn test_template_changes_answer_with_their_effect() {
    let i = installation().await;
    let mut s = served(test_grpc_service().await, &i.api).await;
    let token = administrator(&i).await;

    let req = s
        .new_command(customize("CUSTOM: Security Alert"), &token)
        .await;
    let changed = s.client.update_template(req).await.unwrap().into_inner();
    assert!(changed.customized);
    assert_eq!(changed.content.unwrap().subject, "CUSTOM: Security Alert");
    let got = s
        .client
        .get_template(bearer(get_alert(), &token))
        .await
        .unwrap()
        .into_inner();
    assert!(got.customized);
    assert_eq!(got.content.unwrap().subject, "CUSTOM: Security Alert");

    let req = s.new_command(reset("security_alert"), &token).await;
    let reset_to = s.client.reset_template(req).await.unwrap().into_inner();
    assert!(!reset_to.customized);
    assert!(reset_to.content.unwrap().subject.contains("Security Alert"));

    let mut unknown = customize("x");
    unknown.template_id = "nonexistent".into();
    let req = s.new_command(unknown, &token).await;
    let err = s.client.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(reason(&err).as_deref(), Some("TEMPLATE_NOT_FOUND"));
    let req = s.new_command(reset("nonexistent"), &token).await;
    let err = s.client.reset_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    let mut empty = customize("x");
    empty.content = None;
    let req = s.new_command(empty, &token).await;
    let err = s.client.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&err).as_deref(), Some("REQUIRED_FIELD_MISSING"));

    let mut nowhere = customize("x");
    nowhere.content.as_mut().unwrap().channel = 0;
    let req = s.new_command(nowhere, &token).await;
    let err = s.client.update_template(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// Regression: a change applied again on its retry. Change A, change B,
/// then A's lost response is retried: the retry answers as A did and B
/// stays.
#[tokio::test]
async fn test_a_change_retry_keeps_a_later_change() {
    let i = installation().await;
    let mut s = served(test_grpc_service().await, &i.api).await;
    let token = administrator(&i).await;

    let req = s.named(customize("A"), &token, "op-a").await;
    let first = s.client.update_template(req).await.unwrap().into_inner();
    let req = s.named(customize("B"), &token, "op-b").await;
    s.client.update_template(req).await.unwrap();
    let req = s.named(customize("A"), &token, "op-a").await;
    let retry = s.client.update_template(req).await.unwrap().into_inner();

    assert_eq!(retry, first);
    let got = s
        .client
        .get_template(bearer(get_alert(), &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        got.content.unwrap().subject,
        "B",
        "the retry wrote A over the later change"
    );
}

/// Regression: a reset applied again on its retry. A customization is reset,
/// customized again, then the reset's lost response is retried: the retry
/// answers as the reset did and the later customization stays.
#[tokio::test]
async fn test_a_reset_retry_keeps_a_later_customization() {
    let i = installation().await;
    let mut s = served(test_grpc_service().await, &i.api).await;
    let token = administrator(&i).await;

    let req = s.new_command(customize("Before"), &token).await;
    s.client.update_template(req).await.unwrap();
    let req = s.named(reset("security_alert"), &token, "op-reset").await;
    let first = s.client.reset_template(req).await.unwrap().into_inner();
    let req = s.new_command(customize("After"), &token).await;
    s.client.update_template(req).await.unwrap();
    let req = s.named(reset("security_alert"), &token, "op-reset").await;
    let retry = s.client.reset_template(req).await.unwrap().into_inner();

    assert_eq!(retry, first);
    let got = s
        .client
        .get_template(bearer(get_alert(), &token))
        .await
        .unwrap()
        .into_inner();
    assert!(got.customized, "the retry removed the later customization");
    assert_eq!(got.content.unwrap().subject, "After");
}

/// Regression: a test send went out again on its retry. A send the channel
/// accepted, retried after its response was lost, answers as it did and
/// sends nothing more.
#[tokio::test]
async fn test_a_test_send_retry_sends_once() {
    let i = installation().await;
    let channel = counting(true);
    let mut s = served(grpc_service_with(vec![channel.clone()]).await, &i.api).await;
    let token = administrator(&i).await;

    for _ in 0..2 {
        let req = s
            .named(send_test_email("test@sid.example.com"), &token, "op-send")
            .await;
        s.client.send_test_notification(req).await.unwrap();
    }
    assert_eq!(channel.sent.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A send whose outcome was not established (the channel gave no answer)
/// is not sent again by its retry, which answers that its outcome is
/// unknown; the administrator sends again as a new command.
#[tokio::test]
async fn test_a_test_send_retry_without_an_outcome_sends_nothing() {
    let i = installation().await;
    let channel = counting(false);
    let mut s = served(grpc_service_with(vec![channel.clone()]).await, &i.api).await;
    let token = administrator(&i).await;

    let req = s
        .named(send_test_email("test@sid.example.com"), &token, "op-lost")
        .await;
    let err = s.client.send_test_notification(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
    let req = s
        .named(send_test_email("test@sid.example.com"), &token, "op-lost")
        .await;
    let err = s.client.send_test_notification(req).await.unwrap_err();
    assert_eq!(reason(&err).as_deref(), Some("OPERATION_OUTCOME_UNKNOWN"));
    assert_eq!(
        channel.sent.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the retry sent the message again"
    );
}

/// A keyed template call without its operation context is refused before
/// any effect, and the period a command is named under comes from this
/// service's own store.
#[tokio::test]
async fn test_template_commands_are_named_under_this_services_periods() {
    let i = installation().await;
    let mut s = served(test_grpc_service().await, &i.api).await;
    let token = administrator(&i).await;

    let err = s
        .client
        .update_template(bearer(customize("Unnamed"), &token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(reason(&err).as_deref(), Some("REQUIRED_FIELD_MISSING"));
    let got = s
        .client
        .get_template(bearer(get_alert(), &token))
        .await
        .unwrap()
        .into_inner();
    assert!(!got.customized, "an unnamed change took effect");

    let period = sid_proto::sid::v1::operation_service_client::OperationServiceClient::new(
        s.channel.clone(),
    )
    .get_operation_period(sid_proto::sid::v1::GetOperationPeriodRequest {})
    .await
    .unwrap()
    .into_inner()
    .period;
    let issued = s
        .operations
        .current_operation_period(chrono::Utc::now(), chrono::Duration::hours(1))
        .await
        .unwrap()
        .period;
    assert_eq!(period, issued.get());
}

/// Every refusal of the served template API, without a token and as the
/// administrator, carries ErrorInfo in the structured.id domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_every_refusal_carries_error_info() {
    let i = installation().await;
    let admin = i.issuer.profile().await;
    i.issuer.administrator(&admin).await;
    let token = i.issuer.token(&admin, API, None).await.token;
    let receiver = Arc::new(Receiver::connect("sid-notify", &i.api).await.unwrap());
    let mut services = sid_serve::Services::new();
    services
        .add(crate::access::guarded(
            NotificationTemplateServiceServer::new(test_grpc_service().await),
            &receiver,
        ))
        .await;
    let (routes, health) = services.into_parts();
    let report = sid_serve::error_contract::probe(
        routes,
        health.names(),
        &[sid_proto::FILE_DESCRIPTOR_SET],
        &[sid_infra::grpc_error::DOMAIN_SID],
        &[
            sid_serve::error_contract::Caller::anonymous("anonymous"),
            sid_serve::error_contract::Caller::bearer("admin", &token),
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
