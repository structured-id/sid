use super::*;

// Config tests construct NotifyConfig directly to avoid env var race conditions
// (env vars are process-global, tests run in parallel).

/// A receiver configuration; nothing connects to it here.
fn test_api() -> sid_auth::config::ReceiverConfig {
    sid_auth::config::ReceiverConfig {
        upstream: "http://127.0.0.1:1".into(),
        issuer_url: "https://sid.example.com".into(),
        resource: "https://sid.example.com/api".into(),
        origin: "https://sid.example.com".into(),
        checker: sid_infra::client_credential::ClientCredentialConfig {
            issuer: "https://sid.example.com/i/test".into(),
            client_id: "sid-notify".into(),
            authentication: sid_infra::client_credential::ClientAuthentication::ClientSecretBasic {
                secret_file: "/nonexistent".into(),
            },
        },
    }
}

#[test]
fn test_config_struct_defaults() {
    let config = NotifyConfig {
        nats_url: "nats://127.0.0.1:4222".into(),
        platform_nats_url: None,
        grpc_bind: "0.0.0.0:9040".parse().unwrap(),
        receiver: WorkRecipient::new(DEFAULT_RECEIVER).unwrap(),
        event_receivers: Vec::new(),
        smtp: SmtpConfig::default(),
        smtp_enabled: true,
        webhook_enabled: true,
        vapid: None,
        database_url: "postgres://sid:sid_dev@localhost:54399/sid".into(),
        identity_grpc_address: None,
        api: test_api(),
    };

    assert_eq!(config.nats_url, "nats://127.0.0.1:4222");
    assert_eq!(config.grpc_bind.port(), 9040);
    assert_eq!(config.receiver.as_str(), "sid-notify");
    assert_eq!(config.smtp.host, "localhost");
    assert_eq!(config.smtp.port, 587);
    assert!(config.smtp_enabled);
    assert!(config.webhook_enabled);
    assert!(config.vapid.is_none());
}

#[test]
fn test_config_with_vapid() {
    let config = NotifyConfig {
        nats_url: "nats://127.0.0.1:4222".into(),
        platform_nats_url: None,
        grpc_bind: "0.0.0.0:9040".parse().unwrap(),
        receiver: WorkRecipient::new(DEFAULT_RECEIVER).unwrap(),
        event_receivers: Vec::new(),
        smtp: SmtpConfig::default(),
        smtp_enabled: true,
        webhook_enabled: true,
        vapid: Some(VapidConfig {
            subject: "mailto:admin@sid.example.com".into(),
            public_key: "BEl62iUYgUivxIkv69yViEuiBIa".into(),
            private_key: "Dt1CLgQlkiaA-tmCkATyKZeoF1".into(),
        }),
        database_url: "postgres://sid:sid_dev@localhost:54399/sid".into(),
        identity_grpc_address: None,
        api: test_api(),
    };

    assert!(config.vapid.is_some());
    let vapid = config.vapid.unwrap();
    assert_eq!(vapid.subject, "mailto:admin@sid.example.com");
}

/// This service's facts are owed to every listed receiver but itself;
/// `none` lists none, and an invalid name is refused.
#[test]
fn test_other_receivers_exclude_this_service() {
    let own = WorkRecipient::new(DEFAULT_RECEIVER).unwrap();
    let names = |list| {
        other_receivers(&own, list)
            .unwrap()
            .into_iter()
            .map(|r| r.recipient.to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(names("sid-notify, audit-sink"), ["audit-sink"]);
    assert_eq!(names("sid-notify"), Vec::<String>::new());
    assert_eq!(names("none"), Vec::<String>::new());
    assert!(other_receivers(&own, "a.b").is_err());
}

#[test]
fn test_config_error_display() {
    let err = ConfigError::Missing("SID_NATS_URL");
    assert!(err.to_string().contains("SID_NATS_URL"));

    let err = ConfigError::Invalid("SID_NOTIFY_BIND", "bad address".into());
    assert!(err.to_string().contains("SID_NOTIFY_BIND"));
    assert!(err.to_string().contains("bad address"));
}

#[test]
fn test_config_disabled_channels() {
    let config = NotifyConfig {
        nats_url: "nats://127.0.0.1:4222".into(),
        platform_nats_url: None,
        grpc_bind: "0.0.0.0:9040".parse().unwrap(),
        receiver: WorkRecipient::new(DEFAULT_RECEIVER).unwrap(),
        event_receivers: Vec::new(),
        smtp: SmtpConfig::default(),
        smtp_enabled: false,
        webhook_enabled: false,
        vapid: None,
        database_url: "postgres://sid:sid_dev@localhost:54399/sid".into(),
        identity_grpc_address: None,
        api: test_api(),
    };

    assert!(!config.smtp_enabled);
    assert!(!config.webhook_enabled);
    assert!(config.vapid.is_none());
}

#[test]
fn test_smtp_config_default() {
    let smtp = SmtpConfig::default();
    assert_eq!(smtp.host, "localhost");
    assert_eq!(smtp.port, 587);
    assert_eq!(smtp.from_address, "noreply@sid.example.com");
    assert_eq!(smtp.from_name, "StructuredID");
    assert_eq!(smtp.tls_mode, SmtpTlsMode::StartTls);
    assert_eq!(smtp.auth_method, EmailAuthMethod::None);
}
