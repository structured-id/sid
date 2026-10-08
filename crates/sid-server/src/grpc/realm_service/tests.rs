use super::*;
use sid_core::models::{EmailProviderConfig, SmtpAuthMethod, SmtpEncryption};

fn plain_config() -> EmailProviderConfig {
    EmailProviderConfig {
        smtp_host: "smtp.example.com".into(),
        smtp_port: 587,
        from_address: "noreply@example.com".into(),
        from_display_name: "Example".into(),
        reply_to: String::new(),
        encryption: SmtpEncryption::Starttls,
        auth_type: SmtpAuthMethod::UsernamePassword,
        username: "user@example.com".into(),
        password: SecretBox::new(Box::new("super-secret".into())),
        xoauth2: None,
    }
}

// ── Encryption round-trip ────────────────────────────────────────────────

#[test]
fn test_encryption_round_trip() {
    for (enc, expected) in [
        (SmtpEncryption::None, SmtpEncryptionType::None as i32),
        (SmtpEncryption::SslTls, SmtpEncryptionType::SslTls as i32),
        (
            SmtpEncryption::Starttls,
            SmtpEncryptionType::Starttls as i32,
        ),
    ] {
        let proto_val = encryption_to_proto(enc);
        assert_eq!(proto_val, expected);
        assert_eq!(encryption_from_proto(proto_val), enc);
    }
}

// ── Auth round-trip ──────────────────────────────────────────────────────

#[test]
fn test_auth_round_trip() {
    for (auth, expected) in [
        (SmtpAuthMethod::None, SmtpAuthType::None as i32),
        (
            SmtpAuthMethod::UsernamePassword,
            SmtpAuthType::UsernamePassword as i32,
        ),
        (SmtpAuthMethod::XOAuth2, SmtpAuthType::Xoauth2 as i32),
    ] {
        let proto_val = auth_to_proto(auth);
        assert_eq!(proto_val, expected);
        assert_eq!(auth_from_proto(proto_val), auth);
    }
}

// ── XOAUTH2 provider round-trip ──────────────────────────────────────────

#[test]
fn test_xoauth2_provider_round_trip() {
    for (prov, expected) in [
        (
            XOAuth2Provider::M365,
            XoAuth2ProviderType::Xoauth2ProviderTypeM365 as i32,
        ),
        (
            XOAuth2Provider::Google,
            XoAuth2ProviderType::Xoauth2ProviderTypeGoogle as i32,
        ),
    ] {
        let proto_val = xoauth2_provider_to_proto(prov);
        assert_eq!(proto_val, expected);
        assert_eq!(xoauth2_provider_from_proto(proto_val), Some(prov));
    }
    // Unspecified → None
    assert!(xoauth2_provider_from_proto(0).is_none());
}

// ── config_to_proto hides write-only fields ──────────────────────────────

#[test]
fn test_config_to_proto_hides_password() {
    let proto = config_to_proto(&plain_config());
    assert_eq!(proto.smtp_host, "smtp.example.com");
    assert_eq!(proto.smtp_port, 587);
    // write-only fields are empty in response
    assert!(proto.username.is_empty());
    assert!(proto.password.is_empty());
}

#[test]
fn test_config_to_proto_hides_xoauth2_secrets() {
    use sid_core::models::XOAuth2Config;

    let cfg = EmailProviderConfig {
        smtp_host: "smtp.office365.com".into(),
        smtp_port: 587,
        from_address: "noreply@corp.com".into(),
        from_display_name: "Corp".into(),
        reply_to: String::new(),
        encryption: SmtpEncryption::Starttls,
        auth_type: SmtpAuthMethod::XOAuth2,
        username: "smtp@corp.com".into(),
        password: SecretBox::new(Box::new(String::new())),
        xoauth2: Some(XOAuth2Config {
            provider: XOAuth2Provider::M365,
            tenant_id: Some("tenant-guid".into()),
            client_id: "client-guid".into(),
            client_secret: SecretBox::new(Box::new("secret".into())),
            service_account_key: None,
            token_endpoint: None,
            user_email: "smtp@corp.com".into(),
        }),
    };

    let proto = config_to_proto(&cfg);
    assert_eq!(
        proto.xoauth2_provider,
        XoAuth2ProviderType::Xoauth2ProviderTypeM365 as i32
    );
    assert_eq!(proto.xoauth2_tenant_id, "tenant-guid");
    assert_eq!(proto.xoauth2_client_id, "client-guid");
    // write-only secrets never returned
    assert!(proto.xoauth2_client_secret.is_empty());
    assert!(proto.xoauth2_service_account_key.is_empty());
    assert!(proto.username.is_empty());
    assert!(proto.password.is_empty());
}

// ── config_to_smtp_config mapping ────────────────────────────────────────

#[test]
fn test_config_to_smtp_config_mapping() {
    let cfg = EmailProviderConfig {
        smtp_host: "smtp.example.com".into(),
        smtp_port: 465,
        from_address: "noreply@example.com".into(),
        from_display_name: "Example".into(),
        reply_to: String::new(),
        encryption: SmtpEncryption::SslTls,
        auth_type: SmtpAuthMethod::UsernamePassword,
        username: "user".into(),
        password: SecretBox::new(Box::new("pass".into())),
        xoauth2: None,
    };
    let smtp = config_to_smtp_config(&cfg);
    assert_eq!(smtp.host, "smtp.example.com");
    assert_eq!(smtp.port, 465);
    assert_eq!(smtp.tls_mode, SmtpTlsMode::Tls);
    assert_eq!(smtp.auth_method, EmailAuthMethod::Plain);
    assert_eq!(smtp.username, Some("user".to_string()));
    assert_eq!(smtp.password, Some("pass".to_string()));
}

// ── xoauth2_config_from_proto: secrets preserved on empty update ─────────

#[test]
fn test_xoauth2_config_preserves_secrets_on_empty_update() {
    use sid_core::models::XOAuth2Config;

    let existing = XOAuth2Config {
        provider: XOAuth2Provider::M365,
        tenant_id: Some("old-tenant".into()),
        client_id: "old-client".into(),
        client_secret: SecretBox::new(Box::new("old-secret".into())),
        service_account_key: None,
        token_endpoint: None,
        user_email: "smtp@corp.com".into(),
    };

    let req = EmailSettings {
        auth_type: SmtpAuthType::Xoauth2 as i32,
        xoauth2_provider: XoAuth2ProviderType::Xoauth2ProviderTypeM365 as i32,
        // All credential fields empty = preserve existing
        xoauth2_client_secret: String::new(),
        xoauth2_tenant_id: "new-tenant".into(),
        xoauth2_client_id: "new-client".into(),
        ..EmailSettings::default()
    };

    let result = xoauth2_config_from_proto(&req, Some(&existing)).unwrap();
    assert_eq!(result.tenant_id, Some("new-tenant".into()));
    assert_eq!(result.client_id, "new-client");
    // Empty secret → preserved from existing
    assert_eq!(result.client_secret.expose_secret(), "old-secret");
}
