use super::*;
use secrecy::SecretBox;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

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

/// Email provider refusals answer with the code and reason clients branch on.
#[test]
fn refusals_keep_their_status() {
    for (refused, code, expected) in [
        (
            EmailProviderError::InvalidField {
                field: "xoauth2_provider",
                reason: "required when auth_type is XOAUTH2".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            EmailProviderError::Internal,
            Code::Internal,
            "INTERNAL_ERROR",
        ),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
    let expected = not_configured("email");
    let status = refusal(EmailProviderError::NotConfigured);
    assert_eq!(status.code(), expected.code());
    assert_eq!(
        extract_error_info(&status).expect("ErrorInfo").0,
        extract_error_info(&expected).expect("ErrorInfo").0
    );
}
