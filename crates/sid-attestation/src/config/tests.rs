use super::*;

/// A receiver configuration; nothing connects to it here.
fn test_api() -> sid_auth::config::ReceiverConfig {
    sid_auth::config::ReceiverConfig {
        upstream: "http://127.0.0.1:1".into(),
        issuer_url: "https://sid.example.com".into(),
        resource: "https://sid.example.com/api".into(),
        origin: "https://sid.example.com".into(),
        checker: sid_infra::client_credential::ClientCredentialConfig {
            issuer: "https://sid.example.com/i/test".into(),
            client_id: "sid-attestation".into(),
            authentication: sid_infra::client_credential::ClientAuthentication::ClientSecretBasic {
                secret_file: "/nonexistent".into(),
            },
        },
    }
}

#[test]
fn test_database_url_display_masks_password() {
    let config = AttestationConfig {
        grpc_bind: "127.0.0.1:50061".parse().unwrap(),
        database_url: "postgres://sid:secret_pass@localhost:5432/sid".into(),
        api: test_api(),
    };
    let display = config.database_url_display();
    assert!(!display.contains("secret_pass"));
    assert!(display.contains("***"));
    assert!(display.contains("localhost:5432/sid"));
}

#[test]
fn test_database_url_display_no_password() {
    let config = AttestationConfig {
        grpc_bind: "127.0.0.1:50061".parse().unwrap(),
        database_url: "postgres://localhost:5432/sid".into(),
        api: test_api(),
    };
    let display = config.database_url_display();
    assert_eq!(display, "postgres://localhost:5432/sid");
}
