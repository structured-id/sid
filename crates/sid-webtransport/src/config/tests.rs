use super::*;
use std::collections::HashMap;

fn config(settings: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let settings: HashMap<String, String> = settings
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Config::from_lookup(|name| settings.get(name).cloned())
}

/// Without a bind setting the endpoint listens on the local default.
#[test]
fn test_default_bind_address() {
    let config = config(&[("SID_WEBTRANSPORT_DEV_TLS", "true")]).unwrap();
    assert_eq!(config.bind, "127.0.0.1:4433".parse::<SocketAddr>().unwrap());
}

#[test]
fn test_custom_bind_address() {
    let config = config(&[
        ("SID_WEBTRANSPORT_BIND", "0.0.0.0:5555"),
        ("SID_WEBTRANSPORT_DEV_TLS", "true"),
    ])
    .unwrap();
    assert_eq!(config.bind, "0.0.0.0:5555".parse::<SocketAddr>().unwrap());
}

#[test]
fn test_dev_tls_mode() {
    let config = config(&[("SID_WEBTRANSPORT_DEV_TLS", "true")]).unwrap();
    assert!(matches!(config.tls, TlsMode::Dev));
}

#[test]
fn test_dev_tls_with_numeric_flag() {
    let config = config(&[("SID_WEBTRANSPORT_DEV_TLS", "1")]).unwrap();
    assert!(matches!(config.tls, TlsMode::Dev));
}

#[test]
fn test_pem_tls_mode() {
    let config = config(&[
        ("SID_WEBTRANSPORT_CERT_PATH", "/etc/ssl/cert.pem"),
        ("SID_WEBTRANSPORT_KEY_PATH", "/etc/ssl/key.pem"),
    ])
    .unwrap();
    match config.tls {
        TlsMode::Pem { cert, key } => {
            assert_eq!(cert, PathBuf::from("/etc/ssl/cert.pem"));
            assert_eq!(key, PathBuf::from("/etc/ssl/key.pem"));
        }
        TlsMode::Dev => panic!("expected TlsMode::Pem"),
    }
}

/// A malformed bind address is a configuration error naming the value.
#[test]
fn test_invalid_bind_address_rejected() {
    let err = config(&[
        ("SID_WEBTRANSPORT_BIND", "not-an-address"),
        ("SID_WEBTRANSPORT_DEV_TLS", "true"),
    ])
    .err()
    .expect("invalid bind");
    assert!(matches!(err, ConfigError::InvalidBind(v) if v == "not-an-address"));
}

/// PEM mode needs both files; each missing one is reported.
#[test]
fn test_pem_mode_requires_cert_and_key() {
    assert!(matches!(config(&[]).err(), Some(ConfigError::MissingCert)));
    assert!(matches!(
        config(&[("SID_WEBTRANSPORT_CERT_PATH", "/c.pem")]).err(),
        Some(ConfigError::MissingKey)
    ));
}
