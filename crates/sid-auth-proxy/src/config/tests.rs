// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn test_yaml_deserialize_minimal() {
    let yaml = r#"
upstream:
  default: "http://127.0.0.1:50051"
oidc:
  issuer_url: "https://sid.example.com"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.grpc_upstream(), "http://127.0.0.1:50051");
    assert_eq!(config.issuer_url(), "https://sid.example.com");
    assert_eq!(config.bind_addr(), "0.0.0.0:8080"); // default
    assert_eq!(config.service.name, "sid-auth-proxy");
    assert!(config.cors_origins().is_empty());
    assert_eq!(config.shield.auth_rate, 20); // default
}

#[test]
fn test_yaml_deserialize_full() {
    let yaml = r#"
service:
  name: "my-proxy"
listen:
  http: "0.0.0.0:9090"
upstream:
  default: "http://grpc:50051"
oidc:
  issuer_url: "https://auth.example.com"
cors:
  origins:
    - "https://app.example.com"
    - "https://admin.example.com"
shield:
  auth_rate: 30
  register_rate: 10
  endpoint_classes:
    - prefix: "/health"
      class: "health"
    - prefix: "/v1/auth/"
      class: "auth"
cache_url: "redis://cache:6379"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.service.name, "my-proxy");
    assert_eq!(config.bind_addr(), "0.0.0.0:9090");
    assert_eq!(config.grpc_upstream(), "http://grpc:50051");
    assert_eq!(config.issuer_url(), "https://auth.example.com");
    assert_eq!(config.cors_origins().len(), 2);
    assert_eq!(config.shield.auth_rate, 30);
    assert_eq!(config.shield.register_rate, 10);
    assert_eq!(config.shield.endpoint_classes.len(), 2);
    assert_eq!(config.cache_url(), Some("redis://cache:6379"));
}

/// Settings of the old decision edge (transcoder aliases, forwarded headers,
/// maintenance, route policies) are not read here: they are refused rather
/// than silently ignored.
#[test]
fn test_settings_this_proxy_does_not_read_are_refused() {
    for extra in [
        "aliases: []",
        "forwarded_headers: []",
        "maintenance: { enabled: true }",
        "forward_auth: {}",
        // The connection comes from SID, never from the file.
        "bff: { issuer: \"https://x.example/i/abc\" }",
        "bff: { external_url: \"https://app.example\" }",
    ] {
        let yaml = format!(
            "upstream: {{ default: \"http://grpc:50051\" }}\noidc: {{ issuer_url: \"https://x.example\" }}\n{extra}\n"
        );
        assert!(
            serde_yaml::from_str::<ProxyConfig>(&yaml).is_err(),
            "{extra}"
        );
    }
}

#[test]
fn test_shield_defaults() {
    let shield = ShieldYamlConfig::default();
    assert!(shield.enabled);
    assert_eq!(shield.auth_rate, 20);
    assert_eq!(shield.register_rate, 5);
    assert_eq!(shield.default_rate, 100);
    assert_eq!(shield.principal_rate, 5);
    assert_eq!(shield.magic_link_rate, 3);
    assert_eq!(shield.magic_link_principal_rate, 1);
    assert_eq!(shield.window_secs, 60);
    assert!(!shield.endpoint_classes.is_empty());
}

#[test]
fn test_default_endpoint_classes() {
    let classes = default_endpoint_classes();
    assert_eq!(classes[0].prefix, "/health");
    assert_eq!(classes[0].class, "health");
    assert!(classes.iter().any(|c| c.class == "auth"));
    assert!(classes.iter().any(|c| c.class == "register"));
    assert!(classes.iter().any(|c| c.class == "magic_link"));
}

#[test]
fn test_reference_yaml_parses() {
    let yaml = include_str!("../../sid-auth-proxy.yaml");
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.service.name, "sid-auth-proxy");
    assert_eq!(config.bind_addr(), "0.0.0.0:8080");
    assert_eq!(config.grpc_upstream(), "http://127.0.0.1:50051");
    assert_eq!(config.issuer_url(), "https://auth.example.com");
    assert!(config.shield.enabled);
    assert_eq!(config.shield.auth_rate, 20);
}

#[test]
fn test_bff_config_defaults() {
    let bff = BffConfig::default();
    assert!(!bff.enabled);
    assert_eq!(bff.cookie_name, "__Host-sid-bff");
    assert_eq!(bff.max_age, 86400);
    assert_eq!(bff.idle_timeout, 3600);
    assert_eq!(bff.pending_ttl, 300);
}

/// Dev mode drops the Secure flag, and the `__Host-` prefix needs it
/// (RFC 6265bis §4.1.3.2): a browser refuses the prefixed cookie without
/// it and the sign-in never lands. The prefix goes with the flag.
#[test]
fn test_dev_mode_drops_the_host_prefix() {
    let yaml = r#"
upstream:
  default: "http://127.0.0.1:50051"
oidc:
  issuer_url: "https://sid.example.com"
bff:
  enabled: true
  dev_mode: true
"#;
    let dev: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(dev.bff_cookie_name(), "sid-bff");

    let prod: ProxyConfig =
        serde_yaml::from_str(&yaml.replace("dev_mode: true", "dev_mode: false")).unwrap();
    assert_eq!(prod.bff_cookie_name(), "__Host-sid-bff");
}

/// A setting nothing reads is not a setting. These three decide how long a
/// session and a half-finished login survive, so the accessors the proxy
/// builds its store from are checked against a file that sets them.
#[test]
fn test_bff_lifetimes_come_from_the_file() {
    let yaml = r#"
upstream:
  default: "http://127.0.0.1:50051"
oidc:
  issuer_url: "https://sid.example.com"
bff:
  enabled: true
  max_age: 7200
  idle_timeout: 600
  pending_ttl: 45
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.bff_max_age(), 7200);
    assert_eq!(config.bff_idle_timeout(), 600);
    assert_eq!(config.bff_pending_ttl(), 45);
}

/// The key and the API the BFF reaches are read from the file.
#[test]
fn test_bff_key_and_api_come_from_the_file() {
    let yaml = r#"
upstream:
  default: "http://127.0.0.1:50051"
oidc:
  issuer_url: "https://sid.example.com"
bff:
  enabled: true
  client_key: "/etc/sid/bff-key.pem"
  api_upstream: "http://sid:8080"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.bff_client_key(), Some("/etc/sid/bff-key.pem"));
    assert_eq!(config.bff_api_upstream(), Some("http://sid:8080"));
}
