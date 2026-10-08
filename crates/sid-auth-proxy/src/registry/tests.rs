// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const SAMPLE_YAML: &str = r#"
applications:
  - id: grafana
    name: "Grafana Monitoring"
    upstream: http://grafana:3000
    external_url: https://grafana.example.com
    auth_translation:
      mode: header
      headers:
        X-WEBAUTH-USER: "{{ .Email }}"
    policy:
      auth: required
      require:
        roles: ["ops", "dev", "admin"]
    health_check:
      path: /api/health
      interval: "30s"

  - id: wiki
    name: "Internal Wiki"
    upstream: http://wiki:8080
    external_url: https://wiki.example.com
    policy:
      auth: required
"#;

#[test]
fn test_load_yaml() {
    let registry = AppRegistry::from_yaml(SAMPLE_YAML).unwrap();
    assert_eq!(registry.len(), 2);
}

#[test]
fn test_get_app() {
    let registry = AppRegistry::from_yaml(SAMPLE_YAML).unwrap();
    let grafana = registry.get("grafana").unwrap();
    assert_eq!(grafana.name, "Grafana Monitoring");
    assert_eq!(grafana.upstream.as_deref(), Some("http://grafana:3000"));
}

#[test]
fn test_get_nonexistent() {
    let registry = AppRegistry::from_yaml(SAMPLE_YAML).unwrap();
    assert!(registry.get("nonexistent").is_none());
}

#[test]
fn test_health_check() {
    let registry = AppRegistry::from_yaml(SAMPLE_YAML).unwrap();
    let grafana = registry.get("grafana").unwrap();
    let hc = grafana.health_check.as_ref().unwrap();
    assert_eq!(hc.path, "/api/health");
    assert_eq!(hc.interval, "30s");
}
