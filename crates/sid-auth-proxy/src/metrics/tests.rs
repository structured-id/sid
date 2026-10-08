// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn test_path_class() {
    assert_eq!(path_class("/health"), "health");
    assert_eq!(path_class("/health/ready"), "health");
    assert_eq!(path_class("/.well-known/openid-configuration"), "discovery");
    assert_eq!(path_class("/metrics"), "metrics");
    assert_eq!(path_class("/v1/auth/magic-link/send"), "magic_link");
    assert_eq!(path_class("/v1/auth/opaque/register/start"), "register");
    assert_eq!(path_class("/v1/auth/opaque/login/start"), "auth");
    assert_eq!(path_class("/oauth2/token"), "oauth2");
    let issuer = "/i/0123456789abcdef0123456789abcdef";
    assert_eq!(path_class(&format!("{issuer}/oauth2/token")), "oauth2");
    assert_eq!(path_class(&format!("{issuer}/jwks")), "discovery");
    assert_eq!(
        path_class(&format!("{issuer}/.well-known/openid-configuration")),
        "discovery"
    );
    assert_eq!(path_class(&format!("{issuer}/userinfo")), "userinfo");
    assert_eq!(path_class("/v1/admin/bootstrap"), "admin");
    assert_eq!(path_class("/v1/identity/profiles"), "identity");
    assert_eq!(path_class("/v1/projects/list"), "project");
    assert_eq!(path_class("/v1/authz/check"), "project");
    assert_eq!(path_class("/unknown"), "other");
}

#[test]
fn test_metrics_registered() {
    // Access lazy statics to trigger registration
    let _ = HTTP_REQUESTS_TOTAL.with_label_values(&["GET", "health", "200"]);
    let _ = HTTP_REQUEST_DURATION_SECONDS.with_label_values(&["GET", "health"]);

    let families = prometheus::default_registry().gather();
    let has_requests = families
        .iter()
        .any(|f| f.name().contains("http_requests_total"));
    let has_duration = families
        .iter()
        .any(|f| f.name().contains("http_request_duration"));
    assert!(has_requests, "requests counter not found in registry");
    assert!(has_duration, "duration histogram not found in registry");
}
