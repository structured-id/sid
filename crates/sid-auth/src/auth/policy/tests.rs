// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";

const SAMPLE_YAML: &str = r#"
applications:
  - name: portal
    origin: https://portal.example.com
    issuer: https://sid.example.com/i/0123456789abcdef0123456789abcdef
    resource: https://portal.example.com/
    routes:
      - match:
          path: "/health"
          methods: ["GET"]
        policy:
          auth: none

      - match:
          path: "/app/**"
        policy:
          auth: required
          headers:
            inject: [user, email, groups]

      - match:
          path: "/admin/**"
        policy:
          auth: required
          require:
            roles: ["admin", "super_admin"]
          headers:
            inject: [user, email, groups]

      - match:
          path: "/api/v1/**"
          methods: ["GET", "HEAD", "OPTIONS"]
        policy:
          auth: required

      - match:
          path: "/api/v1/**"
          methods: ["POST", "PUT", "DELETE", "PATCH"]
        policy:
          auth: required
          require:
            roles: ["editor", "admin"]

      - match:
          path: "/public/**"
        policy:
          auth: none
"#;

fn portal() -> PolicyEngine {
    PolicyEngine::from_yaml(SAMPLE_YAML).unwrap()
}

fn matched(path: &str, method: Method) -> RoutePolicy {
    portal()
        .application("portal")
        .unwrap()
        .match_route(path, &method)
        .clone()
}

/// The application keeps its target as configured and its origin as
/// scheme and authority.
#[test]
fn test_load_yaml() {
    let engine = portal();
    let app = engine.application("portal").unwrap();
    assert_eq!(app.routes.len(), 6);
    assert_eq!(app.origin, "https://portal.example.com");
    assert_eq!(
        app.target,
        Target {
            issuer: ISSUER.into(),
            resource: "https://portal.example.com/".into(),
        }
    );
}

/// Only a configured application is found; the ingress cannot reach another
/// target by naming one that does not exist.
#[test]
fn test_unknown_application_is_absent() {
    assert!(portal().application("other").is_none());
    assert!(PolicyEngine::empty().application("portal").is_none());
}

#[test]
fn test_match_health() {
    assert_eq!(matched("/health", Method::GET).auth, AuthRequirement::None);
}

/// POST /health does not match the GET-only route and falls through to the
/// default, which requires authentication.
#[test]
fn test_match_health_wrong_method() {
    assert_eq!(
        matched("/health", Method::POST).auth,
        AuthRequirement::Required
    );
}

#[test]
fn test_match_app() {
    let policy = matched("/app/dashboard", Method::GET);
    assert_eq!(policy.auth, AuthRequirement::Required);
    assert!(policy.required_roles.is_empty());
    assert_eq!(policy.inject_headers, vec!["user", "email", "groups"]);
}

#[test]
fn test_match_admin_roles() {
    let policy = matched("/admin/users", Method::GET);
    assert_eq!(policy.auth, AuthRequirement::Required);
    assert_eq!(policy.required_roles, vec!["admin", "super_admin"]);
}

#[test]
fn test_match_api_read() {
    let policy = matched("/api/v1/projects", Method::GET);
    assert_eq!(policy.auth, AuthRequirement::Required);
    assert!(policy.required_roles.is_empty());
}

#[test]
fn test_match_api_write() {
    let policy = matched("/api/v1/projects", Method::POST);
    assert_eq!(policy.required_roles, vec!["editor", "admin"]);
}

#[test]
fn test_match_public() {
    assert_eq!(
        matched("/public/assets/logo.png", Method::GET).auth,
        AuthRequirement::None
    );
}

/// DELETE on /api/v1/foo matches the write route, the first one listing it.
#[test]
fn test_first_match_wins() {
    assert_eq!(
        matched("/api/v1/foo", Method::DELETE).required_roles,
        vec!["editor", "admin"]
    );
}

/// An unmatched path requires authentication with no further requirement.
#[test]
fn test_default_policy() {
    let policy = matched("/unknown/path", Method::GET);
    assert_eq!(policy.auth, AuthRequirement::Required);
    assert!(policy.required_roles.is_empty());
}

fn with_application(fields: &str) -> Result<PolicyEngine, PolicyError> {
    PolicyEngine::from_yaml(&format!("applications:\n  - {fields}\n"))
}

const VALID: &str = "name: portal\n    origin: https://portal.example.com\n    issuer: https://sid.example.com/i/0123456789abcdef0123456789abcdef\n    resource: https://portal.example.com/";

/// A misspelled method used to drop out of the set, and an emptied set
/// matched every method: a route meant for GET opened POST too. It is now
/// refused when the file loads.
#[test]
fn test_invalid_method_is_refused() {
    let yaml = format!(
        "{VALID}\n    routes:\n      - match: {{ path: \"/public/**\", methods: [\"G E T\"] }}\n        policy: {{ auth: none }}"
    );
    assert!(matches!(
        with_application(&yaml),
        Err(PolicyError::InvalidMethod(m)) if m == "G E T"
    ));
}

/// One name, one target: a second application under the same name is
/// refused rather than silently replacing the first.
#[test]
fn test_duplicate_application_is_refused() {
    let yaml = format!("applications:\n  - {VALID}\n  - {VALID}\n");
    assert!(matches!(
        PolicyEngine::from_yaml(&yaml),
        Err(PolicyError::DuplicateApplication(name)) if name == "portal"
    ));
}

/// Every application names a target; one without an issuer or resource,
/// or with a resource that is no indicator, does not load.
#[test]
fn test_application_without_a_valid_target_is_refused() {
    let no_resource = "name: portal\n    origin: https://portal.example.com\n    issuer: https://sid.example.com/i/0123456789abcdef0123456789abcdef";
    assert!(matches!(
        with_application(no_resource),
        Err(PolicyError::YamlError(_))
    ));
    let fragment = "name: portal\n    origin: https://portal.example.com\n    issuer: https://sid.example.com/i/0123456789abcdef0123456789abcdef\n    resource: https://portal.example.com/#frag";
    assert!(matches!(
        with_application(fragment),
        Err(PolicyError::InvalidApplication {
            field: "resource",
            ..
        })
    ));
    let bad_issuer = "name: portal\n    origin: https://portal.example.com\n    issuer: not-a-url\n    resource: https://portal.example.com/";
    assert!(matches!(
        with_application(bad_issuer),
        Err(PolicyError::InvalidApplication {
            field: "issuer",
            ..
        })
    ));
}

/// The origin is scheme and authority only: a path, query or credentials
/// would change the request URI a DPoP proof is checked against.
#[test]
fn test_origin_must_be_an_origin() {
    for origin in [
        "https://portal.example.com/app",
        "https://portal.example.com/?q=1",
        "https://user@portal.example.com",
        "ftp://portal.example.com",
        "portal.example.com",
    ] {
        let yaml = format!(
            "name: portal\n    origin: {origin}\n    issuer: {ISSUER}\n    resource: https://portal.example.com/"
        );
        assert!(
            matches!(
                with_application(&yaml),
                Err(PolicyError::InvalidApplication {
                    field: "origin",
                    ..
                })
            ),
            "{origin}"
        );
    }
    let engine = with_application(&format!(
        "name: portal\n    origin: https://Portal.Example.com:8443/\n    issuer: {ISSUER}\n    resource: https://portal.example.com/"
    ))
    .unwrap();
    assert_eq!(
        engine.application("portal").unwrap().origin,
        "https://portal.example.com:8443"
    );
}

/// A name the forward-auth path cannot carry is refused.
#[test]
fn test_application_name_is_path_safe() {
    for name in ["", "a/b", "a b", "..", "a?b"] {
        let yaml = format!(
            "name: \"{name}\"\n    origin: https://portal.example.com\n    issuer: {ISSUER}\n    resource: https://portal.example.com/"
        );
        assert!(
            matches!(
                with_application(&yaml),
                Err(PolicyError::InvalidApplication { field: "name", .. })
            ),
            "{name:?}"
        );
    }
}

/// A route asking sid-authz names the application operation it decides; a
/// route asking without one, or naming one it does not ask about, does not
/// load: the operation is never derived from the HTTP method or path.
#[test]
fn test_a_checked_route_names_its_action() {
    let route = |policy: &str| {
        format!(
            "{VALID}\n    routes:\n      - match: {{ path: \"/orders/**\" }}\n        policy: {policy}"
        )
    };
    let engine = with_application(&route(
        "{ auth: required, check_authz: true, action: orders.read }",
    ))
    .unwrap();
    let policy = engine
        .application("portal")
        .unwrap()
        .match_route("/orders/1", &Method::GET)
        .clone();
    assert_eq!(policy.authz_action.as_deref(), Some("orders.read"));
    assert!(
        portal()
            .application("portal")
            .unwrap()
            .match_route("/app/x", &Method::GET)
            .authz_action
            .is_none()
    );
    for (case, policy) in [
        (
            "asking without an action",
            "{ auth: required, check_authz: true }",
        ),
        (
            "an action not asked about",
            "{ auth: required, action: orders.read }",
        ),
        (
            "an empty action",
            "{ auth: required, check_authz: true, action: \"\" }",
        ),
    ] {
        assert!(
            matches!(
                with_application(&route(policy)),
                Err(PolicyError::InvalidApplication {
                    field: "action",
                    ..
                })
            ),
            "{case}"
        );
    }
}

/// The old top-level route list, which named no target, no longer loads:
/// a misplaced key must not leave the routes it meant to protect unconfigured.
#[test]
fn test_unknown_keys_are_refused() {
    let yaml = "routes:\n  - match: { path: \"/**\" }\n    policy: { auth: none }\n";
    assert!(matches!(
        PolicyEngine::from_yaml(yaml),
        Err(PolicyError::YamlError(_))
    ));
}
