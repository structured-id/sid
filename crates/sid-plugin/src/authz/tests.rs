use super::*;

#[test]
fn test_authz_check_response_is_allowed() {
    let allow = AuthzCheckResponse::Allow {
        reason: "role:admin".into(),
    };
    assert!(allow.is_allowed());

    let deny = AuthzCheckResponse::Deny {
        reason: "no role".into(),
    };
    assert!(!deny.is_allowed());
}

#[test]
fn test_authz_check_request_construction() {
    let req = AuthzCheckRequest {
        subject: "user:abc123".into(),
        action: "profiles:read".into(),
        resource: "project:def456".into(),
        context: HashMap::new(),
    };
    assert_eq!(req.subject, "user:abc123");
    assert_eq!(req.action, "profiles:read");
    assert_eq!(req.resource, "project:def456");
    assert!(req.context.is_empty());
}

#[test]
fn test_authz_check_request_with_context() {
    let mut context = HashMap::new();
    context.insert("ip".into(), "192.168.1.1".into());
    context.insert("device_id".into(), "dev_abc".into());

    let req = AuthzCheckRequest {
        subject: "user:abc".into(),
        action: "admin:delete".into(),
        resource: "project:xyz".into(),
        context,
    };
    assert_eq!(req.context.get("ip").unwrap(), "192.168.1.1");
    assert_eq!(req.context.len(), 2);
}

#[test]
fn test_authz_error_display() {
    let e = AuthzError::NotSupported("list_objects".into());
    assert!(e.to_string().contains("not supported in CE"));
}

// Verify traits are object-safe
#[test]
fn test_authz_engine_object_safety() {
    fn _assert_object_safe(_: &dyn AuthzEngine) {}
}
