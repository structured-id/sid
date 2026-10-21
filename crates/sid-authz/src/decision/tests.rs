use super::*;

#[test]
fn test_authz_check_response_is_allowed() {
    let allow = AuthzCheckResponse::Allow {
        reason: "role:admin".into(),
    };
    assert!(allow.is_allowed());
    assert_eq!(allow.reason(), "role:admin");

    let deny = AuthzCheckResponse::Deny {
        reason: "no role".into(),
    };
    assert!(!deny.is_allowed());
    assert_eq!(deny.reason(), "no role");
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
    let e = AuthzError::Storage("unreachable".into());
    assert_eq!(e.to_string(), "storage error: unreachable");
}
