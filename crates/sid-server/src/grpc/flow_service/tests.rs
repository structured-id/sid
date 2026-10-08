use super::*;

#[test]
fn test_flow_type_to_proto() {
    use pb::admin::FlowType as P;
    let cases = [
        (FlowType::Authentication, P::Authentication),
        (FlowType::Registration, P::Registration),
        (FlowType::Recovery, P::Recovery),
        (FlowType::DeviceGrant, P::DeviceGrant),
        (FlowType::DirectGrant, P::DirectGrant),
        (FlowType::Enrollment, P::Enrollment),
    ];
    for (domain, proto) in cases {
        assert_eq!(domain_flow_type_to_proto(&domain), proto as i32);
    }
}

#[test]
fn test_action_point_proto_roundtrip() {
    for ap in ActionPoint::all() {
        let proto = domain_action_point_to_proto(ap);
        let back = proto_action_point_to_domain(proto).unwrap();
        assert_eq!(&back, ap);
    }
}

/// An unspecified or undefined action point names no point to run at.
#[test]
fn test_action_point_unspecified_or_unknown_is_refused() {
    for v in [pb::admin::ActionPoint::Unspecified as i32, 99] {
        let err = proto_action_point_to_domain(v).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{v}");
    }
}

#[test]
fn test_action_on_error_proto_roundtrip() {
    let cases = [ActionOnError::Continue, ActionOnError::Deny];
    for onerr in &cases {
        let proto = domain_action_on_error_to_proto(onerr);
        let back = proto_action_on_error_to_domain(proto).unwrap();
        assert_eq!(&back, onerr);
    }
}

/// Regression: an on-error value the enum does not define was read as
/// continue, so a failing check let the sign-in pass. It is refused;
/// unspecified keeps the default, continue.
#[test]
fn test_action_on_error_unknown_is_refused() {
    let err = proto_action_on_error_to_domain(99).unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        proto_action_on_error_to_domain(pb::admin::ActionOnError::Unspecified as i32).unwrap(),
        ActionOnError::Continue
    );
}

#[test]
fn test_step_config_proto_roundtrip() {
    let step = StepConfig {
        enabled: true,
        params: serde_json::json!({"fields": ["email", "phone"]}),
    };
    let proto = domain_step_to_proto("identification", &step);
    assert_eq!(proto.step_type, "identification");
    assert!(proto.enabled);
    assert!(proto.params.is_some());

    let (key, back) = proto_step_to_domain(&proto);
    assert_eq!(key, "identification");
    assert!(back.enabled);
}

#[test]
fn test_step_config_null_params() {
    let step = StepConfig::default();
    let proto = domain_step_to_proto("password", &step);
    assert!(proto.params.is_none());

    let (_, back) = proto_step_to_domain(&proto);
    assert!(back.params.is_null());
}

#[test]
fn test_flow_config_proto_roundtrip() {
    let mut steps = HashMap::new();
    steps.insert("identification".to_string(), StepConfig::default());

    let config = FlowConfig {
        project_id: ProjectId::new(),
        flow_type: FlowType::Authentication,
        steps,
        timeout_seconds: 300,
        updated_at: chrono::Utc::now(),
    };

    let proto = domain_config_to_proto(&config);
    assert_eq!(proto.project_id, config.project_id.0.to_string());
    assert_eq!(proto.flow_type, pb::admin::FlowType::Authentication as i32);
    assert_eq!(proto.steps.len(), 1);
    assert_eq!(proto.timeout_seconds, 300);
}

#[test]
fn test_flow_action_proto_roundtrip() {
    let action = FlowAction {
        id: ActionId::new(),
        project_id: ProjectId::new(),
        flow_type: FlowType::Registration,
        action_point: ActionPoint::PostRegistration,
        name: "Welcome webhook".into(),
        action_type: ActionType::Webhook,
        config: ActionConfig::Webhook {
            url: "https://api.sid.example.com/hooks/welcome".into(),
            timeout_seconds: 5,
            retry_count: 1,
            headers: HashMap::from([("X-Secret".into(), "abc".into())]),
        },
        order: 1,
        on_error: ActionOnError::Continue,
        enabled: true,
        revision: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let proto = domain_action_to_proto(&action);
    assert_eq!(proto.action_id, action.id.0.to_string());
    assert_eq!(proto.name, "Welcome webhook");
    assert_eq!(proto.flow_type, pb::admin::FlowType::Registration as i32);
    assert_eq!(
        proto.action_point,
        pb::admin::ActionPoint::PostRegistration as i32
    );
    assert_eq!(proto.action_type, pb::admin::ActionType::Webhook as i32);
    assert!(proto.enabled);

    match proto.config {
        Some(pb::flow_action::Config::Webhook(ref wh)) => {
            assert_eq!(wh.url, "https://api.sid.example.com/hooks/welcome");
            assert_eq!(wh.timeout_seconds, 5);
            assert_eq!(wh.retry_count, 1);
            assert_eq!(wh.headers.get("X-Secret").unwrap(), "abc");
        }
        None => panic!("expected webhook config"),
    }
}

#[test]
fn test_proto_webhook_to_domain() {
    let wh = pb::WebhookConfig {
        url: "https://sid.example.com/hook".into(),
        timeout_seconds: 10,
        retry_count: 2,
        headers: HashMap::new(),
    };
    let config = proto_webhook_to_domain(&wh);
    match config {
        ActionConfig::Webhook {
            url,
            timeout_seconds,
            retry_count,
            ..
        } => {
            assert_eq!(url, "https://sid.example.com/hook");
            assert_eq!(timeout_seconds, 10);
            assert_eq!(retry_count, 2);
        }
    }
}
