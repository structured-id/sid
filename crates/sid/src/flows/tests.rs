use super::*;
use sid_core::models::ProjectId;

fn refused_on<T: std::fmt::Debug>(result: Result<T, FlowError>, expected: &str) {
    match result {
        Err(FlowError::InvalidField { field, .. }) => assert_eq!(field, expected),
        other => panic!("expected a refusal on {expected}, got {other:?}"),
    }
}

#[test]
fn test_flow_type_proto_roundtrip() {
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
        assert_eq!(flow_type_to_proto(&domain), proto as i32);
        assert_eq!(flow_type_from_proto(proto as i32).unwrap(), domain);
    }
    for v in [P::Unspecified as i32, 99] {
        refused_on(flow_type_from_proto(v), "flow_type");
    }
}

#[test]
fn test_action_point_proto_roundtrip() {
    for ap in ActionPoint::all() {
        let back = action_point_from_proto(action_point_to_proto(ap)).unwrap();
        assert_eq!(&back, ap);
    }
}

/// An unspecified or undefined action point names no point to run at.
#[test]
fn test_action_point_unspecified_or_unknown_is_refused() {
    for v in [pb::admin::ActionPoint::Unspecified as i32, 99] {
        refused_on(action_point_from_proto(v), "action_point");
    }
}

#[test]
fn test_action_on_error_proto_roundtrip() {
    for onerr in [ActionOnError::Continue, ActionOnError::Deny] {
        assert_eq!(
            on_error_from_proto(on_error_to_proto(&onerr)).unwrap(),
            onerr
        );
    }
}

/// Regression: an on-error value the enum does not define was read as
/// continue, so a failing check let the sign-in pass. It is refused;
/// unspecified keeps the default, continue.
#[test]
fn test_action_on_error_unknown_is_refused() {
    refused_on(on_error_from_proto(99), "on_error");
    assert_eq!(
        on_error_from_proto(pb::admin::ActionOnError::Unspecified as i32).unwrap(),
        ActionOnError::Continue
    );
}

#[test]
fn test_step_config_proto_roundtrip() {
    let step = StepConfig {
        enabled: true,
        params: serde_json::json!({"fields": ["email", "phone"], "max": 3, "on": true}),
    };
    let proto = step_to_proto("identification", &step);
    assert_eq!(proto.step_type, "identification");
    assert!(proto.enabled);
    let (key, back) = step_from_proto(&proto);
    assert_eq!(key, "identification");
    assert!(back.enabled);
    assert_eq!(back.params["fields"][1], "phone");
    assert_eq!(back.params["max"], 3.0);
    assert_eq!(back.params["on"], true);
}

#[test]
fn test_step_config_null_params() {
    let proto = step_to_proto("password", &StepConfig::default());
    assert!(proto.params.is_none());
    let (_, back) = step_from_proto(&proto);
    assert!(back.params.is_null());
}

#[test]
fn test_flow_config_proto() {
    let mut steps = HashMap::new();
    steps.insert("identification".to_string(), StepConfig::default());
    let config = FlowConfig {
        project_id: ProjectId::generate(),
        flow_type: FlowType::Authentication,
        steps,
        timeout_seconds: 300,
        updated_at: chrono::Utc::now(),
    };
    let proto = config_to_proto(&config);
    assert_eq!(proto.project_id, Some(config.project_id.into()));
    assert_eq!(proto.flow_type, pb::admin::FlowType::Authentication as i32);
    assert_eq!(proto.steps.len(), 1);
    assert_eq!(proto.timeout_seconds, 300);
}

#[test]
fn test_flow_action_proto() {
    let action = FlowAction {
        id: FlowActionId::generate(),
        project_id: ProjectId::generate(),
        flow_type: FlowType::Registration,
        action_point: ActionPoint::PostRegistration,
        name: "Welcome webhook".into(),
        action_type: ActionType::Webhook,
        config: ActionConfig::Webhook {
            url: "https://api.sid.example.com/hooks/welcome".into(),
            timeout_seconds: 5,
            retry_count: 1,
            headers: std::collections::BTreeMap::from([("X-Secret".into(), "abc".into())]),
        },
        order: 1,
        on_error: ActionOnError::Continue,
        enabled: true,
        revision: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let proto = action_to_proto(&action);
    assert_eq!(proto.action_id, Some(action.id.into()));
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
fn test_webhook_from_proto() {
    let wh = pb::WebhookConfig {
        url: "https://sid.example.com/hook".into(),
        timeout_seconds: 10,
        retry_count: 2,
        headers: Default::default(),
    };
    let ActionConfig::Webhook {
        url,
        timeout_seconds,
        retry_count,
        ..
    } = webhook_from_proto(&wh);
    assert_eq!(url, "https://sid.example.com/hook");
    assert_eq!(timeout_seconds, 10);
    assert_eq!(retry_count, 2);
}
