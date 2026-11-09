use super::*;
use crate::test_support::{administrator, operation, storage, stored_profile};
use sid_core::models::ProjectId;

/// The flows of a fresh store and an administrator of it.
async fn flows() -> (Flows, Caller, Arc<sid_storage::sqlite::SqliteBackend>) {
    let storage = storage().await;
    let admin = administrator(stored_profile(storage.as_ref(), "flow_admin").await);
    (Flows::new(storage.clone()), admin, storage)
}

fn save(timeout_seconds: u32) -> pb::SaveFlowConfigRequest {
    pb::SaveFlowConfigRequest {
        project_id: Some(ProjectId::SYSTEM.into()),
        flow_type: pb::admin::FlowType::Authentication as i32,
        steps: Vec::new(),
        timeout_seconds,
    }
}

fn create_webhook(name: &str) -> pb::CreateFlowActionRequest {
    pb::CreateFlowActionRequest {
        project_id: Some(ProjectId::SYSTEM.into()),
        flow_type: pb::admin::FlowType::Authentication as i32,
        action_point: pb::admin::ActionPoint::PostLogin as i32,
        name: name.into(),
        action_type: pb::admin::ActionType::Webhook as i32,
        config: Some(pb::create_flow_action_request::Config::Webhook(
            pb::WebhookConfig {
                url: "https://hooks.sid.example.com/login".into(),
                timeout_seconds: 5,
                retry_count: 1,
                headers: Default::default(),
            },
        )),
        order: 1,
        on_error: pb::admin::ActionOnError::Continue as i32,
        enabled: true,
    }
}

/// A configuration is saved, saved again, then the first save's lost
/// response is retried: the retry answers as the first save did and the
/// later configuration stays (it was written over).
#[tokio::test]
async fn test_save_config_retry_keeps_a_later_save() {
    let (flows, admin, storage) = flows().await;
    let first = flows
        .save_config(&admin, operation(storage.as_ref(), "op-a").await, save(120))
        .await
        .unwrap();
    flows
        .save_config(&admin, operation(storage.as_ref(), "op-b").await, save(600))
        .await
        .unwrap();
    let retry = flows
        .save_config(&admin, operation(storage.as_ref(), "op-a").await, save(120))
        .await
        .unwrap();

    assert_eq!(retry, first);
    let stored = storage
        .get_flow_config(ProjectId::SYSTEM, FlowType::Authentication)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.timeout_seconds, 600,
        "the retry wrote the first save over the later one"
    );
}

/// An action's creation is retried after its response was lost: the retry
/// answers with the action it created and no second action exists.
#[tokio::test]
async fn test_create_action_retry_answers_with_its_action() {
    let (flows, admin, storage) = flows().await;
    let first = flows
        .create_action(
            &admin,
            operation(storage.as_ref(), "op-create").await,
            create_webhook("audit"),
        )
        .await
        .unwrap();
    let retry = flows
        .create_action(
            &admin,
            operation(storage.as_ref(), "op-create").await,
            create_webhook("audit"),
        )
        .await
        .unwrap();

    assert_eq!(retry, first);
    let stored = storage
        .list_flow_actions(ProjectId::SYSTEM, FlowType::Authentication, None)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1, "the retry created another action");
}

/// An action is disabled, re-enabled, then the disabling's lost response is
/// retried: the retry answers as the disabling did and the action stays
/// enabled.
#[tokio::test]
async fn test_update_action_retry_keeps_a_later_update() {
    let (flows, admin, storage) = flows().await;
    let action = flows
        .create_action(
            &admin,
            operation(storage.as_ref(), "op-new").await,
            create_webhook("audit"),
        )
        .await
        .unwrap();
    let toggle = |enabled: bool| pb::UpdateFlowActionRequest {
        project_id: action.project_id.clone(),
        flow_type: action.flow_type,
        action_id: action.action_id.clone(),
        enabled: Some(enabled),
        ..Default::default()
    };

    let first = flows
        .update_action(
            &admin,
            operation(storage.as_ref(), "op-off").await,
            toggle(false),
        )
        .await
        .unwrap();
    flows
        .update_action(
            &admin,
            operation(storage.as_ref(), "op-on").await,
            toggle(true),
        )
        .await
        .unwrap();
    let retry = flows
        .update_action(
            &admin,
            operation(storage.as_ref(), "op-off").await,
            toggle(false),
        )
        .await
        .unwrap();

    assert!(!first.enabled);
    assert_eq!(retry, first);
    let id = wire_id(action.action_id.as_ref(), "action_id").unwrap();
    assert!(
        storage.get_flow_action(id).await.unwrap().unwrap().enabled,
        "the retry disabled the action again"
    );
}

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
