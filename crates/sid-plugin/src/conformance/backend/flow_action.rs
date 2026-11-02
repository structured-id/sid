// SPDX-License-Identifier: AGPL-3.0-only
//! Flow actions: created once, listed per hook point in execution order, and
//! updated only over the revision they were read at.

use std::collections::HashMap;

use chrono::Utc;
use sid_core::models::{
    ActionConfig, ActionId, ActionOnError, ActionPoint, ActionType, FlowAction, FlowType, Project,
    ProjectId,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

async fn project(backend: &dyn StorageBackend) -> ProjectId {
    let project = Project::new(format!("flow_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    project.id
}

fn action(project_id: ProjectId, point: ActionPoint, order: i32) -> FlowAction {
    let now = Utc::now();
    FlowAction {
        id: ActionId::new(),
        project_id,
        flow_type: FlowType::Authentication,
        action_point: point,
        name: format!("hook {order}"),
        action_type: ActionType::Webhook,
        config: ActionConfig::Webhook {
            url: "https://hooks.sid.example.com/login".into(),
            timeout_seconds: 5,
            retry_count: 0,
            headers: HashMap::new(),
        },
        order,
        on_error: ActionOnError::Continue,
        enabled: true,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

async fn listed(
    backend: &dyn StorageBackend,
    project_id: ProjectId,
    point: Option<ActionPoint>,
) -> Vec<ActionId> {
    backend
        .list_flow_actions(project_id, FlowType::Authentication, point)
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect()
}

/// Actions are listed per hook point in their execution order; an action
/// moved to another point is listed there and no longer at the old one.
pub async fn test_flow_actions_listed_by_point_in_order(backend: &dyn StorageBackend) {
    let project_id = project(backend).await;
    let second = action(project_id, ActionPoint::PostLogin, 20);
    let first = action(project_id, ActionPoint::PostLogin, 10);
    let other = action(project_id, ActionPoint::PreConsent, 5);
    for a in [&second, &first, &other] {
        backend.create_flow_action(a, test_audit()).await.unwrap();
    }
    assert_eq!(
        listed(backend, project_id, Some(ActionPoint::PostLogin)).await,
        [first.id, second.id]
    );
    assert_eq!(listed(backend, project_id, None).await.len(), 3);

    let mut moved = backend.get_flow_action(first.id).await.unwrap().unwrap();
    moved.action_point = ActionPoint::PreConsent;
    assert!(
        backend
            .update_flow_action(&moved, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        listed(backend, project_id, Some(ActionPoint::PostLogin)).await,
        [second.id],
        "a moved action still runs at its old hook point"
    );
    assert_eq!(
        listed(backend, project_id, Some(ActionPoint::PreConsent)).await,
        [other.id, first.id],
        "the moved action runs at its new point in its order"
    );
}

/// A second create never replaces an action; a stale copy never re-enables
/// an action disabled since, and an update never recreates a deleted one.
pub async fn test_flow_action_write_contract(backend: &dyn StorageBackend) {
    let project_id = project(backend).await;
    let created = action(project_id, ActionPoint::PostLogin, 1);
    backend
        .create_flow_action(&created, test_audit())
        .await
        .unwrap();
    let mut takeover = created.clone();
    takeover.config = ActionConfig::Webhook {
        url: "https://attacker.sid.example.com".into(),
        timeout_seconds: 5,
        retry_count: 0,
        headers: HashMap::new(),
    };
    assert!(matches!(
        backend.create_flow_action(&takeover, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));

    let read = backend.get_flow_action(created.id).await.unwrap().unwrap();
    let mut disable = read.clone();
    disable.enabled = false;
    assert!(
        backend
            .update_flow_action(&disable, test_audit())
            .await
            .unwrap()
    );
    let mut stale = read;
    stale.name = "renamed".into();
    assert!(
        !backend
            .update_flow_action(&stale, test_audit())
            .await
            .unwrap(),
        "an update over a stale revision must not apply"
    );
    let current = backend.get_flow_action(created.id).await.unwrap().unwrap();
    assert!(!current.enabled, "a stale copy re-enabled the action");

    backend
        .delete_flow_action(created.id, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .update_flow_action(&current, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend.get_flow_action(created.id).await.unwrap().is_none(),
        "an update recreated a deleted action"
    );
}
