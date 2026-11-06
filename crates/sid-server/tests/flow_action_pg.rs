// SPDX-License-Identifier: AGPL-3.0-only
//! FlowActionService over PostgreSQL (port 54399): an action is addressed
//! by its project, flow type and id together.

mod common;

use common::{issue_admin_token, test_jwt};
use sid_core::models::{AuditEntry, FlowActionId, ProfileId, ProjectId};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::flow_action_service_server::FlowActionService;
use sid_proto::sid::v1::admin::{
    CreateFlowActionRequest, DeleteFlowActionRequest, FlowType, GetFlowActionRequest,
    UpdateFlowActionRequest, WebhookConfig, create_flow_action_request,
};
use sid_server::grpc::flow_service::FlowActionServiceImpl;
use sid_storage::PostgresBackend;
use std::sync::Arc;
use tonic::{Code, Request};

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn setup() -> (FlowActionServiceImpl, Arc<dyn StorageBackend>, String) {
    let schema = format!("flow_action_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("Failed to run migrations");
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    storage
        .ensure_system_project(AuditEntry::system("test", "setup").into())
        .await
        .expect("system project");
    let jwt = test_jwt();
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let svc = FlowActionServiceImpl::new(storage.clone(), jwt, common::test_revocation());
    (svc, storage, token)
}

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// Regression: get, update and delete looked the action up by its id alone,
/// so a request naming another project or flow type read, changed or deleted
/// it. An action outside the addressed project and flow type is not found
/// there, and stays as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_action_is_found_only_under_its_own_project_and_flow_type() {
    let (svc, storage, token) = setup().await;
    let created = svc
        .create_flow_action(authed(
            CreateFlowActionRequest {
                project_id: Some(ProjectId::SYSTEM.into()),
                flow_type: FlowType::Authentication as i32,
                action_point: 2, // POST_AUTHENTICATION
                name: "Risk check".to_string(),
                action_type: 1, // WEBHOOK
                config: Some(create_flow_action_request::Config::Webhook(WebhookConfig {
                    url: "https://risk.sid.example.com/evaluate".to_string(),
                    timeout_seconds: 3,
                    retry_count: 0,
                    headers: Default::default(),
                })),
                order: 1,
                on_error: 1, // CONTINUE
                enabled: true,
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let action_id = created.action_id.clone();
    let id: FlowActionId = action_id.as_ref().unwrap().try_into().unwrap();

    let elsewhere = [
        (ProjectId::generate(), FlowType::Authentication),
        (ProjectId::SYSTEM, FlowType::Registration),
    ];
    for (project, flow_type) in elsewhere {
        let get = svc
            .get_flow_action(authed(
                GetFlowActionRequest {
                    project_id: Some(project.into()),
                    flow_type: flow_type as i32,
                    action_id: action_id.clone(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            get.code(),
            Code::NotFound,
            "get under {project}/{flow_type:?}"
        );

        let update = svc
            .update_flow_action(authed(
                UpdateFlowActionRequest {
                    project_id: Some(project.into()),
                    flow_type: flow_type as i32,
                    action_id: action_id.clone(),
                    enabled: Some(false),
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            update.code(),
            Code::NotFound,
            "update under {project}/{flow_type:?}"
        );

        let delete = svc
            .delete_flow_action(authed(
                DeleteFlowActionRequest {
                    project_id: Some(project.into()),
                    flow_type: flow_type as i32,
                    action_id: action_id.clone(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            delete.code(),
            Code::NotFound,
            "delete under {project}/{flow_type:?}"
        );

        let stored = storage.get_flow_action(id).await.unwrap();
        let stored = stored.expect("the action was deleted from another scope");
        assert!(stored.enabled, "the action was changed from another scope");
    }

    // Under its own project and flow type it is read and deleted.
    let read = svc
        .get_flow_action(authed(
            GetFlowActionRequest {
                project_id: Some(ProjectId::SYSTEM.into()),
                flow_type: FlowType::Authentication as i32,
                action_id: action_id.clone(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read.action_id, action_id);
    svc.delete_flow_action(authed(
        DeleteFlowActionRequest {
            project_id: Some(ProjectId::SYSTEM.into()),
            flow_type: FlowType::Authentication as i32,
            action_id,
        },
        &token,
    ))
    .await
    .unwrap();
    assert!(storage.get_flow_action(id).await.unwrap().is_none());
}
