// SPDX-License-Identifier: AGPL-3.0-only
//! A SCIM provisioning connector holds its roles through the ordinary
//! role-assignment API, on one live protected resource only, and while it is
//! not retired. The engine then lets it perform SCIM actions there and
//! nothing else.

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token};
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::{
    AuditEntry, ConnectorState, OrgId, ProjectId, ProvisioningConnector, ProvisioningConnectorId,
    ProvisioningDirection, ResourceId, SCIM_PROVISIONER_ROLE, SCIM_USER_CREATE, TOKEN_INTROSPECT,
};
use sid_plugin::authz::{AuthzCheckRequest, AuthzEngine};
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::list_role_assignments_request::Filter;
use sid_proto::sid::v1::authz::role_assignment;
use sid_proto::sid::v1::authz::{AssignRoleRequest, ListRoleAssignmentsRequest};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use tonic::{Code, Request};

fn authz(svc: &TestServices) -> AuthzServiceImpl {
    AuthzServiceImpl::new(
        Arc::new(sid_authz::CeAuthzEngine::new(svc.storage.clone())),
        svc.storage.clone(),
        CedarService::new(),
        Arc::new(AtomicBool::new(false)),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
        common::RecordingAuditLog::shared(),
    )
}

fn as_admin<T>(svc: &TestServices, message: T) -> Request<T> {
    let token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

async fn provisioner_role(svc: &TestServices) -> String {
    svc.storage
        .list_roles(ProjectId::system())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.key == SCIM_PROVISIONER_ROLE)
        .expect("provisioned at start")
        .id
        .0
        .to_string()
}

async fn stored_connector(svc: &TestServices) -> ProvisioningConnector {
    let connector = ProvisioningConnector::new(
        OrgId::generate(),
        ProvisioningDirection::Inbound,
        "Directory sync",
    );
    svc.storage
        .create_provisioning_connector(&connector, AuditEntry::system("test", "connector").into())
        .await
        .unwrap();
    connector
}

fn on(resource: impl std::fmt::Display) -> Option<String> {
    Some(format!("oauth_resource:{resource}"))
}

fn assign(principal: Principal, role_id: String, scope: Option<String>) -> AssignRoleRequest {
    AssignRoleRequest {
        principal: Some(principal),
        role_id,
        scope,
        expires_at: None,
        admin: None,
    }
}

/// An administrator assigns the provisioner role to a connector on one
/// resource; it is listed under the connector and lets the connector create
/// users there, and only there.
#[tokio::test]
async fn a_connector_is_assigned_provisioning_on_a_resource() {
    let svc = TestServices::new(MockStorage::new());
    let authz = authz(&svc);
    let directory = common::userinfo_resource(&svc).await;
    let connector = stored_connector(&svc).await;
    let assigned = authz
        .assign_role(as_admin(
            &svc,
            assign(
                Principal::ProvisioningConnectorId(connector.id.into()),
                provisioner_role(&svc).await,
                on(directory),
            ),
        ))
        .await
        .unwrap()
        .into_inner()
        .assignment
        .unwrap();
    assert_eq!(
        assigned.principal,
        Some(role_assignment::Principal::ProvisioningConnectorId(
            connector.id.into()
        ))
    );

    let listed = authz
        .list_role_assignments(as_admin(
            &svc,
            ListRoleAssignmentsRequest {
                filter: Some(Filter::ProvisioningConnectorId(connector.id.into())),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.assignments.len(), 1);
    assert_eq!(listed.assignments[0].id, assigned.id);

    let engine = sid_authz::CeAuthzEngine::new(svc.storage.clone());
    let check = |action: &str, resource: String| AuthzCheckRequest {
        subject: format!("provisioning_connector:{}", connector.id),
        action: action.into(),
        resource,
        context: Default::default(),
    };
    let here = format!("oauth_resource:{directory}");
    assert!(
        engine
            .check(&check(SCIM_USER_CREATE, here.clone()))
            .await
            .unwrap()
            .is_allowed()
    );
    assert!(
        !engine
            .check(&check(TOKEN_INTROSPECT, here))
            .await
            .unwrap()
            .is_allowed()
    );
    assert!(
        !engine
            .check(&check(
                SCIM_USER_CREATE,
                format!("oauth_resource:{}", ResourceId::generate())
            ))
            .await
            .unwrap()
            .is_allowed()
    );
}

/// A connector's role is refused without a resource scope, project-wide, on
/// an unknown resource, for an unknown or malformed connector and for a
/// retired one; nothing is stored.
#[tokio::test]
async fn provisioning_is_assigned_only_to_a_live_connector_on_one_resource() {
    let svc = TestServices::new(MockStorage::new());
    let authz = authz(&svc);
    let role = provisioner_role(&svc).await;
    let directory = common::userinfo_resource(&svc).await;
    let live = stored_connector(&svc).await;
    let retired = stored_connector(&svc).await;
    assert!(
        svc.storage
            .transition_provisioning_connector(
                retired.id,
                ConnectorState::Active,
                ConnectorState::Retired,
                AuditEntry::system("test", "connector").into(),
            )
            .await
            .unwrap()
    );
    let of = |c: &ProvisioningConnector| Principal::ProvisioningConnectorId(c.id.into());
    let cases = [
        (of(&live), None, Code::InvalidArgument),
        (
            of(&live),
            Some(format!("project:{}", ProjectId::system().0)),
            Code::InvalidArgument,
        ),
        (of(&live), on(ResourceId::generate()), Code::NotFound),
        (
            Principal::ProvisioningConnectorId(ProvisioningConnectorId::generate().into()),
            on(directory),
            Code::NotFound,
        ),
        (
            // 15 bytes: no identifier.
            Principal::ProvisioningConnectorId(sid_proto::sid::v1::ids::ProvisioningConnectorId {
                value: vec![1; 15],
            }),
            on(directory),
            Code::InvalidArgument,
        ),
        (of(&retired), on(directory), Code::FailedPrecondition),
    ];
    for (i, (principal, scope, code)) in cases.into_iter().enumerate() {
        let err = authz
            .assign_role(as_admin(&svc, assign(principal, role.clone(), scope)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "case {i}: {err:?}");
    }
    for connector in [live.id, retired.id] {
        assert!(
            svc.storage
                .list_role_assignments_for_provisioning_connector(connector)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
