use super::*;
use crate::test_mock::MockStorage;
use sid_core::models::machine_user::MachineUserId;
use sid_core::models::*;
use std::collections::HashMap;

fn create_test_role(project_id: ProjectId, key: &str, permissions: &[&str]) -> Role {
    let mut role = Role::new(project_id, key, key);
    role.permissions = permissions.iter().map(|s| s.to_string()).collect();
    role
}

async fn setup() -> (CeAuthzEngine<MockStorage>, Arc<MockStorage>, ProjectId) {
    let storage = Arc::new(MockStorage::new());
    let engine = CeAuthzEngine::new(storage.clone());
    let project_id = ProjectId::new();
    (engine, storage, project_id)
}

// ── Subject/Resource parsing ─────────────────────────────────

#[test]
fn test_parse_subject_user_prefix() {
    let uuid = Uuid::now_v7();
    let principal = CeAuthzEngine::<MockStorage>::parse_subject(&format!("user:{uuid}")).unwrap();
    assert_eq!(
        principal.as_profile_id().unwrap(),
        ProfileId::from_uuid(uuid).unwrap()
    );
}

#[test]
fn test_parse_subject_bare_uuid() {
    let uuid = Uuid::now_v7();
    let principal = CeAuthzEngine::<MockStorage>::parse_subject(&uuid.to_string()).unwrap();
    assert_eq!(
        principal.as_profile_id().unwrap(),
        ProfileId::from_uuid(uuid).unwrap()
    );
}

#[test]
fn test_parse_subject_machine_prefix() {
    let uuid = Uuid::now_v7();
    let principal =
        CeAuthzEngine::<MockStorage>::parse_subject(&format!("machine:{uuid}")).unwrap();
    assert_eq!(
        principal.as_machine_user_id().unwrap(),
        MachineUserId::from_uuid(uuid).unwrap()
    );
    assert!(principal.as_profile_id().is_none());
}

#[test]
fn test_parse_subject_invalid() {
    let result = CeAuthzEngine::<MockStorage>::parse_subject("not-a-uuid");
    assert!(result.is_err());
}

#[test]
fn test_parse_subject_machine_invalid_uuid() {
    let result = CeAuthzEngine::<MockStorage>::parse_subject("machine:not-a-uuid");
    assert!(result.is_err());
}

#[test]
fn test_parse_project_with_prefix() {
    let uuid = Uuid::now_v7();
    let id = CeAuthzEngine::<MockStorage>::parse_project(&format!("project:{uuid}")).unwrap();
    assert_eq!(id.0, uuid);
}

#[test]
fn test_parse_project_typed_resource() {
    let uuid = Uuid::now_v7();
    let id = CeAuthzEngine::<MockStorage>::parse_project(&format!("doc:{uuid}")).unwrap();
    assert_eq!(id.0, uuid);
}

#[test]
fn test_parse_project_bare_uuid() {
    let uuid = Uuid::now_v7();
    let id = CeAuthzEngine::<MockStorage>::parse_project(&uuid.to_string()).unwrap();
    assert_eq!(id.0, uuid);
}

#[test]
fn test_parse_project_invalid() {
    let result = CeAuthzEngine::<MockStorage>::parse_project("bad");
    assert!(result.is_err());
}

// ── RBAC checks via AuthzEngine ──────────────────────────────

#[tokio::test]
async fn test_check_no_roles_denies() {
    let (engine, _, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();

    assert!(!resp.is_allowed());
}

#[tokio::test]
async fn test_check_rbac_allows() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "admin", &["profiles:read", "profiles:write"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(&assignment, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();

    assert!(resp.is_allowed());
    match resp {
        AuthzCheckResponse::Allow { reason } => {
            assert!(reason.contains("RBAC"));
            assert!(reason.contains("admin"));
        }
        _ => panic!("expected Allow"),
    }
}

#[tokio::test]
async fn test_check_rbac_wrong_permission_denies() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "viewer", &["profiles:read"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(&assignment, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:delete".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();

    assert!(!resp.is_allowed());
}

#[tokio::test]
async fn test_check_via_group_allows() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "editor", &["docs:write"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let group = Group::new(project_id, "editors");
    storage
        .create_group(&group, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    storage
        .add_to_group(
            &GroupMember::new(group.id, profile_id),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();

    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), role.id);
    storage
        .create_role_assignment(&assignment, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "docs:write".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();

    assert!(resp.is_allowed());
}

#[tokio::test]
async fn test_check_expired_role_denies() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "temp", &["profiles:read"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let mut assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    assignment.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    storage
        .create_role_assignment(&assignment, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();

    assert!(!resp.is_allowed());
}

#[tokio::test]
async fn test_check_invalid_subject() {
    let (engine, _, project_id) = setup().await;

    let result = engine
        .check(&AuthzCheckRequest {
            subject: "not-a-uuid".into(),
            action: "read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_check_invalid_resource() {
    let (engine, _, _) = setup().await;
    let profile_id = ProfileId::generate();

    let result = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "read".into(),
            resource: "not-a-uuid".into(),
            context: HashMap::new(),
        })
        .await;

    assert!(result.is_err());
}

// ── Cedar policy evaluation via engine ────────────────────────

#[tokio::test]
async fn test_check_cedar_permits_when_rbac_denies() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    // No RBAC roles assigned. Cedar policy permits.
    let policy = sid_core::models::CedarPolicy::new(
        project_id,
        "allow_read",
        r#"permit(principal, action == Action::"profiles:read", resource);"#,
        sid_core::models::PolicyEffect::Permit,
    );
    storage
        .create_cedar_policy(&policy, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();

    assert!(resp.is_allowed());
    match resp {
        AuthzCheckResponse::Allow { reason } => {
            assert!(reason.contains("Cedar"));
        }
        _ => panic!("expected Allow"),
    }
}

#[tokio::test]
async fn test_check_disabled_cedar_policy_ignored() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let mut policy = sid_core::models::CedarPolicy::new(
        project_id,
        "allow_read",
        r#"permit(principal, action, resource);"#,
        sid_core::models::PolicyEffect::Permit,
    );
    policy.enabled = false;
    storage
        .create_cedar_policy(&policy, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();

    assert!(!resp.is_allowed());
}

// ── Batch check ──────────────────────────────────────────────

#[tokio::test]
async fn test_batch_check() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "viewer", &["profiles:read"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(&assignment, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let requests = vec![
        AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        },
        AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:delete".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        },
    ];

    let results = engine.batch_check(&requests).await.unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].is_allowed());
    assert!(!results[1].is_allowed());
}

/// A machine user's and an OAuth client's own project roles decide their
/// project checks, as a profile's do; an expired one does not.
#[tokio::test]
async fn test_service_principals_hold_project_roles() {
    let (engine, storage, project_id) = setup().await;
    let role = create_test_role(project_id, "deployer", &["releases:write"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let machine = MachineUserId::generate();
    let expired_machine = MachineUserId::generate();
    for assignment in [
        RoleAssignment::new(RoleAssignmentPrincipal::MachineUser(machine), role.id),
        RoleAssignment::new(RoleAssignmentPrincipal::OAuthClient("ci".into()), role.id),
        RoleAssignment::new(
            RoleAssignmentPrincipal::MachineUser(expired_machine),
            role.id,
        )
        .with_expiry(chrono::Utc::now() - chrono::Duration::seconds(1)),
    ] {
        storage
            .create_role_assignment(&assignment, AuditEntry::system("test", "test").into())
            .await
            .unwrap();
    }
    let check = |subject: String, action: &str| AuthzCheckRequest {
        subject,
        action: action.into(),
        resource: format!("project:{}", project_id.0),
        context: HashMap::new(),
    };

    for subject in [format!("machine:{machine}"), "oauth_client:ci".into()] {
        assert!(
            engine
                .check(&check(subject.clone(), "releases:write"))
                .await
                .unwrap()
                .is_allowed(),
            "{subject}"
        );
        assert!(
            !engine
                .check(&check(subject.clone(), "releases:delete"))
                .await
                .unwrap()
                .is_allowed(),
            "{subject}"
        );
    }
    assert!(
        !engine
            .check(&check(
                format!("machine:{expired_machine}"),
                "releases:write"
            ))
            .await
            .unwrap()
            .is_allowed()
    );
    // Another project's check is not decided by this project's role.
    let mut elsewhere = check(format!("machine:{machine}"), "releases:write");
    elsewhere.resource = format!("project:{}", ProjectId::new().0);
    assert!(!engine.check(&elsewhere).await.unwrap().is_allowed());
}

/// A role held on one protected resource grants nothing project-wide, though
/// the role belongs to the project.
#[tokio::test]
async fn test_resource_role_is_not_a_project_role() {
    let (engine, storage, _) = setup().await;
    let role = Role::token_inspector();
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &RoleAssignment::new(RoleAssignmentPrincipal::OAuthClient("pdp".into()), role.id)
                .on_resource(ResourceId::generate()),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    let project_wide = AuthzCheckRequest {
        subject: "oauth_client:pdp".into(),
        action: TOKEN_INTROSPECT.into(),
        resource: format!("project:{}", ProjectId::system().0),
        context: HashMap::new(),
    };
    assert!(!engine.check(&project_wide).await.unwrap().is_allowed());
}

/// Inspecting tokens and asking about others' permissions belong to service
/// identities only: a Profile or a group holding a role that grants either on
/// a resource (a custom role, or one edited after its assignment) is still
/// refused, while a machine user and an OAuth client with the same role are
/// allowed (D054).
#[tokio::test]
async fn test_service_actions_are_held_by_services_only() {
    let (engine, storage, project_id) = setup().await;
    let role = create_test_role(project_id, "service-like", &[TOKEN_INTROSPECT, AUTHZ_CHECK]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let resource = ResourceId::generate();
    let profile = ProfileId::generate();
    let machine = MachineUserId::generate();
    for principal in [
        RoleAssignmentPrincipal::Profile(profile),
        RoleAssignmentPrincipal::MachineUser(machine),
        RoleAssignmentPrincipal::OAuthClient("orders-pdp".into()),
    ] {
        assign(
            &storage,
            &RoleAssignment::new(principal, role.id).on_resource(resource),
        )
        .await;
    }
    let ask = |subject: String, action: &str| AuthzCheckRequest {
        subject,
        action: action.into(),
        resource: format!("oauth_resource:{resource}"),
        context: HashMap::new(),
    };
    for action in [TOKEN_INTROSPECT, AUTHZ_CHECK] {
        assert!(
            !engine
                .check(&ask(format!("user:{profile}"), action))
                .await
                .unwrap()
                .is_allowed(),
            "a Profile was allowed {action}"
        );
        for service in [
            format!("machine:{machine}"),
            "oauth_client:orders-pdp".into(),
        ] {
            assert!(
                engine
                    .check(&ask(service.clone(), action))
                    .await
                    .unwrap()
                    .is_allowed(),
                "{service} {action}"
            );
        }
    }
}

// ── Token inspection on a protected resource ─────────────────

fn inspect(subject: String, resource: ResourceId) -> AuthzCheckRequest {
    AuthzCheckRequest {
        subject,
        action: TOKEN_INTROSPECT.into(),
        resource: format!("oauth_resource:{resource}"),
        context: HashMap::new(),
    }
}

async fn stored_inspector_role(storage: &MockStorage) -> Role {
    let role = Role::token_inspector();
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    role
}

async fn assign(storage: &MockStorage, assignment: &RoleAssignment) {
    storage
        .create_role_assignment(assignment, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
}

/// The inspector role on resource R lets a machine user and an OAuth client
/// inspect R's tokens, and nothing else: not another resource, not another
/// action, not another principal.
#[tokio::test]
async fn test_inspection_is_scoped_to_the_resource() {
    let (engine, storage, _) = setup().await;
    let role = stored_inspector_role(&storage).await;
    let (orders, wiki) = (ResourceId::generate(), ResourceId::generate());
    let machine = MachineUserId::generate();
    assign(
        &storage,
        &RoleAssignment::new(RoleAssignmentPrincipal::MachineUser(machine), role.id)
            .on_resource(orders),
    )
    .await;
    assign(
        &storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::OAuthClient("orders-pdp".into()),
            role.id,
        )
        .on_resource(orders),
    )
    .await;

    for subject in [
        format!("machine:{machine}"),
        "oauth_client:orders-pdp".into(),
    ] {
        assert!(
            engine
                .check(&inspect(subject.clone(), orders))
                .await
                .unwrap()
                .is_allowed(),
            "{subject}"
        );
        assert!(
            !engine
                .check(&inspect(subject.clone(), wiki))
                .await
                .unwrap()
                .is_allowed(),
            "{subject} on another resource"
        );
        let mut other_action = inspect(subject.clone(), orders);
        other_action.action = "oauth.token.revoke".into();
        assert!(
            !engine.check(&other_action).await.unwrap().is_allowed(),
            "{subject} for another action"
        );
    }
    assert!(
        !engine
            .check(&inspect("oauth_client:other".into(), orders))
            .await
            .unwrap()
            .is_allowed()
    );
    assert!(
        !engine
            .check(&inspect(
                format!("machine:{}", MachineUserId::generate()),
                orders
            ))
            .await
            .unwrap()
            .is_allowed()
    );
}

/// An expired assignment, an assignment scoped to a project, and a Cedar
/// policy of the project grant no inspection of a resource.
#[tokio::test]
async fn test_inspection_needs_a_live_resource_assignment() {
    let (engine, storage, _) = setup().await;
    let role = stored_inspector_role(&storage).await;
    let resource = ResourceId::generate();
    assign(
        &storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::OAuthClient("expired".into()),
            role.id,
        )
        .on_resource(resource)
        .with_expiry(chrono::Utc::now() - chrono::Duration::seconds(1)),
    )
    .await;
    let mut project_wide =
        RoleAssignment::new(RoleAssignmentPrincipal::OAuthClient("wide".into()), role.id);
    project_wide.scope = Some(format!("project:{}", ProjectId::system().0));
    assign(&storage, &project_wide).await;
    assign(
        &storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::OAuthClient("unscoped".into()),
            role.id,
        ),
    )
    .await;
    storage
        .create_cedar_policy(
            &sid_core::models::CedarPolicy::new(
                ProjectId::system(),
                "allow_all",
                "permit(principal, action, resource);",
                sid_core::models::PolicyEffect::Permit,
            ),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();

    for client in ["expired", "wide", "unscoped"] {
        assert!(
            !engine
                .check(&inspect(format!("oauth_client:{client}"), resource))
                .await
                .unwrap()
                .is_allowed(),
            "{client}"
        );
    }
}

// ── Provisioning connectors ──────────────────────────────────

fn scim(subject: String, action: &str, resource: String) -> AuthzCheckRequest {
    AuthzCheckRequest {
        subject,
        action: action.into(),
        resource,
        context: HashMap::new(),
    }
}

/// A connector holding the SCIM provisioner role on its directory resource
/// may provision there, and only there: not on another resource, not for an
/// action outside SCIM even when a role grants it, and never project-wide.
#[tokio::test]
async fn test_connector_is_held_to_scim_on_its_resource() {
    let (engine, storage, project_id) = setup().await;
    let role = Role::scim_provisioner();
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let mut broad = create_test_role(project_id, "broad", &[SCIM_USER_CREATE, "releases:write"]);
    broad.permissions.push(TOKEN_INTROSPECT.into());
    storage
        .create_role(&broad, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let (directory, other) = (ResourceId::generate(), ResourceId::generate());
    let connector = ProvisioningConnectorId::generate();
    assign(
        &storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::ProvisioningConnector(connector),
            role.id,
        )
        .on_resource(directory),
    )
    .await;
    assign(
        &storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::ProvisioningConnector(connector),
            broad.id,
        )
        .on_resource(directory),
    )
    .await;
    // A project-wide grant of the same role must not reach the connector.
    assign(
        &storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::ProvisioningConnector(connector),
            broad.id,
        ),
    )
    .await;

    let subject = format!("provisioning_connector:{connector}");
    let on = |r: ResourceId| format!("oauth_resource:{r}");
    for action in SCIM_ACTIONS {
        assert!(
            engine
                .check(&scim(subject.clone(), action, on(directory)))
                .await
                .unwrap()
                .is_allowed(),
            "{action}"
        );
        assert!(
            !engine
                .check(&scim(subject.clone(), action, on(other)))
                .await
                .unwrap()
                .is_allowed(),
            "{action} on another resource"
        );
    }
    for outside in [TOKEN_INTROSPECT, "releases:write"] {
        assert!(
            !engine
                .check(&scim(subject.clone(), outside, on(directory)))
                .await
                .unwrap()
                .is_allowed(),
            "a connector was allowed {outside}"
        );
    }
    for action in [SCIM_USER_CREATE, "releases:write"] {
        assert!(
            !engine
                .check(&scim(
                    subject.clone(),
                    action,
                    format!("project:{}", project_id.0)
                ))
                .await
                .unwrap()
                .is_allowed(),
            "a connector was allowed {action} project-wide"
        );
    }
    assert!(
        !engine
            .check(&scim(
                format!(
                    "provisioning_connector:{}",
                    ProvisioningConnectorId::generate()
                ),
                SCIM_USER_CREATE,
                on(directory)
            ))
            .await
            .unwrap()
            .is_allowed()
    );
}

#[test]
fn test_parse_subject_connector() {
    let connector = ProvisioningConnectorId::generate();
    assert_eq!(
        CeAuthzEngine::<MockStorage>::parse_subject(&format!("provisioning_connector:{connector}"))
            .unwrap(),
        AuthzPrincipal::ProvisioningConnector(connector)
    );
    assert!(
        CeAuthzEngine::<MockStorage>::parse_subject("provisioning_connector:not-an-id").is_err()
    );
}

#[test]
fn test_parse_subject_oauth_client() {
    assert_eq!(
        CeAuthzEngine::<MockStorage>::parse_subject("oauth_client:orders-pdp").unwrap(),
        AuthzPrincipal::OAuthClient("orders-pdp".into())
    );
    assert!(CeAuthzEngine::<MockStorage>::parse_subject("oauth_client:").is_err());
}

#[tokio::test]
async fn test_malformed_protected_resource_is_an_error() {
    let (engine, _, _) = setup().await;
    let mut request = inspect("oauth_client:x".into(), ResourceId::generate());
    request.resource = "oauth_resource:not-an-id".into();
    assert!(matches!(
        engine.check(&request).await,
        Err(AuthzError::InvalidResource(_))
    ));
}

// ── EE-only methods return NotSupported ──────────────────────

#[tokio::test]
async fn test_list_accessible_objects_not_supported() {
    let (engine, _, _) = setup().await;
    let result = engine
        .list_accessible_objects("user:abc", "read", "project")
        .await;
    assert!(matches!(result, Err(AuthzError::NotSupported(_))));
}

#[tokio::test]
async fn test_list_subjects_not_supported() {
    let (engine, _, _) = setup().await;
    let result = engine
        .list_subjects_with_access("read", "project:abc")
        .await;
    assert!(matches!(result, Err(AuthzError::NotSupported(_))));
}

// ── Object safety ────────────────────────────────────────────

#[tokio::test]
async fn test_engine_as_trait_object() {
    let storage = Arc::new(MockStorage::new());
    let engine: Box<dyn AuthzEngine> = Box::new(CeAuthzEngine::new(storage));
    let project_id = ProjectId::new();
    let profile_id = ProfileId::generate();

    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "read".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();
    assert!(!resp.is_allowed());
}
