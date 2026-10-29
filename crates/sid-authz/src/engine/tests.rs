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

// ── RBAC checks ──────────────────────────────────────────────

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
        sid_core::models::PolicyScope::Project(project_id),
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
        sid_core::models::PolicyScope::Project(project_id),
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

/// An explicit Cedar `forbid` applies to a subject whatever role it holds:
/// a role grant is a permission, not an exemption from the project's
/// prohibitions. The same role without the forbid still allows, and a
/// forbid on another action leaves the granted one allowed.
#[tokio::test]
async fn test_explicit_forbid_overrides_a_role_grant() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();
    let role = create_test_role(project_id, "editor", &["profiles:read", "profiles:write"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    let ask = |action: &str| AuthzCheckRequest {
        subject: format!("user:{profile_id}"),
        action: action.into(),
        resource: format!("project:{}", project_id.0),
        context: HashMap::new(),
    };
    assert!(
        engine
            .check(&ask("profiles:write"))
            .await
            .unwrap()
            .is_allowed()
    );

    let forbid = sid_core::models::CedarPolicy::new(
        sid_core::models::PolicyScope::Project(project_id),
        "no_writes",
        r#"forbid(principal, action == Action::"profiles:write", resource);"#,
        sid_core::models::PolicyEffect::Forbid,
    );
    storage
        .create_cedar_policy(&forbid, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    let refused = engine.check(&ask("profiles:write")).await.unwrap();
    assert!(
        !refused.is_allowed(),
        "a role grant bypassed a forbid: {refused:?}"
    );
    assert!(refused.reason().contains("forbid"), "{refused:?}");
    assert!(
        engine
            .check(&ask("profiles:read"))
            .await
            .unwrap()
            .is_allowed(),
        "a forbid on another action"
    );
}

/// A policy set that cannot be evaluated denies, even where a role grants:
/// the broken policy might be the prohibition that applies.
#[tokio::test]
async fn test_an_unevaluable_policy_set_denies_a_role_grant() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();
    let role = create_test_role(project_id, "editor", &["profiles:write"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    storage
        .create_cedar_policy(
            &sid_core::models::CedarPolicy::new(
                sid_core::models::PolicyScope::Project(project_id),
                "broken",
                "forbid(principal, action, resource) when { nonsense",
                sid_core::models::PolicyEffect::Forbid,
            ),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    let decision = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:write".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();
    assert!(!decision.is_allowed(), "{decision:?}");
}

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
    let resource = storage.register_resource(Some(project_id));
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

/// The invite actions are held by a machine user only: a Profile, a group
/// member or an OAuth client given the same role on the enrollment resource
/// is refused, as the invite RPCs refuse them, so a permission answer never
/// says Allow for a caller the receiver turns away.
#[tokio::test]
async fn test_invite_actions_are_held_by_machine_users_only() {
    let (engine, storage, project_id) = setup().await;
    let role = create_test_role(project_id, "invite-like", &INVITE_ACTIONS);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let resource = storage.register_resource(Some(project_id));
    let profile = ProfileId::generate();
    let machine = MachineUserId::generate();
    for principal in [
        RoleAssignmentPrincipal::Profile(profile),
        RoleAssignmentPrincipal::MachineUser(machine),
        RoleAssignmentPrincipal::OAuthClient("onboarding".into()),
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
    for action in INVITE_ACTIONS {
        for refused in [format!("user:{profile}"), "oauth_client:onboarding".into()] {
            assert!(
                !engine
                    .check(&ask(refused.clone(), action))
                    .await
                    .unwrap()
                    .is_allowed(),
                "{refused} was allowed {action}"
            );
        }
        assert!(
            engine
                .check(&ask(format!("machine:{machine}"), action))
                .await
                .unwrap()
                .is_allowed(),
            "machine {action}"
        );
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
    let (orders, wiki) = (
        storage.register_resource(Some(ProjectId::system())),
        storage.register_resource(Some(ProjectId::system())),
    );
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
/// policy of the resource's own project, which applies to it, grant no
/// inspection of a resource.
#[tokio::test]
async fn test_inspection_needs_a_live_resource_assignment() {
    let (engine, storage, _) = setup().await;
    let role = stored_inspector_role(&storage).await;
    let resource = storage.register_resource(Some(ProjectId::system()));
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
                sid_core::models::PolicyScope::Project(ProjectId::system()),
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
    let (directory, other) = (
        storage.register_resource(Some(project_id)),
        storage.register_resource(Some(project_id)),
    );
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

// ── Failure and scope ────────────────────────────────────────

/// A granted role in `project_id` for a fresh Profile, stored in `storage`.
async fn granted(storage: &MockStorage, project_id: ProjectId, action: &str) -> ProfileId {
    let profile_id = ProfileId::generate();
    let role = create_test_role(project_id, "editor", &[action]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    profile_id
}

// A check whose reads fail answers an error, never an allow: a store that
// cannot say what is granted grants nothing.
#[tokio::test]
async fn test_unreachable_storage_never_allows() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = granted(&storage, project_id, "profiles:read").await;
    let request = AuthzCheckRequest {
        subject: format!("user:{profile_id}"),
        action: "profiles:read".into(),
        resource: format!("project:{}", project_id.0),
        context: HashMap::new(),
    };
    assert!(engine.check(&request).await.unwrap().is_allowed());

    storage
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        engine.check(&request).await,
        Err(AuthzError::Storage(_))
    ));
}

// A role grants only in its own project: the same action on another
// project is denied.
#[tokio::test]
async fn test_a_role_grants_only_in_its_project() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = granted(&storage, project_id, "profiles:read").await;
    let other = ProjectId::new();
    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:read".into(),
            resource: format!("project:{}", other.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();
    assert!(!resp.is_allowed());
}

/// Store `text` as an enabled Cedar policy of `project_id`.
async fn stored_policy(
    storage: &MockStorage,
    project_id: ProjectId,
    text: &str,
    effect: sid_core::models::PolicyEffect,
) {
    storage
        .create_cedar_policy(
            &sid_core::models::CedarPolicy::new(
                sid_core::models::PolicyScope::Project(project_id),
                "policy",
                text,
                effect,
            ),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
}

// Regression: a forbid whose condition fails to evaluate at runtime (it
// reads a context attribute the request lacks) is skipped by Cedar, which
// answers without an error; the role grant then allowed. A policy set that
// cannot be evaluated denies, at runtime as at parse time.
#[tokio::test]
async fn test_a_forbid_failing_at_runtime_denies_a_role_grant() {
    let (engine, storage, project_id) = setup().await;
    let profile_id = granted(&storage, project_id, "profiles:write").await;
    stored_policy(
        &storage,
        project_id,
        r#"forbid(principal, action, resource) when { context.network == "untrusted" };"#,
        sid_core::models::PolicyEffect::Forbid,
    )
    .await;
    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("user:{profile_id}"),
            action: "profiles:write".into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();
    assert!(!resp.is_allowed(), "{resp:?}");
}

// Regression: an OAuth client id or an action holding a quote or a
// backslash was interpolated into a Cedar entity literal, which then failed
// to parse, and the fail-closed branch denied the client's role grant. The
// entities are built from their components, so the grant applies.
#[tokio::test]
async fn test_identifiers_with_quotes_reach_the_policies_intact() {
    let (engine, storage, project_id) = setup().await;
    let client = r#"orders"pdp\v2"#;
    let action = r#"orders:"read""#;
    let role = create_test_role(project_id, "reader", &[action]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &RoleAssignment::new(RoleAssignmentPrincipal::OAuthClient(client.into()), role.id),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    // A project policy, so the decision goes through Cedar.
    stored_policy(
        &storage,
        project_id,
        r#"forbid(principal, action == Action::"orders:delete", resource);"#,
        sid_core::models::PolicyEffect::Forbid,
    )
    .await;
    let resp = engine
        .check(&AuthzCheckRequest {
            subject: format!("oauth_client:{client}"),
            action: action.into(),
            resource: format!("project:{}", project_id.0),
            context: HashMap::new(),
        })
        .await
        .unwrap();
    assert!(resp.is_allowed(), "{resp:?}");
}

// ── Scoped policies on a protected resource ──────────────────

/// A resource of an application of a project, with a user holding a role
/// that grants `orders.cancel` on it.
struct Granted {
    engine: CeAuthzEngine<MockStorage>,
    storage: Arc<MockStorage>,
    project: ProjectId,
    resource: ResourceId,
    user: ProfileId,
}

async fn granted_on_resource() -> Granted {
    let (engine, storage, project) = setup().await;
    let role = create_test_role(project, "canceller", &["orders.cancel"]);
    storage
        .create_role(&role, AuditEntry::system("test", "test").into())
        .await
        .unwrap();
    let resource = storage.register_resource(Some(project));
    let user = ProfileId::generate();
    assign(
        &storage,
        &RoleAssignment::new(RoleAssignmentPrincipal::Profile(user), role.id).on_resource(resource),
    )
    .await;
    Granted {
        engine,
        storage,
        project,
        resource,
        user,
    }
}

impl Granted {
    async fn policy(&self, scope: PolicyScope, effect: PolicyEffect, text: &str) {
        self.storage
            .create_cedar_policy(
                &CedarPolicy::new(
                    scope,
                    format!("p-{}", Uuid::now_v7().simple()),
                    text,
                    effect,
                ),
                AuditEntry::system("test", "test").into(),
            )
            .await
            .unwrap();
    }

    /// The decision on the user cancelling `object` on the resource.
    async fn cancels(&self, object: &str) -> bool {
        self.decide(self.user, object).await
    }

    async fn decide(&self, user: ProfileId, object: &str) -> bool {
        let mut context = HashMap::new();
        if !object.is_empty() {
            context.insert("object".to_owned(), object.to_owned());
        }
        self.engine
            .check(&AuthzCheckRequest {
                subject: format!("user:{user}"),
                action: "orders.cancel".into(),
                resource: format!("oauth_resource:{}", self.resource),
                context,
            })
            .await
            .unwrap()
            .is_allowed()
    }
}

const FORBID_ALL: &str = "forbid(principal, action, resource);";
const PERMIT_ALL: &str = "permit(principal, action, resource);";

/// Regression: a protected resource's decision used only its role
/// assignments, so an assigned user bypassed any prohibition by taking the
/// resource route. A `forbid` of the installation, of the resource's parent
/// project or of the resource itself now denies the live grant; without it
/// the grant works.
#[tokio::test]
async fn a_resource_grant_is_denied_by_a_forbid_at_every_applicable_scope() {
    let baseline = granted_on_resource().await;
    assert!(baseline.cancels("order:1").await, "the grant alone allows");
    let installation = granted_on_resource().await;
    installation
        .policy(PolicyScope::Installation, PolicyEffect::Forbid, FORBID_ALL)
        .await;
    assert!(
        !installation.cancels("order:1").await,
        "installation forbid"
    );

    let project = granted_on_resource().await;
    project
        .policy(
            PolicyScope::Project(project.project),
            PolicyEffect::Forbid,
            FORBID_ALL,
        )
        .await;
    assert!(!project.cancels("order:1").await, "parent project forbid");

    let resource = granted_on_resource().await;
    resource
        .policy(
            PolicyScope::Resource(resource.resource),
            PolicyEffect::Forbid,
            FORBID_ALL,
        )
        .await;
    assert!(!resource.cancels("order:1").await, "resource forbid");
}

/// A resource policy restricting the object of the action denies that
/// object and leaves another allowed: the object the receiver names reaches
/// the policies as `context.object`.
#[tokio::test]
async fn a_resource_forbid_on_one_object_denies_only_that_object() {
    let g = granted_on_resource().await;
    g.policy(
        PolicyScope::Resource(g.resource),
        PolicyEffect::Forbid,
        r#"forbid(principal, action, resource) when { context has object && context.object == "order:foreign" };"#,
    )
    .await;
    assert!(!g.cancels("order:foreign").await, "the restricted object");
    assert!(g.cancels("order:own").await, "another object");
}

/// A permit cannot override a prohibition inherited from a wider scope.
#[tokio::test]
async fn a_local_permit_does_not_override_an_inherited_forbid() {
    let g = granted_on_resource().await;
    g.policy(PolicyScope::Installation, PolicyEffect::Forbid, FORBID_ALL)
        .await;
    g.policy(
        PolicyScope::Resource(g.resource),
        PolicyEffect::Permit,
        PERMIT_ALL,
    )
    .await;
    assert!(!g.cancels("order:1").await);
}

/// A forbid of another project or of another resource does not reach this
/// resource's decision.
#[tokio::test]
async fn an_unrelated_projects_or_resources_policy_has_no_effect() {
    let g = granted_on_resource().await;
    let other_resource = g.storage.register_resource(Some(ProjectId::new()));
    g.policy(
        PolicyScope::Project(ProjectId::new()),
        PolicyEffect::Forbid,
        FORBID_ALL,
    )
    .await;
    g.policy(
        PolicyScope::Resource(other_resource),
        PolicyEffect::Forbid,
        FORBID_ALL,
    )
    .await;
    assert!(g.cancels("order:1").await);
}

/// A broad permit allows an ordinary action without a role, but never token
/// inspection or permission checking, which need their own live assignment
/// on the exact resource.
#[tokio::test]
async fn a_broad_permit_does_not_replace_a_mandatory_assignment() {
    let g = granted_on_resource().await;
    g.policy(PolicyScope::Installation, PolicyEffect::Permit, PERMIT_ALL)
        .await;
    assert!(
        g.decide(ProfileId::generate(), "order:1").await,
        "an ordinary action by permit"
    );
    for action in [TOKEN_INTROSPECT, AUTHZ_CHECK] {
        let allowed = g
            .engine
            .check(&AuthzCheckRequest {
                subject: "oauth_client:anyone".into(),
                action: action.into(),
                resource: format!("oauth_resource:{}", g.resource),
                context: HashMap::new(),
            })
            .await
            .unwrap()
            .is_allowed();
        assert!(!allowed, "{action} by permit alone");
    }
}

/// A policy that cannot be evaluated might be the prohibition that applies:
/// the grant is denied.
#[tokio::test]
async fn an_unevaluable_resource_policy_denies() {
    let g = granted_on_resource().await;
    g.policy(
        PolicyScope::Resource(g.resource),
        PolicyEffect::Forbid,
        r#"forbid(principal, action, resource) when { context.missing == "x" };"#,
    )
    .await;
    assert!(!g.cancels("order:1").await);
}

/// A resource that is not registered, or whose registration names an
/// application that does not exist, refuses the decision: it cannot select a
/// smaller policy set.
#[tokio::test]
async fn a_resource_without_a_consistent_registration_refuses_the_decision() {
    let g = granted_on_resource().await;
    let ask = |resource: ResourceId| AuthzCheckRequest {
        subject: format!("user:{}", g.user),
        action: "orders.cancel".into(),
        resource: format!("oauth_resource:{resource}"),
        context: HashMap::new(),
    };
    assert!(matches!(
        g.engine.check(&ask(ResourceId::generate())).await,
        Err(AuthzError::InvalidResource(_))
    ));
    g.storage.applications.lock().unwrap().clear();
    assert!(matches!(
        g.engine.check(&ask(g.resource)).await,
        Err(AuthzError::InvalidResource(_))
    ));
}

// ── Installation administrator ───────────────────────────────

/// A Profile holding the installation administrator role across the
/// installation, and one holding nothing, with a project and a protected
/// resource neither has another role on.
struct Administered {
    engine: CeAuthzEngine<MockStorage>,
    storage: Arc<MockStorage>,
    project: ProjectId,
    resource: ResourceId,
    admin: ProfileId,
    other: ProfileId,
}

async fn administered() -> Administered {
    let (engine, storage, project) = setup().await;
    storage
        .create_role(
            &Role::installation_administrator(),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    let resource = storage.register_resource(Some(project));
    let admin = ProfileId::generate();
    assign(
        &storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(admin),
            Role::installation_administrator().id,
        )
        .on_installation(),
    )
    .await;
    Administered {
        engine,
        storage,
        project,
        resource,
        admin,
        other: ProfileId::generate(),
    }
}

impl Administered {
    async fn on_project(&self, user: ProfileId, action: &str) -> bool {
        self.engine
            .check(&AuthzCheckRequest {
                subject: format!("user:{user}"),
                action: action.into(),
                resource: format!("project:{}", self.project.0),
                context: HashMap::new(),
            })
            .await
            .unwrap()
            .is_allowed()
    }

    async fn on_resource(&self, user: ProfileId, action: &str) -> bool {
        self.engine
            .check(&AuthzCheckRequest {
                subject: format!("user:{user}"),
                action: action.into(),
                resource: format!("oauth_resource:{}", self.resource),
                context: HashMap::new(),
            })
            .await
            .unwrap()
            .is_allowed()
    }
}

/// Regression: the installation's administrator was a string in the
/// Profile's roles that no decision read, so it held nothing on a project or
/// a protected resource. The installation-wide administrator assignment now
/// allows any action on both, with no other role; without it the same
/// actions are denied.
#[tokio::test]
async fn the_installation_administrator_holds_every_action() {
    let a = administered().await;
    for action in ["profiles.write", "ops.org.suspend", "orders.cancel"] {
        assert!(a.on_project(a.admin, action).await, "project {action}");
        assert!(a.on_resource(a.admin, action).await, "resource {action}");
        assert!(
            !a.on_project(a.other, action).await,
            "other project {action}"
        );
        assert!(
            !a.on_resource(a.other, action).await,
            "other resource {action}"
        );
    }
}

/// The administrator role counts only as an installation-wide assignment:
/// held on one resource it grants that resource's actions no more than any
/// other role would, and an expired assignment grants nothing.
#[tokio::test]
async fn only_a_live_installation_wide_assignment_administers() {
    let a = administered().await;
    let scoped = ProfileId::generate();
    assign(
        &a.storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(scoped),
            Role::installation_administrator().id,
        )
        .on_resource(a.resource),
    )
    .await;
    assert!(!a.on_project(scoped, "profiles.write").await);
    assert!(!a.on_resource(scoped, "orders.cancel").await);

    let expired = ProfileId::generate();
    assign(
        &a.storage,
        &RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(expired),
            Role::installation_administrator().id,
        )
        .on_installation()
        .with_expiry(chrono::Utc::now() - chrono::Duration::seconds(1)),
    )
    .await;
    assert!(!a.on_project(expired, "profiles.write").await);
    assert!(!a.on_resource(expired, "orders.cancel").await);
}

/// The administrator is still subject to the installation's prohibitions: an
/// applicable `forbid` denies it on a project and on a protected resource.
#[tokio::test]
async fn a_forbid_denies_the_installation_administrator() {
    let a = administered().await;
    a.storage
        .create_cedar_policy(
            &CedarPolicy::new(
                PolicyScope::Installation,
                "no-one",
                FORBID_ALL,
                PolicyEffect::Forbid,
            ),
            AuditEntry::system("test", "test").into(),
        )
        .await
        .unwrap();
    assert!(!a.on_project(a.admin, "profiles.write").await);
    assert!(!a.on_resource(a.admin, "orders.cancel").await);
}

/// Actions held only by services stay refused to the administrator Profile:
/// token inspection, permission checks and invites are not a human's to
/// exercise, whatever its authority.
#[tokio::test]
async fn service_actions_stay_refused_to_the_administrator() {
    let a = administered().await;
    for action in [TOKEN_INTROSPECT, AUTHZ_CHECK, INVITE_CREATE] {
        assert!(
            !a.on_resource(a.admin, action).await,
            "the administrator was allowed {action}"
        );
    }
}

// ── Over an erased store ─────────────────────────────────────

// The engine decides the same over a store held as `dyn StorageBackend`, as
// the services compose it.
#[tokio::test]
async fn test_engine_over_a_dyn_store() {
    let storage: Arc<dyn sid_plugin::StorageBackend> = Arc::new(MockStorage::new());
    let engine = CeAuthzEngine::new(storage);
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
