use super::*;
use crate::export::export_snapshot;
use sid_core::models::{BindingScope, Profile};
use sid_storage::sqlite::SqliteBackend;

/// A migrated instance gives every pairwise client the `sub` it already
/// holds: the bindings move with their ids, and a second import is a no-op.
#[tokio::test]
async fn service_bindings_survive_migration() {
    let source = SqliteBackend::new_in_memory().await.unwrap();
    let profile = Profile::new(Some("migrating"));
    source
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    let scope = BindingScope::try_from("org-migrating".to_string()).unwrap();
    let before = source
        .service_binding(
            profile.id,
            &scope,
            AuditEntry::system("test", "binding").into(),
        )
        .await
        .unwrap();

    let snapshot = export_snapshot(&source, "sqlite::memory:", false)
        .await
        .unwrap();
    assert_eq!(snapshot.service_bindings.len(), 1);

    let target = SqliteBackend::new_in_memory().await.unwrap();
    let first = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(first.service_bindings, 1);
    let second = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(second.service_bindings, 0, "a repeated import adds nothing");

    let after = target
        .find_service_binding(profile.id, &scope)
        .await
        .unwrap()
        .expect("the binding moved");
    assert_eq!(after.binding_id, before.binding_id);
    assert_eq!(after.binding_index, before.binding_index);
}

/// Store the same installation organization and issuer in `backend`, as a
/// restored installation has them.
async fn provision_issuer(
    backend: &SqliteBackend,
    org: &sid_core::models::Organization,
    issuer: &sid_core::models::OidcIssuer,
) {
    backend
        .insert_instance_organization(org, AuditEntry::system("test", "org").into())
        .await
        .unwrap();
    let key = sid_core::models::IssuerSigningKey {
        issuer_id: issuer.id,
        generation: 1,
        key_id: "kid".into(),
        public_key: [3; 32],
        sealed_private_key: vec![1],
        created_at: issuer.created_at,
    };
    backend
        .insert_oidc_issuer(issuer, &key, AuditEntry::system("test", "issuer").into())
        .await
        .unwrap();
}

/// Applications move with their roles: a resource keeps its id and
/// indicator, a retired one stays retired (its indicator stays reserved), a
/// client keeps its application and default resource, and access moves with
/// its scopes. A second import adds nothing.
#[tokio::test]
async fn applications_resources_and_access_survive_migration() {
    use chrono::{SubsecRound, Utc};
    use sid_core::models::{
        Application, ApplicationId, IssuerAuthority, IssuerHandle, IssuerId, OidcIssuer,
        Organization, ProjectId, ProtectedResource, ResourceAccess, ResourceId, ResourceIndicator,
        ResourceState,
    };

    let org = Organization::implicit_community("sid.example.com");
    let handle = IssuerHandle::generate();
    let now = Utc::now().trunc_subsecs(3);
    let issuer = OidcIssuer {
        id: IssuerId::generate(),
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org.id,
        created_at: now,
    };
    let source = SqliteBackend::new_in_memory().await.unwrap();
    provision_issuer(&source, &org, &issuer).await;
    let ctx = || -> MutationContext { AuditEntry::system("test", "app").into() };
    let app = |name: &str| Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: name.into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = |app: &Application, path: &str| ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: issuer.id,
        indicator: ResourceIndicator::parse(&format!("https://resources.example/{path}")).unwrap(),
        scopes: vec!["orders.read".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };

    let api_app = app("Orders API");
    let api = resource(&api_app, "orders");
    source
        .create_application(&api_app, None, Some(&api), ctx())
        .await
        .unwrap();
    let old_app = app("Old API");
    let old = resource(&old_app, "old");
    source
        .create_application(&old_app, None, Some(&old), ctx())
        .await
        .unwrap();
    source.delete_application(old_app.id, ctx()).await.unwrap();

    let web_app = app("Web");
    let mut web = client_for(&web_app);
    web.org_id = Some(org.id);
    source
        .create_application(&web_app, Some(&web), None, ctx())
        .await
        .unwrap();
    let access = ResourceAccess {
        client_id: web.client_id.clone(),
        resource_id: api.id,
        scopes: vec!["orders.read".into()],
        created_at: now,
    };
    source.set_resource_access(&access, ctx()).await.unwrap();
    web.default_resource = Some(api.id);
    assert!(source.update_oauth2_client(&web, ctx()).await.unwrap());

    // A machine user calling the API, with a credential, and the token
    // inspector role held by the machine and by the web client.
    use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential, OwnerType};
    use sid_core::models::{MachineUser, Role, RoleAssignment, RoleAssignmentPrincipal};
    source.ensure_system_project(ctx()).await.unwrap();
    let ci = MachineUser::new(ProjectId::system(), "ci", "CI", OwnerType::System, "system");
    source.create_machine_user(&ci, ctx()).await.unwrap();
    source
        .add_machine_credential(
            &MachineUserCredential::new(ci.id, "kid-ci", MachineCredentialType::ClientSecret, "h"),
            None,
            ctx(),
        )
        .await
        .unwrap();
    let ci_access = ResourceAccess {
        client_id: ci.client_id.clone(),
        resource_id: api.id,
        scopes: vec!["orders.read".into()],
        created_at: now,
    };
    source.set_resource_access(&ci_access, ctx()).await.unwrap();
    let inspector = Role::token_inspector();
    source.create_role(&inspector, ctx()).await.unwrap();
    let assignments = [
        RoleAssignment::new(RoleAssignmentPrincipal::MachineUser(ci.id), inspector.id)
            .on_resource(api.id),
        RoleAssignment::new(
            RoleAssignmentPrincipal::OAuthClient(web.client_id.clone()),
            inspector.id,
        )
        .on_resource(api.id),
    ];
    for assignment in &assignments {
        source
            .create_role_assignment(assignment, ctx())
            .await
            .unwrap();
    }

    let snapshot = export_snapshot(&source, "sqlite::memory:", false)
        .await
        .unwrap();
    assert_eq!(snapshot.applications.len(), 2);
    assert_eq!(snapshot.protected_resources.len(), 2);
    assert_eq!(snapshot.resource_access.len(), 2);
    assert_eq!(snapshot.role_assignments.len(), 2);

    let target = SqliteBackend::new_in_memory().await.unwrap();
    provision_issuer(&target, &org, &issuer).await;
    let first = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(first.applications, 2);
    assert_eq!(first.protected_resources, 2);
    assert_eq!(first.oauth2_clients, 1);
    assert_eq!(first.resource_access, 2);
    assert_eq!(first.role_assignments, 2);
    let second = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(
        (
            second.applications,
            second.protected_resources,
            second.oauth2_clients,
            second.resource_access,
            second.machine_users,
            second.machine_credentials,
            second.role_assignments,
        ),
        (0, 0, 0, 0, 0, 0, 0),
        "a repeated import adds nothing"
    );
    assert!(
        target
            .resource_access(&ci.client_id, api.id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        target
            .list_role_assignments_for_oauth_client(&web.client_id)
            .await
            .unwrap()[0]
            .resource_scope(),
        Some(api.id)
    );
    assert_eq!(
        target
            .list_role_assignments_for_machine_user(ci.id)
            .await
            .unwrap()[0]
            .id,
        assignments[0].id
    );

    assert_eq!(
        target.get_protected_resource(api.id).await.unwrap(),
        Some(api.clone())
    );
    let retired = target
        .get_protected_resource(old.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.state, ResourceState::Retired);
    assert_eq!(retired.application_id, None);
    let moved = target
        .get_oauth2_client(&web.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(moved.application_id, web_app.id);
    assert_eq!(moved.default_resource, Some(api.id));
    assert_eq!(
        target
            .resource_access(&web.client_id, api.id)
            .await
            .unwrap()
            .unwrap()
            .scopes,
        access.scopes
    );
}

/// A client role of `app`, as an administrator registers one.
fn client_for(app: &sid_core::models::Application) -> sid_core::models::OAuth2Client {
    use sid_core::models::*;
    OAuth2Client {
        client_id: format!("client-{}", app.id),
        project_id: app.project_id,
        application_id: app.id,
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/cb".into()],
        allowed_scopes: vec!["openid".into()],
        grant_types: vec!["authorization_code".into()],
        client_name: app.name.clone(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: app.created_at,
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: None,
        revision: 0,
        created_at: app.created_at,
    }
}

/// A keyed command completed before a migration is still completed after it:
/// the retry finds the recorded result and executes nothing on the target.
#[tokio::test]
async fn operation_results_survive_migration() {
    use sid_core::models::{OperationCompletion, OperationKey, Project};

    let source = SqliteBackend::new_in_memory().await.unwrap();
    let key = OperationKey::parse("create-project-1").unwrap();
    let completion = OperationCompletion::new(
        "profile:p",
        key.clone(),
        "sid.v1.ProjectService/CreateProject",
        b"inputs",
        b"result".to_vec(),
    );
    let ctx: MutationContext = AuditEntry::system("test", "project").into();
    source
        .create_project(
            &Project::new("before".to_string(), None),
            ctx.with_operation(completion.clone()),
        )
        .await
        .unwrap();

    let snapshot = export_snapshot(&source, "sqlite::memory:", false)
        .await
        .unwrap();
    assert_eq!(snapshot.operation_results.len(), 1);

    let target = SqliteBackend::new_in_memory().await.unwrap();
    let first = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(first.operation_results, 1);
    let second = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(
        second.operation_results, 0,
        "a repeated import adds nothing"
    );

    let moved = target
        .get_operation_result("profile:p", &key)
        .await
        .unwrap()
        .expect("the completion moved");
    assert_eq!(moved.completion, completion);
    assert_eq!(
        moved.completed_at,
        snapshot.operation_results[0].completed_at
    );

    let retry: MutationContext = AuditEntry::system("test", "project").into();
    let refused = target
        .create_project(
            &Project::new("retry".to_string(), None),
            retry.with_operation(completion),
        )
        .await;
    assert!(
        matches!(refused, Err(sid_core::Error::OperationCompleted(_))),
        "{refused:?}"
    );
}

/// Administrative assignments move with their envelope and provenance, and
/// a redelegated one imports after the assignment it depends on wherever
/// the snapshot lists it (the export walks profiles, not dependencies).
#[tokio::test]
async fn administrative_assignments_survive_migration() {
    use sid_core::models::{
        AdminEnvelope, AdminOperation, AssignmentProvenance, ProjectId, RecipientKind, Role,
        RoleAssignment, RoleAssignmentPrincipal,
    };

    let source = SqliteBackend::new_in_memory().await.unwrap();
    let ctx = || -> MutationContext { AuditEntry::system("test", "admin").into() };
    source.ensure_system_project(ctx()).await.unwrap();
    let mut working = Role::new(ProjectId::system(), "editor", "Editor");
    working.permissions = vec!["documents:read".into()];
    source.create_role(&working, ctx()).await.unwrap();
    let administrator = Role::new(ProjectId::system(), "admins", "Admins");
    source.create_role(&administrator, ctx()).await.unwrap();
    let mut holders = Vec::new();
    for name in ["root-holder", "delegate", "worker"] {
        let profile = Profile::new(Some(name));
        source.create_profile(&profile, ctx()).await.unwrap();
        holders.push(profile.id);
    }

    let envelope = AdminEnvelope {
        operations: [AdminOperation::Assign, AdminOperation::Redelegate].into(),
        roles: [working.id].into(),
        permission_ceiling: ["documents:read".to_string()].into(),
        recipient_kinds: [RecipientKind::Profile].into(),
        recipient_group: None,
        max_validity_secs: 86_400,
    };
    let root = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(holders[0]),
        administrator.id,
    )
    .administering(envelope.clone())
    .granted(AssignmentProvenance {
        granted_by: "user:admin".into(),
        basis: None,
        depends_on: None,
        ceiling: None,
    });
    let mut narrower = envelope.clone();
    narrower.operations = [AdminOperation::Assign].into();
    let delegated = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(holders[1]),
        administrator.id,
    )
    .administering(narrower)
    .granted(AssignmentProvenance {
        granted_by: format!("user:{}", holders[0]),
        basis: Some(root.id),
        depends_on: Some(root.id),
        ceiling: None,
    });
    // A working grant made under the root envelope keeps its ceiling.
    let worked = RoleAssignment::new(RoleAssignmentPrincipal::Profile(holders[2]), working.id)
        .granted(AssignmentProvenance {
            granted_by: format!("user:{}", holders[0]),
            basis: Some(root.id),
            depends_on: None,
            ceiling: Some(envelope.permission_ceiling.clone()),
        });
    for assignment in [&root, &delegated, &worked] {
        source
            .create_role_assignment(assignment, ctx())
            .await
            .unwrap();
    }

    let mut snapshot = export_snapshot(&source, "sqlite::memory:", false)
        .await
        .unwrap();
    assert_eq!(snapshot.role_assignments.len(), 3);
    // The dependent first, as the export may list it.
    snapshot
        .role_assignments
        .sort_by_key(|a| a.provenance.as_ref().and_then(|p| p.depends_on).is_none());

    let target = SqliteBackend::new_in_memory().await.unwrap();
    let first = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(first.role_assignments, 3);
    let second = import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(second.role_assignments, 0, "a repeated import adds nothing");

    for original in [&root, &delegated, &worked] {
        let moved = target
            .get_role_assignment(original.id)
            .await
            .unwrap()
            .expect("the assignment moved");
        assert_eq!(moved.admin, original.admin);
        assert_eq!(moved.provenance, original.provenance);
    }

    // The dependency moved too: ending the source ends the redelegation.
    target.delete_role_assignment(root.id, ctx()).await.unwrap();
    assert!(
        target
            .get_role_assignment(delegated.id)
            .await
            .unwrap()
            .is_none()
    );
}

/// A snapshot whose assignments depend on each other in a cycle cannot have
/// come from a store; it is refused instead of imported in some order.
#[test]
fn a_dependency_cycle_is_refused() {
    use sid_core::models::{AssignmentProvenance, RoleAssignment, RoleAssignmentPrincipal, RoleId};
    let profile = Profile::new(Some("cycle")).id;
    let mut first = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile), RoleId::new());
    let second = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile), RoleId::new())
        .granted(AssignmentProvenance {
            granted_by: "user:a".into(),
            basis: Some(first.id),
            depends_on: Some(first.id),
            ceiling: None,
        });
    first = first.granted(AssignmentProvenance {
        granted_by: "user:b".into(),
        basis: Some(second.id),
        depends_on: Some(second.id),
        ceiling: None,
    });
    let err = sources_first(&[first, second]).expect_err("a cycle");
    assert!(err.to_string().contains("cycle"), "{err}");
}
