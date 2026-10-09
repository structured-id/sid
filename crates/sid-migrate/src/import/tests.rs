use super::*;
use crate::export::export_snapshot;
use sid_core::models::{BindingScope, Profile};
use sid_storage::sqlite::SqliteBackend;

/// Moving credentials must also move the history that prevents password reuse.
/// A prepared epoch alone is nonempty durable state, even before its first entry.
#[tokio::test]
async fn password_history_survives_migration() {
    use sid_core::models::{
        HistoryEpoch, HistoryEpochId, HistoryEpochUse, HistoryKsf, HistorySuite, NewHistoryEpoch,
        WrappedHistoryKey,
    };
    let source = SqliteBackend::new_in_memory().await.unwrap();
    let profile = Profile::new(Some("history-migration"));
    let ctx = || AuditEntry::system("test", "history").into();
    source.create_profile(&profile, ctx()).await.unwrap();
    let id = HistoryEpochId::generate();
    let epoch = NewHistoryEpoch {
        epoch: HistoryEpoch {
            id,
            owner: profile.id,
            suite: HistorySuite::PallasPoseidonV1,
            public_key: [3; 32],
            ksf: HistoryKsf::DEFAULT,
            ksf_salt: [4; 32],
            status: HistoryEpochUse::Active,
            created_at: chrono::DateTime::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis(),
            )
            .unwrap(),
        },
        key: WrappedHistoryKey(
            sid_keys::EncryptedField {
                key_version: 1,
                nonce: [0; 12],
                context: format!("password-history-key:{}:{}", id.0, profile.id),
                ciphertext: vec![5; 48],
            }
            .to_bytes(),
        ),
    };
    source
        .insert_key_version(
            &sid_keys::KeyVersionParams::new(1, vec![1; 16], "key-v1"),
            ctx(),
        )
        .await
        .unwrap();
    source.ensure_history_epoch(&epoch, ctx()).await.unwrap();
    let password = sid_core::models::Credential::new(
        profile.id,
        sid_core::models::CredentialType::Opaque,
        b"before".to_vec(),
        None,
    );
    source.create_credential(&password, ctx()).await.unwrap();
    let mut changed = password.clone();
    changed.data = sid_core::models::CredentialData::new(b"after".to_vec());
    let commit = sid_core::models::HistoryCommit {
        owner: profile.id,
        expected_revision: source
            .get_password_history(profile.id)
            .await
            .unwrap()
            .revision,
        new_epoch: None,
        entries: vec![(epoch.epoch.id, [9; 32])],
        evidence: sid_core::models::HistoryEvidence {
            operation: uuid::Uuid::now_v7(),
            policy_version: 1,
        },
        depth: 24,
    };
    assert!(
        source
            .change_password(password.id, b"before", &changed, Some(&commit), ctx())
            .await
            .unwrap()
    );
    let before = source.get_password_history(profile.id).await.unwrap();
    let snapshot = export_snapshot(&source, "sqlite::memory:", false)
        .await
        .unwrap();
    let target = SqliteBackend::new_in_memory().await.unwrap();
    import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(
        target.get_password_history(profile.id).await.unwrap(),
        before
    );
    assert_eq!(
        target.get_history_epoch_key(epoch.epoch.id).await.unwrap(),
        Some(epoch.key.clone())
    );
    import_snapshot(&target, &snapshot).await.unwrap();
    assert_eq!(
        target.get_password_history(profile.id).await.unwrap(),
        before
    );
    let mut corrupted = snapshot.clone();
    corrupted.password_histories[0].1.as_mut().unwrap().entries[0].entry = [10; 32];
    assert!(import_snapshot(&target, &corrupted).await.is_err());
    assert_eq!(
        target.get_password_history(profile.id).await.unwrap(),
        before
    );
    assert_eq!(
        target
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"after"
    );
    let blank = SqliteBackend::new_in_memory().await.unwrap();
    corrupted.password_histories.clear();
    assert!(import_snapshot(&blank, &corrupted).await.is_err());
    assert_eq!(blank.count_profiles().await.unwrap(), 0);
    assert!(
        crate::verify::verify_backends(&source, &target)
            .await
            .unwrap()
            .passed
    );
    // Equal counts are insufficient: a different target profile must not hide
    // the complete loss of the source owner's nonempty history.
    let wrong = SqliteBackend::new_in_memory().await.unwrap();
    wrong
        .create_profile(&Profile::new(Some("wrong-history-owner")), ctx())
        .await
        .unwrap();
    for params in &snapshot.key_versions {
        wrong.insert_key_version(params, ctx()).await.unwrap();
    }
    assert!(
        !crate::verify::verify_backends(&source, &wrong)
            .await
            .unwrap()
            .passed
    );
}

/// History input domains include the installation organization: importing
/// under a different organization would make retained passwords incomparable.
#[tokio::test]
async fn history_transfer_refuses_a_different_authority() {
    let source = SqliteBackend::new_in_memory().await.unwrap();
    let ctx = || AuditEntry::system("test", "authority").into();
    let org = sid_core::models::Organization::implicit_community("source.example.com");
    source
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    let profile = Profile::new(Some("authority-transfer"));
    source.create_profile(&profile, ctx()).await.unwrap();
    let snapshot = export_snapshot(&source, "sqlite::memory:", false)
        .await
        .unwrap();
    let target = SqliteBackend::new_in_memory().await.unwrap();
    let other = sid_core::models::Organization::implicit_community("other.example.com");
    target
        .insert_instance_organization(&other, ctx())
        .await
        .unwrap();
    assert!(import_snapshot(&target, &snapshot).await.is_err());
    assert_eq!(target.count_profiles().await.unwrap(), 0);
}

/// The DB archive preserves sealed random key material and public derivation
/// metadata; restoring the independent master key opens the original secret,
/// while a different master key cannot silently create substitute history.
#[tokio::test]
async fn history_key_restore_requires_the_original_external_key() {
    use sid_core::models::*;
    use sid_keys::{KeyManager, KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};
    use std::sync::Arc;
    let params = KeyVersionParams::new(1, vec![7; 16], "restore-key-v1");
    let manager = |master| {
        SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new(master)),
            vec![params.clone()],
            Arc::new(RustCryptoPrimitives::new()),
        )
        .unwrap()
    };
    let keys = manager([9u8; 32]);
    let source = SqliteBackend::new_in_memory().await.unwrap();
    let ctx = || AuditEntry::system("test", "restore").into();
    let profile = Profile::new(Some("history-key-restore"));
    source.create_profile(&profile, ctx()).await.unwrap();
    source.insert_key_version(&params, ctx()).await.unwrap();
    let id = HistoryEpochId::generate();
    let context = format!("password-history-key:{}:{}", id.0, profile.id);
    let secret = [0xcc; 32];
    let sealed = keys.encrypt(&secret, &context).await.unwrap();
    let epoch = NewHistoryEpoch {
        epoch: HistoryEpoch {
            id,
            owner: profile.id,
            suite: HistorySuite::PallasPoseidonV1,
            public_key: [3; 32],
            ksf: HistoryKsf::DEFAULT,
            ksf_salt: [4; 32],
            status: HistoryEpochUse::Active,
            created_at: chrono::DateTime::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis(),
            )
            .unwrap(),
        },
        key: WrappedHistoryKey(sealed.to_bytes()),
    };
    source.ensure_history_epoch(&epoch, ctx()).await.unwrap();
    let snapshot = export_snapshot(&source, "sqlite::memory:", false)
        .await
        .unwrap();
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let restored: crate::snapshot::Snapshot = serde_json::from_slice(&encoded).unwrap();
    let target = SqliteBackend::new_in_memory().await.unwrap();
    import_snapshot(&target, &restored).await.unwrap();
    assert_eq!(
        target.list_key_versions().await.unwrap(),
        vec![params.clone()]
    );
    let wrapped = target.get_history_epoch_key(id).await.unwrap().unwrap();
    assert_eq!(wrapped, epoch.key);
    let field = sid_keys::EncryptedField::from_bytes(&wrapped.0).unwrap();
    let recovered_keys = manager([9u8; 32]);
    assert_eq!(recovered_keys.decrypt(&field).await.unwrap(), secret);
    assert!(manager([10u8; 32]).decrypt(&field).await.is_err());
    let mut missing_version = restored.clone();
    missing_version.key_versions.clear();
    let blank = SqliteBackend::new_in_memory().await.unwrap();
    assert!(import_snapshot(&blank, &missing_version).await.is_err());
    assert_eq!(blank.count_profiles().await.unwrap(), 0);
    let mut swapped = restored;
    let key = &mut swapped.password_histories[0].1.as_mut().unwrap().epochs[0].key;
    let mut field = sid_keys::EncryptedField::from_bytes(&key.0).unwrap();
    field.context = format!("password-history-key:{}:{}", id.0, ProfileId::generate());
    *key = WrappedHistoryKey(field.to_bytes());
    assert!(import_snapshot(&blank, &swapped).await.is_err());
    assert_eq!(blank.count_profiles().await.unwrap(), 0);
}

/// Retained old-format data is a reconciliation requirement, not an empty
/// history that export may omit and thereby weaken after a move.
#[tokio::test]
async fn unconverted_history_refuses_export() {
    let source = SqliteBackend::new_in_memory().await.unwrap();
    let profile = Profile::new(Some("old-history-transfer"));
    source
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    // The schema of a file adopted from an older unversioned implementation.
    sqlx::query("ALTER TABLE credentials ADD COLUMN history_commitment BLOB")
        .execute(source.pool())
        .await
        .unwrap();
    let credential = sid_core::models::Credential::new(
        profile.id,
        sid_core::models::CredentialType::Opaque,
        b"record".to_vec(),
        None,
    );
    source
        .create_credential(&credential, AuditEntry::system("test", "credential").into())
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET history_commitment = ? WHERE id = ?")
        .bind(vec![1u8; 32])
        .bind(credential.id.0.to_string())
        .execute(source.pool())
        .await
        .unwrap();
    assert!(
        export_snapshot(&source, "sqlite::memory:", false)
            .await
            .is_err()
    );
}

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
