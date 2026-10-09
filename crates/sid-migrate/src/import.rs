// SPDX-License-Identifier: AGPL-3.0-only
//! Import a Snapshot into a StorageBackend.

use sid_core::models::{AuditEntry, MutationContext};
use sid_plugin::storage::StorageBackend;
use tracing::info;

use crate::snapshot::Snapshot;

/// Validate public setup metadata without reading the independently held key.
/// Supported OPAQUE setups contain a seed and keypairs, well below this bound;
/// a snapshot cannot cause unbounded copies through sealed-field inspection.
pub(crate) fn validate_opaque_setup(snapshot: &Snapshot) -> anyhow::Result<()> {
    let Some(setup) = &snapshot.opaque_server_setup else {
        anyhow::ensure!(
            !snapshot
                .credentials
                .iter()
                .any(|c| c.credential_type == sid_core::models::CredentialType::Opaque),
            "snapshot contains OPAQUE credentials without their server setup"
        );
        return Ok(());
    };
    anyhow::ensure!(setup.len() <= 4096, "sealed OPAQUE setup is oversized");
    let context =
        sid_authn::instance_secret::context(sid_core::models::InstanceSecret::OpaqueServerSetup);
    let field = sid_authn::sealed_secret::inspect(&context, setup)?;
    anyhow::ensure!(
        field.ciphertext.len() > 16,
        "sealed OPAQUE setup has no encrypted payload"
    );
    anyhow::ensure!(
        snapshot
            .key_versions
            .iter()
            .any(|v| v.version == field.key_version),
        "snapshot omits the OPAQUE setup's key derivation version"
    );
    Ok(())
}

/// Import a snapshot into a target storage backend.
///
/// Entities are imported in dependency order: projects first, then profiles,
/// then entities that reference profiles/projects.
///
/// All writes include an audit entry referencing "sid-migrate" as the actor.
pub async fn import_snapshot(
    backend: &dyn StorageBackend,
    snapshot: &Snapshot,
) -> anyhow::Result<ImportResult> {
    anyhow::ensure!(
        snapshot.metadata.version == 3,
        "unsupported snapshot format: export a new snapshot with password history and OPAQUE setup"
    );
    anyhow::ensure!(
        snapshot.metadata.installation_org == backend.instance_organization().await?.map(|o| o.id),
        "restore the same installation authority before importing its data"
    );
    validate_opaque_setup(snapshot)?;
    let setup_kind = sid_core::models::InstanceSecret::OpaqueServerSetup;
    let current_setup = backend.get_instance_secret(setup_kind).await?;
    anyhow::ensure!(
        current_setup.is_none() || current_setup == snapshot.opaque_server_setup,
        "target OPAQUE setup conflicts with snapshot"
    );
    let profiles: std::collections::BTreeSet<_> = snapshot.profiles.iter().map(|p| p.id).collect();
    let mut owners = std::collections::BTreeSet::new();
    for (owner, archive) in &snapshot.password_histories {
        anyhow::ensure!(
            profiles.contains(owner) && owners.insert(*owner),
            "invalid snapshot history owner"
        );
        if let Some(archive) = archive {
            anyhow::ensure!(archive.owner == *owner, "history archive owner mismatch");
            archive.validate()?;
            for epoch in &archive.epochs {
                if epoch.epoch.status == sid_core::models::HistoryEpochUse::Retired
                    && epoch.key.0.is_empty()
                {
                    continue;
                }
                let sealed = sid_keys::EncryptedField::from_bytes(&epoch.key.0)?;
                anyhow::ensure!(
                    snapshot
                        .key_versions
                        .iter()
                        .any(|v| v.version == sealed.key_version),
                    "snapshot omits a required history key derivation version"
                );
            }
        }
        let current = backend.export_password_history(*owner).await?;
        anyhow::ensure!(
            current.is_none() || current.as_ref() == archive.as_ref(),
            "target password history conflicts with snapshot"
        );
    }
    anyhow::ensure!(
        owners == profiles,
        "snapshot must include history state for every profile"
    );
    let mut result = ImportResult::default();
    let actor = "sid-migrate".to_string();
    let current_versions = backend.list_key_versions().await?;
    let mut versions = std::collections::BTreeSet::new();
    for params in &snapshot.key_versions {
        anyhow::ensure!(
            versions.insert(params.version),
            "duplicate key version in snapshot"
        );
        if let Some(current) = current_versions
            .iter()
            .find(|v| v.version == params.version)
        {
            anyhow::ensure!(
                current == params,
                "target key derivation parameters conflict with snapshot"
            );
        }
    }
    for params in &snapshot.key_versions {
        if backend
            .insert_key_version(
                params,
                make_audit(&actor, "import_key_version", &params.version.to_string()),
            )
            .await?
        {
            result.key_versions += 1;
        } else {
            let current = backend.list_key_versions().await?;
            anyhow::ensure!(
                current.iter().any(|v| v == params),
                "key version changed during import"
            );
        }
    }

    // The setup precedes credentials and is insert-only. Recheck the stored
    // value after insertion: a concurrent initializer must never replace it.
    if let Some(setup) = &snapshot.opaque_server_setup {
        backend
            .insert_instance_secret(
                setup_kind,
                setup,
                make_audit(&actor, "import_opaque_setup", "opaque_server_setup"),
            )
            .await?;
        anyhow::ensure!(
            backend.get_instance_secret(setup_kind).await?.as_ref() == Some(setup),
            "target OPAQUE setup changed during import"
        );
    }

    // 1. Projects (must exist before anything else)
    info!(count = snapshot.projects.len(), "importing projects...");
    for project in &snapshot.projects {
        let audit = make_audit(&actor, "import_project", &project.id.0.to_string());
        // Already in the store (the system project, or an earlier import): kept as stored.
        result.projects += created(backend.create_project(project, audit).await, || async {
            Ok(backend.get_project(project.id).await?.is_some())
        })
        .await?;
    }

    // Ensure system project exists
    let audit = make_audit(&actor, "ensure_system_project", "system");
    backend.ensure_system_project(audit).await?;

    // 2. Profiles
    info!(count = snapshot.profiles.len(), "importing profiles...");
    for profile in &snapshot.profiles {
        let audit = make_audit(&actor, "import_profile", &profile.id.to_string());
        match backend.create_profile(profile, audit).await {
            Ok(()) => result.profiles += 1,
            // Imported before: a repeated import adds nothing. Another
            // profile holding the user name is a real conflict.
            Err(sid_core::Error::Conflict(_))
                if backend.get_profile(profile.id).await?.is_some() => {}
            Err(e) => return Err(e.into()),
        }
    }

    // History precedes credentials: failure cannot install a password without
    // the retained comparison state. Instance migration requires quiesced writers.
    for (_, archive) in &snapshot.password_histories {
        if let Some(archive) = archive
            && backend
                .import_password_history(
                    archive,
                    make_audit(
                        &actor,
                        "import_password_history",
                        &archive.owner.to_string(),
                    ),
                )
                .await?
        {
            result.password_histories += 1;
        }
    }

    // 3. Principals (depend on profiles)
    info!(count = snapshot.principals.len(), "importing principals...");
    for principal in &snapshot.principals {
        let audit = make_audit(&actor, "import_principal", &principal.id.0.to_string());
        backend.save_principal(principal, audit).await?;
        result.principals += 1;
    }

    // 4. Credentials (depend on profiles)
    info!(
        count = snapshot.credentials.len(),
        "importing credentials..."
    );
    for credential in &snapshot.credentials {
        let audit = make_audit(&actor, "import_credential", &credential.id.0.to_string());
        match backend.create_credential(credential, audit).await {
            Ok(()) => result.credentials += 1,
            Err(sid_core::Error::Conflict(_))
                if backend.get_credential(credential.id).await?.as_ref() == Some(credential) => {}
            Err(e) => return Err(e.into()),
        }
    }

    // 5. Sessions (depend on profiles)
    info!(count = snapshot.sessions.len(), "importing sessions...");
    for session in &snapshot.sessions {
        let audit = make_audit(&actor, "import_session", &session.id.to_string());
        backend.create_session(session, audit).await?;
        result.sessions += 1;
    }

    // Service bindings (depend on profiles): the pairwise `sub` of every client.
    info!(
        count = snapshot.service_bindings.len(),
        "importing service bindings..."
    );
    for binding in &snapshot.service_bindings {
        let audit = make_audit(
            &actor,
            "import_service_binding",
            &binding.binding_id.to_string(),
        );
        if backend.import_service_binding(binding, audit).await? {
            result.service_bindings += 1;
        }
    }

    // Machine users (depend on projects), before the resource access and role
    // assignments that name them.
    info!(
        count = snapshot.machine_users.len(),
        "importing machine users..."
    );
    for mu in &snapshot.machine_users {
        let audit = make_audit(&actor, "import_machine_user", &mu.id.to_string());
        result.machine_users += created(backend.create_machine_user(mu, audit).await, || async {
            Ok(backend.get_machine_user(mu.id).await?.is_some())
        })
        .await?;
    }

    // 6. Applications (depend on projects), then their resource roles (the
    // retired ones keep their indicators reserved), then their client roles
    // (a client may name a resource as its default), then access.
    info!(
        count = snapshot.applications.len(),
        "importing applications..."
    );
    for app in &snapshot.applications {
        let audit = make_audit(&actor, "import_application", &app.id.to_string());
        result.applications += created(
            backend.create_application(app, None, None, audit).await,
            || async { Ok(backend.get_application(app.id).await?.is_some()) },
        )
        .await?;
    }
    info!(
        count = snapshot.protected_resources.len(),
        "importing protected resources..."
    );
    for resource in &snapshot.protected_resources {
        let audit = make_audit(
            &actor,
            "import_protected_resource",
            &resource.id.to_string(),
        );
        if backend.import_protected_resource(resource, audit).await? {
            result.protected_resources += 1;
        }
    }
    info!(
        count = snapshot.oauth2_clients.len(),
        "importing oauth2 clients..."
    );
    for client in &snapshot.oauth2_clients {
        let audit = make_audit(&actor, "import_oauth2_client", &client.client_id);
        result.oauth2_clients += created(
            backend.create_oauth2_client(client, audit).await,
            || async {
                Ok(backend
                    .get_oauth2_client(&client.client_id)
                    .await?
                    .is_some())
            },
        )
        .await?;
    }
    info!(
        count = snapshot.resource_access.len(),
        "importing resource access..."
    );
    for access in &snapshot.resource_access {
        let subject = format!("{}:{}", access.client_id, access.resource_id);
        let audit = make_audit(&actor, "import_resource_access", &subject);
        // Setting access is idempotent: a repeated import keeps it as stored.
        if backend
            .resource_access(&access.client_id, access.resource_id)
            .await?
            .is_none()
        {
            backend.set_resource_access(access, audit).await?;
            result.resource_access += 1;
        }
    }

    // 7. Refresh tokens (depend on sessions)
    info!(
        count = snapshot.refresh_tokens.len(),
        "importing refresh tokens..."
    );
    for token in &snapshot.refresh_tokens {
        let audit = make_audit(&actor, "import_refresh_token", &token.id.to_string());
        result.refresh_tokens +=
            created(backend.create_refresh_token(token, audit).await, || async {
                Ok(backend
                    .get_refresh_token_by_hash(&token.token_hash)
                    .await?
                    .is_some_and(|stored| stored.id == token.id))
            })
            .await?;
    }

    // 8. IATs (depend on projects)
    info!(
        count = snapshot.initial_access_tokens.len(),
        "importing initial access tokens..."
    );
    for iat in &snapshot.initial_access_tokens {
        let audit = make_audit(&actor, "import_iat", &iat.id.0.to_string());
        backend.create_initial_access_token(iat, audit).await?;
        result.initial_access_tokens += 1;
    }

    // 9. Roles (depend on projects)
    info!(count = snapshot.roles.len(), "importing roles...");
    for role in &snapshot.roles {
        let audit = make_audit(&actor, "import_role", &role.id.0.to_string());
        result.roles += created(backend.create_role(role, audit).await, || async {
            Ok(backend.get_role(role.id).await?.is_some())
        })
        .await?;
    }

    // 10. Groups (depend on projects)
    info!(count = snapshot.groups.len(), "importing groups...");
    for group in &snapshot.groups {
        let audit = make_audit(&actor, "import_group", &group.id.0.to_string());
        backend.create_group(group, audit).await?;
        result.groups += 1;
    }

    // 11. Group members (depend on groups + profiles)
    info!(
        count = snapshot.group_members.len(),
        "importing group members..."
    );
    for member in &snapshot.group_members {
        let audit = make_audit(
            &actor,
            "import_group_member",
            &format!("{}:{}", member.group_id.0, member.profile_id),
        );
        backend.add_to_group(member, audit).await?;
        result.group_members += 1;
    }

    // 12. Role assignments (depend on roles and their principals: profiles,
    // groups, machine users, OAuth clients; a redelegated one on its source).
    // They are restored as recorded, envelope and provenance included: the
    // source installation authorized them.
    info!(
        count = snapshot.role_assignments.len(),
        "importing role assignments..."
    );
    for assignment in sources_first(&snapshot.role_assignments)? {
        let audit = make_audit(
            &actor,
            "import_role_assignment",
            &assignment.id.0.to_string(),
        );
        result.role_assignments += created(
            backend.create_role_assignment(assignment, audit).await,
            || async {
                Ok(assignments_of(backend, &assignment.principal)
                    .await?
                    .iter()
                    .any(|a| a.id == assignment.id))
            },
        )
        .await?;
    }

    // 13. Cedar policies (depend on projects)
    info!(
        count = snapshot.cedar_policies.len(),
        "importing cedar policies..."
    );
    for policy in &snapshot.cedar_policies {
        let audit = make_audit(&actor, "import_cedar_policy", &policy.id.0.to_string());
        backend.create_cedar_policy(policy, audit).await?;
        result.cedar_policies += 1;
    }

    // 14. Profile metadata (depend on profiles)
    info!(
        count = snapshot.profile_metadata.len(),
        "importing profile metadata..."
    );
    for meta in &snapshot.profile_metadata {
        let audit = make_audit(
            &actor,
            "import_profile_metadata",
            &format!("{}:{}", meta.profile_id, meta.key),
        );
        backend.set_profile_metadata(meta, audit).await?;
        result.profile_metadata += 1;
    }

    // 15. Devices (depend on profiles)
    info!(count = snapshot.devices.len(), "importing devices...");
    for device in &snapshot.devices {
        let audit = make_audit(&actor, "import_device", &device.id.to_string());
        backend.create_device(device, audit).await?;
        result.devices += 1;
    }

    // 16. Device auth codes
    info!(
        count = snapshot.device_auth_codes.len(),
        "importing device auth codes..."
    );
    for code in &snapshot.device_auth_codes {
        let audit = make_audit(&actor, "import_device_auth_code", &code.id.0.to_string());
        backend.create_device_auth_code(code, audit).await?;
        result.device_auth_codes += 1;
    }

    // 17. Profile grants (depend on profiles + projects)
    info!(
        count = snapshot.profile_grants.len(),
        "importing profile grants..."
    );
    for grant in &snapshot.profile_grants {
        let audit = make_audit(&actor, "import_profile_grant", &grant.id.0.to_string());
        result.profile_grants +=
            created(backend.create_profile_grant(grant, audit).await, || async {
                Ok(backend.get_profile_grant(grant.id).await?.is_some())
            })
            .await?;
    }

    // 18. Upstream providers
    info!(
        count = snapshot.upstream_providers.len(),
        "importing upstream providers..."
    );
    for provider in &snapshot.upstream_providers {
        let audit = make_audit(
            &actor,
            "import_upstream_provider",
            &provider.id.0.to_string(),
        );
        result.upstream_providers += created(
            backend.create_upstream_provider(provider, audit).await,
            || async { Ok(backend.get_upstream_provider(provider.id).await?.is_some()) },
        )
        .await?;
    }

    // 19. Upstream identities (depend on providers + profiles)
    info!(
        count = snapshot.upstream_identities.len(),
        "importing upstream identities..."
    );
    for identity in &snapshot.upstream_identities {
        let audit = make_audit(
            &actor,
            "import_upstream_identity",
            &identity.id.0.to_string(),
        );
        result.upstream_identities += created(
            backend.create_upstream_identity(identity, audit).await,
            || async {
                Ok(backend
                    .get_upstream_identity_by_provider_subject(
                        identity.provider_id,
                        &identity.upstream_subject,
                    )
                    .await?
                    .is_some_and(|stored| stored.id == identity.id))
            },
        )
        .await?;
    }

    // 20. PATs (depend on profiles)
    info!(
        count = snapshot.personal_access_tokens.len(),
        "importing PATs..."
    );
    for pat in &snapshot.personal_access_tokens {
        let audit = make_audit(&actor, "import_pat", &pat.id.0.to_string());
        backend.create_pat(pat, None, audit).await?;
        result.personal_access_tokens += 1;
    }

    // 22. Machine credentials (depend on machine users)
    info!(
        count = snapshot.machine_credentials.len(),
        "importing machine credentials..."
    );
    for cred in &snapshot.machine_credentials {
        let audit = make_audit(&actor, "import_machine_credential", &cred.kid);
        result.machine_credentials += created(
            backend.add_machine_credential(cred, None, audit).await,
            || async {
                Ok(backend
                    .get_machine_credential_by_kid(&cred.kid)
                    .await?
                    .is_some())
            },
        )
        .await?;
    }

    // 23. Impersonation grants (depend on machine users)
    info!(
        count = snapshot.impersonation_grants.len(),
        "importing impersonation grants..."
    );
    for grant in &snapshot.impersonation_grants {
        let audit = make_audit(
            &actor,
            "import_impersonation_grant",
            &grant.machine_user_id.to_string(),
        );
        backend.save_impersonation_grant(grant, audit).await?;
        result.impersonation_grants += 1;
    }

    // 24. Closure requests (depend on profiles)
    info!(
        count = snapshot.closure_requests.len(),
        "importing closure requests..."
    );
    for req in &snapshot.closure_requests {
        let audit = make_audit(
            &actor,
            "import_closure_request",
            &req.profile_id.to_string(),
        );
        result.closure_requests +=
            created(backend.create_closure_request(req, audit).await, || async {
                Ok(backend.get_closure_request(req.profile_id).await?.is_some())
            })
            .await?;
    }

    // 25. Export jobs (depend on profiles)
    info!(
        count = snapshot.export_jobs.len(),
        "importing export jobs..."
    );
    for job in &snapshot.export_jobs {
        let audit = make_audit(&actor, "import_export_job", &job.id.to_string());
        result.export_jobs += created(backend.create_export_job(job, audit).await, || async {
            Ok(backend.get_export_job_by_id(job.id).await?.is_some())
        })
        .await?;
    }

    // 26. Durable work (owed deliveries and dead letters)
    info!(
        count = snapshot.durable_work.len(),
        "importing durable work..."
    );
    for work in &snapshot.durable_work {
        if backend.import_work(work).await? {
            result.durable_work += 1;
        }
    }

    // 26b. Completed keyed commands (their results answer retries)
    info!(
        count = snapshot.operation_results.len(),
        "importing operation results..."
    );
    for record in &snapshot.operation_results {
        if backend.import_operation_result(record).await? {
            result.operation_results += 1;
        }
    }

    // 27. Magic link sessions
    info!(
        count = snapshot.magic_link_sessions.len(),
        "importing magic link sessions..."
    );
    for session in &snapshot.magic_link_sessions {
        let audit = make_audit(&actor, "import_magic_link", &session.id.to_string());
        backend.create_magic_link_session(session, audit).await?;
        result.magic_link_sessions += 1;
    }

    // 28. SCIM outbound targets
    info!(
        count = snapshot.scim_outbound_targets.len(),
        "importing SCIM outbound targets..."
    );
    for target in &snapshot.scim_outbound_targets {
        let audit = make_audit(
            &actor,
            "import_scim_outbound_target",
            &target.id.0.to_string(),
        );
        result.scim_outbound_targets += created(
            backend.create_scim_outbound_target(target, audit).await,
            || async { Ok(backend.get_scim_outbound_target(target.id).await?.is_some()) },
        )
        .await?;
    }

    // 29. SCIM outbound records
    info!(
        count = snapshot.scim_outbound_records.len(),
        "importing SCIM outbound records..."
    );
    for record in &snapshot.scim_outbound_records {
        let audit = make_audit(
            &actor,
            "import_scim_outbound_record",
            &format!("{}:{}", record.target_id, record.sid_entity_id),
        );
        // A mapping is identified by its target, entity and type.
        result.scim_outbound_records += created(
            backend.create_scim_outbound_record(record, audit).await,
            || async {
                Ok(backend
                    .get_scim_outbound_record(
                        record.target_id,
                        record.sid_entity_id,
                        record.entity_type,
                    )
                    .await?
                    .is_some())
            },
        )
        .await?;
    }

    // 30. Branding configs (depend on projects)
    info!(
        count = snapshot.branding_configs.len(),
        "importing branding configs..."
    );
    for config in &snapshot.branding_configs {
        let audit = make_audit(&actor, "import_branding_config", &config.id.to_string());
        result.branding_configs += created(
            backend.create_branding_config(config, audit).await,
            || async { Ok(backend.get_branding_config(config.id).await?.is_some()) },
        )
        .await?;
    }

    // 31. Outbound DLQ entries
    info!(
        count = snapshot.outbound_dlq_entries.len(),
        "importing outbound DLQ entries..."
    );
    for entry in &snapshot.outbound_dlq_entries {
        let audit = make_audit(&actor, "import_outbound_dlq", &entry.id.to_string());
        result.outbound_dlq_entries += created(
            backend.create_outbound_dlq_entry(entry, audit).await,
            || async {
                Ok(backend
                    .list_outbound_dlq_entries(entry.target_id)
                    .await?
                    .iter()
                    .any(|stored| stored.id == entry.id))
            },
        )
        .await?;
    }

    info!(total = result.total(), "import complete");
    Ok(result)
}

/// Count of records a create added: 1, or 0 when the same record (`stored`
/// finds it by its id) was imported before. Any other conflict, such as a
/// different record holding the same unique name, fails the import.
async fn created<Fut>(
    result: sid_core::Result<()>,
    stored: impl FnOnce() -> Fut,
) -> anyhow::Result<u64>
where
    Fut: std::future::Future<Output = sid_core::Result<bool>>,
{
    match result {
        Ok(()) => Ok(1),
        Err(sid_core::Error::Conflict(reason)) => {
            if stored().await? {
                Ok(0)
            } else {
                Err(sid_core::Error::Conflict(reason).into())
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// The stored role assignments of `principal`.
async fn assignments_of(
    backend: &dyn StorageBackend,
    principal: &sid_core::models::RoleAssignmentPrincipal,
) -> sid_core::Result<Vec<sid_core::models::RoleAssignment>> {
    use sid_core::models::RoleAssignmentPrincipal as P;
    match principal {
        P::Profile(id) => backend.list_role_assignments_for_profile(*id).await,
        P::Group(id) => backend.list_role_assignments_for_group(*id).await,
        P::MachineUser(id) => backend.list_role_assignments_for_machine_user(*id).await,
        P::OAuthClient(id) => backend.list_role_assignments_for_oauth_client(id).await,
        P::ProvisioningConnector(id) => {
            backend
                .list_role_assignments_for_provisioning_connector(*id)
                .await
        }
    }
}

/// `assignments` with every redelegated assignment after the source it
/// depends on. A source missing from the snapshot must already be stored,
/// or the store refuses the dependent; a dependency cycle is refused here.
fn sources_first(
    assignments: &[sid_core::models::RoleAssignment],
) -> anyhow::Result<Vec<&sid_core::models::RoleAssignment>> {
    use std::collections::HashSet;
    let listed: HashSet<_> = assignments.iter().map(|a| a.id).collect();
    let mut placed = HashSet::with_capacity(assignments.len());
    let mut ordered = Vec::with_capacity(assignments.len());
    let mut pending: Vec<_> = assignments.iter().collect();
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|a| {
            let waits = a
                .provenance
                .as_ref()
                .and_then(|p| p.depends_on)
                .is_some_and(|source| listed.contains(&source) && !placed.contains(&source));
            if !waits {
                placed.insert(a.id);
                ordered.push(*a);
            }
            waits
        });
        if pending.len() == before {
            anyhow::bail!(
                "role assignments {:?} depend on each other in a cycle",
                pending.iter().map(|a| a.id.0).collect::<Vec<_>>()
            );
        }
    }
    Ok(ordered)
}

/// Create a migration audit entry.
fn make_audit(_actor: &str, action: &str, resource: &str) -> MutationContext {
    AuditEntry::system(action, resource)
        .with_metadata(serde_json::json!({"tool": "sid-migrate"}))
        .into()
}

/// Result of an import operation with per-entity counts.
#[derive(Debug, Default)]
pub struct ImportResult {
    pub key_versions: u64,
    pub password_histories: u64,
    pub projects: u64,
    pub profiles: u64,
    pub principals: u64,
    pub credentials: u64,
    pub sessions: u64,
    pub service_bindings: u64,
    pub applications: u64,
    pub protected_resources: u64,
    pub oauth2_clients: u64,
    pub resource_access: u64,
    pub refresh_tokens: u64,
    pub initial_access_tokens: u64,
    pub roles: u64,
    pub groups: u64,
    pub group_members: u64,
    pub role_assignments: u64,
    pub cedar_policies: u64,
    pub profile_metadata: u64,
    pub devices: u64,
    pub device_auth_codes: u64,
    pub profile_grants: u64,
    pub upstream_providers: u64,
    pub upstream_identities: u64,
    pub personal_access_tokens: u64,
    pub machine_users: u64,
    pub machine_credentials: u64,
    pub impersonation_grants: u64,
    pub closure_requests: u64,
    pub export_jobs: u64,
    pub durable_work: u64,
    pub operation_results: u64,
    pub magic_link_sessions: u64,
    pub scim_outbound_targets: u64,
    pub scim_outbound_records: u64,
    pub outbound_dlq_entries: u64,
    pub branding_configs: u64,
}

impl ImportResult {
    /// Total imported entities.
    pub fn total(&self) -> u64 {
        self.projects
            + self.key_versions
            + self.password_histories
            + self.profiles
            + self.principals
            + self.credentials
            + self.sessions
            + self.service_bindings
            + self.applications
            + self.protected_resources
            + self.oauth2_clients
            + self.resource_access
            + self.refresh_tokens
            + self.initial_access_tokens
            + self.roles
            + self.groups
            + self.group_members
            + self.role_assignments
            + self.cedar_policies
            + self.profile_metadata
            + self.devices
            + self.device_auth_codes
            + self.profile_grants
            + self.upstream_providers
            + self.upstream_identities
            + self.personal_access_tokens
            + self.machine_users
            + self.machine_credentials
            + self.impersonation_grants
            + self.closure_requests
            + self.export_jobs
            + self.durable_work
            + self.operation_results
            + self.magic_link_sessions
            + self.scim_outbound_targets
            + self.scim_outbound_records
            + self.outbound_dlq_entries
            + self.branding_configs
    }
}

impl std::fmt::Display for ImportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Import Summary:")?;
        writeln!(f, "  Key Versions:         {}", self.key_versions)?;
        writeln!(f, "  Password Histories:   {}", self.password_histories)?;
        writeln!(f, "  Projects:             {}", self.projects)?;
        writeln!(f, "  Profiles:             {}", self.profiles)?;
        writeln!(f, "  Principals:           {}", self.principals)?;
        writeln!(f, "  Credentials:          {}", self.credentials)?;
        writeln!(f, "  Sessions:             {}", self.sessions)?;
        writeln!(f, "  Service Bindings:     {}", self.service_bindings)?;
        writeln!(f, "  Applications:         {}", self.applications)?;
        writeln!(f, "  Protected Resources:  {}", self.protected_resources)?;
        writeln!(f, "  OAuth2 Clients:       {}", self.oauth2_clients)?;
        writeln!(f, "  Resource Access:      {}", self.resource_access)?;
        writeln!(f, "  Refresh Tokens:       {}", self.refresh_tokens)?;
        writeln!(f, "  IATs:                 {}", self.initial_access_tokens)?;
        writeln!(f, "  Roles:                {}", self.roles)?;
        writeln!(f, "  Groups:               {}", self.groups)?;
        writeln!(f, "  Group Members:        {}", self.group_members)?;
        writeln!(f, "  Role Assignments:     {}", self.role_assignments)?;
        writeln!(f, "  Cedar Policies:       {}", self.cedar_policies)?;
        writeln!(f, "  Profile Metadata:     {}", self.profile_metadata)?;
        writeln!(f, "  Devices:              {}", self.devices)?;
        writeln!(f, "  Device Auth Codes:    {}", self.device_auth_codes)?;
        writeln!(f, "  Profile Grants:       {}", self.profile_grants)?;
        writeln!(f, "  Upstream Providers:   {}", self.upstream_providers)?;
        writeln!(f, "  Upstream Identities:  {}", self.upstream_identities)?;
        writeln!(f, "  PATs:                 {}", self.personal_access_tokens)?;
        writeln!(f, "  Machine Users:        {}", self.machine_users)?;
        writeln!(f, "  Machine Credentials:  {}", self.machine_credentials)?;
        writeln!(f, "  Impersonation Grants: {}", self.impersonation_grants)?;
        writeln!(f, "  Operation Results:    {}", self.operation_results)?;
        writeln!(f, "  SCIM Targets:         {}", self.scim_outbound_targets)?;
        writeln!(f, "  Branding Configs:     {}", self.branding_configs)?;
        writeln!(f, "  ─────────────────────────────")?;
        writeln!(f, "  Total:                {}", self.total())
    }
}

#[cfg(test)]
mod tests;
