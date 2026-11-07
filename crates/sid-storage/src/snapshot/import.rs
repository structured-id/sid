// SPDX-License-Identifier: AGPL-3.0-only
//! Import a snapshot into a target installation's database.

use sid_core::models::{AuditEntry, MutationContext, OperationKey, OperationResourceBinding};
use sid_crypto::CryptoPrimitives;
use sid_plugin::SnapshotRules;
use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use tracing::info;

use super::{FORMAT_VERSION, Result, Snapshot, SnapshotError};

/// The namespace the import of a snapshot is recorded in, keyed by the
/// snapshot's id.
const IMPORT_NAMESPACE: &str = "snapshot-import";

/// The method the import of a snapshot is recorded as.
const IMPORT_METHOD: &str = "sid.snapshot.Import";

/// The largest sealed OPAQUE setup a snapshot may carry. Supported setups
/// contain a seed and keypairs, well below it; a snapshot cannot cause
/// unbounded copies through sealed-field inspection.
const MAX_OPAQUE_SETUP: usize = 4096;

fn invalid(what: impl Into<String>) -> SnapshotError {
    SnapshotError::Invalid(what.into())
}

fn ensure(holds: bool, what: &str) -> Result<()> {
    if holds { Ok(()) } else { Err(invalid(what)) }
}

/// Check the snapshot as a whole before anything uses it: its format, its
/// installation identity, its issuers and device bindings, the sealed
/// OPAQUE setup's public metadata and the password history state. Export
/// and import both run it; a host may run it on an opened archive first.
pub fn validate(snapshot: &Snapshot, rules: &dyn SnapshotRules) -> Result<()> {
    if snapshot.metadata.version != FORMAT_VERSION {
        return Err(SnapshotError::Format(snapshot.metadata.version));
    }
    validate_identity(snapshot)?;
    validate_opaque_setup(snapshot, rules)?;
    validate_history(snapshot, rules)
}

/// The installation identity: the organization the metadata names, the one
/// every issuer serves, and each issuer's own key history; each device
/// binding on a snapshot device of the same Profile.
fn validate_identity(snapshot: &Snapshot) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let org = snapshot.organization.as_ref().map(|o| o.id);
    ensure(
        org == snapshot.metadata.installation_org,
        "snapshot organization and metadata disagree",
    )?;
    ensure(
        org.is_some() || (snapshot.profiles.is_empty() && snapshot.oidc_issuers.is_empty()),
        "snapshot has accounts or issuers but no installation organization",
    )?;
    let mut issuers = BTreeSet::new();
    for entry in &snapshot.oidc_issuers {
        ensure(
            Some(entry.issuer.recipient_org) == org,
            "snapshot issuer serves another organization",
        )?;
        ensure(
            issuers.insert(entry.issuer.id),
            "duplicate issuer in snapshot",
        )?;
        entry
            .issuer
            .check_keys(&entry.keys)
            .map_err(|e| invalid(e.to_string()))?;
    }
    let devices: BTreeMap<_, _> = snapshot
        .devices
        .iter()
        .map(|d| (d.id, d.profile_id))
        .collect();
    let mut bound = BTreeSet::new();
    for binding in &snapshot.device_attestations {
        ensure(
            devices.get(&binding.device_id) == Some(&binding.profile_id),
            "snapshot device binding names no snapshot device of its profile",
        )?;
        ensure(
            bound.insert(binding.device_id),
            "a snapshot device has two key bindings",
        )?;
    }
    Ok(())
}

/// Validate public setup metadata without reading the independently held key.
fn validate_opaque_setup(snapshot: &Snapshot, rules: &dyn SnapshotRules) -> Result<()> {
    let Some(setup) = &snapshot.opaque_server_setup else {
        return ensure(
            !snapshot
                .credentials
                .iter()
                .any(|c| c.credential_type == sid_core::models::CredentialType::Opaque),
            "snapshot contains OPAQUE credentials without their server setup",
        );
    };
    ensure(
        setup.len() <= MAX_OPAQUE_SETUP,
        "sealed OPAQUE setup is oversized",
    )?;
    let version = rules
        .opaque_setup_key_version(setup)
        .map_err(|e| invalid(format!("sealed OPAQUE setup: {e}")))?;
    ensure(
        snapshot.key_versions.iter().any(|v| v.version == version),
        "snapshot omits the OPAQUE setup's key derivation version",
    )
}

/// Validate the password history state of a snapshot as a whole: one history
/// entry per profile; each archive and each key archive well formed; every
/// key archive belongs to the history domain of a snapshot profile, once,
/// with the evaluator's key derivation versions it is sealed under included
/// (its own custody, not the credential service's); and every epoch a history
/// names has its key with the same descriptor, so no history arrives that
/// its owner's operations could not evaluate.
fn validate_history(snapshot: &Snapshot, rules: &dyn SnapshotRules) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let profiles: BTreeSet<_> = snapshot.profiles.iter().map(|p| p.id).collect();
    let mut owners = BTreeSet::new();
    for (owner, archive) in &snapshot.password_histories {
        ensure(
            profiles.contains(owner) && owners.insert(*owner),
            "invalid snapshot history owner",
        )?;
        if let Some(archive) = archive {
            ensure(archive.owner == *owner, "history archive owner mismatch")?;
            archive.validate().map_err(|e| invalid(e.to_string()))?;
        }
    }
    ensure(
        owners == profiles,
        "snapshot must include history state for every profile",
    )?;

    // The evaluator's owner domain of each profile.
    let domains: BTreeMap<[u8; 32], sid_core::models::ProfileId> =
        match snapshot.metadata.installation_org {
            Some(installation) => profiles
                .iter()
                .map(|p| (rules.history_owner_domain(installation, *p), *p))
                .collect(),
            None => BTreeMap::new(),
        };
    let mut keys = BTreeMap::new();
    for archive in &snapshot.history_keys {
        archive.validate().map_err(|e| invalid(e.to_string()))?;
        let owner = domains
            .get(&archive.owner_domain)
            .ok_or_else(|| invalid("history keys of no snapshot profile"))?;
        ensure(
            keys.insert(*owner, archive).is_none(),
            "duplicate history keys of one owner",
        )?;
        for epoch in &archive.epochs {
            let sealed = sid_keys::EncryptedField::from_bytes(&epoch.key.0)
                .map_err(|e| invalid(format!("sealed history key: {e}")))?;
            ensure(
                snapshot
                    .history_key_versions
                    .iter()
                    .any(|v| v.version == sealed.key_version),
                "snapshot omits a required history key derivation version",
            )?;
        }
    }
    for (owner, archive) in &snapshot.password_histories {
        let Some(archive) = archive else { continue };
        // The evaluator selects its active epoch first, and an operation
        // accepts only the history's active epoch there or a replacement the
        // history does not record yet (a rotation not committed when the
        // snapshot was taken). Any other recorded epoch active on the key
        // side would refuse every later operation of the owner.
        let key_active = keys.get(owner).and_then(|k| {
            k.epochs
                .iter()
                .find(|e| e.epoch.status == sid_core::models::HistoryEpochUse::Active)
        });
        if let Some(key_active) = key_active {
            let recorded = archive.epochs.iter().find(|e| e.id == key_active.epoch.id);
            ensure(
                recorded.is_none_or(|e| e.status == sid_core::models::HistoryEpochUse::Active),
                "snapshot history and keys disagree on the active epoch",
            )?;
        }
        for epoch in &archive.epochs {
            let key = keys
                .get(owner)
                .and_then(|k| {
                    k.epochs
                        .iter()
                        .find(|e| e.epoch.descriptor() == epoch.descriptor())
                })
                .ok_or_else(|| invalid("snapshot history names an epoch without its key"))?;
            // An entry retained under an epoch is compared at every later
            // replacement, which a retired key no longer evaluates.
            ensure(
                key.epoch.status != sid_core::models::HistoryEpochUse::Retired
                    || !archive.entries.iter().any(|e| e.epoch == epoch.id),
                "snapshot history retains an entry under a retired key",
            )?;
        }
    }
    Ok(())
}

/// The record of this snapshot's import in a target: the snapshot's id and
/// the digest of its contents. Its presence in a target that already holds
/// the snapshot's organization is what tells a resumed import from an
/// import into an initialized installation.
fn import_record(
    snapshot: &Snapshot,
    crypto: &dyn CryptoPrimitives,
) -> Result<OperationResourceBinding> {
    Ok(OperationResourceBinding {
        namespace: IMPORT_NAMESPACE.to_owned(),
        key: OperationKey::parse(&snapshot.metadata.snapshot_id.to_string())
            .map_err(|e| invalid(format!("snapshot id: {e}")))?,
        method: IMPORT_METHOD.to_owned(),
        fingerprint: crypto.sha256(&snapshot.to_json()?).to_vec(),
        period: None,
        resource: snapshot.metadata.snapshot_id,
    })
}

/// Whether the target may take this snapshot, decided before anything is
/// written: `true` for a fresh import into an uninitialized target, `false`
/// to resume the interrupted import of this same snapshot into it. An
/// initialized installation, or one holding another identity or another
/// snapshot's import, is refused.
async fn admit_target(
    backend: &dyn StorageBackend,
    snapshot: &Snapshot,
    record: &OperationResourceBinding,
) -> Result<bool> {
    let refused = |what: &str| SnapshotError::Target(what.to_owned());
    match backend.instance_organization().await? {
        None => {
            if !backend.list_oidc_issuers().await?.is_empty() || backend.count_profiles().await? > 0
            {
                return Err(refused(
                    "the target holds data without an installation organization",
                ));
            }
            Ok(true)
        }
        Some(held) => {
            if snapshot.organization.as_ref() != Some(&held) {
                return Err(refused("the target is another installation"));
            }
            let resumed = backend.export_operation_resources().await?.iter().any(|b| {
                b.namespace == record.namespace
                    && b.key == record.key
                    && b.same_command(record)
                    && b.resource == record.resource
            });
            if !resumed {
                return Err(refused(
                    "an initialized installation is not an import destination; \
                     only the interrupted import of this same snapshot is resumed",
                ));
            }
            Ok(false)
        }
    }
}

/// Import `snapshot` into the target store `backend` and the history
/// evaluator's key store `history_keys`, checked by `rules`.
///
/// The snapshot, its identity and its consistency with the target are
/// checked before the first write. A target is either uninitialized (no
/// installation organization, issuers or profiles), or holds this same
/// snapshot's interrupted import, which the call then resumes. Entities are
/// written in dependency order, each with an audit entry; nothing is served,
/// issued or run: the host activates the restored installation afterwards.
pub async fn import(
    backend: &dyn StorageBackend,
    history_keys: &dyn HistoryKeyStore,
    rules: &dyn SnapshotRules,
    crypto: &dyn CryptoPrimitives,
    snapshot: &Snapshot,
) -> Result<ImportResult> {
    validate(snapshot, rules)?;
    let record = import_record(snapshot, crypto)?;
    let fresh = admit_target(backend, snapshot, &record).await?;
    let setup_kind = sid_core::models::InstanceSecret::OpaqueServerSetup;
    let target = |what: &str| SnapshotError::Target(what.to_owned());
    let current_setup = backend.get_instance_secret(setup_kind).await?;
    if current_setup.is_some() && current_setup != snapshot.opaque_server_setup {
        return Err(target("target OPAQUE setup conflicts with snapshot"));
    }
    for (owner, archive) in &snapshot.password_histories {
        let current = backend.export_password_history(*owner).await?;
        if current.is_some() && current.as_ref() != archive.as_ref() {
            return Err(target("target password history conflicts with snapshot"));
        }
    }
    for archive in &snapshot.history_keys {
        let current = history_keys.export_keys(&archive.owner_domain).await?;
        if current.is_some() && current.as_ref() != Some(archive) {
            return Err(target(
                "target password history keys conflict with snapshot",
            ));
        }
    }
    // The evaluator's custody versions, checked like the field-key versions
    // before anything is written: a conflicting version would open its keys
    // under another derivation.
    check_versions(
        &snapshot.history_key_versions,
        &history_keys.list_key_versions().await?,
        "history key",
    )?;
    check_versions(
        &snapshot.key_versions,
        &backend.list_key_versions().await?,
        "key",
    )?;

    let mut result = ImportResult::default();

    // The import is recorded first: an interruption from here on leaves a
    // target that only this same snapshot's import resumes.
    if fresh {
        backend.bind_operation_resource(&record).await?;
    }
    if let Some(org) = &snapshot.organization {
        if backend
            .insert_instance_organization(org, audit("import_organization", &org.id.to_string()))
            .await?
        {
            result.organizations += 1;
        } else if backend.instance_organization().await?.as_ref() != Some(org) {
            return Err(target("the target took another installation organization"));
        }
    }
    for entry in &snapshot.oidc_issuers {
        if backend
            .import_oidc_issuer(
                &entry.issuer,
                &entry.keys,
                audit("import_oidc_issuer", &entry.issuer.id.to_string()),
            )
            .await?
        {
            result.oidc_issuers += 1;
        }
    }

    for params in &snapshot.key_versions {
        if backend
            .insert_key_version(
                params,
                audit("import_key_version", &params.version.to_string()),
            )
            .await?
        {
            result.key_versions += 1;
        } else if !backend.list_key_versions().await?.contains(params) {
            return Err(target("key version changed during import"));
        }
    }

    // The setup precedes credentials and is insert-only. Recheck the stored
    // value after insertion: a concurrent initializer must never replace it.
    if let Some(setup) = &snapshot.opaque_server_setup {
        backend
            .insert_instance_secret(
                setup_kind,
                setup,
                audit("import_opaque_setup", "opaque_server_setup"),
            )
            .await?;
        if backend.get_instance_secret(setup_kind).await?.as_ref() != Some(setup) {
            return Err(target("target OPAQUE setup changed during import"));
        }
    }

    info!(count = snapshot.projects.len(), "importing projects...");
    for project in &snapshot.projects {
        // Already in the store (the system project, or an earlier import): kept as stored.
        result.projects += created(
            backend
                .create_project(project, audit("import_project", &project.id.to_string()))
                .await,
            || async { Ok(backend.get_project(project.id).await?.is_some()) },
        )
        .await?;
    }
    backend
        .ensure_system_project(audit("ensure_system_project", "system"))
        .await?;

    info!(count = snapshot.profiles.len(), "importing profiles...");
    for profile in &snapshot.profiles {
        match backend
            .create_profile(profile, audit("import_profile", &profile.id.to_string()))
            .await
        {
            Ok(()) => result.profiles += 1,
            // Imported before: a repeated import adds nothing. Another
            // profile holding the user name is a real conflict.
            Err(sid_core::Error::Conflict(_))
                if backend.get_profile(profile.id).await?.is_some() => {}
            Err(e) => return Err(e.into()),
        }
    }

    // The write cutoffs precede the epochs they fence: from the first
    // imported key, no write goes under an epoch the source had withdrawn.
    // Raising is monotonic, so a target already past a cutoff keeps its own.
    if let Some(cutoff) = snapshot.history_write_cutoff {
        backend
            .raise_history_write_cutoff(
                cutoff,
                audit("import_history_write_cutoff", "password_history"),
            )
            .await?;
    }
    if let Some(cutoff) = snapshot.history_key_write_cutoff {
        history_keys
            .raise_write_cutoff(
                cutoff,
                entry("import_history_key_write_cutoff", "password_history_keys"),
            )
            .await?;
    }

    // Keys precede history and history precedes credentials: a failure never
    // installs a password without its retained comparison state, nor a
    // history whose keys are missing. The evaluator's custody versions
    // precede the keys they open.
    for params in &snapshot.history_key_versions {
        if history_keys
            .insert_key_version(
                params,
                entry("import_history_key_version", &params.version.to_string()),
            )
            .await?
        {
            result.key_versions += 1;
        } else if !history_keys.list_key_versions().await?.contains(params) {
            return Err(target("history key version changed during import"));
        }
    }
    for archive in &snapshot.history_keys {
        if history_keys
            .import_keys(
                archive,
                entry("import_history_keys", "password_history_keys"),
            )
            .await?
        {
            result.history_keys += 1;
        }
    }
    for (_, archive) in &snapshot.password_histories {
        if let Some(archive) = archive
            && backend
                .import_password_history(
                    archive,
                    audit("import_password_history", &archive.owner.to_string()),
                )
                .await?
        {
            result.password_histories += 1;
        }
    }

    info!(count = snapshot.principals.len(), "importing principals...");
    for principal in &snapshot.principals {
        backend
            .save_principal(
                principal,
                audit("import_principal", &principal.id.to_string()),
            )
            .await?;
        result.principals += 1;
    }

    info!(
        count = snapshot.credentials.len(),
        "importing credentials..."
    );
    for credential in &snapshot.credentials {
        match backend
            .create_credential(
                credential,
                audit("import_credential", &credential.id.to_string()),
            )
            .await
        {
            Ok(()) => result.credentials += 1,
            Err(sid_core::Error::Conflict(_))
                if backend.get_credential(credential.id).await?.as_ref() == Some(credential) => {}
            Err(e) => return Err(e.into()),
        }
    }

    info!(count = snapshot.sessions.len(), "importing sessions...");
    for session in &snapshot.sessions {
        backend
            .create_session(session, audit("import_session", &session.id.to_string()))
            .await?;
        result.sessions += 1;
    }

    // Service bindings: the pairwise `sub` of every client.
    for binding in &snapshot.service_bindings {
        if backend
            .import_service_binding(
                binding,
                audit("import_service_binding", &binding.binding_id.to_string()),
            )
            .await?
        {
            result.service_bindings += 1;
        }
    }

    // Machine users before the resource access and role assignments that
    // name them.
    for mu in &snapshot.machine_users {
        result.machine_users += created(
            backend
                .create_machine_user(mu, audit("import_machine_user", &mu.id.to_string()))
                .await,
            || async { Ok(backend.get_machine_user(mu.id).await?.is_some()) },
        )
        .await?;
    }

    // Applications, then their resource roles (the retired ones keep their
    // indicators reserved), then their client roles (a client may name a
    // resource as its default), then access.
    for app in &snapshot.applications {
        result.applications += created(
            backend
                .create_application(
                    app,
                    None,
                    None,
                    audit("import_application", &app.id.to_string()),
                )
                .await,
            || async { Ok(backend.get_application(app.id).await?.is_some()) },
        )
        .await?;
    }
    for resource in &snapshot.protected_resources {
        if backend
            .import_protected_resource(
                resource,
                audit("import_protected_resource", &resource.id.to_string()),
            )
            .await?
        {
            result.protected_resources += 1;
        }
    }
    for client in &snapshot.oauth2_clients {
        result.oauth2_clients += created(
            backend
                .create_oauth2_client(client, audit("import_oauth2_client", &client.client_id))
                .await,
            || async {
                Ok(backend
                    .get_oauth2_client(&client.client_id)
                    .await?
                    .is_some())
            },
        )
        .await?;
    }
    for access in &snapshot.resource_access {
        // Setting access is idempotent: a repeated import keeps it as stored.
        if backend
            .resource_access(&access.client_id, access.resource_id)
            .await?
            .is_none()
        {
            let subject = format!("{}:{}", access.client_id, access.resource_id);
            backend
                .set_resource_access(access, audit("import_resource_access", &subject))
                .await?;
            result.resource_access += 1;
        }
    }

    for token in &snapshot.refresh_tokens {
        result.refresh_tokens += created(
            backend
                .create_refresh_token(token, audit("import_refresh_token", &token.id.to_string()))
                .await,
            || async {
                Ok(backend
                    .get_refresh_token_by_hash(&token.token_hash)
                    .await?
                    .is_some_and(|stored| stored.id == token.id))
            },
        )
        .await?;
    }

    for iat in &snapshot.initial_access_tokens {
        backend
            .create_initial_access_token(iat, audit("import_iat", &iat.id.to_string()))
            .await?;
        result.initial_access_tokens += 1;
    }

    for role in &snapshot.roles {
        result.roles += created(
            backend
                .create_role(role, audit("import_role", &role.id.to_string()))
                .await,
            || async { Ok(backend.get_role(role.id).await?.is_some()) },
        )
        .await?;
    }
    for group in &snapshot.groups {
        backend
            .create_group(group, audit("import_group", &group.id.to_string()))
            .await?;
        result.groups += 1;
    }
    for member in &snapshot.group_members {
        backend
            .add_to_group(
                member,
                audit(
                    "import_group_member",
                    &format!("{}:{}", member.group_id, member.profile_id),
                ),
            )
            .await?;
        result.group_members += 1;
    }

    // Role assignments after their roles and principals, a redelegated one
    // after its source. They are restored as recorded, envelope and
    // provenance included: the source installation authorized them.
    for assignment in sources_first(&snapshot.role_assignments)? {
        result.role_assignments += created(
            backend
                .create_role_assignment(
                    assignment,
                    audit("import_role_assignment", &assignment.id.to_string()),
                )
                .await,
            || async {
                Ok(assignments_of(backend, &assignment.principal)
                    .await?
                    .iter()
                    .any(|a| a.id == assignment.id))
            },
        )
        .await?;
    }

    for policy in &snapshot.cedar_policies {
        backend
            .create_cedar_policy(policy, audit("import_cedar_policy", &policy.id.to_string()))
            .await?;
        result.cedar_policies += 1;
    }
    for meta in &snapshot.profile_metadata {
        backend
            .set_profile_metadata(
                meta,
                audit(
                    "import_profile_metadata",
                    &format!("{}:{}", meta.profile_id, meta.key),
                ),
            )
            .await?;
        result.profile_metadata += 1;
    }

    info!(count = snapshot.devices.len(), "importing devices...");
    for device in &snapshot.devices {
        result.devices += created(
            backend
                .create_device(device, audit("import_device", &device.id.to_string()))
                .await,
            || async { Ok(backend.get_device(device.id).await?.is_some()) },
        )
        .await?;
    }
    // Key bindings after their devices, revoked ones included.
    for binding in &snapshot.device_attestations {
        if backend
            .import_device_attestation(
                binding,
                audit("import_device_attestation", &binding.device_id.to_string()),
            )
            .await?
        {
            result.device_attestations += 1;
        }
    }
    for code in &snapshot.device_auth_codes {
        backend
            .create_device_auth_code(code, audit("import_device_auth_code", &code.id.to_string()))
            .await?;
        result.device_auth_codes += 1;
    }

    for grant in &snapshot.profile_grants {
        result.profile_grants += created(
            backend
                .create_profile_grant(grant, audit("import_profile_grant", &grant.id.to_string()))
                .await,
            || async { Ok(backend.get_profile_grant(grant.id).await?.is_some()) },
        )
        .await?;
    }
    for provider in &snapshot.upstream_providers {
        result.upstream_providers += created(
            backend
                .create_upstream_provider(
                    provider,
                    audit("import_upstream_provider", &provider.id.to_string()),
                )
                .await,
            || async { Ok(backend.get_upstream_provider(provider.id).await?.is_some()) },
        )
        .await?;
    }
    for identity in &snapshot.upstream_identities {
        result.upstream_identities += created(
            backend
                .create_upstream_identity(
                    identity,
                    audit("import_upstream_identity", &identity.id.to_string()),
                )
                .await,
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
    for pat in &snapshot.personal_access_tokens {
        backend
            .create_pat(pat, None, audit("import_pat", &pat.id.to_string()))
            .await?;
        result.personal_access_tokens += 1;
    }
    for cred in &snapshot.machine_credentials {
        result.machine_credentials += created(
            backend
                .add_machine_credential(cred, None, audit("import_machine_credential", &cred.kid))
                .await,
            || async {
                Ok(backend
                    .get_machine_credential_by_kid(&cred.kid)
                    .await?
                    .is_some())
            },
        )
        .await?;
    }
    for grant in &snapshot.impersonation_grants {
        backend
            .save_impersonation_grant(
                grant,
                audit(
                    "import_impersonation_grant",
                    &grant.machine_user_id.to_string(),
                ),
            )
            .await?;
        result.impersonation_grants += 1;
    }
    for req in &snapshot.closure_requests {
        result.closure_requests += created(
            backend
                .create_closure_request(
                    req,
                    audit("import_closure_request", &req.profile_id.to_string()),
                )
                .await,
            || async { Ok(backend.get_closure_request(req.profile_id).await?.is_some()) },
        )
        .await?;
    }
    for job in &snapshot.export_jobs {
        result.export_jobs += created(
            backend
                .create_export_job(job, audit("import_export_job", &job.id.to_string()))
                .await,
            || async { Ok(backend.get_export_job_by_id(job.id).await?.is_some()) },
        )
        .await?;
    }

    // Owed deliveries and dead letters: stored, not run. The restored
    // installation's workers take them when the host activates it.
    for work in &snapshot.durable_work {
        if backend.import_work(work).await? {
            result.durable_work += 1;
        }
    }
    // The periods keyed commands are admitted under, before the completions
    // named with them; then the completions (their results answer retries)
    // and the identifiers keyed creations bound.
    backend
        .import_operation_periods(&snapshot.operation_periods)
        .await?;
    for record in &snapshot.operation_results {
        if backend.import_operation_result(record).await? {
            result.operation_results += 1;
        }
    }
    for binding in &snapshot.operation_resources {
        if backend.import_operation_resource(binding).await? {
            result.operation_resources += 1;
        }
    }

    for session in &snapshot.magic_link_sessions {
        backend
            .create_magic_link_session(session, audit("import_magic_link", &session.id.to_string()))
            .await?;
        result.magic_link_sessions += 1;
    }
    for target in &snapshot.scim_outbound_targets {
        result.scim_outbound_targets += created(
            backend
                .create_scim_outbound_target(
                    target,
                    audit("import_scim_outbound_target", &target.id.to_string()),
                )
                .await,
            || async { Ok(backend.get_scim_outbound_target(target.id).await?.is_some()) },
        )
        .await?;
    }
    for record in &snapshot.scim_outbound_records {
        // A mapping is identified by its target, entity and type.
        result.scim_outbound_records += created(
            backend
                .create_scim_outbound_record(
                    record,
                    audit(
                        "import_scim_outbound_record",
                        &format!("{}:{}", record.target_id, record.sid_entity_id),
                    ),
                )
                .await,
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
    for config in &snapshot.branding_configs {
        result.branding_configs += created(
            backend
                .create_branding_config(
                    config,
                    audit("import_branding_config", &config.id.to_string()),
                )
                .await,
            || async { Ok(backend.get_branding_config(config.id).await?.is_some()) },
        )
        .await?;
    }
    for entry in &snapshot.outbound_dlq_entries {
        result.outbound_dlq_entries += created(
            backend
                .create_outbound_dlq_entry(
                    entry,
                    audit("import_outbound_dlq", &entry.id.to_string()),
                )
                .await,
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

/// Refuse a snapshot whose derivation parameters repeat a version or
/// conflict with the target's for the same version.
fn check_versions(
    snapshot: &[sid_keys::KeyVersionParams],
    target: &[sid_keys::KeyVersionParams],
    what: &str,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for params in snapshot {
        if !seen.insert(params.version) {
            return Err(invalid(format!("duplicate {what} version in snapshot")));
        }
        if target
            .iter()
            .any(|v| v.version == params.version && v != params)
        {
            return Err(SnapshotError::Target(format!(
                "target {what} derivation parameters conflict with snapshot"
            )));
        }
    }
    Ok(())
}

/// Count of records a create added: 1, or 0 when the same record (`stored`
/// finds it by its id) was imported before. Any other conflict, such as a
/// different record holding the same unique name, fails the import.
async fn created<Fut>(result: sid_core::Result<()>, stored: impl FnOnce() -> Fut) -> Result<u64>
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
) -> Result<Vec<&sid_core::models::RoleAssignment>> {
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
            return Err(invalid(format!(
                "role assignments {:?} depend on each other in a cycle",
                pending.iter().map(|a| a.id.to_string()).collect::<Vec<_>>()
            )));
        }
    }
    Ok(ordered)
}

/// The audit entry of an imported record.
fn entry(action: &str, resource: &str) -> AuditEntry {
    AuditEntry::system(action, resource).with_metadata(serde_json::json!({"tool": "snapshot"}))
}

/// The mutation context of an imported record.
fn audit(action: &str, resource: &str) -> MutationContext {
    entry(action, resource).into()
}

/// Result of an import operation with per-entity counts.
#[derive(Debug, Default)]
pub struct ImportResult {
    pub organizations: u64,
    pub oidc_issuers: u64,
    pub key_versions: u64,
    pub history_keys: u64,
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
    pub device_attestations: u64,
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
    pub operation_resources: u64,
    pub magic_link_sessions: u64,
    pub scim_outbound_targets: u64,
    pub scim_outbound_records: u64,
    pub outbound_dlq_entries: u64,
    pub branding_configs: u64,
}

impl ImportResult {
    /// Total imported entities.
    pub fn total(&self) -> u64 {
        [
            self.organizations,
            self.oidc_issuers,
            self.key_versions,
            self.history_keys,
            self.password_histories,
            self.projects,
            self.profiles,
            self.principals,
            self.credentials,
            self.sessions,
            self.service_bindings,
            self.applications,
            self.protected_resources,
            self.oauth2_clients,
            self.resource_access,
            self.refresh_tokens,
            self.initial_access_tokens,
            self.roles,
            self.groups,
            self.group_members,
            self.role_assignments,
            self.cedar_policies,
            self.profile_metadata,
            self.devices,
            self.device_attestations,
            self.device_auth_codes,
            self.profile_grants,
            self.upstream_providers,
            self.upstream_identities,
            self.personal_access_tokens,
            self.machine_users,
            self.machine_credentials,
            self.impersonation_grants,
            self.closure_requests,
            self.export_jobs,
            self.durable_work,
            self.operation_results,
            self.operation_resources,
            self.magic_link_sessions,
            self.scim_outbound_targets,
            self.scim_outbound_records,
            self.outbound_dlq_entries,
            self.branding_configs,
        ]
        .iter()
        .sum()
    }
}

impl std::fmt::Display for ImportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Import Summary:")?;
        writeln!(f, "  Organization:         {}", self.organizations)?;
        writeln!(f, "  OIDC Issuers:         {}", self.oidc_issuers)?;
        writeln!(f, "  Key Versions:         {}", self.key_versions)?;
        writeln!(f, "  History Keys:         {}", self.history_keys)?;
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
        writeln!(f, "  Device Key Bindings:  {}", self.device_attestations)?;
        writeln!(f, "  Device Auth Codes:    {}", self.device_auth_codes)?;
        writeln!(f, "  Profile Grants:       {}", self.profile_grants)?;
        writeln!(f, "  Upstream Providers:   {}", self.upstream_providers)?;
        writeln!(f, "  Upstream Identities:  {}", self.upstream_identities)?;
        writeln!(f, "  PATs:                 {}", self.personal_access_tokens)?;
        writeln!(f, "  Machine Users:        {}", self.machine_users)?;
        writeln!(f, "  Machine Credentials:  {}", self.machine_credentials)?;
        writeln!(f, "  Impersonation Grants: {}", self.impersonation_grants)?;
        writeln!(f, "  Closure Requests:     {}", self.closure_requests)?;
        writeln!(f, "  Export Jobs:          {}", self.export_jobs)?;
        writeln!(f, "  Durable Work:         {}", self.durable_work)?;
        writeln!(f, "  Operation Results:    {}", self.operation_results)?;
        writeln!(f, "  Operation Resources:  {}", self.operation_resources)?;
        writeln!(f, "  Magic Link Sessions:  {}", self.magic_link_sessions)?;
        writeln!(f, "  SCIM Targets:         {}", self.scim_outbound_targets)?;
        writeln!(f, "  SCIM Records:         {}", self.scim_outbound_records)?;
        writeln!(f, "  SCIM DLQ Entries:     {}", self.outbound_dlq_entries)?;
        writeln!(f, "  Branding Configs:     {}", self.branding_configs)?;
        writeln!(f, "  Total:                {}", self.total())
    }
}

#[cfg(test)]
mod tests;
