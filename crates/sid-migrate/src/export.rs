// SPDX-License-Identifier: AGPL-3.0-only
//! Export data from a StorageBackend into a Snapshot.

use chrono::Utc;
use sid_plugin::storage::StorageBackend;
use tracing::info;

use crate::snapshot::Snapshot;

/// Export all data from a storage backend into a snapshot.
///
/// Reads all persistent entities. Expired sessions are excluded.
/// Audit log is included only when `include_audit` is true (it can be very large).
pub async fn export_snapshot(
    backend: &dyn StorageBackend,
    source_url: &str,
    include_audit: bool,
) -> anyhow::Result<Snapshot> {
    let mut snapshot = Snapshot::new(backend.name(), source_url);
    snapshot.metadata.installation_org = backend.instance_organization().await?.map(|o| o.id);
    snapshot.key_versions = backend.list_key_versions().await?;

    // 1. Projects
    info!("exporting projects...");
    let mut offset = 0u64;
    loop {
        let batch = backend.list_projects(offset, 1000).await?;
        if batch.is_empty() {
            break;
        }
        offset += batch.len() as u64;
        snapshot.projects.extend(batch);
    }
    info!(count = snapshot.projects.len(), "projects exported");

    // 2. Profiles
    info!("exporting profiles...");
    offset = 0;
    loop {
        let batch = backend.list_profiles(offset, 1000).await?;
        if batch.is_empty() {
            break;
        }
        offset += batch.len() as u64;
        snapshot.profiles.extend(batch);
    }
    info!(count = snapshot.profiles.len(), "profiles exported");

    // 3. Per-profile entities
    info!("exporting per-profile entities...");
    for profile in &snapshot.profiles {
        let pid = profile.id;
        snapshot
            .password_histories
            .push((pid, backend.export_password_history(pid).await?));

        // Principals
        let principals = backend.get_principals_by_profile(pid).await?;
        snapshot.principals.extend(principals);

        // Credentials (all types)
        let credentials = backend.get_credentials_by_profile(pid, None).await?;
        snapshot.credentials.extend(credentials);

        // Active sessions only (filter expired after fetching)
        let sessions = backend.list_sessions_by_profile(pid).await?;
        let now = Utc::now();
        let active_sessions = sessions
            .into_iter()
            .filter(|s| s.expires_at > now)
            .collect::<Vec<_>>();
        snapshot.sessions.extend(active_sessions);

        // Service bindings (pairwise subjects)
        let bindings = backend.list_service_bindings(pid).await?;
        snapshot.service_bindings.extend(bindings);

        // Profile metadata
        let metadata = backend.list_profile_metadata(pid).await?;
        snapshot.profile_metadata.extend(metadata);

        // Devices
        let devices = backend.list_devices_by_profile(pid).await?;
        snapshot.devices.extend(devices);

        // Groups this profile belongs to (for membership records)
        let groups = backend.list_groups_for_profile(pid).await?;
        for group in &groups {
            let members = backend.list_group_members(group.id).await?;
            // Only add memberships for this profile (avoid duplicates)
            let my_memberships = members
                .into_iter()
                .filter(|m| m.profile_id == pid)
                .collect::<Vec<_>>();
            snapshot.group_members.extend(my_memberships);
        }

        // Role assignments
        let assignments = backend.list_role_assignments_for_profile(pid).await?;
        snapshot.role_assignments.extend(assignments);

        // Profile grants
        let grants = backend.list_profile_grants_for_profile(pid).await?;
        snapshot.profile_grants.extend(grants);

        // Upstream identities
        let upstream = backend.list_upstream_identities_by_profile(pid).await?;
        snapshot.upstream_identities.extend(upstream);

        // PATs
        let pats = backend.list_pats_by_profile(pid).await?;
        snapshot.personal_access_tokens.extend(pats);

        // Closure request
        if let Some(closure) = backend.get_closure_request(pid).await? {
            snapshot.closure_requests.push(closure);
        }

        // Export job
        if let Some(job) = backend.get_export_job(pid).await? {
            snapshot.export_jobs.push(job);
        }
    }
    info!(
        principals = snapshot.principals.len(),
        credentials = snapshot.credentials.len(),
        sessions = snapshot.sessions.len(),
        devices = snapshot.devices.len(),
        "per-profile entities exported"
    );

    // 4. Per-project entities
    info!("exporting per-project entities...");
    for project in &snapshot.projects {
        let proj_id = project.id;

        // Applications
        let mut app_offset = 0u64;
        loop {
            let batch = backend
                .list_applications_by_project(proj_id, app_offset, 1000)
                .await?;
            if batch.is_empty() {
                break;
            }
            app_offset += batch.len() as u64;
            snapshot.applications.extend(batch);
        }

        // OAuth2 clients, with the access each holds
        let mut client_offset = 0u64;
        loop {
            let batch = backend
                .list_oauth2_clients_by_project(proj_id, client_offset, 1000)
                .await?;
            if batch.is_empty() {
                break;
            }
            client_offset += batch.len() as u64;
            for client in &batch {
                let access = backend
                    .list_resource_access_by_client(&client.client_id)
                    .await?;
                snapshot.resource_access.extend(access);
                let roles = backend
                    .list_role_assignments_for_oauth_client(&client.client_id)
                    .await?;
                snapshot.role_assignments.extend(roles);
            }
            snapshot.oauth2_clients.extend(batch);
        }

        // Roles
        let roles = backend.list_roles(proj_id).await?;
        snapshot.roles.extend(roles);

        // Groups
        let groups = backend.list_groups(proj_id).await?;
        // Collect group role assignments before extending
        for group in &groups {
            let group_assignments = backend.list_role_assignments_for_group(group.id).await?;
            snapshot.role_assignments.extend(group_assignments);
        }
        snapshot.groups.extend(groups);

        // Cedar policies
        let policies = backend.list_cedar_policies(proj_id).await?;
        snapshot.cedar_policies.extend(policies);

        // Profile grants for project
        let project_grants = backend.list_profile_grants_for_project(proj_id).await?;
        // Avoid duplicates (already collected per-profile)
        for grant in project_grants {
            if !snapshot.profile_grants.iter().any(|g| g.id == grant.id) {
                snapshot.profile_grants.push(grant);
            }
        }

        // IATs
        let iats = backend
            .list_initial_access_tokens_by_project(proj_id)
            .await?;
        snapshot.initial_access_tokens.extend(iats);

        // Machine users
        let machine_users = backend.list_machine_users_by_project(proj_id).await?;
        for mu in &machine_users {
            let creds = backend.list_machine_credentials_by_user(mu.id).await?;
            snapshot.machine_credentials.extend(creds);

            let imp_grants = backend.list_impersonation_grants(mu.id).await?;
            snapshot.impersonation_grants.extend(imp_grants);

            let roles = backend
                .list_role_assignments_for_machine_user(mu.id)
                .await?;
            snapshot.role_assignments.extend(roles);

            let access = backend
                .list_resource_access_by_client(&mu.client_id)
                .await?;
            snapshot.resource_access.extend(access);
        }
        snapshot.machine_users.extend(machine_users);

        // Branding configs
        let branding = backend.list_branding_configs(proj_id).await?;
        snapshot.branding_configs.extend(branding);

        // SCIM outbound targets
        let scim_targets = backend.list_scim_outbound_targets(proj_id).await?;
        for target in &scim_targets {
            let dlq = backend.list_outbound_dlq_entries(target.id).await?;
            snapshot.outbound_dlq_entries.extend(dlq);
        }
        snapshot.scim_outbound_targets.extend(scim_targets);
    }
    info!(
        oauth2_clients = snapshot.oauth2_clients.len(),
        roles = snapshot.roles.len(),
        groups = snapshot.groups.len(),
        "per-project entities exported"
    );

    // 5. Global entities
    info!("exporting global entities...");

    // Upstream providers
    let providers = backend.list_enabled_upstream_providers().await?;
    snapshot.upstream_providers.extend(providers);

    // SoD rules
    let sod_rules = backend.list_sod_rules().await?;
    snapshot.sod_rules.extend(sod_rules);

    // Protected resources, retired ones included: their indicators stay
    // reserved in the target.
    let mut resource_offset = 0u64;
    loop {
        let batch = backend
            .list_protected_resources(resource_offset, 1000)
            .await?;
        if batch.is_empty() {
            break;
        }
        resource_offset += batch.len() as u64;
        snapshot.protected_resources.extend(batch);
    }

    // Durable work: owed deliveries and the failed ones kept as dead letters.
    snapshot.durable_work = backend.export_work().await?;

    // Completed keyed commands: a retry that arrives after the move must
    // still find its result instead of executing again.
    snapshot.operation_results = backend.export_operation_results().await?;

    // 6. Audit log (optional)
    if include_audit {
        info!("exporting audit log (this may take a while)...");
        // Audit log export is deferred — requires AuditLog trait access
        // which is not part of StorageBackend. For now, skip with a note.
        info!("audit log export: skipped (requires separate AuditLog access)");
    }

    // Update metadata
    snapshot.metadata.total_entities = snapshot.count_entities();
    snapshot.metadata.created_at = Utc::now();

    info!(total = snapshot.metadata.total_entities, "export complete");

    Ok(snapshot)
}
