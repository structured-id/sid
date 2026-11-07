// SPDX-License-Identifier: AGPL-3.0-only
//! Export an installation's database into a snapshot.

use chrono::Utc;
use sid_plugin::SnapshotRules;
use tracing::info;

use super::{IssuerSnapshot, Result, Snapshot, SnapshotError, Store};

/// More anomaly events than a page offset counts.
fn invalid_count() -> SnapshotError {
    SnapshotError::Invalid("more anomaly events than an export pages through".into())
}

/// Read every persistent entity of `store`, every chain of its audit log
/// and the history evaluator's sealed keys into a snapshot checked by
/// `rules`. The caller quiesces the installation first: the snapshot is
/// consistent only when nothing writes while it is read. Expired sessions
/// are left out.
pub async fn export(store: Store<'_>, rules: &dyn SnapshotRules) -> Result<Snapshot> {
    let Store {
        storage: backend,
        audit,
        history_keys: keys,
    } = store;
    let mut snapshot = Snapshot::new(backend.name());
    let mut chains = audit.list_chain_ids().await?;
    chains.sort();
    for chain in chains {
        snapshot
            .audit_chains
            .push(audit.export_chain(&chain).await?);
    }
    snapshot.organization = backend.instance_organization().await?;
    snapshot.metadata.installation_org = snapshot.organization.as_ref().map(|o| o.id);
    for issuer in backend.list_oidc_issuers().await? {
        let keys = backend.oidc_issuer_signing_keys(issuer.id).await?;
        snapshot.oidc_issuers.push(IssuerSnapshot { issuer, keys });
    }
    snapshot.key_versions = backend.list_key_versions().await?;
    // The evaluator's keys are sealed under its own custody, which may run
    // apart from this service and rotate on its own.
    snapshot.history_key_versions = keys.list_key_versions().await?;
    // A raised cutoff withdraws keys; the target must keep refusing them.
    snapshot.history_write_cutoff = backend.history_write_cutoff().await?;
    snapshot.history_key_write_cutoff = keys.write_cutoff().await?;
    // Fences keep refusing what they refused; the trail is its record.
    snapshot.history_key_records = keys.export_key_records().await?;
    snapshot.opaque_server_setup = backend
        .get_instance_secret(sid_core::models::InstanceSecret::OpaqueServerSetup)
        .await?;

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

    info!("exporting per-profile entities...");
    let installation = snapshot.metadata.installation_org;
    for profile in &snapshot.profiles {
        let pid = profile.id;
        snapshot
            .password_histories
            .push((pid, backend.export_password_history(pid).await?));
        // The evaluator keys its store by the owner's history domain, which
        // the installation authority and the profile define.
        if let Some(installation) = installation
            && let Some(archive) = keys
                .export_keys(&rules.history_owner_domain(installation, pid))
                .await?
        {
            snapshot.history_keys.push(archive);
        }
        snapshot
            .profile_emails
            .extend(backend.list_profile_emails(pid).await?);
        snapshot
            .profile_phones
            .extend(backend.list_profile_phones(pid).await?);
        snapshot
            .webauthn_user_handles
            .extend(backend.export_webauthn_user_handles(pid).await?);
        snapshot
            .credentials
            .extend(backend.get_credentials_by_profile(pid, None).await?);
        let now = Utc::now();
        for session in backend.list_sessions(&pid).await? {
            if session.expires_at <= now {
                continue;
            }
            let grants = backend.export_session_grants(session.id).await?;
            if !(grants.refresh_tokens.is_empty()
                && grants.authorization_codes.is_empty()
                && grants.native_generations.is_empty())
            {
                snapshot.session_grants.push(grants);
            }
            snapshot.sessions.push(session);
        }
        snapshot
            .service_bindings
            .extend(backend.list_service_bindings(pid).await?);
        snapshot
            .profile_metadata
            .extend(backend.list_profile_metadata(pid).await?);
        snapshot
            .devices
            .extend(backend.list_devices_by_profile(pid).await?);
        snapshot
            .device_attestations
            .extend(backend.list_device_attestations_by_profile(pid).await?);
        // Memberships of this profile only: each is listed once.
        for group in backend.list_groups_for_profile(pid).await? {
            snapshot.group_members.extend(
                backend
                    .list_group_members(group.id)
                    .await?
                    .into_iter()
                    .filter(|m| m.profile_id == pid),
            );
        }
        snapshot
            .role_assignments
            .extend(backend.list_role_assignments_for_profile(pid).await?);
        snapshot
            .profile_grants
            .extend(backend.list_profile_grants_for_profile(pid).await?);
        snapshot
            .upstream_identities
            .extend(backend.list_upstream_identities_by_profile(pid).await?);
        snapshot
            .personal_access_tokens
            .extend(backend.list_pats_by_profile(pid).await?);
        if let Some(closure) = backend.get_closure_request(pid).await? {
            snapshot.closure_requests.push(closure);
        }
        if let Some(job) = backend.get_export_job(pid).await? {
            snapshot.export_jobs.push(job);
        }
        snapshot
            .consents
            .extend(backend.list_consents_by_profile(pid).await?);
        if let Some(preferences) = backend.get_notification_preferences(pid).await? {
            snapshot.notification_preferences.push(preferences);
        }
        if let Some(source) = backend.get_registration_source(pid).await? {
            snapshot.registration_sources.push((pid, source));
        }
    }

    info!("exporting per-project entities...");
    for project in &snapshot.projects {
        let proj_id = project.id;
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

        // OAuth2 clients, with the access and roles each holds.
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
                snapshot.resource_access.extend(
                    backend
                        .list_resource_access_by_client(&client.client_id)
                        .await?,
                );
                snapshot.role_assignments.extend(
                    backend
                        .list_role_assignments_for_oauth_client(&client.client_id)
                        .await?,
                );
            }
            snapshot.oauth2_clients.extend(batch);
        }

        snapshot.roles.extend(backend.list_roles(proj_id).await?);
        let groups = backend.list_groups(proj_id).await?;
        for group in &groups {
            snapshot
                .role_assignments
                .extend(backend.list_role_assignments_for_group(group.id).await?);
        }
        snapshot.groups.extend(groups);
        snapshot.cedar_policies.extend(
            backend
                .list_cedar_policies(sid_core::models::PolicyScope::Project(proj_id))
                .await?,
        );
        // Grants already collected per profile are listed once.
        for grant in backend.list_profile_grants_for_project(proj_id).await? {
            if !snapshot.profile_grants.iter().any(|g| g.id == grant.id) {
                snapshot.profile_grants.push(grant);
            }
        }
        snapshot.initial_access_tokens.extend(
            backend
                .list_initial_access_tokens_by_project(proj_id)
                .await?,
        );
        let machine_users = backend.list_machine_users_by_project(proj_id).await?;
        for mu in &machine_users {
            snapshot
                .machine_credentials
                .extend(backend.list_machine_credentials_by_user(mu.id).await?);
            snapshot
                .impersonation_grants
                .extend(backend.list_impersonation_grants(mu.id).await?);
            snapshot.role_assignments.extend(
                backend
                    .list_role_assignments_for_machine_user(mu.id)
                    .await?,
            );
            snapshot.resource_access.extend(
                backend
                    .list_resource_access_by_client(&mu.client_id)
                    .await?,
            );
        }
        snapshot.machine_users.extend(machine_users);
        snapshot
            .branding_configs
            .extend(backend.list_branding_configs(proj_id).await?);
        let scim_targets = backend.list_scim_outbound_targets(proj_id).await?;
        for target in &scim_targets {
            snapshot
                .scim_outbound_records
                .extend(backend.list_scim_outbound_records(target.id).await?);
            snapshot
                .outbound_dlq_entries
                .extend(backend.list_outbound_dlq_entries(target.id).await?);
        }
        snapshot.scim_outbound_targets.extend(scim_targets);
        snapshot
            .flow_configs
            .extend(backend.list_flow_configs(proj_id).await?);
        for flow in sid_core::models::FlowType::all() {
            snapshot
                .flow_actions
                .extend(backend.list_flow_actions(proj_id, *flow, None).await?);
        }
    }

    info!("exporting principals...");
    snapshot.email_policy = Some(backend.email_policy_activation().await?);
    let mut after = None;
    loop {
        let batch = backend.export_principals(after, 1000).await?;
        let Some(last) = batch.last() else { break };
        after = Some(last.entity.id);
        snapshot.principals.extend(batch);
    }
    snapshot.principal_quarantine = backend.export_principal_quarantine().await?;

    info!("exporting installation-wide entities...");
    // Upstream providers, disabled ones included: an import restores them as
    // they were.
    snapshot
        .upstream_providers
        .extend(backend.list_upstream_providers().await?);
    snapshot.sod_rules.extend(backend.list_sod_rules().await?);
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
    // Cedar policies of the installation and of each protected resource.
    snapshot.cedar_policies.extend(
        backend
            .list_cedar_policies(sid_core::models::PolicyScope::Installation)
            .await?,
    );
    for resource in &snapshot.protected_resources {
        snapshot.cedar_policies.extend(
            backend
                .list_cedar_policies(sid_core::models::PolicyScope::Resource(resource.id))
                .await?,
        );
    }
    // Sign-ins in flight: a device code awaiting its decision or redeemed,
    // a magic link sent or consumed.
    snapshot.device_auth_codes = backend.export_device_auth_codes().await?;
    snapshot.magic_link_sessions = backend.export_magic_link_sessions().await?;
    // Durable work: owed deliveries and the failed ones kept as dead letters.
    snapshot.durable_work = backend.export_work().await?;
    // Completed keyed commands and the periods they were named with: a retry
    // that arrives after the move must still find its result instead of
    // executing again, and a retired period stays retired.
    snapshot.operation_periods = backend.export_operation_periods().await?;
    snapshot.operation_results = backend.export_operation_results().await?;
    snapshot.operation_resources = backend.export_operation_resources().await?;

    // Invites in every state, and each one's redemptions.
    let all = sid_core::models::InviteFilter::default();
    let mut invite_offset = 0u64;
    loop {
        let batch = backend.list_invites(&all, invite_offset, 1000).await?;
        if batch.is_empty() {
            break;
        }
        invite_offset += batch.len() as u64;
        for invite in &batch {
            let mut offset = 0u64;
            loop {
                let used = backend
                    .list_invite_redemptions(invite.id, offset, 1000)
                    .await?;
                if used.is_empty() {
                    break;
                }
                offset += used.len() as u64;
                snapshot
                    .invite_redemptions
                    .extend(used.into_iter().map(|r| (invite.id, r)));
            }
        }
        snapshot.invites.extend(batch);
    }
    snapshot.access_requests = backend.export_access_requests().await?;
    snapshot.reset_sessions = backend.export_reset_sessions().await?;
    // The policies a sign-in or a registration is admitted under.
    snapshot.enrollment_policy = backend.enrollment_policy().await?;
    snapshot.bootstrap_policy = backend.bootstrap_policy().await?;
    snapshot.login_policy_epoch = backend.export_login_policy_epoch().await?;
    snapshot.ip_allowlist = backend.list_ip_allowlist_entries().await?;
    // What the sign-in rules learned and fired.
    snapshot.ip_reputation = backend.export_ip_reputation().await?;
    let mut event_offset = 0i32;
    loop {
        let batch = backend
            .list_anomaly_events(None, 1000, event_offset)
            .await?;
        if batch.is_empty() {
            break;
        }
        event_offset = event_offset
            .checked_add(i32::try_from(batch.len()).map_err(|_| invalid_count())?)
            .ok_or_else(invalid_count)?;
        snapshot.anomaly_events.extend(batch);
    }
    snapshot.login_locations = backend.export_login_locations().await?;
    // Provisioning connectors of every organization, with their credentials
    // and the roles they hold.
    snapshot.provisioning_connectors = backend.export_provisioning_connectors().await?;
    for connector in &snapshot.provisioning_connectors {
        snapshot
            .provisioning_credentials
            .extend(backend.list_provisioning_credentials(connector.id).await?);
        snapshot.role_assignments.extend(
            backend
                .list_role_assignments_for_provisioning_connector(connector.id)
                .await?,
        );
    }
    snapshot.ceremony = backend.export_ceremony_state().await?;

    super::import::validate(&snapshot, rules)?;
    snapshot.metadata.total_entities = snapshot.count_entities();
    snapshot.metadata.created_at = Utc::now();
    info!(total = snapshot.metadata.total_entities, "export complete");
    Ok(snapshot)
}
