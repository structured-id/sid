// SPDX-License-Identifier: AGPL-3.0-only
//! The schema SID's records rely on: what keeps an identifier unique across
//! concurrent writers, and the lookups its queries use. Nodes that writers
//! of one thing meet on (an audit chain's head, a command key) are unique
//! too, so the first writers create one node and conflict instead of each
//! creating its own.
//!
//! The uniqueness constraints are published as one schema package, and SID
//! serves only once every one of them is in force over the stored data: a
//! store that cannot hold one is refused before the first request.

use std::time::Duration;

use coordinode_core::schema::definition::ConstraintKind;
use coordinode_embed::{Database, DatabaseError, PackageConstraint, Readiness, SchemaPackage};
use sid_core::{Error as SidError, Result as SidResult};

use super::storage;

/// How long opening waits for the constraints to come in force over the
/// stored data before it refuses to serve.
const SCHEMA_WAIT: Duration = Duration::from_secs(60);

/// Each uniqueness constraint: its name, its label and the property it
/// keeps unique.
const UNIQUE: &[(&str, &str, &str)] = &[
    ("sid_work_id", "SidWork", "id"),
    ("sid_audit_head", "SidAuditHead", "chain"),
    ("sid_audit_record", "SidAuditRecord", "id"),
    ("sid_operation_slot", "SidOperation", "slot"),
    ("sid_operation_period", "SidOperationPeriod", "period"),
    (
        "sid_operation_period_place",
        "SidOperationPeriodPlace",
        "key",
    ),
    ("sid_operation_state", "SidOperationState", "id"),
    ("sid_ceremony_state", "SidCeremonyState", "slot"),
    ("sid_ceremony_count", "SidCeremonyCount", "slot"),
    ("sid_instance_secret", "SidInstanceSecret", "name"),
    ("sid_profile_id", "SidProfile", "id"),
    ("sid_profile_username", "SidProfile", "username"),
    ("sid_phone_id", "SidPhone", "id"),
    ("sid_phone_number", "SidPhone", "number_key"),
    ("sid_phone_primary", "SidPhone", "primary_of"),
    ("sid_email_id", "SidEmail", "id"),
    ("sid_email_address", "SidEmail", "address_key"),
    ("sid_email_primary", "SidEmail", "primary_of"),
    ("sid_principal_id", "SidPrincipal", "id"),
    ("sid_principal_value", "SidPrincipal", "type_value"),
    ("sid_principal_binding_id", "SidPrincipalBinding", "id"),
    ("sid_principal_binding_pair", "SidPrincipalBinding", "pair"),
    ("sid_email_policy", "SidEmailPolicy", "scope"),
    (
        "sid_email_disposition",
        "SidEmailDisposition",
        "principal_id",
    ),
    ("sid_principal_quarantine", "SidPrincipalQuarantine", "hash"),
    ("sid_project_id", "SidProject", "id"),
    ("sid_session_id", "SidSession", "id"),
    ("sid_session_browser", "SidSession", "browser_secret_hash"),
    ("sid_refresh_token_id", "SidRefreshToken", "id"),
    ("sid_refresh_token_hash", "SidRefreshToken", "token_hash"),
    ("sid_auth_code_hash", "SidAuthCode", "code_hash"),
    ("sid_native_generation_id", "SidNativeGeneration", "id"),
    (
        "sid_native_generation_successor",
        "SidNativeGeneration",
        "successor_id",
    ),
    (
        "sid_native_credential",
        "SidNativeCredential",
        "credential_hash",
    ),
    ("sid_issuer_id", "SidIssuer", "id"),
    ("sid_issuer_handle", "SidIssuer", "handle"),
    ("sid_issuer_url", "SidIssuer", "canonical_url"),
    ("sid_issuer_authority", "SidIssuer", "authority_key"),
    ("sid_issuer_key", "SidIssuerKey", "generation_key"),
    ("sid_organization_id", "SidOrganization", "id"),
    (
        "sid_organization_instance",
        "SidOrganization",
        "is_instance",
    ),
    ("sid_application_id", "SidApplication", "id"),
    (
        "sid_application_system",
        "SidApplication",
        "system_integration",
    ),
    ("sid_client_id", "SidClient", "client_id"),
    ("sid_client_application", "SidClient", "application_id"),
    ("sid_resource_id", "SidResource", "id"),
    ("sid_resource_indicator", "SidResource", "indicator_key"),
    ("sid_resource_application", "SidResource", "application_id"),
    ("sid_resource_access", "SidResourceAccess", "pair"),
    ("sid_iat_id", "SidInitialAccessToken", "id"),
    ("sid_iat_hash", "SidInitialAccessToken", "token_hash"),
    ("sid_credential_id", "SidCredential", "id"),
    (
        "sid_credential_active_password",
        "SidCredential",
        "active_password_of",
    ),
    ("sid_webauthn_pair", "SidWebAuthnHandle", "pair"),
    ("sid_webauthn_handle", "SidWebAuthnHandle", "handle_key"),
    ("sid_password_history", "SidPasswordHistory", "owner_id"),
    ("sid_history_epoch_id", "SidHistoryEpoch", "id"),
    ("sid_history_epoch_active", "SidHistoryEpoch", "active_of"),
    ("sid_history_entry", "SidHistoryEntry", "key"),
    ("sid_history_cutoff", "SidHistoryCutoff", "id"),
    ("sid_role_id", "SidRole", "id"),
    ("sid_role_key", "SidRole", "project_key"),
    ("sid_role_name", "SidRole", "project_name"),
    ("sid_group_id", "SidGroup", "id"),
    ("sid_group_name", "SidGroup", "project_name"),
    ("sid_group_member", "SidGroupMember", "pair"),
    ("sid_assignment_id", "SidRoleAssignment", "id"),
    ("sid_assignment_set", "SidAssignmentSet", "key"),
    ("sid_admin_role", "SidAdminRole", "pair"),
    ("sid_policy_id", "SidCedarPolicy", "id"),
    ("sid_policy_name", "SidCedarPolicy", "scope_name"),
    ("sid_access_request_id", "SidAccessRequest", "id"),
    ("sid_enrollment_policy", "SidEnrollmentPolicy", "scope"),
    ("sid_bootstrap_policy", "SidBootstrapPolicy", "scope"),
    ("sid_invite_id", "SidInvite", "id"),
    ("sid_invite_code", "SidInvite", "code_key"),
    ("sid_invite_redemption", "SidInviteRedemption", "pair"),
    (
        "sid_registration_source",
        "SidRegistrationSource",
        "profile_id",
    ),
    ("sid_machine_user_id", "SidMachineUser", "id"),
    ("sid_machine_user_client", "SidMachineUser", "client_id"),
    ("sid_machine_credential", "SidMachineCredential", "kid"),
    ("sid_impersonation_grant", "SidImpersonationGrant", "triple"),
    ("sid_connector_id", "SidProvisioningConnector", "id"),
    (
        "sid_connector_client",
        "SidProvisioningConnector",
        "client_id",
    ),
    (
        "sid_connector_credential_id",
        "SidProvisioningCredential",
        "id",
    ),
    (
        "sid_connector_credential_verifier",
        "SidProvisioningCredential",
        "verifier",
    ),
    ("sid_login_policy_epoch", "SidLoginPolicyEpoch", "id"),
    ("sid_login_settings", "SidLoginSettings", "scope"),
    ("sid_profile_metadata", "SidProfileMetadata", "pair"),
    ("sid_pat_id", "SidPat", "id"),
    ("sid_pat_hash", "SidPat", "token_hash"),
    ("sid_closure_request", "SidClosureRequest", "profile_id"),
    ("sid_export_job", "SidExportJob", "id"),
    ("sid_magic_link", "SidMagicLink", "id"),
    ("sid_device_id", "SidDevice", "id"),
    ("sid_attestation_id", "SidDeviceAttestation", "id"),
    (
        "sid_attestation_device",
        "SidDeviceAttestation",
        "device_id",
    ),
    ("sid_device_auth_id", "SidDeviceAuth", "id"),
    ("sid_device_auth_hash", "SidDeviceAuth", "device_code_hash"),
    ("sid_device_auth_user_code", "SidDeviceAuth", "user_code"),
    ("sid_consent_id", "SidConsent", "id"),
    ("sid_consent_pair", "SidConsent", "pair"),
    ("sid_claim_grant_id", "SidClaimGrant", "id"),
    ("sid_claim_grant_pair", "SidClaimGrant", "pair"),
    ("sid_profile_grant_id", "SidProfileGrant", "id"),
    ("sid_profile_grant_pair", "SidProfileGrant", "pair"),
    ("sid_upstream_provider_id", "SidUpstreamProvider", "id"),
    ("sid_upstream_provider_name", "SidUpstreamProvider", "name"),
    ("sid_upstream_identity_id", "SidUpstreamIdentity", "id"),
    (
        "sid_upstream_identity_profile",
        "SidUpstreamIdentity",
        "profile_key",
    ),
    (
        "sid_upstream_identity_subject",
        "SidUpstreamIdentity",
        "subject_key",
    ),
    ("sid_reset_session", "SidResetSession", "id"),
    ("sid_anomaly_event", "SidAnomalyEvent", "id"),
    ("sid_ip_reputation", "SidIpReputation", "ip"),
    ("sid_ip_allowlist", "SidIpAllowlistEntry", "cidr"),
    (
        "sid_notification_preferences",
        "SidNotificationPreferences",
        "profile_id",
    ),
    ("sid_login_location", "SidLoginLocation", "pair"),
    ("sid_scim_target", "SidScimTarget", "id"),
    ("sid_scim_record", "SidScimRecord", "pair"),
    ("sid_scim_dead_letter", "SidScimDeadLetter", "id"),
    ("sid_flow_config", "SidFlowConfig", "pair"),
    ("sid_flow_action", "SidFlowAction", "id"),
    ("sid_branding", "SidBranding", "id"),
    ("sid_key_version", "SidKeyVersion", "version"),
    ("sid_binding", "SidBinding", "binding_id"),
    ("sid_binding_pair", "SidBinding", "pair"),
    ("sid_binding_slot", "SidBinding", "slot"),
    ("sid_job_lock", "SidJobLock", "job"),
    ("sid_audit_checkpoint", "SidAuditCheckpoint", "chain"),
    ("sid_history_key_version", "SidHistoryKeyVersion", "version"),
    ("sid_history_owner", "SidHistoryOwner", "domain"),
    ("sid_history_key_epoch", "SidHistoryKeyEpoch", "id"),
    ("sid_history_key_use", "SidHistoryKeyUse", "pair"),
    ("sid_history_abandoned", "SidHistoryAbandoned", "operation"),
];

/// The lookups SID's queries select by.
const INDEXES: &[&str] = &[
    "CREATE INDEX sid_profile_status ON :SidProfile(status)",
    "CREATE INDEX sid_operation_period_place_period ON :SidOperationPeriodPlace(period)",
    "CREATE INDEX sid_profile_migration ON :SidProfile(migration_pending)",
    "CREATE INDEX sid_phone_profile ON :SidPhone(profile_id)",
    "CREATE INDEX sid_email_profile ON :SidEmail(profile_id)",
    "CREATE INDEX sid_email_address_lookup ON :SidEmail(email)",
    "CREATE INDEX sid_principal_assigned ON :SidPrincipal(assigned_profile_id)",
    "CREATE INDEX sid_principal_binding_principal ON :SidPrincipalBinding(principal_id)",
    "CREATE INDEX sid_principal_binding_profile ON :SidPrincipalBinding(profile_id)",
    "CREATE INDEX sid_project_owner ON :SidProject(owner_id)",
    "CREATE INDEX sid_session_profile ON :SidSession(profile_id)",
    "CREATE INDEX sid_session_authenticated_by ON :SidSession(authenticated_by)",
    "CREATE INDEX sid_refresh_token_session ON :SidRefreshToken(session_id)",
    "CREATE INDEX sid_refresh_token_family ON :SidRefreshToken(family_id)",
    "CREATE INDEX sid_refresh_token_profile ON :SidRefreshToken(profile_id)",
    "CREATE INDEX sid_auth_code_session ON :SidAuthCode(authorizing_session_id)",
    "CREATE INDEX sid_auth_code_profile ON :SidAuthCode(profile_id)",
    "CREATE INDEX sid_native_generation_session ON :SidNativeGeneration(session_id)",
    "CREATE INDEX sid_native_credential_generation ON :SidNativeCredential(generation_id)",
    "CREATE INDEX sid_issuer_key_issuer ON :SidIssuerKey(issuer_id)",
    "CREATE INDEX sid_application_project ON :SidApplication(project_id)",
    "CREATE INDEX sid_client_project ON :SidClient(project_id)",
    "CREATE INDEX sid_client_default_resource ON :SidClient(default_resource)",
    "CREATE INDEX sid_resource_access_client ON :SidResourceAccess(client_id)",
    "CREATE INDEX sid_resource_access_resource ON :SidResourceAccess(resource_id)",
    "CREATE INDEX sid_iat_project ON :SidInitialAccessToken(project_id)",
    "CREATE INDEX sid_credential_profile ON :SidCredential(profile_id)",
    "CREATE INDEX sid_credential_type ON :SidCredential(credential_type)",
    "CREATE INDEX sid_webauthn_profile ON :SidWebAuthnHandle(profile_id)",
    "CREATE INDEX sid_history_epoch_owner ON :SidHistoryEpoch(owner_id)",
    "CREATE INDEX sid_history_entry_owner ON :SidHistoryEntry(owner_id)",
    "CREATE INDEX sid_role_project ON :SidRole(project_id)",
    "CREATE INDEX sid_group_project ON :SidGroup(project_id)",
    "CREATE INDEX sid_group_parent ON :SidGroup(parent_group_id)",
    "CREATE INDEX sid_group_member_group ON :SidGroupMember(group_id)",
    "CREATE INDEX sid_group_member_profile ON :SidGroupMember(profile_id)",
    "CREATE INDEX sid_assignment_profile ON :SidRoleAssignment(profile_id)",
    "CREATE INDEX sid_assignment_group ON :SidRoleAssignment(group_id)",
    "CREATE INDEX sid_assignment_machine_user ON :SidRoleAssignment(machine_user_id)",
    "CREATE INDEX sid_assignment_client ON :SidRoleAssignment(oauth_client_id)",
    "CREATE INDEX sid_assignment_connector ON :SidRoleAssignment(connector_id)",
    "CREATE INDEX sid_assignment_role ON :SidRoleAssignment(role_id)",
    "CREATE INDEX sid_assignment_depends_on ON :SidRoleAssignment(depends_on_id)",
    "CREATE INDEX sid_assignment_admin_group ON :SidRoleAssignment(admin_group)",
    "CREATE INDEX sid_assignment_expires ON :SidRoleAssignment(expires_at)",
    "CREATE INDEX sid_assignment_set_holder ON :SidAssignmentSet(holder)",
    "CREATE INDEX sid_admin_role_assignment ON :SidAdminRole(assignment_id)",
    "CREATE INDEX sid_admin_role_role ON :SidAdminRole(role_id)",
    "CREATE INDEX sid_policy_kind ON :SidCedarPolicy(scope_kind)",
    "CREATE INDEX sid_policy_project ON :SidCedarPolicy(project_id)",
    "CREATE INDEX sid_policy_resource ON :SidCedarPolicy(resource_id)",
    "CREATE INDEX sid_access_request_status ON :SidAccessRequest(status)",
    "CREATE INDEX sid_access_request_requester ON :SidAccessRequest(requester_id)",
    "CREATE INDEX sid_access_request_project ON :SidAccessRequest(project_id)",
    "CREATE INDEX sid_invite_redemption_invite ON :SidInviteRedemption(invite_id)",
    "CREATE INDEX sid_invite_redemption_profile ON :SidInviteRedemption(profile_id)",
    "CREATE INDEX sid_registration_source_created ON :SidRegistrationSource(created_at)",
    "CREATE INDEX sid_machine_user_project ON :SidMachineUser(project_id)",
    "CREATE INDEX sid_machine_credential_user ON :SidMachineCredential(machine_user_id)",
    "CREATE INDEX sid_machine_credential_expires ON :SidMachineCredential(expires_at)",
    "CREATE INDEX sid_impersonation_grant_user ON :SidImpersonationGrant(machine_user_id)",
    "CREATE INDEX sid_connector_org ON :SidProvisioningConnector(org_id)",
    "CREATE INDEX sid_connector_credential_connector ON :SidProvisioningCredential(connector_id)",
    "CREATE INDEX sid_profile_metadata_profile ON :SidProfileMetadata(profile_id)",
    "CREATE INDEX sid_pat_profile ON :SidPat(profile_id)",
    "CREATE INDEX sid_pat_status ON :SidPat(status)",
    "CREATE INDEX sid_export_job_profile ON :SidExportJob(profile_id)",
    "CREATE INDEX sid_magic_link_email ON :SidMagicLink(email)",
    "CREATE INDEX sid_magic_link_expires ON :SidMagicLink(expires_at)",
    "CREATE INDEX sid_device_profile ON :SidDevice(profile_id)",
    "CREATE INDEX sid_device_fingerprint ON :SidDevice(fingerprint_hash)",
    "CREATE INDEX sid_attestation_profile ON :SidDeviceAttestation(profile_id)",
    "CREATE INDEX sid_device_auth_expires ON :SidDeviceAuth(expires_at)",
    "CREATE INDEX sid_device_auth_project ON :SidDeviceAuth(project_id)",
    "CREATE INDEX sid_device_auth_authorized_by ON :SidDeviceAuth(authorized_by)",
    "CREATE INDEX sid_consent_profile ON :SidConsent(profile_id)",
    "CREATE INDEX sid_claim_grant_consent ON :SidClaimGrant(consent_id)",
    "CREATE INDEX sid_profile_grant_profile ON :SidProfileGrant(profile_id)",
    "CREATE INDEX sid_profile_grant_project ON :SidProfileGrant(project_id)",
    "CREATE INDEX sid_upstream_provider_enabled ON :SidUpstreamProvider(enabled)",
    "CREATE INDEX sid_upstream_identity_profile_id ON :SidUpstreamIdentity(profile_id)",
    "CREATE INDEX sid_upstream_identity_provider ON :SidUpstreamIdentity(provider_id)",
    "CREATE INDEX sid_reset_session_profile ON :SidResetSession(profile_id)",
    "CREATE INDEX sid_reset_session_expires ON :SidResetSession(expires_at)",
    "CREATE INDEX sid_anomaly_event_rule ON :SidAnomalyEvent(rule_id)",
    "CREATE INDEX sid_ip_reputation_score ON :SidIpReputation(score)",
    "CREATE INDEX sid_ip_reputation_updated ON :SidIpReputation(updated_at)",
    "CREATE INDEX sid_login_location_profile ON :SidLoginLocation(profile_id)",
    "CREATE INDEX sid_scim_target_project ON :SidScimTarget(project_id)",
    "CREATE INDEX sid_scim_record_target ON :SidScimRecord(target_id)",
    "CREATE INDEX sid_scim_dead_letter_target ON :SidScimDeadLetter(target_id)",
    "CREATE INDEX sid_flow_config_project ON :SidFlowConfig(project_id)",
    "CREATE INDEX sid_flow_action_project ON :SidFlowAction(project_id)",
    "CREATE INDEX sid_branding_project ON :SidBranding(project_id)",
    "CREATE INDEX sid_binding_profile ON :SidBinding(profile_id)",
    "CREATE INDEX sid_audit_record_at ON :SidAuditRecord(at)",
    "CREATE INDEX sid_history_key_epoch_owner ON :SidHistoryKeyEpoch(owner_domain)",
    "CREATE INDEX sid_history_key_use_owner ON :SidHistoryKeyUse(owner_domain)",
];

/// The package of SID's uniqueness constraints.
fn package() -> SchemaPackage {
    SchemaPackage {
        constraints: UNIQUE
            .iter()
            .map(|(name, label, property)| PackageConstraint {
                name: Some((*name).to_owned()),
                label: (*label).to_owned(),
                properties: vec![(*property).to_owned()],
                kind: ConstraintKind::Unique,
                scope: None,
                on_duplicate_rename: None,
            })
            .collect(),
        ..SchemaPackage::default()
    }
}

/// Declare SID's schema in `db` and wait until its constraints hold over
/// the stored data. A constraint the store refuses, or one not in force
/// within the wait, refuses the opening: SID never serves without the
/// uniqueness its writers rely on.
pub(super) fn declare(db: &Database) -> SidResult<()> {
    let publication = db.publish_schema(package()).map_err(storage)?;
    for statement in INDEXES {
        match db.execute_cypher_shared(statement, None, None, None, None) {
            Ok(_) | Err(DatabaseError::CatalogObjectExists { .. }) => {}
            Err(e) => return Err(storage(e)),
        }
    }
    let readiness = db
        .await_schema(&publication, SCHEMA_WAIT)
        .map_err(storage)?;
    for (_, name, state) in readiness.objects {
        match state {
            Readiness::Ready => {}
            Readiness::Pending => {
                return Err(SidError::Unavailable(format!(
                    "the constraint {name} is not yet in force over the stored records"
                )));
            }
            Readiness::Failed(why) => {
                return Err(SidError::Storage(format!(
                    "the store cannot hold the constraint {name}: {why}"
                )));
            }
        }
    }
    Ok(())
}
