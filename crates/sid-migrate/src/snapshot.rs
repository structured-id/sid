// SPDX-License-Identifier: AGPL-3.0-only
//! Snapshot format for data export/import.
//!
//! Contains all exportable entities from a SID instance in a single
//! serializable structure. Used as the intermediate format for JSON
//! export files and direct migrations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_core::models::{Application, ProtectedResource, ResourceAccess};
use sid_core::models::{
    BrandingConfig, CedarPolicy, ClosureRequest, Credential, Device, DeviceAuthorizationCode,
    ExportJob, Group, GroupMember, ImpersonationGrant, InitialAccessToken, MachineUser,
    MachineUserCredential, MagicLinkSession, OAuth2Client, OperationRecord, OutboundDlqEntry,
    PersonalAccessToken, Principal, Profile, ProfileGrant, ProfileMetadata, Project, RefreshToken,
    Role, RoleAssignment, ScimOutboundRecord, ScimOutboundTarget, ServiceBinding, Session,
    SodConflictRule, UpstreamIdentity, UpstreamProvider, WorkSnapshot,
};

/// Data snapshot from a SID instance.
///
/// Contains all persistent entities needed to recreate the instance state.
/// Ephemeral data (caches, locks, NATS offsets) is excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot metadata.
    pub metadata: SnapshotMetadata,

    /// Public derivation parameters for sealed fields. No master key or
    /// unwrapped epoch secret is included.
    pub key_versions: Vec<sid_keys::KeyVersionParams>,

    /// Projects (including system project).
    pub projects: Vec<Project>,

    /// User profiles.
    pub profiles: Vec<Profile>,

    /// Profile principals (email, phone, username login handles).
    pub principals: Vec<Principal>,

    /// Authentication credentials (OPAQUE, WebAuthn, TOTP, recovery).
    pub credentials: Vec<Credential>,

    /// Complete history for every profile, including an explicit None for an
    /// owner with no history. Missing owners are refused, never treated as empty.
    pub password_histories: Vec<(
        sid_core::models::ProfileId,
        Option<sid_core::models::HistoryArchive>,
    )>,

    /// Active sessions (expired sessions are excluded).
    pub sessions: Vec<Session>,

    /// Pairwise service bindings: their ids are the `sub` every pairwise
    /// client already holds, so they move unchanged.
    #[serde(default)]
    pub service_bindings: Vec<ServiceBinding>,

    /// Applications: the containers of client and resource roles.
    #[serde(default)]
    pub applications: Vec<Application>,

    /// Protected resources, retired ones included: a retired indicator stays
    /// reserved in the target too.
    #[serde(default)]
    pub protected_resources: Vec<ProtectedResource>,

    /// OAuth2 client registrations.
    pub oauth2_clients: Vec<OAuth2Client>,

    /// Explicit client-to-resource access.
    #[serde(default)]
    pub resource_access: Vec<ResourceAccess>,

    /// Refresh tokens.
    pub refresh_tokens: Vec<RefreshToken>,

    /// Initial access tokens (DCR).
    pub initial_access_tokens: Vec<InitialAccessToken>,

    /// RBAC roles.
    pub roles: Vec<Role>,

    /// RBAC groups.
    pub groups: Vec<Group>,

    /// Group membership records.
    pub group_members: Vec<GroupMember>,

    /// Role assignments (profile→role and group→role).
    pub role_assignments: Vec<RoleAssignment>,

    /// SoD conflict rules.
    pub sod_rules: Vec<SodConflictRule>,

    /// Cedar policies (ABAC).
    pub cedar_policies: Vec<CedarPolicy>,

    /// Profile metadata key-value pairs.
    pub profile_metadata: Vec<ProfileMetadata>,

    /// Registered devices.
    pub devices: Vec<Device>,

    /// Device authorization codes (RFC 8628).
    pub device_auth_codes: Vec<DeviceAuthorizationCode>,

    /// Profile grants (consent records).
    pub profile_grants: Vec<ProfileGrant>,

    /// Upstream identity providers (Social/OIDC/SAML).
    pub upstream_providers: Vec<UpstreamProvider>,

    /// Upstream identity links (profile↔provider).
    pub upstream_identities: Vec<UpstreamIdentity>,

    /// Personal access tokens.
    pub personal_access_tokens: Vec<PersonalAccessToken>,

    /// Machine users (service accounts).
    pub machine_users: Vec<MachineUser>,

    /// Machine user credentials.
    pub machine_credentials: Vec<MachineUserCredential>,

    /// Impersonation grants.
    pub impersonation_grants: Vec<ImpersonationGrant>,

    /// Closure requests.
    pub closure_requests: Vec<ClosureRequest>,

    /// Data export jobs.
    pub export_jobs: Vec<ExportJob>,

    /// Durable work in every state: owed deliveries still to run and the
    /// failed ones kept as dead letters.
    #[serde(default)]
    pub durable_work: Vec<WorkSnapshot>,

    /// Completions of keyed commands with their results, so a retry after
    /// the move resolves to its recorded result.
    pub operation_results: Vec<OperationRecord>,

    /// Magic link sessions.
    pub magic_link_sessions: Vec<MagicLinkSession>,

    /// SCIM outbound targets.
    pub scim_outbound_targets: Vec<ScimOutboundTarget>,

    /// SCIM outbound records (downstream ID mappings).
    pub scim_outbound_records: Vec<ScimOutboundRecord>,

    /// SCIM outbound DLQ entries.
    pub outbound_dlq_entries: Vec<OutboundDlqEntry>,

    /// Branding configurations (per-project theming).
    #[serde(default)]
    pub branding_configs: Vec<BrandingConfig>,

    /// Audit log entries (optional — can be very large).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<Vec<serde_json::Value>>,
}

/// Metadata about the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Snapshot format version.
    pub version: u32,

    /// Authority whose id forms the password-history domain. The target must
    /// already have this authority; a data transfer cannot change its identity.
    pub installation_org: Option<sid_core::models::OrgId>,

    /// When the snapshot was created.
    pub created_at: DateTime<Utc>,

    /// Source backend type ("postgresql" or "sqlite").
    pub source_backend: String,

    /// Source connection string (sanitized — password removed).
    pub source_url: String,

    /// Total entity count across all collections.
    pub total_entities: u64,
}

impl Snapshot {
    /// Create a new empty snapshot with metadata.
    pub fn new(source_backend: &str, source_url: &str) -> Self {
        Self {
            metadata: SnapshotMetadata {
                version: 2,
                installation_org: None,
                created_at: Utc::now(),
                source_backend: source_backend.to_string(),
                source_url: sanitize_url(source_url),
                total_entities: 0,
            },
            projects: Vec::new(),
            key_versions: Vec::new(),
            profiles: Vec::new(),
            principals: Vec::new(),
            credentials: Vec::new(),
            password_histories: Vec::new(),
            sessions: Vec::new(),
            service_bindings: Vec::new(),
            applications: Vec::new(),
            protected_resources: Vec::new(),
            oauth2_clients: Vec::new(),
            resource_access: Vec::new(),
            refresh_tokens: Vec::new(),
            initial_access_tokens: Vec::new(),
            roles: Vec::new(),
            groups: Vec::new(),
            group_members: Vec::new(),
            role_assignments: Vec::new(),
            sod_rules: Vec::new(),
            cedar_policies: Vec::new(),
            profile_metadata: Vec::new(),
            devices: Vec::new(),
            device_auth_codes: Vec::new(),
            profile_grants: Vec::new(),
            upstream_providers: Vec::new(),
            upstream_identities: Vec::new(),
            personal_access_tokens: Vec::new(),
            machine_users: Vec::new(),
            machine_credentials: Vec::new(),
            impersonation_grants: Vec::new(),
            closure_requests: Vec::new(),
            export_jobs: Vec::new(),
            durable_work: Vec::new(),
            operation_results: Vec::new(),
            magic_link_sessions: Vec::new(),
            scim_outbound_targets: Vec::new(),
            scim_outbound_records: Vec::new(),
            outbound_dlq_entries: Vec::new(),
            branding_configs: Vec::new(),
            audit_log: None,
        }
    }

    /// Count total entities in the snapshot.
    pub fn count_entities(&self) -> u64 {
        let mut count: u64 = 0;
        count += self.key_versions.len() as u64;
        count += self.projects.len() as u64;
        count += self.profiles.len() as u64;
        count += self.principals.len() as u64;
        count += self.credentials.len() as u64;
        count += self
            .password_histories
            .iter()
            .filter(|(_, h)| h.is_some())
            .count() as u64;
        count += self.sessions.len() as u64;
        count += self.service_bindings.len() as u64;
        count += self.applications.len() as u64;
        count += self.protected_resources.len() as u64;
        count += self.oauth2_clients.len() as u64;
        count += self.resource_access.len() as u64;
        count += self.refresh_tokens.len() as u64;
        count += self.initial_access_tokens.len() as u64;
        count += self.roles.len() as u64;
        count += self.groups.len() as u64;
        count += self.group_members.len() as u64;
        count += self.role_assignments.len() as u64;
        count += self.sod_rules.len() as u64;
        count += self.cedar_policies.len() as u64;
        count += self.profile_metadata.len() as u64;
        count += self.devices.len() as u64;
        count += self.device_auth_codes.len() as u64;
        count += self.profile_grants.len() as u64;
        count += self.upstream_providers.len() as u64;
        count += self.upstream_identities.len() as u64;
        count += self.personal_access_tokens.len() as u64;
        count += self.machine_users.len() as u64;
        count += self.machine_credentials.len() as u64;
        count += self.impersonation_grants.len() as u64;
        count += self.closure_requests.len() as u64;
        count += self.export_jobs.len() as u64;
        count += self.durable_work.len() as u64;
        count += self.operation_results.len() as u64;
        count += self.magic_link_sessions.len() as u64;
        count += self.scim_outbound_targets.len() as u64;
        count += self.scim_outbound_records.len() as u64;
        count += self.outbound_dlq_entries.len() as u64;
        count += self.branding_configs.len() as u64;
        if let Some(ref audit) = self.audit_log {
            count += audit.len() as u64;
        }
        count
    }
}

/// Remove password from connection URL for safe storage in metadata.
fn sanitize_url(url: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("***"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests;
