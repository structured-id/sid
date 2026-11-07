// SPDX-License-Identifier: AGPL-3.0-only
//! The portable snapshot of an installation's database: every persistent
//! entity of any supported backend in one backend-agnostic structure,
//! exported from a quiesced source, sealed into an encrypted archive
//! ([`archive`]), imported into a target and verified against its source.
//!
//! Sealed fields, sealed keys and key-version references travel as stored:
//! nothing is opened or exported from a key store. Import checks the archive,
//! its identity scope, schema and references before it changes the target,
//! takes only an uninitialized target or resumes the same archive's import
//! into the same target, and starts nothing: serving, issuance and restored
//! work begin only when the host activates the restored installation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_core::models::{
    Application, BrandingConfig, CedarPolicy, ClosureRequest, Credential, Device,
    DeviceAttestation, DeviceAuthorizationCode, ExportJob, Group, GroupMember, ImpersonationGrant,
    InitialAccessToken, IssuerSigningKey, MachineUser, MachineUserCredential, MagicLinkSession,
    OAuth2Client, OidcIssuer, OperationPeriodState, OperationRecord, OperationResourceBinding,
    Organization, OutboundDlqEntry, PersonalAccessToken, Principal, Profile, ProfileGrant,
    ProfileMetadata, Project, ProtectedResource, ResourceAccess, Role, RoleAssignment,
    ScimOutboundRecord, ScimOutboundTarget, ServiceBinding, Session, SessionGrants,
    SodConflictRule, UpstreamIdentity, UpstreamProvider, WorkSnapshot,
};

pub mod archive;
mod export;
mod import;
mod verify;

pub use export::export;
pub use import::{ImportResult, import, validate};
pub use verify::{CountCheck, VerifyResult, verify};

/// Why a snapshot could not be exported, sealed, opened, imported or
/// verified.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// A snapshot of another format: its contents are not this format's.
    #[error("unsupported snapshot format {0}: export a new snapshot with this build")]
    Format(u32),
    /// The snapshot contradicts itself or omits what its contents need.
    #[error("invalid snapshot: {0}")]
    Invalid(String),
    /// The target is not one this snapshot may be imported into, or holds
    /// state the snapshot conflicts with; nothing was written.
    #[error("the target refuses the snapshot: {0}")]
    Target(String),
    /// The archive is not a sealed snapshot, or does not open under the key.
    #[error("invalid archive: {0}")]
    Archive(String),
    /// The store failed or refused a write.
    #[error(transparent)]
    Store(#[from] sid_core::Error),
}

/// The result of snapshot operations.
pub type Result<T> = std::result::Result<T, SnapshotError>;

/// An OIDC issuer with every generation of its signing key, sealed as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSnapshot {
    pub issuer: OidcIssuer,
    pub keys: Vec<IssuerSigningKey>,
}

/// Data snapshot of a SID installation.
///
/// Contains all persistent entities needed to recreate the installation.
/// Ephemeral data (caches, locks, broker cursors) is excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot metadata.
    pub metadata: SnapshotMetadata,

    /// The installation's own organization, the authority its issuers,
    /// clients and history domains belong to. None for a source that was
    /// never initialized.
    pub organization: Option<Organization>,

    /// The OIDC issuer registry with each issuer's sealed signing keys:
    /// clients, protected resources and tokens name these issuers.
    pub oidc_issuers: Vec<IssuerSnapshot>,

    /// Public derivation parameters for sealed fields. No master key or
    /// unwrapped epoch secret is included.
    pub key_versions: Vec<sid_keys::KeyVersionParams>,

    /// Sealed OPAQUE server setup on which imported password files depend.
    /// The independent master key is never included. None means the source
    /// has not initialized OPAQUE; such a snapshot cannot contain OPAQUE files.
    pub opaque_server_setup: Option<Vec<u8>>,

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

    /// The history evaluator's sealed keys, one archive per owner domain that
    /// holds any; no unsealed key is included. Every epoch a history names
    /// has its key here.
    pub history_keys: Vec<sid_core::models::KeyArchive>,

    /// Public derivation parameters of the evaluator's own key custody,
    /// which seals `history_keys`; apart from `key_versions`, which seal the
    /// credential service's fields. The evaluator's master key is never
    /// included.
    pub history_key_versions: Vec<sid_keys::KeyVersionParams>,

    /// The credential service's history write cutoff, when one was raised:
    /// no history entry is written under an epoch created before it.
    pub history_write_cutoff: Option<DateTime<Utc>>,

    /// The evaluator's history key write cutoff, when one was raised: no
    /// epoch created before it is selected or evaluated.
    pub history_key_write_cutoff: Option<DateTime<Utc>>,

    /// Active sessions (expired sessions are excluded).
    pub sessions: Vec<Session>,

    /// Pairwise service bindings: their ids are the `sub` every pairwise
    /// client already holds, so they move unchanged.
    pub service_bindings: Vec<ServiceBinding>,

    /// Applications: the containers of client and resource roles.
    pub applications: Vec<Application>,

    /// Protected resources, retired ones included: a retired indicator stays
    /// reserved in the target too.
    pub protected_resources: Vec<ProtectedResource>,

    /// OAuth2 client registrations.
    pub oauth2_clients: Vec<OAuth2Client>,

    /// Explicit client-to-resource access.
    pub resource_access: Vec<ResourceAccess>,

    /// The grants of each exported session: refresh tokens, the
    /// authorization codes it authorized and native generations, revoked,
    /// used and rotated ones included, so a reused grant is still recognized.
    pub session_grants: Vec<SessionGrants>,

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

    /// The devices' key bindings, live and revoked: a revoked one keeps its
    /// device from being enrolled by a ceremony that did not find it.
    pub device_attestations: Vec<DeviceAttestation>,

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
    pub durable_work: Vec<WorkSnapshot>,

    /// The periods keyed commands are admitted under and the last issued: a
    /// period retired before the move is never admitted after it.
    pub operation_periods: OperationPeriodState,

    /// Completions of keyed commands with their results, so a retry after
    /// the move resolves to its recorded result.
    pub operation_results: Vec<OperationRecord>,

    /// The identifiers keyed creations bound, so a creation resumed after the
    /// move finds the identifier it began under.
    pub operation_resources: Vec<OperationResourceBinding>,

    /// Magic link sessions.
    pub magic_link_sessions: Vec<MagicLinkSession>,

    /// SCIM outbound targets.
    pub scim_outbound_targets: Vec<ScimOutboundTarget>,

    /// SCIM outbound records (downstream ID mappings).
    pub scim_outbound_records: Vec<ScimOutboundRecord>,

    /// SCIM outbound DLQ entries.
    pub outbound_dlq_entries: Vec<OutboundDlqEntry>,

    /// Branding configurations (per-project theming).
    pub branding_configs: Vec<BrandingConfig>,
}

/// Metadata about the snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Snapshot format version.
    pub version: u32,

    /// This snapshot's identity: an import of it, interrupted, is resumed only
    /// as the import of this same snapshot.
    pub snapshot_id: uuid::Uuid,

    /// Authority whose id forms the password-history domain; the id of
    /// [`Snapshot::organization`].
    pub installation_org: Option<sid_core::models::OrgId>,

    /// When the snapshot was created.
    pub created_at: DateTime<Utc>,

    /// Source backend type (its `StorageBackend::name`).
    pub source_backend: String,

    /// Total entity count across all collections.
    pub total_entities: u64,
}

/// The snapshot format this build writes and reads. A snapshot of another
/// format is refused, never converted: its contents are not this format's.
pub const FORMAT_VERSION: u32 = 9;

impl Snapshot {
    /// `json` as a snapshot of [`FORMAT_VERSION`]; another format is refused
    /// by its version before its contents are read.
    pub fn parse(json: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Head {
            metadata: HeadMetadata,
        }
        #[derive(Deserialize)]
        struct HeadMetadata {
            version: u32,
        }
        let head: Head = serde_json::from_slice(json)
            .map_err(|e| SnapshotError::Invalid(format!("snapshot JSON: {e}")))?;
        if head.metadata.version != FORMAT_VERSION {
            return Err(SnapshotError::Format(head.metadata.version));
        }
        serde_json::from_slice(json)
            .map_err(|e| SnapshotError::Invalid(format!("snapshot JSON: {e}")))
    }

    /// The snapshot as JSON, the payload an archive seals.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| SnapshotError::Invalid(format!("snapshot JSON: {e}")))
    }

    /// A new empty snapshot of a source of backend `source_backend`.
    pub fn new(source_backend: &str) -> Self {
        Self {
            metadata: SnapshotMetadata {
                version: FORMAT_VERSION,
                snapshot_id: uuid::Uuid::now_v7(),
                installation_org: None,
                created_at: Utc::now(),
                source_backend: source_backend.to_string(),
                total_entities: 0,
            },
            organization: None,
            oidc_issuers: Vec::new(),
            projects: Vec::new(),
            key_versions: Vec::new(),
            opaque_server_setup: None,
            profiles: Vec::new(),
            principals: Vec::new(),
            credentials: Vec::new(),
            password_histories: Vec::new(),
            history_keys: Vec::new(),
            history_key_versions: Vec::new(),
            history_write_cutoff: None,
            history_key_write_cutoff: None,
            sessions: Vec::new(),
            service_bindings: Vec::new(),
            applications: Vec::new(),
            protected_resources: Vec::new(),
            oauth2_clients: Vec::new(),
            resource_access: Vec::new(),
            session_grants: Vec::new(),
            initial_access_tokens: Vec::new(),
            roles: Vec::new(),
            groups: Vec::new(),
            group_members: Vec::new(),
            role_assignments: Vec::new(),
            sod_rules: Vec::new(),
            cedar_policies: Vec::new(),
            profile_metadata: Vec::new(),
            devices: Vec::new(),
            device_attestations: Vec::new(),
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
            operation_periods: OperationPeriodState {
                issued_through: sid_core::models::OperationPeriod::new(0),
                active: Vec::new(),
            },
            operation_results: Vec::new(),
            operation_resources: Vec::new(),
            magic_link_sessions: Vec::new(),
            scim_outbound_targets: Vec::new(),
            scim_outbound_records: Vec::new(),
            outbound_dlq_entries: Vec::new(),
            branding_configs: Vec::new(),
        }
    }

    /// Count total entities in the snapshot.
    pub fn count_entities(&self) -> u64 {
        let sizes = [
            u64::from(self.organization.is_some()),
            self.oidc_issuers.len() as u64,
            self.oidc_issuers.iter().map(|i| i.keys.len() as u64).sum(),
            self.key_versions.len() as u64,
            u64::from(self.opaque_server_setup.is_some()),
            self.projects.len() as u64,
            self.profiles.len() as u64,
            self.principals.len() as u64,
            self.credentials.len() as u64,
            self.password_histories
                .iter()
                .filter(|(_, h)| h.is_some())
                .count() as u64,
            self.history_keys.len() as u64,
            self.history_key_versions.len() as u64,
            self.sessions.len() as u64,
            self.service_bindings.len() as u64,
            self.applications.len() as u64,
            self.protected_resources.len() as u64,
            self.oauth2_clients.len() as u64,
            self.resource_access.len() as u64,
            self.session_grants
                .iter()
                .map(|g| {
                    (g.refresh_tokens.len()
                        + g.authorization_codes.len()
                        + g.native_generations.len()) as u64
                })
                .sum(),
            self.initial_access_tokens.len() as u64,
            self.roles.len() as u64,
            self.groups.len() as u64,
            self.group_members.len() as u64,
            self.role_assignments.len() as u64,
            self.sod_rules.len() as u64,
            self.cedar_policies.len() as u64,
            self.profile_metadata.len() as u64,
            self.devices.len() as u64,
            self.device_attestations.len() as u64,
            self.device_auth_codes.len() as u64,
            self.profile_grants.len() as u64,
            self.upstream_providers.len() as u64,
            self.upstream_identities.len() as u64,
            self.personal_access_tokens.len() as u64,
            self.machine_users.len() as u64,
            self.machine_credentials.len() as u64,
            self.impersonation_grants.len() as u64,
            self.closure_requests.len() as u64,
            self.export_jobs.len() as u64,
            self.durable_work.len() as u64,
            self.operation_periods.active.len() as u64,
            self.operation_results.len() as u64,
            self.operation_resources.len() as u64,
            self.magic_link_sessions.len() as u64,
            self.scim_outbound_targets.len() as u64,
            self.scim_outbound_records.len() as u64,
            self.outbound_dlq_entries.len() as u64,
            self.branding_configs.len() as u64,
        ];
        sizes.iter().sum()
    }
}

#[cfg(test)]
mod tests;
