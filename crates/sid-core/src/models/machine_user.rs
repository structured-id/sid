// SPDX-License-Identifier: AGPL-3.0-only
//! Machine User (Service Account) domain model.
//!
//! First-class non-human identity for CI/CD, bots, and service-to-service auth.
//! Uses OAuth2 client credentials grant. Parallel to Profile but non-interactive.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ProjectId;

/// Validated UUIDv7 identifier of a machine user; construction and decoding go through `sid_ids`.
pub use sid_ids::MachineUserId;

parse_stored!(MachineUserType, "machine user type", [Service, Bot, Agent]);
parse_stored!(
    MachineUserStatus,
    "machine user status",
    [Active, Suspended, Expired, Deleted]
);
parse_stored!(
    MachineCredentialType,
    "machine credential type",
    [ClientSecret, PrivateKeyJwt, Mtls, WorkloadIdentity]
);
parse_stored!(
    OwnerType,
    "machine user owner type",
    [Profile, Organization, System]
);
parse_stored!(
    CredentialStatus,
    "machine credential status",
    [Active, GracePeriod, Expired, Revoked]
);
parse_stored!(
    ImpersonationTargetType,
    "impersonation target type",
    [Role, User]
);

/// Machine user type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineUserType {
    /// Long-running background service.
    #[default]
    Service,
    /// Automated bot (CI/CD, chatops).
    Bot,
    /// AI agent or autonomous system.
    Agent,
}

impl MachineUserType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Bot => "bot",
            Self::Agent => "agent",
        }
    }
}

impl std::fmt::Display for MachineUserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Machine user lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineUserStatus {
    #[default]
    Active,
    Suspended,
    Expired,
    Deleted,
}

impl MachineUserStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Expired => "expired",
            Self::Deleted => "deleted",
        }
    }

    pub fn can_authenticate(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl std::fmt::Display for MachineUserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Credential type for machine user authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineCredentialType {
    /// OAuth2 client_secret (symmetric).
    ClientSecret,
    /// Private Key JWT (RFC 7523, asymmetric).
    PrivateKeyJwt,
    /// mTLS client certificate (EE).
    Mtls,
    /// Workload identity: SPIFFE/OIDC Federation (EE).
    WorkloadIdentity,
}

impl MachineCredentialType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientSecret => "client_secret",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::Mtls => "mtls",
            Self::WorkloadIdentity => "workload_identity",
        }
    }
}

impl std::fmt::Display for MachineCredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who owns this machine user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerType {
    /// Owned by a human profile (personal service account).
    Profile,
    /// Owned by an organization (shared service account).
    Organization,
    /// System-level (sid-operator managed).
    System,
}

impl OwnerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Organization => "organization",
            Self::System => "system",
        }
    }
}

/// Network and rate restrictions for a machine user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MachineRestrictions {
    /// Allowed source IPs/CIDRs. Empty = no restriction.
    pub ip_allowlist: Vec<String>,
    /// Max requests per minute (0 = no limit).
    pub rate_limit_rpm: u32,
}

/// Machine user: non-human identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineUser {
    pub id: MachineUserId,

    /// Project this machine user belongs to.
    pub project_id: ProjectId,

    /// Owner of this machine user.
    pub owner_type: OwnerType,
    /// Owner ID (profile_id, org_id, or "system").
    pub owner_id: String,

    /// OAuth2 client_id used for authentication.
    pub client_id: String,

    /// Human-readable name.
    pub display_name: String,

    /// Purpose description.
    pub description: Option<String>,

    pub machine_type: MachineUserType,
    pub status: MachineUserStatus,

    /// The scopes its tokens may carry at most (same format as PAT scopes).
    /// Its roles are RoleAssignments of its principal, never stored here.
    pub scopes: Vec<String>,

    /// Network and rate restrictions.
    pub restrictions: MachineRestrictions,

    /// Max token lifetime in seconds (caps access_token exp).
    pub max_token_lifetime: Option<u32>,

    /// Hard expiration (if set, machine user stops working after this).
    pub expires_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl MachineUser {
    pub fn new(
        project_id: ProjectId,
        client_id: impl Into<String>,
        display_name: impl Into<String>,
        owner_type: OwnerType,
        owner_id: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: MachineUserId::generate(),
            project_id,
            owner_type,
            owner_id: owner_id.into(),
            client_id: client_id.into(),
            display_name: display_name.into(),
            description: None,
            machine_type: MachineUserType::Service,
            status: MachineUserStatus::Active,
            scopes: vec![],
            restrictions: MachineRestrictions::default(),
            max_token_lifetime: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() >= exp)
            .unwrap_or(false)
    }

    pub fn can_authenticate(&self) -> bool {
        self.status.can_authenticate() && !self.is_expired()
    }

    /// Gateway: obtain typed wrapper if machine user is Active.
    pub fn as_active(&mut self) -> Option<ActiveMachineUser<'_>> {
        if self.status == MachineUserStatus::Active {
            Some(ActiveMachineUser(self))
        } else {
            None
        }
    }

    /// Read-only accessor for status.
    pub fn status(&self) -> MachineUserStatus {
        self.status
    }
}

/// Typed wrapper for an Active machine user.
pub struct ActiveMachineUser<'a>(&'a mut MachineUser);

impl<'a> ActiveMachineUser<'a> {
    /// Suspend the machine user. Consumes wrapper.
    pub fn suspend(self) {
        self.0.status = MachineUserStatus::Suspended;
        self.0.updated_at = Utc::now();
    }

    pub fn inner(&self) -> &MachineUser {
        self.0
    }
}

/// Credential lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    #[default]
    Active,
    /// In rotation grace period: still accepted, but the new credential is primary.
    GracePeriod,
    Expired,
    Revoked,
}

impl CredentialStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod)
    }
}

/// A single credential attached to a machine user.
///
/// Machine users can have up to 2 active credentials (for rotation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineUserCredential {
    /// Key ID (kid) for this credential.
    pub kid: String,

    pub machine_user_id: MachineUserId,

    pub credential_type: MachineCredentialType,

    pub status: CredentialStatus,

    /// For client_secret: argon2 hash. For private_key_jwt: public key PEM.
    /// For mTLS: certificate fingerprint. For workload_identity: trust bundle reference.
    pub credential_data: String,

    /// Algorithm (e.g. "RS256", "ES256" for private_key_jwt).
    pub algorithm: Option<String>,

    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// CE hardcoded credential rotation policy.
pub const MAX_CREDENTIAL_AGE_DAYS: u32 = 365;
pub const ROTATION_GRACE_PERIOD_HOURS: u32 = 72;
pub const MAX_ACTIVE_CREDENTIALS: usize = 2;
/// Alert emitted N days before credential expiry.
pub const CREDENTIAL_ALERT_BEFORE_EXPIRY_DAYS: u32 = 30;

/// CE impersonation: max lifetime of impersonated token (seconds).
pub const IMPERSONATION_MAX_LIFETIME_SECONDS: u32 = 300;

impl MachineUserCredential {
    pub fn new(
        machine_user_id: MachineUserId,
        kid: impl Into<String>,
        credential_type: MachineCredentialType,
        credential_data: impl Into<String>,
    ) -> Self {
        Self {
            kid: kid.into(),
            machine_user_id,
            credential_type,
            status: CredentialStatus::Active,
            credential_data: credential_data.into(),
            algorithm: None,
            expires_at: None,
            created_at: Utc::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() >= exp)
            .unwrap_or(false)
    }

    /// Whether credential exceeds max age policy.
    pub fn exceeds_max_age(&self) -> bool {
        let age = Utc::now() - self.created_at;
        age.num_days() > MAX_CREDENTIAL_AGE_DAYS as i64
    }
}

/// Target type for impersonation grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpersonationTargetType {
    /// Impersonate any user with a specific role.
    Role,
    /// Impersonate a specific user (profile_id).
    User,
}

impl ImpersonationTargetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Role => "role",
            Self::User => "user",
        }
    }
}

impl std::fmt::Display for ImpersonationTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CE impersonation grant: explicit admin permission for RFC 8693 token exchange.
///
/// A machine user can act on behalf of a target user when an admin
/// has created an `ImpersonationGrant`. The impersonated token carries
/// an `act` claim (RFC 8693 §4.1) and is capped at
/// `IMPERSONATION_MAX_LIFETIME_SECONDS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpersonationGrant {
    /// Machine user that is allowed to impersonate.
    pub machine_user_id: MachineUserId,

    /// Type of target: role-based or specific user.
    pub target_type: ImpersonationTargetType,

    /// Target value: role name (e.g. "employee") or profile_id.
    pub target: String,

    /// Scopes allowed when impersonating. `["*"]` = all scopes.
    pub allowed_scopes: Vec<String>,

    pub created_at: DateTime<Utc>,
}

impl ImpersonationGrant {
    pub fn new(
        machine_user_id: MachineUserId,
        target_type: ImpersonationTargetType,
        target: impl Into<String>,
        allowed_scopes: Vec<String>,
    ) -> Self {
        Self {
            machine_user_id,
            target_type,
            target: target.into(),
            allowed_scopes,
            created_at: Utc::now(),
        }
    }

    /// Whether this grant allows all scopes.
    pub fn allows_all_scopes(&self) -> bool {
        self.allowed_scopes.iter().any(|s| s == "*")
    }

    /// Whether this grant covers a specific scope.
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.allows_all_scopes() || self.allowed_scopes.iter().any(|s| s == scope)
    }
}

#[cfg(test)]
mod tests;
