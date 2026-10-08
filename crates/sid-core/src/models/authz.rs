// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization domain models.
//!
//! CE RBAC: roles, groups, role assignments, Cedar policies.
//! All checks = flat SQL queries. No recursion. No graph. No ReBAC.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::event::{Event, event_types};
use super::{MachineUserId, ProfileId, ProjectId, ProvisioningConnectorId};

pub mod admin;
pub use admin::{
    AdminEnvelope, AdminOperation, AssignmentFence, AssignmentProvenance, EnvelopeError,
    RecipientKind, RoleEditFence, Uncovered,
};

// ── Role ──────────────────────────────────────────────────────────────

/// Unique identifier for a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoleId(pub Uuid);

impl RoleId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for RoleId {
    fn default() -> Self {
        Self::new()
    }
}

/// Role represents a named collection of permissions.
///
/// Scoped to a project — each project defines its own role set.
/// `key` is the stable machine identifier (used in Cedar policies, tokens).
/// `name` is the human-readable display name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub project_id: ProjectId,
    /// Machine identifier used in Cedar policies and JWT claims.
    /// e.g., "admin", "editor", "viewer"
    pub key: String,
    /// Human-readable display name.
    pub name: String,
    pub description: Option<String>,
    /// Optional UI grouping label (e.g., "Content", "Settings").
    pub group: Option<String>,
    /// Permissions (actions) granted by this role.
    /// e.g., ["profiles:read", "clients:write"]
    pub permissions: Vec<String>,
    /// Stored revision: 0 for a new role, moved on by every update. An update
    /// applies only over the revision it was read at.
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Role {
    pub fn new(project_id: ProjectId, key: impl Into<String>, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: RoleId::new(),
            project_id,
            key: key.into(),
            name: name.into(),
            description: None,
            group: None,
            permissions: Vec::new(),
            revision: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this role grants a specific permission.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    /// Permissions as space-separated string (for DB storage).
    pub fn permissions_string(&self) -> String {
        self.permissions.join(" ")
    }

    /// Parse permissions from space-separated string.
    pub fn parse_permissions(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    /// The built-in role of the system project granting [`TOKEN_INTROSPECT`],
    /// assigned on one protected resource at a time.
    pub fn token_inspector() -> Self {
        let mut role = Self::new(ProjectId::system(), TOKEN_INSPECTOR_ROLE, "Token inspector");
        // One id in every installation: a snapshot restored where the role was
        // already provisioned names the same role.
        role.id = RoleId(TOKEN_INSPECTOR_ROLE_ID);
        role.description = Some("Inspects access tokens issued for a protected resource".into());
        role.permissions = vec![TOKEN_INTROSPECT.to_string()];
        role
    }

    /// The built-in role of the system project granting [`AUTHZ_CHECK`],
    /// assigned to a service on one protected resource at a time.
    pub fn permission_checker() -> Self {
        let mut role = Self::new(
            ProjectId::system(),
            PERMISSION_CHECKER_ROLE,
            "Permission checker",
        );
        role.id = RoleId(PERMISSION_CHECKER_ROLE_ID);
        role.description =
            Some("Asks whether a subject may act on a protected resource's objects".into());
        role.permissions = vec![AUTHZ_CHECK.to_string()];
        role
    }

    /// The built-in role of the system project granting every SCIM directory
    /// action, assigned to a provisioning connector on one organization's
    /// directory resource. A narrower custom role grants a subset.
    pub fn scim_provisioner() -> Self {
        let mut role = Self::new(
            ProjectId::system(),
            SCIM_PROVISIONER_ROLE,
            "SCIM provisioner",
        );
        role.id = RoleId(SCIM_PROVISIONER_ROLE_ID);
        role.description =
            Some("Provisions an organization's directory users and groups over SCIM".into());
        role.permissions = SCIM_ACTIONS.iter().map(|a| a.to_string()).collect();
        role
    }
}

/// SCIM directory actions a provisioning connector can be granted on its
/// organization's directory resource. Every one starts with
/// [`SCIM_ACTION_PREFIX`], the only actions a connector is ever checked for.
pub const SCIM_USER_READ: &str = "scim.user.read";
pub const SCIM_USER_CREATE: &str = "scim.user.create";
pub const SCIM_USER_UPDATE: &str = "scim.user.update";
/// `active=false`: the account stays, its access ends.
pub const SCIM_USER_DEACTIVATE: &str = "scim.user.deactivate";
/// DELETE: the record leaves the SCIM collection (RFC 7644 §3.6).
pub const SCIM_USER_DELETE: &str = "scim.user.delete";
pub const SCIM_GROUP_READ: &str = "scim.group.read";
pub const SCIM_GROUP_CREATE: &str = "scim.group.create";
pub const SCIM_GROUP_UPDATE: &str = "scim.group.update";
pub const SCIM_GROUP_DELETE: &str = "scim.group.delete";
/// Adding or removing group members.
pub const SCIM_GROUP_MEMBERSHIP: &str = "scim.group.membership";

/// Prefix of every SCIM directory action.
pub const SCIM_ACTION_PREFIX: &str = "scim.";

/// Every SCIM directory action.
pub const SCIM_ACTIONS: [&str; 10] = [
    SCIM_USER_READ,
    SCIM_USER_CREATE,
    SCIM_USER_UPDATE,
    SCIM_USER_DEACTIVATE,
    SCIM_USER_DELETE,
    SCIM_GROUP_READ,
    SCIM_GROUP_CREATE,
    SCIM_GROUP_UPDATE,
    SCIM_GROUP_DELETE,
    SCIM_GROUP_MEMBERSHIP,
];

/// Key of the built-in role holding every SCIM directory action.
pub const SCIM_PROVISIONER_ROLE: &str = "scim-provisioner";

/// Id of the built-in SCIM provisioner role, fixed like the token inspector's.
const SCIM_PROVISIONER_ROLE_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002);

/// The action of inspecting access tokens issued for one protected resource
/// (RFC 7662), independent of the right to obtain them.
pub const TOKEN_INTROSPECT: &str = "oauth.token.introspect";

/// Key of the built-in role holding [`TOKEN_INTROSPECT`].
pub const TOKEN_INSPECTOR_ROLE: &str = "token-inspector";

/// Id of the built-in token inspector role, fixed like the system project's.
const TOKEN_INSPECTOR_ROLE_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001);

/// The action of asking whether another subject may act on one protected
/// resource's objects; the asking service is not that subject and gains none
/// of its rights (D054).
pub const AUTHZ_CHECK: &str = "authz.check";

/// Key of the built-in role holding [`AUTHZ_CHECK`].
pub const PERMISSION_CHECKER_ROLE: &str = "permission-checker";

/// Id of the built-in permission checker role, fixed like the token
/// inspector's.
const PERMISSION_CHECKER_ROLE_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0003);

/// Scope prefix of an assignment on one protected resource; the resource
/// fixes its issuer.
const OAUTH_RESOURCE_SCOPE: &str = "oauth_resource:";

// ── Group ─────────────────────────────────────────────────────────────

/// Unique identifier for a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub Uuid);

impl GroupId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for GroupId {
    fn default() -> Self {
        Self::new()
    }
}

/// Group represents a collection of profiles.
///
/// Scoped to a project — each project defines its own groups.
/// Groups are flat (parent_group_id always None).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub project_id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    /// Parent group for nested hierarchies; always None.
    pub parent_group_id: Option<GroupId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Group {
    pub fn new(project_id: ProjectId, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: GroupId::new(),
            project_id,
            name: name.into(),
            description: None,
            parent_group_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this is a root group (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_group_id.is_none()
    }
}

/// Group membership record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: GroupId,
    pub profile_id: ProfileId,
    pub added_at: DateTime<Utc>,
}

impl GroupMember {
    pub fn new(group_id: GroupId, profile_id: ProfileId) -> Self {
        Self {
            group_id,
            profile_id,
            added_at: Utc::now(),
        }
    }
}

// ── Role Assignment ───────────────────────────────────────────────────

/// Unique identifier for a role assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoleAssignmentId(pub Uuid);

impl RoleAssignmentId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for RoleAssignmentId {
    fn default() -> Self {
        Self::new()
    }
}

/// Who receives the role: a profile, group, machine user, an independent
/// OAuth client acting as a service (its `client_id`), or a provisioning
/// connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleAssignmentPrincipal {
    Profile(ProfileId),
    Group(GroupId),
    MachineUser(MachineUserId),
    OAuthClient(String),
    ProvisioningConnector(ProvisioningConnectorId),
}

/// Principal reference for authorization checks.
/// Used by `AuthzCheckRequest.subject` parsing.
/// Different from `RoleAssignmentPrincipal` — this is for CHECK operations,
/// not for assignment (no Group variant; group membership resolves to individual roles).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzPrincipal {
    /// Human user: subject format `user:<profile_id_uuid>`
    Profile(ProfileId),
    /// Machine user: subject format `machine:<machine_user_id_uuid>`
    MachineUser(MachineUserId),
    /// Independent OAuth client: subject format `oauth_client:<client_id>`
    OAuthClient(String),
    /// Provisioning connector: subject format `provisioning_connector:<uuid>`.
    /// Checked only for SCIM directory actions on a protected resource.
    ProvisioningConnector(ProvisioningConnectorId),
}

impl AuthzPrincipal {
    /// Extract ProfileId if this is a Profile principal.
    pub fn as_profile_id(&self) -> Option<ProfileId> {
        match self {
            Self::Profile(id) => Some(*id),
            Self::MachineUser(_) | Self::OAuthClient(_) | Self::ProvisioningConnector(_) => None,
        }
    }

    /// Extract MachineUserId if this is a MachineUser principal.
    pub fn as_machine_user_id(&self) -> Option<MachineUserId> {
        match self {
            Self::MachineUser(id) => Some(*id),
            Self::Profile(_) | Self::OAuthClient(_) | Self::ProvisioningConnector(_) => None,
        }
    }
}

/// Scope type for role assignments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeType {
    /// Global scope — applies everywhere.
    #[default]
    Global,
    /// Scoped to a specific project.
    Project,
    /// Scoped to a specific site (OAuth2 client).
    Site,
}

impl ScopeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
            Self::Site => "site",
        }
    }
}

impl std::fmt::Display for ScopeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Alert thresholds for expiring role assignments (hours before expiry).
pub const ROLE_EXPIRY_ALERT_HOURS: &[i64] = &[72, 24, 1];

/// Role assignment — binds a role to a principal within an optional scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: RoleAssignmentId,
    pub principal: RoleAssignmentPrincipal,
    pub role_id: RoleId,
    /// Optional scope constraint (e.g., "project:abc123").
    pub scope: Option<String>,
    /// Optional expiry (temporary role assignment).
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// For an administrative assignment, what its holder may administer in
    /// its scope (D050 B); `None` for an ordinary working assignment.
    #[serde(default)]
    pub admin: Option<AdminEnvelope>,
    /// Who created it and on what authority; `None` where it was not
    /// recorded, which confers no delegation authority.
    #[serde(default)]
    pub provenance: Option<AssignmentProvenance>,
    /// Stored revision: 0 when created, moved on by every change, so a
    /// mutation authorized by this assignment commits only over the
    /// revision it was checked at.
    #[serde(default)]
    pub revision: u64,
}

impl RoleAssignment {
    pub fn new(principal: RoleAssignmentPrincipal, role_id: RoleId) -> Self {
        Self {
            id: RoleAssignmentId::new(),
            principal,
            role_id,
            scope: None,
            expires_at: None,
            created_at: Utc::now(),
            admin: None,
            provenance: None,
            revision: 0,
        }
    }

    /// Make this an administrative assignment bounded by `envelope`.
    pub fn administering(mut self, envelope: AdminEnvelope) -> Self {
        self.admin = Some(envelope);
        self
    }

    /// Record who created this assignment and on what authority.
    pub fn granted(mut self, provenance: AssignmentProvenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Scope this assignment to one protected resource.
    pub fn on_resource(mut self, resource: super::ResourceId) -> Self {
        self.scope = Some(format!("{OAUTH_RESOURCE_SCOPE}{resource}"));
        self
    }

    /// The protected resource this assignment is scoped to, if any.
    pub fn resource_scope(&self) -> Option<super::ResourceId> {
        self.scope
            .as_deref()?
            .strip_prefix(OAUTH_RESOURCE_SCOPE)
            .and_then(|id| super::ResourceId::parse(id).ok())
    }

    /// Set expiry for this role assignment (builder pattern).
    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check if this assignment has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Hours remaining until expiry, or None if no expiry / already expired.
    pub fn hours_until_expiry(&self) -> Option<i64> {
        self.expires_at.and_then(|exp| {
            let hours = (exp - Utc::now()).num_hours();
            if hours >= 0 { Some(hours) } else { None }
        })
    }

    /// The `sid.governance.role_expired.v1` event of this assignment, owed by
    /// the commit that removes it at its expiry. Its id follows from the
    /// assignment, so the expiry is announced once.
    pub fn expired_event(&self) -> Event {
        self.governance_event(
            event_types::GOVERNANCE_ROLE_EXPIRED,
            format!("expired:{}", self.id.0),
            serde_json::json!({ "expired_at": self.expires_at.map(|t| t.to_rfc3339()) }),
        )
    }

    /// The warning that this assignment expires within `threshold` hours.
    /// Its id follows from the assignment and the threshold, so each warning
    /// is announced once however often the expiry scan sees it.
    pub fn expiring_event(&self, threshold: i64, hours_left: i64) -> Event {
        self.governance_event(
            event_types::GOVERNANCE_ROLE_EXPIRING,
            format!("expiring:{}:{threshold}", self.id.0),
            serde_json::json!({
                "expires_at": self.expires_at.map(|t| t.to_rfc3339()),
                "hours_left": hours_left,
                "threshold": threshold,
            }),
        )
    }

    fn governance_event(
        &self,
        event_type: &str,
        identity: String,
        extra: serde_json::Value,
    ) -> Event {
        let mut data = serde_json::json!({
            "assignment_id": self.id.0,
            "principal": self.principal,
            "role_id": self.role_id.0,
            "scope": self.scope,
        });
        if let (Some(data), serde_json::Value::Object(extra)) = (data.as_object_mut(), extra) {
            data.extend(extra);
        }
        let mut event = Event::new("sid-governance", event_type)
            .with_subject(format!("role_assignment/{}", self.id.0))
            .with_data(data);
        event.id = Uuid::new_v5(&ROLE_ASSIGNMENT_EVENT_NAMESPACE, identity.as_bytes()).to_string();
        event
    }
}

/// Namespace of role-assignment event ids.
const ROLE_ASSIGNMENT_EVENT_NAMESPACE: Uuid =
    Uuid::from_u128(0x5d2e_8a41_c936_4f07_b1e8_7c94_2a6d_f013);

// ── Cedar Policy ──────────────────────────────────────────────────────

/// Unique identifier for a Cedar policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CedarPolicyId(pub Uuid);

impl CedarPolicyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CedarPolicyId {
    fn default() -> Self {
        Self::new()
    }
}

/// Cedar policy effect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    #[default]
    Permit,
    Forbid,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Forbid => "forbid",
        }
    }
}

parse_stored!(PolicyEffect, "policy effect", [Permit, Forbid]);

impl std::fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cedar policy stored in the database.
///
/// Policies are validated on write (Cedar compile check).
/// CE evaluates policies via embedded cedar-policy crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarPolicy {
    pub id: CedarPolicyId,
    pub project_id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub policy_text: String,
    pub effect: PolicyEffect,
    pub enabled: bool,
    /// Stored revision: 0 for a new policy, moved on by every update. An
    /// update applies only over the revision it was read at.
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CedarPolicy {
    pub fn new(
        project_id: ProjectId,
        name: impl Into<String>,
        policy_text: impl Into<String>,
        effect: PolicyEffect,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: CedarPolicyId::new(),
            project_id,
            name: name.into(),
            description: None,
            policy_text: policy_text.into(),
            effect,
            enabled: true,
            revision: 0,
            created_at: now,
            updated_at: now,
        }
    }
}

// ── User Grant ───────────────────────────────────────────────────────

/// Unique identifier for a user grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileGrantId(pub Uuid);

impl ProfileGrantId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ProfileGrantId {
    fn default() -> Self {
        Self::new()
    }
}

/// User grant — assigns a set of roles to a profile within a project.
///
/// Unlike RoleAssignment (which is a single role→principal binding),
/// ProfileGrant bundles all roles a profile has in a specific project.
/// This is the "application access" entity shown in admin UIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileGrant {
    pub id: ProfileGrantId,
    /// Project scope of this grant.
    pub project_id: ProjectId,
    /// Profile receiving the roles.
    pub profile_id: ProfileId,
    /// Role keys assigned within this project (e.g., ["admin", "editor"]).
    pub role_keys: Vec<String>,
    /// Who granted this access (admin profile ID or "system").
    pub granted_by: Option<String>,
    /// Optional expiry (temporary access).
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProfileGrant {
    pub fn new(project_id: ProjectId, profile_id: ProfileId, role_keys: Vec<String>) -> Self {
        let now = Utc::now();
        Self {
            id: ProfileGrantId::new(),
            project_id,
            profile_id,
            role_keys,
            granted_by: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this grant has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Check if this grant includes a specific role key.
    pub fn has_role(&self, role_key: &str) -> bool {
        self.role_keys.iter().any(|k| k == role_key)
    }
}

// ── Internal Roles (CE RBAC) ──────────────────────────────────────────

/// Well-known internal role names used by SID itself.
pub mod internal_roles {
    /// Full system access (sid-operator).
    pub const SUPERADMIN: &str = "superadmin";
    /// Organization owner (can delete org).
    pub const ORG_OWNER: &str = "org:owner";
    /// Organization admin (manage members, policies).
    pub const ORG_ADMIN: &str = "org:admin";
    /// Organization member (view, basic actions).
    pub const ORG_MEMBER: &str = "org:member";
    /// Site/OIDC client owner.
    pub const SITE_OWNER: &str = "site:owner";
    /// Site admin (configure claims, view sessions).
    pub const SITE_ADMIN: &str = "site:admin";
    /// Profile self-management (always assigned to self).
    pub const PROFILE_OWNER: &str = "profile:owner";
}

// ── Separation of Duties (SoD) ──────────────────────────────────────

/// Severity of an SoD conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SodSeverity {
    /// Warning only, admin can override.
    Warning,
    /// Blocks assignment unless exception approved.
    Block,
}

impl SodSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Block => "block",
        }
    }
}

parse_stored!(SodSeverity, "sod severity", [Warning, Block]);

/// A separation of duties conflict rule.
///
/// Defines pairs of roles that should not be assigned to the same principal.
/// Conflicts produce warnings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodConflictRule {
    /// Rule name (e.g., "payment_segregation").
    pub name: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Roles that conflict with each other.
    pub conflicting_roles: Vec<String>,
    /// Severity level.
    pub severity: SodSeverity,
}

/// A detected SoD conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodConflict {
    /// Rule that was violated.
    pub rule_name: String,
    /// Description of the conflict.
    pub description: String,
    /// Severity.
    pub severity: SodSeverity,
    /// The specific roles that conflict.
    pub conflicting_roles: Vec<String>,
}

#[cfg(test)]
mod tests;
