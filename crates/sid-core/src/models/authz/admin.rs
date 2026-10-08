// SPDX-License-Identifier: AGPL-3.0-only
//! Constrained role administration (D050 B).
//!
//! Permission to use an application and permission to manage its role
//! assignments are independent. An administrative assignment is an ordinary
//! [`RoleAssignment`](super::RoleAssignment) carrying an [`AdminEnvelope`]:
//! the operations, roles, permission ceiling, recipients and validity it may
//! administer within its own scope. Holding a working role never confers the
//! right to grant it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{GroupId, Role, RoleAssignmentPrincipal, RoleId};

/// An administration operation an envelope may permit. None implies another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminOperation {
    /// Create assignments of the envelope's roles.
    Assign,
    /// Remove assignments of the envelope's roles.
    Revoke,
    /// Change the definition of the envelope's roles, within its ceiling.
    EditRole,
    /// Grant administrative assignments narrower than this one.
    Redelegate,
}

impl AdminOperation {
    /// The stored and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assign => "assign",
            Self::Revoke => "revoke",
            Self::EditRole => "edit_role",
            Self::Redelegate => "redelegate",
        }
    }

    /// The operation spelled `s`, if any.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "assign" => Some(Self::Assign),
            "revoke" => Some(Self::Revoke),
            "edit_role" => Some(Self::EditRole),
            "redelegate" => Some(Self::Redelegate),
            _ => None,
        }
    }
}

/// A kind of principal an envelope lets its holder assign roles to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientKind {
    Profile,
    Group,
    MachineUser,
    OAuthClient,
}

impl RecipientKind {
    /// The stored and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Group => "group",
            Self::MachineUser => "machine_user",
            Self::OAuthClient => "oauth_client",
        }
    }

    /// The kind spelled `s`, if any.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "profile" => Some(Self::Profile),
            "group" => Some(Self::Group),
            "machine_user" => Some(Self::MachineUser),
            "oauth_client" => Some(Self::OAuthClient),
            _ => None,
        }
    }

    /// The kind of `principal`; a provisioning connector is never an
    /// administered recipient (its roles follow its own purpose limits).
    pub fn of(principal: &RoleAssignmentPrincipal) -> Option<Self> {
        match principal {
            RoleAssignmentPrincipal::Profile(_) => Some(Self::Profile),
            RoleAssignmentPrincipal::Group(_) => Some(Self::Group),
            RoleAssignmentPrincipal::MachineUser(_) => Some(Self::MachineUser),
            RoleAssignmentPrincipal::OAuthClient(_) => Some(Self::OAuthClient),
            RoleAssignmentPrincipal::ProvisioningConnector(_) => None,
        }
    }
}

/// What an administrative assignment may administer. Every field is an
/// explicit bound: an empty set permits nothing, never everything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminEnvelope {
    /// The permitted operations.
    pub operations: BTreeSet<AdminOperation>,
    /// The roles that may be administered, by identity.
    pub roles: BTreeSet<RoleId>,
    /// The permissions an administered role may hold at most: a role whose
    /// current content exceeds it cannot be assigned, however it is named.
    pub permission_ceiling: BTreeSet<String>,
    /// The kinds of principal roles may be assigned to.
    pub recipient_kinds: BTreeSet<RecipientKind>,
    /// When set, only members of this group (and the group itself) are
    /// eligible recipients.
    pub recipient_group: Option<GroupId>,
    /// The longest validity an administered assignment may be given, in
    /// seconds; every administered assignment expires.
    pub max_validity_secs: i64,
}

/// Why an envelope is not well-formed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("an administrative envelope names no operation")]
    NoOperations,
    #[error("an administrative envelope names no role")]
    NoRoles,
    #[error("an administrative envelope names no permission ceiling")]
    NoPermissionCeiling,
    #[error("an administrative envelope names no recipient kind")]
    NoRecipientKinds,
    #[error("an administrative envelope's maximum validity must be positive")]
    Validity,
}

/// Why an envelope does not cover a proposed effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Uncovered {
    #[error("the operation is not permitted")]
    Operation,
    #[error("the role is not one the envelope administers")]
    Role,
    #[error("the role's permissions exceed the envelope's ceiling")]
    Ceiling,
    #[error("the recipient is not eligible")]
    Recipient,
    #[error("the assignment would outlast the envelope's validity")]
    Validity,
}

impl AdminEnvelope {
    /// Check the envelope is well-formed: every bound present.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.operations.is_empty() {
            return Err(EnvelopeError::NoOperations);
        }
        if self.roles.is_empty() {
            return Err(EnvelopeError::NoRoles);
        }
        if self.permission_ceiling.is_empty() {
            return Err(EnvelopeError::NoPermissionCeiling);
        }
        if self.recipient_kinds.is_empty() {
            return Err(EnvelopeError::NoRecipientKinds);
        }
        if self.max_validity_secs <= 0 {
            return Err(EnvelopeError::Validity);
        }
        Ok(())
    }

    /// Whether this envelope alone covers `operation` of `role` (at its
    /// current content) for `recipient`, lasting `validity_secs`.
    /// `in_recipient_group` says whether the recipient belongs to the
    /// envelope's recipient group, when it names one.
    pub fn covers(
        &self,
        operation: AdminOperation,
        role: &Role,
        recipient: &RoleAssignmentPrincipal,
        in_recipient_group: bool,
        validity_secs: Option<i64>,
    ) -> Result<(), Uncovered> {
        if !self.operations.contains(&operation) {
            return Err(Uncovered::Operation);
        }
        if !self.roles.contains(&role.id) {
            return Err(Uncovered::Role);
        }
        if !role
            .permissions
            .iter()
            .all(|p| self.permission_ceiling.contains(p))
        {
            return Err(Uncovered::Ceiling);
        }
        let kind_ok =
            RecipientKind::of(recipient).is_some_and(|kind| self.recipient_kinds.contains(&kind));
        if !kind_ok || (self.recipient_group.is_some() && !in_recipient_group) {
            return Err(Uncovered::Recipient);
        }
        // Revocation ends authority; only a grant must fit the validity.
        if operation == AdminOperation::Assign
            && !validity_secs.is_some_and(|v| v > 0 && v <= self.max_validity_secs)
        {
            return Err(Uncovered::Validity);
        }
        Ok(())
    }

    /// Whether `child` only narrows this envelope: no operation, role,
    /// permission, recipient kind or validity it adds, and no recipient
    /// restriction it drops.
    pub fn is_narrowed_by(&self, child: &Self) -> bool {
        child.operations.is_subset(&self.operations)
            && child.roles.is_subset(&self.roles)
            && child.permission_ceiling.is_subset(&self.permission_ceiling)
            && child.recipient_kinds.is_subset(&self.recipient_kinds)
            && match self.recipient_group {
                None => true,
                Some(group) => child.recipient_group == Some(group),
            }
            && child.max_validity_secs <= self.max_validity_secs
    }
}

/// Who created an assignment and on what authority. Missing provenance (an
/// assignment created before it was recorded, or by the installation's
/// setup) confers no delegation authority of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignmentProvenance {
    /// The actor that created it, as the authorization engine names it
    /// (`user:<id>`, `machine:<id>`, `oauth_client:<id>`).
    pub granted_by: String,
    /// The administrative assignment that authorized it; absent when the
    /// installation's administrator authorized it as root of its scope.
    pub basis: Option<super::RoleAssignmentId>,
    /// The administrative assignment it continues to depend on: set for a
    /// redelegated administrative assignment, which ends with its source.
    pub depends_on: Option<super::RoleAssignmentId>,
    /// The permissions the role could hold at most when an envelope approved
    /// this working assignment: its role is never edited past them while the
    /// assignment exists, whatever becomes of the envelope. Absent when the
    /// root granted it, or for an administrative assignment.
    #[serde(default)]
    pub ceiling: Option<BTreeSet<String>>,
}

/// What a role edit was checked against, re-verified when it commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleEditFence {
    /// The editor's administrative assignment and its checked revision; it
    /// must still exist, unexpired, at that revision. `None` for the root.
    pub authority: Option<(super::RoleAssignmentId, u64)>,
    /// When the edit adds permissions: every assignment of the role carrying
    /// an approved ceiling, each checked to admit the new content. No other
    /// may exist at commit. `None` when the edit adds nothing.
    pub bounded: Option<BTreeSet<super::RoleAssignmentId>>,
}

/// What an administered mutation was checked against, re-verified when it
/// commits: a check that passed earlier must not commit after its authority
/// changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFence {
    /// The authorizing administrative assignment and the revision it was
    /// checked at; it must still exist, unexpired, at that revision. `None`
    /// when the installation's administrator authorized it as root.
    pub basis: Option<(super::RoleAssignmentId, u64)>,
    /// The administered role and the permissions it was checked with: an
    /// edit of anything else (its name, its description) leaves the check
    /// valid, while any change of its permissions breaks it.
    pub role: (RoleId, BTreeSet<String>),
    /// The recipient group and the member the envelope's restriction was
    /// satisfied by; the membership must still hold.
    pub recipient_membership: Option<(GroupId, super::ProfileId)>,
    /// A group recipient and the Profile granting it a role: the grantor
    /// must still be outside the group, or the grant would reach itself.
    pub grantor_outside: Option<(GroupId, super::ProfileId)>,
}

#[cfg(test)]
mod tests;
