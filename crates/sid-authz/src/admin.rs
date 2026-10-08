// SPDX-License-Identifier: AGPL-3.0-only
//! The one mutation core for role assignments (D050 B, constrained role
//! administration).
//!
//! Every writer of role assignments (the authorization API, governance,
//! imports, embedded callers) goes through [`RoleAdministration`]. It decides
//! on the authenticated actor and the current definitions, never on a
//! claimed grantor, and commits through the storage fence so an authority
//! that changed after the check cannot commit.

use std::collections::BTreeSet;
use std::sync::Arc;

use sid_core::models::{
    AdminOperation, AssignmentFence, AssignmentProvenance, AuthzPrincipal, GroupId,
    MutationContext, RecipientKind, Role, RoleAssignment, RoleAssignmentId,
    RoleAssignmentPrincipal, RoleEditFence,
};
use sid_core::{Error, Result};
use sid_plugin::StorageBackend;

/// Who performs an administration operation.
#[derive(Debug, Clone)]
pub enum Administrator {
    /// The installation's administrator: the root of its own scope, which
    /// may grant broad authority there explicitly.
    Root(AuthzPrincipal),
    /// Any other authenticated principal, administering only through its
    /// own current administrative assignments.
    Holder(AuthzPrincipal),
}

impl Administrator {
    fn principal(&self) -> &AuthzPrincipal {
        match self {
            Self::Root(p) | Self::Holder(p) => p,
        }
    }

    /// The refusal for something `what` that does not exist: the root sees
    /// that it is missing; anyone else gets the refusal of an uncovered
    /// change, so existence is not disclosed beyond its authority.
    fn missing(&self, what: String) -> Error {
        match self {
            Self::Root(_) => Error::NotFound(what),
            Self::Holder(_) => not_permitted(),
        }
    }

    /// The actor as the authorization engine names it.
    pub fn subject(&self) -> String {
        match self.principal() {
            AuthzPrincipal::Profile(id) => format!("user:{id}"),
            AuthzPrincipal::MachineUser(id) => format!("machine:{id}"),
            AuthzPrincipal::OAuthClient(id) => format!("oauth_client:{id}"),
            AuthzPrincipal::ProvisioningConnector(id) => format!("provisioning_connector:{id}"),
        }
    }
}

/// `role` and the permissions a fence re-checks it with.
fn content(role: &Role) -> (sid_core::models::RoleId, BTreeSet<String>) {
    (role.id, role.permissions.iter().cloned().collect())
}

/// Refusal of an operation no current authority covers. It names no
/// foreign subject or envelope.
fn not_permitted() -> Error {
    Error::AuthorizationDenied("no administrative assignment covers this change".into())
}

/// Creates and removes role assignments under the actor's authority.
pub struct RoleAdministration {
    storage: Arc<dyn StorageBackend>,
}

impl RoleAdministration {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// Store `proposed` on `actor`'s authority. An administrative assignment
    /// (with an envelope) is a redelegation and needs that right; a working
    /// one needs assignment of its role. One envelope must cover the whole
    /// effect; the check is re-verified at commit.
    pub async fn assign(
        &self,
        actor: &Administrator,
        mut proposed: RoleAssignment,
        ctx: MutationContext,
    ) -> Result<RoleAssignment> {
        let Some(role) = self.storage.get_role(proposed.role_id).await? else {
            return Err(actor.missing(format!("role {}", proposed.role_id.0)));
        };
        if let Some(envelope) = &proposed.admin {
            envelope
                .validate()
                .map_err(|e| Error::Validation(e.to_string()))?;
            // A connector keeps its own purpose limits; it never administers.
            if RecipientKind::of(&proposed.principal).is_none() {
                return Err(Error::Validation(
                    "a provisioning connector cannot hold administrative authority".into(),
                ));
            }
        }
        let (fence, basis, depends_on, ceiling) = match actor {
            Administrator::Root(_) => (
                AssignmentFence {
                    basis: None,
                    role: content(&role),
                    recipient_membership: None,
                    grantor_outside: None,
                },
                None,
                None,
                None,
            ),
            Administrator::Holder(holder) => {
                let (basis, fence) = self.basis_for_grant(holder, &role, &proposed).await?;
                match proposed.admin {
                    // A redelegation depends on its source.
                    Some(_) => (fence, Some(basis.id), Some(basis.id), None),
                    // A working grant keeps the ceiling it was approved under.
                    None => {
                        let ceiling = basis
                            .admin
                            .map(|envelope| envelope.permission_ceiling)
                            .expect("a basis is an administrative assignment");
                        (fence, Some(basis.id), None, Some(ceiling))
                    }
                }
            }
        };
        proposed.provenance = Some(AssignmentProvenance {
            granted_by: actor.subject(),
            basis,
            depends_on,
            ceiling,
        });
        self.storage
            .create_role_assignment_fenced(&proposed, &fence, ctx)
            .await?;
        Ok(proposed)
    }

    /// Remove assignment `id` on `actor`'s authority; false when it does not
    /// exist. A working assignment needs revocation of its role; an
    /// administrative one is removed only by the assignment it depends on.
    pub async fn revoke(
        &self,
        actor: &Administrator,
        id: RoleAssignmentId,
        ctx: MutationContext,
    ) -> Result<bool> {
        let Some(target) = self.storage.get_role_assignment(id).await? else {
            return match actor {
                Administrator::Root(_) => Ok(false),
                Administrator::Holder(_) => Err(not_permitted()),
            };
        };
        let Some(role) = self.storage.get_role(target.role_id).await? else {
            return Err(actor.missing(format!("role {}", target.role_id.0)));
        };
        let fence = match actor {
            Administrator::Root(_) => AssignmentFence {
                basis: None,
                role: content(&role),
                recipient_membership: None,
                grantor_outside: None,
            },
            Administrator::Holder(holder) => {
                self.basis_for_revocation(holder, &role, &target).await?
            }
        };
        self.storage
            .delete_role_assignment_fenced(id, &fence, ctx)
            .await
    }

    /// Store `edited`, the new content of a role read at `edited.revision`,
    /// on `actor`'s authority; false when the role changed since it was
    /// read. The root edits any role; anyone else needs an envelope
    /// permitting edits of it whose ceiling admits the new content. Either
    /// way a role never grows past a ceiling an envelope approved one of its
    /// assignments under: that assignment is reauthorized first.
    pub async fn edit_role(
        &self,
        actor: &Administrator,
        edited: &Role,
        ctx: MutationContext,
    ) -> Result<bool> {
        let Some(current) = self.storage.get_role(edited.id).await? else {
            return Err(actor.missing(format!("role {}", edited.id.0)));
        };
        let authority = match actor {
            Administrator::Root(_) => None,
            Administrator::Holder(holder) => Some(self.basis_for_edit(holder, edited).await?),
        };
        let widens = edited
            .permissions
            .iter()
            .any(|p| !current.permissions.contains(p));
        let bounded = if widens {
            let mut checked = BTreeSet::new();
            for assignment in self
                .storage
                .list_role_assignments_for_role(edited.id)
                .await?
            {
                let Some(ceiling) = assignment
                    .provenance
                    .as_ref()
                    .and_then(|p| p.ceiling.as_ref())
                else {
                    continue;
                };
                if !edited.permissions.iter().all(|p| ceiling.contains(p)) {
                    return Err(match actor {
                        Administrator::Root(_) => Error::InvalidState(format!(
                            "assignment {} was approved under a narrower ceiling; \
                             reauthorize it before widening the role",
                            assignment.id.0
                        )),
                        Administrator::Holder(_) => not_permitted(),
                    });
                }
                checked.insert(assignment.id);
            }
            Some(checked)
        } else {
            None
        };
        self.storage
            .update_role_fenced(edited, &RoleEditFence { authority, bounded }, ctx)
            .await
    }

    /// The holder's administrative assignment permitting the edit of `role`
    /// to its new content, with the revision its commit re-checks.
    async fn basis_for_edit(
        &self,
        holder: &AuthzPrincipal,
        role: &Role,
    ) -> Result<(RoleAssignmentId, u64)> {
        let project = Some(format!("project:{}", role.project_id.0));
        let mut held = self.envelopes_of(holder, &None).await?;
        held.extend(self.envelopes_of(holder, &project).await?);
        held.into_iter()
            .find(|candidate| {
                let envelope = candidate.admin.as_ref().expect("filtered to envelopes");
                envelope.operations.contains(&AdminOperation::EditRole)
                    && envelope.roles.contains(&role.id)
                    && role
                        .permissions
                        .iter()
                        .all(|p| envelope.permission_ceiling.contains(p))
            })
            .map(|candidate| (candidate.id, candidate.revision))
            .ok_or_else(not_permitted)
    }

    /// The holder's administrative assignments, direct or through its
    /// groups, that are current and scoped exactly to `scope`.
    async fn envelopes_of(
        &self,
        holder: &AuthzPrincipal,
        scope: &Option<String>,
    ) -> Result<Vec<RoleAssignment>> {
        let mut held = match holder {
            AuthzPrincipal::Profile(profile) => {
                let mut all = self
                    .storage
                    .list_role_assignments_for_profile(*profile)
                    .await?;
                for group in self.storage.list_groups_for_profile(*profile).await? {
                    all.extend(
                        self.storage
                            .list_role_assignments_for_group(group.id)
                            .await?,
                    );
                }
                all
            }
            AuthzPrincipal::MachineUser(machine) => {
                self.storage
                    .list_role_assignments_for_machine_user(*machine)
                    .await?
            }
            AuthzPrincipal::OAuthClient(client) => {
                self.storage
                    .list_role_assignments_for_oauth_client(client)
                    .await?
            }
            // A connector's purpose limits never include role administration.
            AuthzPrincipal::ProvisioningConnector(_) => Vec::new(),
        };
        held.retain(|a| a.admin.is_some() && !a.is_expired() && &a.scope == scope);
        Ok(held)
    }

    /// Whether `recipient` is the actor itself, directly or as a group the
    /// actor belongs to: self-assignment is never implied by an envelope.
    async fn is_self(
        &self,
        holder: &AuthzPrincipal,
        recipient: &RoleAssignmentPrincipal,
    ) -> Result<bool> {
        Ok(match (holder, recipient) {
            (AuthzPrincipal::Profile(a), RoleAssignmentPrincipal::Profile(b)) => a == b,
            (AuthzPrincipal::Profile(a), RoleAssignmentPrincipal::Group(group)) => self
                .storage
                .list_group_members(*group)
                .await?
                .iter()
                .any(|m| m.profile_id == *a),
            (AuthzPrincipal::MachineUser(a), RoleAssignmentPrincipal::MachineUser(b)) => a == b,
            (AuthzPrincipal::OAuthClient(a), RoleAssignmentPrincipal::OAuthClient(b)) => a == b,
            _ => false,
        })
    }

    /// Whether `recipient` belongs to `group`, and the membership a fence
    /// must re-check.
    async fn in_group(
        &self,
        group: GroupId,
        recipient: &RoleAssignmentPrincipal,
    ) -> Result<(bool, Option<(GroupId, sid_core::models::ProfileId)>)> {
        Ok(match recipient {
            RoleAssignmentPrincipal::Group(g) => (*g == group, None),
            RoleAssignmentPrincipal::Profile(profile) => {
                let member = self
                    .storage
                    .list_group_members(group)
                    .await?
                    .iter()
                    .any(|m| m.profile_id == *profile);
                (member, member.then_some((group, *profile)))
            }
            _ => (false, None),
        })
    }

    /// The one administrative assignment of `holder` covering the whole
    /// grant of `proposed`, and the fence its commit re-checks.
    async fn basis_for_grant(
        &self,
        holder: &AuthzPrincipal,
        role: &Role,
        proposed: &RoleAssignment,
    ) -> Result<(RoleAssignment, AssignmentFence)> {
        if self.is_self(holder, &proposed.principal).await? {
            return Err(not_permitted());
        }
        let validity = proposed
            .expires_at
            .map(|at| (at - chrono::Utc::now()).num_seconds());
        for candidate in self.envelopes_of(holder, &proposed.scope).await? {
            let envelope = candidate.admin.as_ref().expect("filtered to envelopes");
            // Never outlast the authority it was granted under.
            if candidate
                .expires_at
                .is_some_and(|until| proposed.expires_at.is_none_or(|at| at > until))
            {
                continue;
            }
            let (member, membership) = match envelope.recipient_group {
                Some(group) => self.in_group(group, &proposed.principal).await?,
                None => (false, None),
            };
            let covered = match &proposed.admin {
                // A working role: assignment of exactly this role, at its
                // current content.
                None => envelope
                    .covers(
                        AdminOperation::Assign,
                        role,
                        &proposed.principal,
                        member,
                        validity,
                    )
                    .is_ok(),
                // Redelegation: the same administrative role, only narrower,
                // to an eligible recipient, within the validity.
                Some(child) => {
                    envelope.operations.contains(&AdminOperation::Redelegate)
                        && candidate.role_id == proposed.role_id
                        && envelope.is_narrowed_by(child)
                        && RecipientKind::of(&proposed.principal)
                            .is_some_and(|k| envelope.recipient_kinds.contains(&k))
                        && (envelope.recipient_group.is_none() || member)
                        && validity.is_some_and(|v| v > 0 && v <= envelope.max_validity_secs)
                }
            };
            if covered {
                // Checked outside by `is_self`; the commit re-checks it.
                let grantor_outside = match (holder, &proposed.principal) {
                    (AuthzPrincipal::Profile(grantor), RoleAssignmentPrincipal::Group(group)) => {
                        Some((*group, *grantor))
                    }
                    _ => None,
                };
                let fence = AssignmentFence {
                    basis: Some((candidate.id, candidate.revision)),
                    role: content(role),
                    recipient_membership: membership,
                    grantor_outside,
                };
                return Ok((candidate, fence));
            }
        }
        Err(not_permitted())
    }

    /// The fence for `holder` removing `target`, when one of its
    /// administrative assignments covers it.
    async fn basis_for_revocation(
        &self,
        holder: &AuthzPrincipal,
        role: &Role,
        target: &RoleAssignment,
    ) -> Result<AssignmentFence> {
        for candidate in self.envelopes_of(holder, &target.scope).await? {
            let envelope = candidate.admin.as_ref().expect("filtered to envelopes");
            let covered = if target.admin.is_some() {
                // Only its source ends a redelegated administrative assignment.
                envelope.operations.contains(&AdminOperation::Redelegate)
                    && target
                        .provenance
                        .as_ref()
                        .is_some_and(|p| p.depends_on == Some(candidate.id))
            } else {
                let member = match envelope.recipient_group {
                    Some(group) => self.in_group(group, &target.principal).await?.0,
                    None => false,
                };
                envelope.operations.contains(&AdminOperation::Revoke)
                    && envelope.roles.contains(&role.id)
                    && RecipientKind::of(&target.principal)
                        .is_some_and(|k| envelope.recipient_kinds.contains(&k))
                    && (envelope.recipient_group.is_none() || member)
            };
            if covered {
                return Ok(AssignmentFence {
                    basis: Some((candidate.id, candidate.revision)),
                    role: content(role),
                    recipient_membership: None,
                    grantor_outside: None,
                });
            }
        }
        Err(not_permitted())
    }
}
