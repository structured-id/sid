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
    ActorFence, AdminOperation, AssignmentFence, AssignmentProvenance, AuthorityBasis,
    AuthzPrincipal, GroupId, INSTALLATION_SCOPE, MutationContext, OperationCompletion,
    PolicyOperation, PolicyScope, ProfileId, RecipientKind, Role, RoleAssignment, RoleAssignmentId,
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

/// `assignment` as the authority of `holder`, through the group it reached
/// `holder` by.
fn basis(holder: &AuthzPrincipal, assignment: &RoleAssignment) -> AuthorityBasis {
    let member = match (holder, &assignment.principal) {
        (AuthzPrincipal::Profile(profile), RoleAssignmentPrincipal::Group(group)) => {
            Some((*group, *profile))
        }
        _ => None,
    };
    AuthorityBasis {
        assignment: assignment.id,
        revision: assignment.revision,
        member,
    }
}

/// Creates and removes role assignments under the actor's authority.
pub struct RoleAdministration {
    storage: Arc<dyn StorageBackend>,
}

impl RoleAdministration {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// The root's current installation administrator assignment; none for a
    /// holder. A token's claim only says the actor held it when the token was
    /// issued: without the assignment the root administers nothing.
    async fn root_basis(&self, actor: &Administrator) -> Result<Option<AuthorityBasis>> {
        let Administrator::Root(root) = actor else {
            return Ok(None);
        };
        let AuthzPrincipal::Profile(profile) = root else {
            return Err(not_permitted());
        };
        self.storage
            .list_role_assignments_for_profile(*profile)
            .await?
            .iter()
            .find(|a| {
                a.role_id == Role::installation_administrator().id
                    && a.scope.as_deref() == Some(INSTALLATION_SCOPE)
                    && !a.is_expired()
            })
            .map(|a| Some(basis(root, a)))
            .ok_or_else(not_permitted)
    }

    /// Refuse a `profile` no longer holding its installation administrator
    /// assignment.
    pub async fn require_installation_administrator(&self, profile: ProfileId) -> Result<()> {
        self.root_basis(&Administrator::Root(AuthzPrincipal::Profile(profile)))
            .await
            .map(|_| ())
    }

    /// Store `proposed` on `actor`'s authority. An administrative assignment
    /// (with an envelope) is a redelegation and needs that right; a working
    /// one needs assignment of its role. One envelope must cover the whole
    /// effect; the check is re-verified at commit.
    pub async fn assign(
        &self,
        actor: &Administrator,
        proposed: RoleAssignment,
        ctx: MutationContext,
    ) -> Result<RoleAssignment> {
        self.assign_recording(actor, proposed, ctx, |_| None).await
    }

    /// [`Self::assign`], committing with the assignment the operation
    /// completion `record` makes of the assignment as stored.
    pub async fn assign_recording(
        &self,
        actor: &Administrator,
        mut proposed: RoleAssignment,
        ctx: MutationContext,
        record: impl FnOnce(&RoleAssignment) -> Option<OperationCompletion>,
    ) -> Result<RoleAssignment> {
        let root = self.root_basis(actor).await?;
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
        if let Some(authority) = &proposed.policy_admin {
            if authority.operations.is_empty() {
                return Err(Error::Validation(
                    "a policy authority names no operation".into(),
                ));
            }
            if proposed.resource_scope().is_none() {
                return Err(Error::Validation(
                    "a policy authority is scoped to one protected resource".into(),
                ));
            }
            if RecipientKind::of(&proposed.principal).is_none() {
                return Err(Error::Validation(
                    "a provisioning connector cannot hold administrative authority".into(),
                ));
            }
        }
        let (fence, granted_under, depends_on, ceiling) = match (actor, root) {
            (Administrator::Root(_), Some(basis)) => (
                AssignmentFence {
                    basis,
                    role: content(&role),
                    recipient_membership: None,
                    grantor_outside: None,
                },
                None,
                None,
                None,
            ),
            (Administrator::Root(_), None) => unreachable!("a root has its basis"),
            (Administrator::Holder(holder), _) => {
                let (basis, fence) = self.basis_for_grant(holder, &role, &proposed).await?;
                if proposed.administers() {
                    // A redelegation depends on its source.
                    (fence, Some(basis.id), Some(basis.id), None)
                } else {
                    // A working grant keeps the ceiling it was approved under.
                    let ceiling = basis
                        .admin
                        .map(|envelope| envelope.permission_ceiling)
                        .expect("a working grant's basis holds an envelope");
                    (fence, Some(basis.id), None, Some(ceiling))
                }
            }
        };
        proposed.provenance = Some(AssignmentProvenance {
            granted_by: actor.subject(),
            basis: granted_under,
            depends_on,
            ceiling,
        });
        let ctx = match record(&proposed) {
            Some(completion) => ctx.with_operation(completion),
            None => ctx,
        };
        self.storage
            .create_role_assignment_fenced(&proposed, &fence, ctx)
            .await?;
        Ok(proposed)
    }

    /// Remove assignment `id` on `actor`'s authority; false when it does not
    /// exist. A working assignment needs revocation of its role; an
    /// administrative one is removed only by the assignment it depends on.
    /// The `assignments` `actor` administers: all of them for the root; for a
    /// holder, exactly those its current envelopes let it revoke, so a
    /// delegated administrator can read back what it granted. Assignments it
    /// does not administer are left out, never an error.
    pub async fn administered(
        &self,
        actor: &Administrator,
        assignments: Vec<RoleAssignment>,
    ) -> Result<Vec<RoleAssignment>> {
        let root = self.root_basis(actor).await?;
        let Administrator::Holder(holder) = actor else {
            return root.map(|_| assignments).ok_or_else(not_permitted);
        };
        // The holder's authority and each role are read once per listing.
        let envelopes = self.all_envelopes_of(holder).await?;
        if envelopes.is_empty() {
            return Ok(Vec::new());
        }
        let mut roles: std::collections::HashMap<_, Option<Role>> =
            std::collections::HashMap::new();
        let mut seen = Vec::with_capacity(assignments.len());
        for assignment in assignments {
            let candidates: Vec<&RoleAssignment> = envelopes
                .iter()
                .filter(|e| e.scope == assignment.scope)
                .collect();
            if candidates.is_empty() {
                continue;
            }
            let role = match roles.get(&assignment.role_id) {
                Some(role) => role.clone(),
                None => {
                    let role = self.storage.get_role(assignment.role_id).await?;
                    roles.insert(assignment.role_id, role.clone());
                    role
                }
            };
            let Some(role) = role else {
                continue;
            };
            match self
                .revocation_basis_in(holder, candidates.into_iter(), &role, &assignment)
                .await
            {
                Ok(_) => seen.push(assignment),
                Err(Error::AuthorizationDenied(_)) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(seen)
    }

    pub async fn revoke(
        &self,
        actor: &Administrator,
        id: RoleAssignmentId,
        ctx: MutationContext,
    ) -> Result<bool> {
        let root = self.root_basis(actor).await?;
        let Some(target) = self.storage.get_role_assignment(id).await? else {
            return match actor {
                Administrator::Root(_) => Ok(false),
                Administrator::Holder(_) => Err(not_permitted()),
            };
        };
        let Some(role) = self.storage.get_role(target.role_id).await? else {
            return Err(actor.missing(format!("role {}", target.role_id.0)));
        };
        let fence = match (actor, root) {
            (Administrator::Root(_), Some(basis)) => AssignmentFence {
                basis,
                role: content(&role),
                recipient_membership: None,
                grantor_outside: None,
            },
            (Administrator::Root(_), None) => unreachable!("a root has its basis"),
            (Administrator::Holder(holder), _) => {
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
        let root = self.root_basis(actor).await?;
        let Some(current) = self.storage.get_role(edited.id).await? else {
            return Err(actor.missing(format!("role {}", edited.id.0)));
        };
        let authority = match (actor, root) {
            (Administrator::Root(_), Some(basis)) => basis,
            (Administrator::Root(_), None) => unreachable!("a root has its basis"),
            (Administrator::Holder(holder), _) => self.basis_for_edit(holder, edited).await?,
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
    async fn basis_for_edit(&self, holder: &AuthzPrincipal, role: &Role) -> Result<AuthorityBasis> {
        let project = Some(format!("project:{}", role.project_id.0));
        let mut held = self.envelopes_of(holder, &None).await?;
        held.extend(self.envelopes_of(holder, &project).await?);
        held.into_iter()
            .find(|candidate| {
                candidate.admin.as_ref().is_some_and(|envelope| {
                    envelope.operations.contains(&AdminOperation::EditRole)
                        && envelope.roles.contains(&role.id)
                        && role
                            .permissions
                            .iter()
                            .all(|p| envelope.permission_ceiling.contains(p))
                })
            })
            .map(|candidate| basis(holder, &candidate))
            .ok_or_else(not_permitted)
    }

    /// Whether `actor` may perform `operation` on policies of `scope`, and
    /// the fence its write commits under: the actor's current assignment. A
    /// holder's authority reaches only the policies of the exact protected
    /// resource its assignment is scoped to.
    pub async fn policy_authority(
        &self,
        actor: &Administrator,
        operation: PolicyOperation,
        scope: PolicyScope,
    ) -> Result<ActorFence> {
        if let Some(basis) = self.root_basis(actor).await? {
            return Ok(ActorFence::Authority(basis));
        }
        let Administrator::Holder(holder) = actor else {
            return Err(not_permitted());
        };
        let PolicyScope::Resource(resource) = scope else {
            return Err(not_permitted());
        };
        self.envelopes_of(holder, &Some(format!("oauth_resource:{resource}")))
            .await?
            .into_iter()
            .find(|candidate| {
                candidate
                    .policy_admin
                    .as_ref()
                    .is_some_and(|authority| authority.operations.contains(&operation))
            })
            .map(|candidate| ActorFence::Authority(basis(holder, &candidate)))
            .ok_or_else(not_permitted)
    }

    /// The holder's administrative assignments, direct or through its
    /// groups, that are current and scoped exactly to `scope`.
    async fn envelopes_of(
        &self,
        holder: &AuthzPrincipal,
        scope: &Option<String>,
    ) -> Result<Vec<RoleAssignment>> {
        let mut held = self.all_envelopes_of(holder).await?;
        held.retain(|a| &a.scope == scope);
        Ok(held)
    }

    /// Every live administrative assignment `holder` holds, directly or
    /// through its groups, in any scope.
    async fn all_envelopes_of(&self, holder: &AuthzPrincipal) -> Result<Vec<RoleAssignment>> {
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
        held.retain(|a| a.administers() && !a.is_expired());
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
            // Never outlast the authority it was granted under.
            if candidate
                .expires_at
                .is_some_and(|until| proposed.expires_at.is_none_or(|at| at > until))
            {
                continue;
            }
            let envelope = candidate.admin.as_ref();
            let (member, membership) = match envelope.and_then(|e| e.recipient_group) {
                Some(group) => self.in_group(group, &proposed.principal).await?,
                None => (false, None),
            };
            let roles_covered = match &proposed.admin {
                // Only a policy authority is proposed: no role is administered.
                None if proposed.policy_admin.is_some() => true,
                // A working role: assignment of exactly this role, at its
                // current content.
                None => envelope.is_some_and(|envelope| {
                    envelope
                        .covers(
                            AdminOperation::Assign,
                            role,
                            &proposed.principal,
                            member,
                            validity,
                        )
                        .is_ok()
                }),
                // Redelegation: the same administrative role, only narrower,
                // to an eligible recipient, within the validity.
                Some(child) => envelope.is_some_and(|envelope| {
                    envelope.operations.contains(&AdminOperation::Redelegate)
                        && candidate.role_id == proposed.role_id
                        && envelope.is_narrowed_by(child)
                        && RecipientKind::of(&proposed.principal)
                            .is_some_and(|k| envelope.recipient_kinds.contains(&k))
                        && (envelope.recipient_group.is_none() || member)
                        && validity.is_some_and(|v| v > 0 && v <= envelope.max_validity_secs)
                }),
            };
            // A policy authority passes on through the same one assignment:
            // its redelegation right, the same role, nothing wider, expiring.
            let policies_covered = match &proposed.policy_admin {
                None => true,
                Some(child) => candidate.policy_admin.as_ref().is_some_and(|authority| {
                    authority.operations.contains(&PolicyOperation::Redelegate)
                        && candidate.role_id == proposed.role_id
                        && child.operations.is_subset(&authority.operations)
                        && validity.is_some_and(|v| v > 0)
                }),
            };
            if roles_covered && policies_covered {
                // Checked outside by `is_self`; the commit re-checks it.
                let grantor_outside = match (holder, &proposed.principal) {
                    (AuthzPrincipal::Profile(grantor), RoleAssignmentPrincipal::Group(group)) => {
                        Some((*group, *grantor))
                    }
                    _ => None,
                };
                let fence = AssignmentFence {
                    basis: basis(holder, &candidate),
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
        let candidates = self.envelopes_of(holder, &target.scope).await?;
        self.revocation_basis_in(holder, candidates.iter(), role, target)
            .await
    }

    /// The fence of revoking `target` under the first of `candidates` (the
    /// holder's administrative assignments in the target's scope) that
    /// covers it.
    async fn revocation_basis_in<'a>(
        &self,
        holder: &AuthzPrincipal,
        candidates: impl Iterator<Item = &'a RoleAssignment>,
        role: &Role,
        target: &RoleAssignment,
    ) -> Result<AssignmentFence> {
        for candidate in candidates {
            let envelope = candidate.admin.as_ref();
            let covered = if target.administers() {
                // Only its source ends a redelegated administrative assignment,
                // with the redelegation right of every part it carries.
                let roles = target.admin.is_none()
                    || envelope.is_some_and(|e| e.operations.contains(&AdminOperation::Redelegate));
                let policies = target.policy_admin.is_none()
                    || candidate
                        .policy_admin
                        .as_ref()
                        .is_some_and(|a| a.operations.contains(&PolicyOperation::Redelegate));
                roles
                    && policies
                    && target
                        .provenance
                        .as_ref()
                        .is_some_and(|p| p.depends_on == Some(candidate.id))
            } else {
                let Some(envelope) = envelope else {
                    continue;
                };
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
                    basis: basis(holder, candidate),
                    role: content(role),
                    recipient_membership: None,
                    grantor_outside: None,
                });
            }
        }
        Err(not_permitted())
    }
}
