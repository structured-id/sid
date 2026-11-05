// SPDX-License-Identifier: AGPL-3.0-only
//! CE RBAC authorization service.
//!
//! Flat role resolution: direct role assignments + group-based assignments.
//! No recursion, no graph traversal, no ReBAC.
//! All checks = flat queries. Expired assignments are filtered out.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sid_core::Result;
use sid_core::models::{
    AuthzPrincipal, INSTALLATION_ADMINISTRATOR_ROLE, ProfileId, ProjectId, ResourceId, Role,
    RoleAssignment, RoleId,
};
use sid_plugin::StorageBackend;

/// RBAC authorization service (CE).
///
/// Resolves effective roles for a profile by combining:
/// 1. Direct role assignments (profile → role)
/// 2. Group-based role assignments (profile → group → role)
///
/// All assignments are filtered for expiry.
pub struct RbacService<S: StorageBackend + ?Sized> {
    storage: Arc<S>,
}

impl<S: StorageBackend + ?Sized> RbacService<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

    /// Check if a profile has a specific permission within a project.
    ///
    /// Resolves all effective roles, then checks if any role grants
    /// the requested permission.
    pub async fn check_permission(
        &self,
        profile_id: ProfileId,
        project_id: ProjectId,
        permission: &str,
    ) -> Result<bool> {
        let roles = self.resolve_effective_roles(profile_id, project_id).await?;
        Ok(roles.iter().any(|r| r.has_permission(permission)))
    }

    /// Check if a profile has a specific role (by key) within a project.
    pub async fn check_role(
        &self,
        profile_id: ProfileId,
        project_id: ProjectId,
        role_key: &str,
    ) -> Result<bool> {
        let roles = self.resolve_effective_roles(profile_id, project_id).await?;
        Ok(roles.iter().any(|r| r.key == role_key))
    }

    /// Resolve all effective roles for a profile within a project.
    ///
    /// Combines direct and group-based assignments, filters expired,
    /// deduplicates by role ID, and returns full Role objects.
    pub async fn resolve_effective_roles(
        &self,
        profile_id: ProfileId,
        project_id: ProjectId,
    ) -> Result<Vec<Role>> {
        // Direct and group assignments in one read, then their roles in one.
        let assignments = self
            .storage
            .list_role_assignments_held_by_profile(profile_id)
            .await?;
        let mut seen_role_ids = HashSet::new();
        let mut effective_role_ids = Vec::new();
        for assignment in &assignments {
            // A role held on one protected resource counts only there.
            if assignment.is_expired() || assignment.resource_scope().is_some() {
                continue;
            }
            if seen_role_ids.insert(assignment.role_id) {
                effective_role_ids.push(assignment.role_id);
            }
        }
        let mut roles = self.roles_by_id(&effective_role_ids).await?;
        Ok(effective_role_ids
            .iter()
            .filter_map(|id| roles.remove(id))
            .filter(|role| role.project_id == project_id)
            .collect())
    }

    /// The stored roles among `ids`, by id.
    async fn roles_by_id(&self, ids: &[RoleId]) -> Result<HashMap<RoleId, Role>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        Ok(self
            .storage
            .get_roles(ids)
            .await?
            .into_iter()
            .map(|role| (role.id, role))
            .collect())
    }

    /// Keys of the roles granting `permission` to `principal` through the
    /// unexpired assignments `counts` admits whose role `in_scope` admits, and
    /// the installation administrator's, in assignment order, each role once.
    async fn granting_roles(
        &self,
        principal: &AuthzPrincipal,
        permission: &str,
        counts: impl Fn(&RoleAssignment) -> bool,
        in_scope: impl Fn(&Role) -> bool,
    ) -> Result<Vec<String>> {
        let assignments = self.assignments_of(principal).await?;
        let mut seen = HashSet::new();
        // `None` is the installation administrator's assignment.
        let mut picked = Vec::new();
        for assignment in &assignments {
            if assignment.administers_installation() {
                if seen.insert(assignment.role_id) {
                    picked.push(None);
                }
                continue;
            }
            if assignment.is_expired() || !counts(assignment) || !seen.insert(assignment.role_id) {
                continue;
            }
            picked.push(Some(assignment.role_id));
        }
        let ids: Vec<RoleId> = picked.iter().flatten().copied().collect();
        let mut roles = self.roles_by_id(&ids).await?;
        let mut granting = Vec::new();
        for pick in picked {
            match pick {
                None => granting.push(INSTALLATION_ADMINISTRATOR_ROLE.to_owned()),
                Some(id) => {
                    if let Some(role) = roles.remove(&id)
                        && in_scope(&role)
                        && role.has_permission(permission)
                    {
                        granting.push(role.key);
                    }
                }
            }
        }
        Ok(granting)
    }

    /// Keys of the roles granting `permission` to `principal` on the protected
    /// resource `resource`: unexpired assignments scoped to exactly that
    /// resource (a profile's groups included), and the installation
    /// administrator's. Other project-wide and unscoped assignments grant
    /// nothing on a resource.
    pub async fn resource_granting_roles(
        &self,
        principal: &AuthzPrincipal,
        resource: ResourceId,
        permission: &str,
    ) -> Result<Vec<String>> {
        self.granting_roles(
            principal,
            permission,
            |assignment| assignment.resource_scope() == Some(resource),
            |_| true,
        )
        .await
    }

    /// Keys of the roles of `project` granting `permission` to `principal`:
    /// its unexpired assignments (a profile's groups included), except those
    /// scoped to one protected resource, which count only there, and the
    /// installation administrator's on every project.
    pub async fn project_granting_roles(
        &self,
        principal: &AuthzPrincipal,
        project: ProjectId,
        permission: &str,
    ) -> Result<Vec<String>> {
        self.granting_roles(
            principal,
            permission,
            |assignment| assignment.resource_scope().is_none(),
            |role| role.project_id == project,
        )
        .await
    }

    /// Every stored assignment of `principal`, a profile's groups included.
    async fn assignments_of(&self, principal: &AuthzPrincipal) -> Result<Vec<RoleAssignment>> {
        Ok(match principal {
            AuthzPrincipal::Profile(profile_id) => {
                self.storage
                    .list_role_assignments_held_by_profile(*profile_id)
                    .await?
            }
            AuthzPrincipal::MachineUser(machine) => {
                self.storage
                    .list_role_assignments_for_machine_user(*machine)
                    .await?
            }
            AuthzPrincipal::OAuthClient(client_id) => {
                self.storage
                    .list_role_assignments_for_oauth_client(client_id)
                    .await?
            }
            AuthzPrincipal::ProvisioningConnector(connector) => {
                self.storage
                    .list_role_assignments_for_provisioning_connector(*connector)
                    .await?
            }
        })
    }

    /// List all permissions a profile has within a project.
    ///
    /// Returns deduplicated permission strings.
    pub async fn list_effective_permissions(
        &self,
        profile_id: ProfileId,
        project_id: ProjectId,
    ) -> Result<Vec<String>> {
        let roles = self.resolve_effective_roles(profile_id, project_id).await?;
        let mut permissions = HashSet::new();
        for role in &roles {
            for perm in &role.permissions {
                permissions.insert(perm.clone());
            }
        }
        let mut result: Vec<String> = permissions.into_iter().collect();
        result.sort();
        Ok(result)
    }

    /// Check permission and return a detailed decision.
    pub async fn check_permission_detailed(
        &self,
        profile_id: ProfileId,
        project_id: ProjectId,
        permission: &str,
    ) -> Result<AuthzDecision> {
        let roles = self.resolve_effective_roles(profile_id, project_id).await?;
        let granting: Vec<String> = roles
            .iter()
            .filter(|r| r.has_permission(permission))
            .map(|r| r.key.clone())
            .collect();

        if granting.is_empty() {
            Ok(AuthzDecision::Deny {
                permission: permission.to_string(),
                project_id,
            })
        } else {
            Ok(AuthzDecision::Allow {
                granting_roles: granting,
            })
        }
    }
}

/// Result of a permission check with context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    /// Access allowed — at least one role grants the permission.
    Allow {
        /// Roles that granted the permission.
        granting_roles: Vec<String>,
    },
    /// Access denied — no role grants the permission.
    Deny {
        /// What permission was checked.
        permission: String,
        /// What project scope was checked.
        project_id: ProjectId,
    },
}

impl AuthzDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

#[cfg(test)]
mod tests;
