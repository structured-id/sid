// SPDX-License-Identifier: AGPL-3.0-only
//! CE RBAC authorization service.
//!
//! Flat role resolution: direct role assignments + group-based assignments.
//! No recursion, no graph traversal, no ReBAC.
//! All checks = flat queries. Expired assignments are filtered out.

use std::collections::HashSet;
use std::sync::Arc;

use sid_core::Result;
use sid_core::models::{AuthzPrincipal, ProfileId, ProjectId, ResourceId, Role, RoleAssignment};
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
        // 1. Get direct role assignments for the profile.
        let direct_assignments = self
            .storage
            .list_role_assignments_for_profile(profile_id)
            .await?;

        // 2. Get group memberships → group role assignments.
        let groups = self.storage.list_groups_for_profile(profile_id).await?;
        let mut group_assignments = Vec::new();
        for group in &groups {
            let assignments = self
                .storage
                .list_role_assignments_for_group(group.id)
                .await?;
            group_assignments.extend(assignments);
        }

        // 3. Combine, filter expired, deduplicate role IDs.
        let mut seen_role_ids = HashSet::new();
        let mut effective_role_ids = Vec::new();

        for assignment in direct_assignments.iter().chain(group_assignments.iter()) {
            // A role held on one protected resource counts only there.
            if assignment.is_expired() || assignment.resource_scope().is_some() {
                continue;
            }
            if seen_role_ids.insert(assignment.role_id) {
                effective_role_ids.push(assignment.role_id);
            }
        }

        // 4. Fetch full Role objects, filter to requested project.
        let mut roles = Vec::new();
        for role_id in effective_role_ids {
            if let Some(role) = self.storage.get_role(role_id).await?
                && role.project_id == project_id
            {
                roles.push(role);
            }
        }

        Ok(roles)
    }

    /// Keys of the roles granting `permission` to `principal` on the protected
    /// resource `resource`: unexpired assignments scoped to exactly that
    /// resource (a profile's groups included). Project-wide and unscoped
    /// assignments grant nothing on a resource.
    pub async fn resource_granting_roles(
        &self,
        principal: &AuthzPrincipal,
        resource: ResourceId,
        permission: &str,
    ) -> Result<Vec<String>> {
        let assignments = self.assignments_of(principal).await?;
        let mut seen = HashSet::new();
        let mut granting = Vec::new();
        for assignment in &assignments {
            if assignment.is_expired()
                || assignment.resource_scope() != Some(resource)
                || !seen.insert(assignment.role_id)
            {
                continue;
            }
            if let Some(role) = self.storage.get_role(assignment.role_id).await?
                && role.has_permission(permission)
            {
                granting.push(role.key);
            }
        }
        Ok(granting)
    }

    /// Keys of the roles of `project` granting `permission` to `principal`:
    /// its unexpired assignments (a profile's groups included), except those
    /// scoped to one protected resource, which count only there.
    pub async fn project_granting_roles(
        &self,
        principal: &AuthzPrincipal,
        project: ProjectId,
        permission: &str,
    ) -> Result<Vec<String>> {
        let assignments = self.assignments_of(principal).await?;
        let mut seen = HashSet::new();
        let mut granting = Vec::new();
        for assignment in &assignments {
            if assignment.is_expired()
                || assignment.resource_scope().is_some()
                || !seen.insert(assignment.role_id)
            {
                continue;
            }
            if let Some(role) = self.storage.get_role(assignment.role_id).await?
                && role.project_id == project
                && role.has_permission(permission)
            {
                granting.push(role.key);
            }
        }
        Ok(granting)
    }

    /// Every stored assignment of `principal`, a profile's groups included.
    async fn assignments_of(&self, principal: &AuthzPrincipal) -> Result<Vec<RoleAssignment>> {
        Ok(match principal {
            AuthzPrincipal::Profile(profile_id) => {
                let mut all = self
                    .storage
                    .list_role_assignments_for_profile(*profile_id)
                    .await?;
                for group in self.storage.list_groups_for_profile(*profile_id).await? {
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
