// SPDX-License-Identifier: AGPL-3.0-only
//! Built-in roles every installation holds.

use sid_core::models::{AuditEntry, ProjectId, Role};
use sid_core::{Error, Result};
use sid_plugin::StorageBackend;

/// The built-in token inspector role of the system project.
pub async fn ensure_token_inspector_role(storage: &dyn StorageBackend) -> Result<Role> {
    ensure_builtin(storage, Role::token_inspector()).await
}

/// The built-in SCIM provisioner role of the system project.
pub async fn ensure_scim_provisioner_role(storage: &dyn StorageBackend) -> Result<Role> {
    ensure_builtin(storage, Role::scim_provisioner()).await
}

/// The built-in permission checker role of the system project (D054).
pub async fn ensure_permission_checker_role(storage: &dyn StorageBackend) -> Result<Role> {
    ensure_builtin(storage, Role::permission_checker()).await
}

/// `role` is created on first start; a replica starting at the same time
/// reads the one stored.
async fn ensure_builtin(storage: &dyn StorageBackend, role: Role) -> Result<Role> {
    if let Some(stored) = stored_with_key(storage, &role.key).await? {
        return Ok(stored);
    }
    match storage
        .create_role(&role, AuditEntry::system("role.builtin", &role.key).into())
        .await
    {
        Ok(()) => Ok(role),
        Err(Error::Conflict(_)) => stored_with_key(storage, &role.key).await?.ok_or_else(|| {
            Error::Storage(format!(
                "the built-in role {} conflicted and is not stored",
                role.key
            ))
        }),
        Err(e) => Err(e),
    }
}

async fn stored_with_key(storage: &dyn StorageBackend, key: &str) -> Result<Option<Role>> {
    Ok(storage
        .list_roles(ProjectId::system())
        .await?
        .into_iter()
        .find(|r| r.key == key))
}

#[cfg(test)]
mod tests;
