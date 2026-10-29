// SPDX-License-Identifier: AGPL-3.0-only
//! The roles a Profile's tokens carry: its own labels, and the
//! installation administrator role exactly when it holds the installation
//! administrator assignment.

use sid_core::models::{Profile, ProfileId, RoleAssignment};
use sid_plugin::StorageBackend;

/// The role a token's `roles` claim names its installation administrator by;
/// [`account_roles`] puts it there for a Profile holding the installation
/// administrator assignment, and only for one.
pub const ADMIN_ROLE_CLAIM: &str = "admin";

/// The `roles` of `profile`'s tokens. The administrator role comes from the
/// installation administrator assignment, never from a label stored on the
/// Profile, which is dropped wherever it came from (an import, a directory).
pub async fn account_roles(
    storage: &dyn StorageBackend,
    profile: &Profile,
) -> sid_core::Result<Vec<String>> {
    // Only the assignment is authority: a stored label confers nothing, also
    // one a database initialized before the assignment existed holds. Such a
    // database is initialized again from the current schema, not converted.
    let mut roles: Vec<String> = profile
        .roles
        .iter()
        .filter(|role| *role != ADMIN_ROLE_CLAIM)
        .cloned()
        .collect();
    if administers_installation(storage, profile.id).await? {
        roles.push(ADMIN_ROLE_CLAIM.to_owned());
    }
    Ok(roles)
}

/// Whether `profile` holds a live installation administrator assignment.
pub async fn administers_installation(
    storage: &dyn StorageBackend,
    profile: ProfileId,
) -> sid_core::Result<bool> {
    Ok(storage
        .list_role_assignments_for_profile(profile)
        .await?
        .iter()
        .any(RoleAssignment::administers_installation))
}

#[cfg(test)]
mod tests;
