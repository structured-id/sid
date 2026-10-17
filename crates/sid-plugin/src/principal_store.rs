// SPDX-License-Identifier: AGPL-3.0-only
//! Principal store capability: the account a sign-in principal routes to.
//! `Owner` is the account type the authority authenticates; CE's is the
//! local Profile.

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{PrincipalType, ProfileId, check_principal_eligibility};

use crate::StorageBackend;

#[async_trait]
pub trait PrincipalStore: Send + Sync {
    /// The account a principal signs in to.
    type Owner: Send + Sync;

    /// The account the principal `value` of `principal_type` signs in to:
    /// its explicit assignment, while the assigned account still holds it and
    /// its key is of `key_revision` (the email policy revision it was keyed
    /// under; `None` for other types). `None` for an unknown, unassigned or
    /// released principal and for a key of another revision. Whether the
    /// account may sign in now (its status, lockout) is the caller's.
    async fn resolve_sign_in_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
        key_revision: Option<i64>,
    ) -> Result<Option<Self::Owner>>;
}

/// The CE resolution over a backend's principals and their claims: the
/// assignment routes, and only while the assigned Profile still claims the
/// principal under the current key. Other claims never select an account.
pub async fn resolve_profile_principal<B: StorageBackend + ?Sized>(
    backend: &B,
    principal_type: PrincipalType,
    value: &str,
    key_revision: Option<i64>,
) -> Result<Option<ProfileId>> {
    let Some(principal) = backend
        .get_principal_by_value(principal_type, value)
        .await?
    else {
        return Ok(None);
    };
    let Some(profile_id) = principal.assigned_profile_id else {
        return Ok(None);
    };
    let has_claim = backend
        .get_principal_bindings(principal.id)
        .await?
        .iter()
        .any(|b| b.profile_id == profile_id);
    Ok(
        check_principal_eligibility(&principal, profile_id, has_claim, key_revision)
            .is_eligible()
            .then_some(profile_id),
    )
}
