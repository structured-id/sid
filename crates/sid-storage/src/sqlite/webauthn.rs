// SPDX-License-Identifier: AGPL-3.0-only
//! WebAuthn user handles: one per Profile and relying party. The write runs
//! in a `BEGIN IMMEDIATE` transaction, so concurrent first enrollments of a
//! Profile are serialized and agree on one handle.

use sid_core::models::{MutationContext, ProfileId, WebAuthnUserHandle};
use sid_core::{Error as SidError, Result as SidResult};

use super::{SqliteBackend, insert_error};

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(format!("WebAuthn user handle: {e}"))
}

impl SqliteBackend {
    pub(crate) async fn ensure_webauthn_user_handle_impl(
        &self,
        profile_id: ProfileId,
        rp_id: &str,
        candidate: WebAuthnUserHandle,
        audit: MutationContext,
    ) -> SidResult<WebAuthnUserHandle> {
        let mut tx = self.begin_write().await?;
        let created = sqlx::query(
            "INSERT INTO webauthn_user_handles (profile_id, rp_id, user_handle)
             SELECT id, ?, ? FROM profiles WHERE id = ?
             ON CONFLICT (profile_id, rp_id) DO NOTHING",
        )
        .bind(rp_id)
        .bind(candidate.0.as_slice())
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("WebAuthn user handle", e))?
        .rows_affected();
        let stored: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT user_handle FROM webauthn_user_handles WHERE profile_id = ? AND rp_id = ?",
        )
        .bind(profile_id)
        .bind(rp_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        let stored = stored.ok_or_else(|| SidError::NotFound(format!("profile {profile_id}")))?;
        let handle = WebAuthnUserHandle::from_slice(&stored)
            .ok_or_else(|| SidError::Storage("column user_handle: not 16 bytes".into()))?;
        if created > 0 {
            Self::commit_mutation(tx, &format!("profile:{profile_id}"), audit).await?;
        }
        Ok(handle)
    }

    pub(crate) async fn get_profile_by_webauthn_user_handle_impl(
        &self,
        rp_id: &str,
        handle: WebAuthnUserHandle,
    ) -> SidResult<Option<ProfileId>> {
        sqlx::query_scalar(
            "SELECT profile_id FROM webauthn_user_handles WHERE rp_id = ? AND user_handle = ?",
        )
        .bind(rp_id)
        .bind(handle.0.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)
    }
}
