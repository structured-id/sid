// SPDX-License-Identifier: AGPL-3.0-only
//! Credentials, password history and WebAuthn user handles of local
//! Profiles (`CredentialStore`).

use async_trait::async_trait;
use sid_core::models::{
    Credential, CredentialId, CredentialType, HistoryCommit, MutationContext, PasswordHistory,
    ProfileId, WebAuthnUserHandle,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::CredentialStore;
use uuid::Uuid;

use super::{PostgresBackend, insert_error, password_history};

#[async_trait]
impl CredentialStore for PostgresBackend {
    type Owner = ProfileId;

    async fn get_credential(&self, id: CredentialId) -> SidResult<Option<Credential>> {
        let row = sqlx::query_as::<_, crate::pg_row::CredentialRow>(
            "SELECT * FROM credentials WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        credential_type: Option<CredentialType>,
    ) -> SidResult<Vec<Credential>> {
        let rows = if let Some(cred_type) = credential_type {
            sqlx::query_as::<_, crate::pg_row::CredentialRow>(
                "SELECT * FROM credentials WHERE profile_id = $1 AND credential_type = $2",
            )
            .bind(profile_id)
            .bind(cred_type.as_str())
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, crate::pg_row::CredentialRow>(
                "SELECT * FROM credentials WHERE profile_id = $1",
            )
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn create_credential(
        &self,
        credential: &Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::insert_credential_in_tx(&mut tx, credential).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("profile:{}", credential.profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn set_credential_label(
        &self,
        id: CredentialId,
        label: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET label = $2
             WHERE id = $1 AND status = 'active' RETURNING profile_id",
        )
        .bind(id.0)
        .bind(label)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("set credential label: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn change_password(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential,
        history: Option<&HistoryCommit>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let (verified, policy_version, artifact) =
            crate::policy_evidence::columns(&new.policy_evidence)?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET data = $3,
                policy_version = $4, zkpp_verified = $5,
                opaque_credential_identifier = $6, zkpp_artifact = $7, last_used_at = NOW()
             WHERE id = $1 AND status = 'active' AND data = $2 RETURNING profile_id",
        )
        .bind(id.0)
        .bind(expected)
        .bind(new.data.expose())
        .bind(policy_version)
        .bind(verified)
        .bind(new.opaque_credential_identifier.map(|id| id.to_vec()))
        .bind(artifact)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("change password: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        if let Some(history) = history {
            if history.owner.into_uuid() != profile_id {
                return Err(SidError::Validation(
                    "password history belongs to the credential's profile".into(),
                ));
            }
            if !password_history::apply_in_tx(&mut tx, history).await? {
                return Ok(false);
            }
        }
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn get_password_history(&self, owner: ProfileId) -> SidResult<PasswordHistory> {
        password_history::get(&self.pool, owner).await
    }

    async fn history_write_cutoff(&self) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
        sqlx::query_scalar("SELECT not_before FROM password_history_write_cutoff")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("write cutoff: {e}")))
    }

    async fn raise_history_write_cutoff(
        &self,
        not_before: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<chrono::DateTime<chrono::Utc>> {
        let not_before = sid_core::models::password_history::write_cutoff_instant(not_before);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // The row lock serializes the raise with every history commit, which
        // reads this row shared in its own transaction.
        let current: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT not_before FROM password_history_write_cutoff FOR UPDATE")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("write cutoff: {e}")))?;
        if let Some(current) = current
            && current >= not_before
        {
            return Ok(current);
        }
        sqlx::query("UPDATE password_history_write_cutoff SET not_before = $1")
            .bind(not_before)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("write cutoff raise: {e}")))?;
        Self::audit_in_tx(&mut tx, "password_history_write_cutoff", audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(not_before)
    }

    async fn reseal_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET data = $3
             WHERE id = $1 AND data = $2 RETURNING profile_id",
        )
        .bind(id.0)
        .bind(expected)
        .bind(data)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("reseal credential data: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn mark_credential_used(
        &self,
        id: CredentialId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET last_used_at = NOW()
             WHERE id = $1 AND status = 'active' RETURNING profile_id",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("mark credential used: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn replace_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET data = $3, last_used_at = NOW()
             WHERE id = $1 AND status = 'active' AND data = $2 RETURNING profile_id",
        )
        .bind(id.0)
        .bind(expected)
        .bind(data)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("replace credential data: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn replace_credential(
        &self,
        credential: &Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::replace_credential_in_tx(&mut tx, credential).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("profile:{}", credential.profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn enroll_credential(
        &self,
        credential: &Credential,
        recovery: Option<&Credential>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if let Some(set) = recovery
            && set.credential_type != CredentialType::Recovery
        {
            return Err(SidError::Validation(
                "only recovery codes are issued with an enrolled factor".into(),
            ));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::insert_credential_in_tx(&mut tx, credential).await?;
        if let Some(set) = recovery {
            Self::replace_credential_in_tx(&mut tx, set).await?;
        }
        Self::audit_in_tx(&mut tx, &format!("profile:{}", credential.profile_id), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_credential(&self, id: CredentialId, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM credentials WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("credential:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn revoke_credential(
        &self,
        id: CredentialId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::CredentialRevocation> {
        use sid_core::models::CredentialRevocation;
        let storage = |e: sqlx::Error| SidError::Storage(format!("revoke credential: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let primary_types: Vec<&str> = CredentialType::PRIMARY.iter().map(|t| t.as_str()).collect();
        let owner: Option<ProfileId> =
            sqlx::query_scalar("SELECT profile_id FROM credentials WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let Some(profile_id) = owner else {
            return Ok(CredentialRevocation::AlreadyGone);
        };
        // The profile row lock serializes revocations of one profile, so the
        // count below cannot be raced by a concurrent revocation.
        sqlx::query("SELECT 1 FROM profiles WHERE id = $1 FOR NO KEY UPDATE")
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let target: Option<(String, String)> = sqlx::query_as(
            "SELECT credential_type, status FROM credentials WHERE id = $1 FOR UPDATE",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        let Some((credential_type, status)) = target else {
            return Ok(CredentialRevocation::AlreadyGone);
        };
        if status != "active" {
            return Ok(CredentialRevocation::AlreadyGone);
        }
        if primary_types.contains(&credential_type.as_str()) {
            let others: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM credentials
                 WHERE profile_id = $1 AND id <> $2 AND status = 'active'
                   AND credential_type = ANY($3)",
            )
            .bind(profile_id)
            .bind(id.0)
            .bind(&primary_types)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            if others == 0 {
                return Ok(CredentialRevocation::LastPrimary);
            }
        }
        sqlx::query("UPDATE credentials SET status = 'revoked' WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::audit_in_tx(&mut tx, &format!("credential:{}", id.0), audit).await?;
        tx.commit().await.map_err(storage)?;
        Ok(CredentialRevocation::Revoked)
    }

    async fn delete_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query("DELETE FROM credentials WHERE profile_id = $1")
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}:credentials"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    // === WEBAUTHN USER HANDLES === (sqlx)

    async fn ensure_webauthn_user_handle(
        &self,
        profile_id: ProfileId,
        rp_id: &str,
        candidate: WebAuthnUserHandle,
        audit: MutationContext,
    ) -> SidResult<WebAuthnUserHandle> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("WebAuthn user handle: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // A concurrent first enrollment waits on the key and inserts nothing.
        let created = sqlx::query(
            "INSERT INTO webauthn_user_handles (profile_id, rp_id, user_handle)
             SELECT id, $2, $3 FROM profiles WHERE id = $1
             ON CONFLICT (profile_id, rp_id) DO NOTHING",
        )
        .bind(profile_id)
        .bind(rp_id)
        .bind(candidate.0.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("WebAuthn user handle", e))?
        .rows_affected();
        let stored: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT user_handle FROM webauthn_user_handles WHERE profile_id = $1 AND rp_id = $2",
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
            Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        }
        tx.commit().await.map_err(storage)?;
        Ok(handle)
    }

    async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: WebAuthnUserHandle,
    ) -> SidResult<Option<ProfileId>> {
        sqlx::query_scalar(
            "SELECT profile_id FROM webauthn_user_handles WHERE rp_id = $1 AND user_handle = $2",
        )
        .bind(rp_id)
        .bind(handle.0.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("WebAuthn user handle lookup: {e}")))
    }
}
