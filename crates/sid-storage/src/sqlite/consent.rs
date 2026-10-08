// SPDX-License-Identifier: AGPL-3.0-only
//! Consent and claim grant operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, ProfileId,
        consent::{
            ClaimDecision, ClaimGrant, ClaimGrantChange, ClaimGrantId, ConsentId, ConsentRecord,
        },
    },
};
use uuid::Uuid;

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, uuid_col};

macro_rules! select_consents {
    ($where:literal) => {
        concat!(
            "SELECT id, profile_id, client_id, status, consented_at, revoked_at, updated_at \
             FROM consents WHERE ",
            $where
        )
    };
}

fn row_to_grant(row: &sqlx::sqlite::SqliteRow) -> SidResult<ClaimGrant> {
    Ok(ClaimGrant {
        id: ClaimGrantId(uuid_col(row, "id")?),
        consent_id: ConsentId(uuid_col(row, "consent_id")?),
        claim_name: col(row, "claim_name")?,
        claim_type: col::<String>(row, "claim_type")?
            .parse()
            .map_err(SidError::Storage)?,
        granted_at: dt_col(row, "granted_at")?,
        revoked_at: dt_col_opt(row, "revoked_at")?,
    })
}

impl SqliteBackend {
    async fn claim_grants(&self, consent_id: Uuid) -> SidResult<Vec<ClaimGrant>> {
        let rows = sqlx::query(
            "SELECT id, consent_id, claim_name, claim_type, granted_at, revoked_at \
             FROM claim_grants WHERE consent_id = ? ORDER BY granted_at",
        )
        .bind(consent_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_grant).collect()
    }

    async fn consent_from_row(&self, row: &sqlx::sqlite::SqliteRow) -> SidResult<ConsentRecord> {
        let id = uuid_col(row, "id")?;
        Ok(ConsentRecord {
            id: ConsentId(id),
            profile_id: col(row, "profile_id")?,
            client_id: col(row, "client_id")?,
            status: col::<String>(row, "status")?
                .parse()
                .map_err(SidError::Storage)?,
            grants: self.claim_grants(id).await?,
            consented_at: dt_col(row, "consented_at")?,
            revoked_at: dt_col_opt(row, "revoked_at")?,
            updated_at: dt_col(row, "updated_at")?,
        })
    }

    pub(crate) async fn create_consent_impl(
        &self,
        consent: &ConsentRecord,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO consents (id, profile_id, client_id, status, consented_at, revoked_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(consent.id.0.to_string())
        .bind(consent.profile_id)
        .bind(&consent.client_id)
        .bind(consent.status.as_str())
        .bind(fmt_dt(&consent.consented_at))
        .bind(fmt_dt_opt(consent.revoked_at))
        .bind(fmt_dt(&consent.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("consent", e))?;
        for grant in &consent.grants {
            sqlx::query(
                "INSERT INTO claim_grants (id, consent_id, claim_name, claim_type, granted_at, revoked_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(grant.id.0.to_string())
            .bind(consent.id.0.to_string())
            .bind(&grant.claim_name)
            .bind(grant.claim_type.as_str())
            .bind(fmt_dt(&grant.granted_at))
            .bind(fmt_dt_opt(grant.revoked_at))
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("claim grant", e))?;
        }
        Self::commit_mutation(tx, &format!("consent:{}", consent.id.0), audit).await
    }

    /// Apply `decision` to one claim of the active consent `id`; the write
    /// lock of `BEGIN IMMEDIATE` orders it with every other decision and with
    /// the consent's revocation or deletion.
    pub(crate) async fn change_claim_grant_impl(
        &self,
        id: ConsentId,
        claim_name: &str,
        decision: ClaimDecision,
        audit: MutationContext,
    ) -> SidResult<ClaimGrantChange> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("change claim grant: {e}"));
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let active = sqlx::query_scalar::<_, String>("SELECT status FROM consents WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
            .is_some_and(|status| status == "active");
        if !active {
            return Ok(ClaimGrantChange::ConsentNotActive);
        }
        let changed = match decision {
            ClaimDecision::Grant(claim_type) => sqlx::query(
                "INSERT INTO claim_grants (id, consent_id, claim_name, claim_type, granted_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (consent_id, claim_name) DO UPDATE SET \
                   claim_type = excluded.claim_type, granted_at = ?5, revoked_at = NULL \
                 WHERE claim_grants.revoked_at IS NOT NULL",
            )
            .bind(Uuid::now_v7().to_string())
            .bind(id.0.to_string())
            .bind(claim_name)
            .bind(claim_type.as_str())
            .bind(&now),
            ClaimDecision::Revoke => sqlx::query(
                "UPDATE claim_grants SET revoked_at = ?1 \
                 WHERE consent_id = ?2 AND claim_name = ?3 AND revoked_at IS NULL",
            )
            .bind(&now)
            .bind(id.0.to_string())
            .bind(claim_name),
        }
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        if !changed {
            return Ok(ClaimGrantChange::Unchanged);
        }
        sqlx::query("UPDATE consents SET updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::commit_mutation(tx, &format!("consent:{}", id.0), audit).await?;
        Ok(ClaimGrantChange::Changed)
    }

    pub(crate) async fn get_consent_impl(&self, id: ConsentId) -> SidResult<Option<ConsentRecord>> {
        let row = sqlx::query(select_consents!("id = ?"))
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        match row {
            Some(row) => self.consent_from_row(&row).await.map(Some),
            None => Ok(None),
        }
    }

    pub(crate) async fn get_consent_by_client_impl(
        &self,
        profile_id: ProfileId,
        client_id: &str,
    ) -> SidResult<Option<ConsentRecord>> {
        let row = sqlx::query(select_consents!("profile_id = ? AND client_id = ?"))
            .bind(profile_id)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        match row {
            Some(row) => self.consent_from_row(&row).await.map(Some),
            None => Ok(None),
        }
    }

    pub(crate) async fn list_consents_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ConsentRecord>> {
        let rows = sqlx::query(select_consents!(
            "profile_id = ? ORDER BY consented_at DESC"
        ))
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let mut consents = Vec::with_capacity(rows.len());
        for row in &rows {
            consents.push(self.consent_from_row(row).await?);
        }
        Ok(consents)
    }

    pub(crate) async fn revoke_consents_by_profile_impl(
        &self,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let revoked = sqlx::query(
            "UPDATE consents SET status = 'revoked', revoked_at = ?, updated_at = ? \
             WHERE profile_id = ? AND status = 'active'",
        )
        .bind(&now)
        .bind(&now)
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected();
        // A revoked consent shares nothing: its grants end with it.
        sqlx::query(
            "UPDATE claim_grants SET revoked_at = ? \
             WHERE revoked_at IS NULL AND consent_id IN \
               (SELECT id FROM consents WHERE profile_id = ? AND status = 'revoked')",
        )
        .bind(&now)
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("revoke claim grants: {e}")))?;
        Self::commit_mutation(tx, &format!("profile:{profile_id}:consents"), audit).await?;
        Ok(revoked)
    }

    pub(crate) async fn delete_consent_impl(
        &self,
        id: ConsentId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        // Its claim grants go with it (ON DELETE CASCADE).
        let deleted = sqlx::query("DELETE FROM consents WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?
            .rows_affected()
            == 1;
        if !deleted {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("consent:{}", id.0), audit).await?;
        Ok(true)
    }
}
