// SPDX-License-Identifier: AGPL-3.0-only
//! Principals, the email policy revision and the principal quarantine as
//! stored, for a move between stores.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        EmailKeyDisposition, EmailKeyOutcome, EmailPolicyActivation, MutationContext,
        PrincipalEntity, PrincipalId, QuarantinedPrincipal, StoredPrincipal,
    },
};

use super::{SqliteBackend, WriteTx, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error};

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

fn entity(row: &sqlx::sqlite::SqliteRow) -> SidResult<PrincipalEntity> {
    Ok(PrincipalEntity {
        id: PrincipalId(super::uuid_col(row, "id")?),
        principal_type: col::<String>(row, "principal_type")?
            .parse()
            .map_err(|e| SidError::Storage(format!("principal: {e}")))?,
        value: col(row, "value")?,
        verified: col(row, "verified")?,
        verified_at: dt_col_opt(row, "verified_at")?,
        verification_expires: dt_col_opt(row, "verification_expires")?,
        assigned_profile_id: col(row, "assigned_profile_id")?,
        assignment_revision: col(row, "assignment_revision")?,
        email_policy_revision: col(row, "email_policy_revision")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn outcome(value: &str) -> SidResult<EmailKeyOutcome> {
    match value {
        "migrated" => Ok(EmailKeyOutcome::Migrated),
        "quarantined" => Ok(EmailKeyOutcome::Quarantined),
        other => Err(SidError::Storage(format!("disposition: unknown {other}"))),
    }
}

fn outcome_text(outcome: EmailKeyOutcome) -> &'static str {
    match outcome {
        EmailKeyOutcome::Migrated => "migrated",
        EmailKeyOutcome::Quarantined => "quarantined",
    }
}

/// Principal `id` as stored, read on `conn`.
async fn stored(
    conn: &mut sqlx::SqliteConnection,
    id: PrincipalId,
) -> SidResult<Option<StoredPrincipal>> {
    let Some(row) = sqlx::query("SELECT * FROM principals WHERE id = ?")
        .bind(id.0)
        .fetch_optional(&mut *conn)
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    let entity = entity(&row)?;
    let mut claims = Vec::new();
    for row in sqlx::query("SELECT * FROM principal_bindings WHERE principal_id = ? ORDER BY id")
        .bind(id.0)
        .fetch_all(&mut *conn)
        .await
        .map_err(storage)?
    {
        claims.push(sid_core::models::PrincipalBinding {
            id: sid_core::models::PrincipalBindingId(super::uuid_col(&row, "id")?),
            principal_id: id,
            profile_id: col(&row, "profile_id")?,
            is_primary: col(&row, "is_primary")?,
            source_field: col(&row, "source_field")?,
            source_email_id: col::<Option<uuid::Uuid>>(&row, "source_email_id")?
                .map(sid_core::models::ProfileEmailId),
            source_phone_id: col::<Option<uuid::Uuid>>(&row, "source_phone_id")?
                .map(sid_core::models::ProfilePhoneId),
            created_at: dt_col(&row, "created_at")?,
        });
    }
    let disposition = sqlx::query("SELECT * FROM email_policy_dispositions WHERE principal_id = ?")
        .bind(id.0)
        .fetch_optional(&mut *conn)
        .await
        .map_err(storage)?
        .map(|row| {
            Ok::<_, SidError>(EmailKeyDisposition {
                from_revision: col(&row, "from_revision")?,
                to_revision: col(&row, "to_revision")?,
                outcome: outcome(&col::<String>(&row, "disposition")?)?,
                reason: col(&row, "reason")?,
                recorded_at: dt_col(&row, "recorded_at")?,
            })
        })
        .transpose()?;
    Ok(Some(StoredPrincipal {
        entity,
        claims,
        disposition,
    }))
}

async fn insert(tx: &mut WriteTx, principal: &StoredPrincipal) -> SidResult<()> {
    let e = &principal.entity;
    sqlx::query(
        "INSERT INTO principals (id, principal_type, value, verified, verified_at,
            verification_expires, assigned_profile_id, assignment_revision,
            email_policy_revision, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(e.id.0)
    .bind(e.principal_type.as_str())
    .bind(&e.value)
    .bind(e.verified)
    .bind(fmt_dt_opt(e.verified_at))
    .bind(fmt_dt_opt(e.verification_expires))
    .bind(e.assigned_profile_id)
    .bind(e.assignment_revision)
    .bind(e.email_policy_revision)
    .bind(fmt_dt(&e.created_at))
    .bind(fmt_dt(&e.updated_at))
    .execute(&mut **tx)
    .await
    .map_err(|err| match &err {
        // The email key fence: the revision is not the active one.
        sqlx::Error::Database(db) if db.message().contains("email policy fence") => {
            SidError::Conflict("the email key was written under another policy revision".into())
        }
        _ => insert_error("principal", err),
    })?;
    for claim in &principal.claims {
        sqlx::query(
            "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary,
                source_field, source_email_id, source_phone_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(claim.id.0)
        .bind(claim.principal_id.0)
        .bind(claim.profile_id)
        .bind(claim.is_primary)
        .bind(&claim.source_field)
        .bind(claim.source_email_id.map(|id| id.0))
        .bind(claim.source_phone_id.map(|id| id.0))
        .bind(fmt_dt(&claim.created_at))
        .execute(&mut **tx)
        .await
        .map_err(|err| insert_error("principal binding", err))?;
    }
    if let Some(d) = &principal.disposition {
        sqlx::query(
            "INSERT INTO email_policy_dispositions (principal_id, from_revision, to_revision,
                disposition, reason, recorded_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(e.id.0)
        .bind(d.from_revision)
        .bind(d.to_revision)
        .bind(outcome_text(d.outcome))
        .bind(&d.reason)
        .bind(fmt_dt(&d.recorded_at))
        .execute(&mut **tx)
        .await
        .map_err(|err| insert_error("email key disposition", err))?;
    }
    Ok(())
}

fn quarantined(row: &sqlx::sqlite::SqliteRow) -> SidResult<QuarantinedPrincipal> {
    Ok(QuarantinedPrincipal {
        principal_hash: col(row, "principal_hash")?,
        principal_type: col(row, "principal_type")?,
        until: dt_col(row, "quarantine_until")?,
        created_at: dt_col(row, "created_at")?,
    })
}

impl SqliteBackend {
    pub(crate) async fn export_principals_impl(
        &self,
        after: Option<PrincipalId>,
        limit: u32,
    ) -> SidResult<Vec<StoredPrincipal>> {
        let ids: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM principals WHERE ? IS NULL OR id > ? ORDER BY id LIMIT ?",
        )
        .bind(after.map(|a| a.0))
        .bind(after.map(|a| a.0))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        let mut conn = self.pool.acquire().await.map_err(storage)?;
        let mut principals = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(principal) = stored(&mut conn, PrincipalId(id)).await? {
                principals.push(principal);
            }
        }
        Ok(principals)
    }

    pub(crate) async fn import_principal_impl(
        &self,
        principal: &StoredPrincipal,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if principal
            .claims
            .iter()
            .any(|c| c.principal_id != principal.entity.id)
        {
            return Err(SidError::Validation(
                "a claim names another principal than the one it moves with".into(),
            ));
        }
        let mut given = principal.clone();
        given.claims.sort_by_key(|c| c.id.0);
        let mut tx = self.begin_write().await?;
        match stored(&mut tx, given.entity.id).await? {
            Some(held) if held == given => {
                Self::commit_unchanged(tx, &ctx).await?;
                return Ok(false);
            }
            Some(_) => {
                return Err(SidError::Conflict(format!(
                    "another principal {} is stored",
                    given.entity.id.0
                )));
            }
            None => {}
        }
        insert(&mut tx, &given).await?;
        Self::commit_mutation(tx, &format!("principal:{}", given.entity.id.0), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn email_policy_activation_impl(&self) -> SidResult<EmailPolicyActivation> {
        let row = sqlx::query(
            "SELECT revision, activated_at FROM email_policy_activations WHERE scope = 'installation'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(storage)?;
        Ok(EmailPolicyActivation {
            revision: col(&row, "revision")?,
            activated_at: dt_col(&row, "activated_at")?,
        })
    }

    pub(crate) async fn import_email_policy_activation_impl(
        &self,
        activation: &EmailPolicyActivation,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let row = sqlx::query(
            "SELECT revision, activated_at FROM email_policy_activations WHERE scope = 'installation'",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        let held = EmailPolicyActivation {
            revision: col(&row, "revision")?,
            activated_at: dt_col(&row, "activated_at")?,
        };
        if held == *activation {
            Self::commit_unchanged(tx, &ctx).await?;
            return Ok(false);
        }
        let keys: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM principals WHERE principal_type = 'email'")
                .fetch_one(&mut *tx)
                .await
                .map_err(storage)?;
        if keys > 0 {
            return Err(SidError::Conflict(
                "email keys are stored under another policy revision".into(),
            ));
        }
        sqlx::query(
            "UPDATE email_policy_activations SET revision = ?, activated_at = ?
             WHERE scope = 'installation'",
        )
        .bind(activation.revision)
        .bind(fmt_dt(&activation.activated_at))
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::commit_mutation(tx, "email_policy", ctx).await?;
        Ok(true)
    }

    pub(crate) async fn export_principal_quarantine_impl(
        &self,
    ) -> SidResult<Vec<QuarantinedPrincipal>> {
        sqlx::query("SELECT * FROM principal_quarantine ORDER BY principal_hash")
            .fetch_all(&self.pool)
            .await
            .map_err(storage)?
            .iter()
            .map(quarantined)
            .collect()
    }

    pub(crate) async fn import_principal_quarantine_impl(
        &self,
        entry: &QuarantinedPrincipal,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let held = sqlx::query("SELECT * FROM principal_quarantine WHERE principal_hash = ?")
            .bind(&entry.principal_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
            .as_ref()
            .map(quarantined)
            .transpose()?;
        match held {
            Some(held) if held == *entry => {
                Self::commit_unchanged(tx, &ctx).await?;
                return Ok(false);
            }
            Some(_) => {
                return Err(SidError::Conflict(
                    "another quarantine entry of the same principal is stored".into(),
                ));
            }
            None => {}
        }
        sqlx::query(
            "INSERT INTO principal_quarantine (principal_hash, principal_type, quarantine_until,
                created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&entry.principal_hash)
        .bind(&entry.principal_type)
        .bind(fmt_dt(&entry.until))
        .bind(fmt_dt(&entry.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("principal quarantine", e))?;
        Self::commit_mutation(tx, "quarantine", ctx).await?;
        Ok(true)
    }
}
