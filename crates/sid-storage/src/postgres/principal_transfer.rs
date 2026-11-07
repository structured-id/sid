// SPDX-License-Identifier: AGPL-3.0-only
//! Principals, the email policy revision and the principal quarantine as
//! stored, for a move between stores. An import locks the activation row
//! first, the row every email key write reads.

use chrono::{DateTime, Utc};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        EmailKeyDisposition, EmailKeyOutcome, EmailPolicyActivation, MutationContext,
        PrincipalBinding, PrincipalBindingId, PrincipalEntity, PrincipalId, ProfileEmailId,
        ProfileId, ProfilePhoneId, QuarantinedPrincipal, StoredPrincipal, StoredUserHandle,
        WebAuthnUserHandle,
    },
};
use sqlx::Row;

use super::PostgresBackend;

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

fn get<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    name: &str,
) -> SidResult<T> {
    row.try_get(name)
        .map_err(|e| SidError::Storage(format!("column {name}: {e}")))
}

fn entity(row: &sqlx::postgres::PgRow) -> SidResult<PrincipalEntity> {
    Ok(PrincipalEntity {
        id: PrincipalId(get(row, "id")?),
        principal_type: get::<String>(row, "principal_type")?
            .parse()
            .map_err(|e| SidError::Storage(format!("principal: {e}")))?,
        value: get(row, "value")?,
        verified: get(row, "verified")?,
        verified_at: get(row, "verified_at")?,
        verification_expires: get(row, "verification_expires")?,
        assigned_profile_id: get(row, "assigned_profile_id")?,
        assignment_revision: get(row, "assignment_revision")?,
        email_policy_revision: get(row, "email_policy_revision")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
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
    conn: &mut sqlx::PgConnection,
    id: PrincipalId,
) -> SidResult<Option<StoredPrincipal>> {
    let Some(row) = sqlx::query("SELECT * FROM principals WHERE id = $1")
        .bind(id.0)
        .fetch_optional(&mut *conn)
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    let entity = entity(&row)?;
    let mut claims = Vec::new();
    for row in sqlx::query("SELECT * FROM principal_bindings WHERE principal_id = $1 ORDER BY id")
        .bind(id.0)
        .fetch_all(&mut *conn)
        .await
        .map_err(storage)?
    {
        claims.push(PrincipalBinding {
            id: PrincipalBindingId(get(&row, "id")?),
            principal_id: id,
            profile_id: get(&row, "profile_id")?,
            is_primary: get(&row, "is_primary")?,
            source_field: get(&row, "source_field")?,
            source_email_id: get::<Option<uuid::Uuid>>(&row, "source_email_id")?
                .map(ProfileEmailId),
            source_phone_id: get::<Option<uuid::Uuid>>(&row, "source_phone_id")?
                .map(ProfilePhoneId),
            created_at: get(&row, "created_at")?,
        });
    }
    let disposition =
        sqlx::query("SELECT * FROM email_policy_dispositions WHERE principal_id = $1")
            .bind(id.0)
            .fetch_optional(&mut *conn)
            .await
            .map_err(storage)?
            .map(|row| {
                Ok::<_, SidError>(EmailKeyDisposition {
                    from_revision: get(&row, "from_revision")?,
                    to_revision: get(&row, "to_revision")?,
                    outcome: outcome(&get::<String>(&row, "disposition")?)?,
                    reason: get(&row, "reason")?,
                    recorded_at: get(&row, "recorded_at")?,
                })
            })
            .transpose()?;
    Ok(Some(StoredPrincipal {
        entity,
        claims,
        disposition,
    }))
}

async fn insert(tx: &mut Tx<'_>, principal: &StoredPrincipal) -> SidResult<()> {
    let e = &principal.entity;
    if let Some(revision) = e.email_policy_revision {
        let active: i64 = sqlx::query_scalar(
            "SELECT revision FROM email_policy_activations WHERE scope = 'installation'",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?;
        if !principal.restores_under(active) {
            return Err(SidError::Conflict(format!(
                "the email key was written under policy revision {revision} \
                 and carries no quarantine from it"
            )));
        }
    }
    // A quarantined key's record first: the fence admits a key at an earlier
    // revision only with it, and its reference to the key is checked at commit.
    if let Some(d) = &principal.disposition {
        sqlx::query(
            "INSERT INTO email_policy_dispositions (principal_id, from_revision, to_revision,
                disposition, reason, recorded_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(e.id.0)
        .bind(d.from_revision)
        .bind(d.to_revision)
        .bind(outcome_text(d.outcome))
        .bind(&d.reason)
        .bind(d.recorded_at)
        .execute(&mut **tx)
        .await
        .map_err(|err| super::insert_error("email key disposition", err))?;
    }
    sqlx::query(
        "INSERT INTO principals (id, principal_type, value, verified, verified_at,
            verification_expires, assigned_profile_id, assignment_revision,
            email_policy_revision, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(e.id.0)
    .bind(e.principal_type.as_str())
    .bind(&e.value)
    .bind(e.verified)
    .bind(e.verified_at)
    .bind(e.verification_expires)
    .bind(e.assigned_profile_id)
    .bind(e.assignment_revision)
    .bind(e.email_policy_revision)
    .bind(e.created_at)
    .bind(e.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(|err| super::insert_error("principal", err))?;
    for claim in &principal.claims {
        sqlx::query(
            "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary,
                source_field, source_email_id, source_phone_id, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(claim.id.0)
        .bind(claim.principal_id.0)
        .bind(claim.profile_id)
        .bind(claim.is_primary)
        .bind(&claim.source_field)
        .bind(claim.source_email_id.map(|id| id.0))
        .bind(claim.source_phone_id.map(|id| id.0))
        .bind(claim.created_at)
        .execute(&mut **tx)
        .await
        .map_err(|err| super::insert_error("principal binding", err))?;
    }
    Ok(())
}

fn quarantined(row: &sqlx::postgres::PgRow) -> SidResult<QuarantinedPrincipal> {
    Ok(QuarantinedPrincipal {
        principal_hash: get(row, "principal_hash")?,
        principal_type: get(row, "principal_type")?,
        until: get::<DateTime<Utc>>(row, "quarantine_until")?,
        created_at: get(row, "created_at")?,
    })
}

fn user_handle(row: &sqlx::postgres::PgRow) -> SidResult<StoredUserHandle> {
    Ok(StoredUserHandle {
        profile_id: get(row, "profile_id")?,
        rp_id: get(row, "rp_id")?,
        handle: WebAuthnUserHandle::from_slice(&get::<Vec<u8>>(row, "user_handle")?)
            .ok_or_else(|| SidError::Storage("column user_handle: not 16 bytes".into()))?,
        created_at: get(row, "created_at")?,
    })
}

impl PostgresBackend {
    pub(crate) async fn export_webauthn_user_handles_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<StoredUserHandle>> {
        sqlx::query("SELECT * FROM webauthn_user_handles WHERE profile_id = $1 ORDER BY rp_id")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage)?
            .iter()
            .map(user_handle)
            .collect()
    }

    pub(crate) async fn import_webauthn_user_handle_impl(
        &self,
        handle: &StoredUserHandle,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // The Profile is held: its deletion takes its handles.
        let held_profile: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM profiles WHERE id = $1 FOR SHARE")
                .bind(handle.profile_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        if held_profile.is_none() {
            return Err(SidError::NotFound(format!("profile {}", handle.profile_id)));
        }
        let held = sqlx::query(
            "SELECT * FROM webauthn_user_handles
             WHERE (profile_id = $1 AND rp_id = $2) OR (rp_id = $2 AND user_handle = $3)",
        )
        .bind(handle.profile_id)
        .bind(&handle.rp_id)
        .bind(handle.handle.0.as_slice())
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?
        .iter()
        .map(user_handle)
        .collect::<SidResult<Vec<_>>>()?;
        if held.iter().any(|h| h != handle) {
            return Err(SidError::Conflict(
                "another user handle is stored at the relying party".into(),
            ));
        }
        if !held.is_empty() {
            Self::unchanged_in_tx(tx, &ctx).await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO webauthn_user_handles (profile_id, rp_id, user_handle, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(handle.profile_id)
        .bind(&handle.rp_id)
        .bind(handle.handle.0.as_slice())
        .bind(handle.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("WebAuthn user handle", e))?;
        Self::audit_in_tx(&mut tx, &format!("profile:{}", handle.profile_id), ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }

    pub(crate) async fn export_principals_impl(
        &self,
        after: Option<PrincipalId>,
        limit: u32,
    ) -> SidResult<Vec<StoredPrincipal>> {
        let ids: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM principals WHERE $1::uuid IS NULL OR id > $1 ORDER BY id LIMIT $2",
        )
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
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // The revision every email key is written under, held for the commit.
        sqlx::query(
            "SELECT 1 FROM email_policy_activations WHERE scope = 'installation' FOR SHARE",
        )
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        match stored(&mut tx, given.entity.id).await? {
            Some(held) if held == given => {
                Self::unchanged_in_tx(tx, &ctx).await?;
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
        Self::audit_in_tx(&mut tx, &format!("principal:{}", given.entity.id.0), ctx).await?;
        tx.commit().await.map_err(storage)?;
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
            revision: get(&row, "revision")?,
            activated_at: get(&row, "activated_at")?,
        })
    }

    pub(crate) async fn import_email_policy_activation_impl(
        &self,
        activation: &EmailPolicyActivation,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let row = sqlx::query(
            "SELECT revision, activated_at FROM email_policy_activations
             WHERE scope = 'installation' FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;
        let held = EmailPolicyActivation {
            revision: get(&row, "revision")?,
            activated_at: get(&row, "activated_at")?,
        };
        if held == *activation {
            Self::unchanged_in_tx(tx, &ctx).await?;
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
            "UPDATE email_policy_activations SET revision = $1, activated_at = $2
             WHERE scope = 'installation'",
        )
        .bind(activation.revision)
        .bind(activation.activated_at)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::audit_in_tx(&mut tx, "email_policy", ctx).await?;
        tx.commit().await.map_err(storage)?;
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
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let held = sqlx::query("SELECT * FROM principal_quarantine WHERE principal_hash = $1")
            .bind(&entry.principal_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
            .as_ref()
            .map(quarantined)
            .transpose()?;
        match held {
            Some(held) if held == *entry => {
                Self::unchanged_in_tx(tx, &ctx).await?;
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
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&entry.principal_hash)
        .bind(&entry.principal_type)
        .bind(entry.until)
        .bind(entry.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("principal quarantine", e))?;
        Self::audit_in_tx(&mut tx, "quarantine", ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }
}
