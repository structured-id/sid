// SPDX-License-Identifier: AGPL-3.0-only
//! Browser authorization operations in SQLite. Every write runs in the
//! single writer's `BEGIN IMMEDIATE` transaction, so a decision or a
//! completion reads the stored operation and writes over it as one step,
//! applying the one rule of [`AuthorizationOperation::decide`]; an approval
//! commits the consent it grants with it, a completion the code.

use async_trait::async_trait;
use jiff::Timestamp;
use sid_core::models::consent::{ConsentRecord, ScopeGrant};
use sid_core::models::{
    AuthorizationCode, AuthorizationDecision, AuthorizationOperation, AuthorizationOperationId,
    CompletionOutcome, DecisionOutcome, DecisionStep, MutationContext, SessionId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::authorization_operation::AuthorizationOperationStore;

use super::auth::insert_auth_code;
use super::consent::row_to_grant;
use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error};

type Tx = sqlx::Transaction<'static, sqlx::Sqlite>;

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn chain(id: AuthorizationOperationId) -> String {
    format!("authorization_operation:{id}")
}

fn revision_of(value: u64) -> SidResult<i64> {
    i64::try_from(value).map_err(|_| SidError::Validation("operation revision".into()))
}

fn operation_of(row: &sqlx::sqlite::SqliteRow) -> SidResult<AuthorizationOperation> {
    let revision: i64 = col(row, "revision")?;
    let decision: Option<String> = col(row, "decision")?;
    Ok(AuthorizationOperation {
        id: col(row, "id")?,
        issuer_id: col(row, "issuer_id")?,
        client_id: col(row, "client_id")?,
        redirect_uri: col(row, "redirect_uri")?,
        response_type: col(row, "response_type")?,
        state: col(row, "state")?,
        code_challenge: col(row, "code_challenge")?,
        code_challenge_method: col(row, "code_challenge_method")?,
        nonce: col(row, "nonce")?,
        resource_id: col(row, "resource_id")?,
        scopes: col::<String>(row, "scopes")?
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        session_id: col(row, "session_id")?,
        profile_id: col(row, "profile_id")?,
        status: col::<String>(row, "status")?
            .parse()
            .map_err(SidError::Storage)?,
        revision: u64::try_from(revision)
            .map_err(|_| SidError::Storage("a negative operation revision".into()))?,
        decision: decision
            .map(|d| serde_json::from_str(&d))
            .transpose()
            .map_err(|e| SidError::Storage(format!("operation decision: {e}")))?,
        created_at: dt_col(row, "created_at")?,
        expires_at: dt_col(row, "expires_at")?,
        decided_at: dt_col_opt(row, "decided_at")?,
    })
}

fn decision_text(decision: &Option<AuthorizationDecision>) -> SidResult<Option<String>> {
    decision
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| SidError::Validation(format!("operation decision: {e}")))
}

async fn stored(
    tx: &mut Tx,
    id: AuthorizationOperationId,
) -> SidResult<Option<AuthorizationOperation>> {
    sqlx::query("SELECT * FROM authorization_operations WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage("read an authorization operation"))?
        .as_ref()
        .map(operation_of)
        .transpose()
}

/// The consent of the operation's Profile to its client as held in `tx`,
/// or a new one.
async fn held_consent(
    tx: &mut Tx,
    operation: &AuthorizationOperation,
) -> SidResult<Option<ConsentRecord>> {
    let Some(row) = sqlx::query(
        "SELECT id, profile_id, client_id, status, consented_at, revoked_at, updated_at
         FROM consents WHERE profile_id = ? AND client_id = ?",
    )
    .bind(operation.profile_id)
    .bind(&operation.client_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage("read a consent"))?
    else {
        return Ok(None);
    };
    let id: uuid::Uuid = super::uuid_col(&row, "id")?;
    let grants = sqlx::query(
        "SELECT id, consent_id, claim_name, claim_type, mode, granted_at, revoked_at
         FROM claim_grants WHERE consent_id = ? ORDER BY granted_at",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("read claim grants"))?
    .iter()
    .map(row_to_grant)
    .collect::<SidResult<Vec<_>>>()?;
    let scope_grants = sqlx::query(
        "SELECT resource_id, scopes, granted_at FROM consent_scope_grants
         WHERE consent_id = ? ORDER BY granted_at, resource_id",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("read scope grants"))?
    .iter()
    .map(|r| {
        Ok(ScopeGrant {
            resource_id: col(r, "resource_id")?,
            scopes: col::<String>(r, "scopes")?
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            granted_at: dt_col(r, "granted_at")?,
        })
    })
    .collect::<SidResult<Vec<_>>>()?;
    Ok(Some(ConsentRecord {
        id: sid_core::models::consent::ConsentId(id),
        profile_id: col(&row, "profile_id")?,
        client_id: col(&row, "client_id")?,
        status: col::<String>(&row, "status")?
            .parse()
            .map_err(SidError::Storage)?,
        grants,
        scope_grants,
        consented_at: dt_col(&row, "consented_at")?,
        revoked_at: dt_col_opt(&row, "revoked_at")?,
        updated_at: dt_col(&row, "updated_at")?,
    }))
}

/// Write `consent` in `tx`: created when new, else its state and its claim
/// and scope grants as they now stand.
async fn store_consent(tx: &mut Tx, consent: &ConsentRecord) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO consents (id, profile_id, client_id, status, consented_at, revoked_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (id) DO UPDATE SET status = ?4, revoked_at = ?6, updated_at = ?7",
    )
    .bind(consent.id.0)
    .bind(consent.profile_id)
    .bind(&consent.client_id)
    .bind(consent.status.as_str())
    .bind(fmt_dt(&consent.consented_at))
    .bind(fmt_dt_opt(consent.revoked_at))
    .bind(fmt_dt(&consent.updated_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("consent", e))?;
    for grant in &consent.grants {
        sqlx::query(
            "INSERT INTO claim_grants (id, consent_id, claim_name, claim_type, mode, granted_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (consent_id, claim_name) DO UPDATE SET
               claim_type = ?4, mode = ?5, granted_at = ?6, revoked_at = ?7",
        )
        .bind(grant.id.0)
        .bind(consent.id.0)
        .bind(&grant.claim_name)
        .bind(grant.claim_type.as_str())
        .bind(grant.mode.as_str())
        .bind(fmt_dt(&grant.granted_at))
        .bind(fmt_dt_opt(grant.revoked_at))
        .execute(&mut **tx)
        .await
        .map_err(storage("store a claim grant"))?;
    }
    for grant in &consent.scope_grants {
        sqlx::query(
            "INSERT INTO consent_scope_grants (consent_id, resource_id, scopes, granted_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (consent_id, resource_id) DO UPDATE SET scopes = ?3, granted_at = ?4",
        )
        .bind(consent.id.0)
        .bind(grant.resource_id)
        .bind(grant.scopes.join(" "))
        .bind(fmt_dt(&grant.granted_at))
        .execute(&mut **tx)
        .await
        .map_err(storage("store a scope grant"))?;
    }
    Ok(())
}

#[async_trait]
impl AuthorizationOperationStore for SqliteBackend {
    async fn create_authorization_operation(
        &self,
        operation: &AuthorizationOperation,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO authorization_operations (id, issuer_id, client_id, redirect_uri,
                response_type, state, code_challenge, code_challenge_method, nonce, resource_id,
                scopes, session_id, profile_id, status, revision, decision,
                created_at, expires_at, decided_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(operation.id)
        .bind(operation.issuer_id)
        .bind(&operation.client_id)
        .bind(&operation.redirect_uri)
        .bind(&operation.response_type)
        .bind(&operation.state)
        .bind(&operation.code_challenge)
        .bind(&operation.code_challenge_method)
        .bind(&operation.nonce)
        .bind(operation.resource_id)
        .bind(operation.scopes.join(" "))
        .bind(operation.session_id)
        .bind(operation.profile_id)
        .bind(operation.status.as_str())
        .bind(revision_of(operation.revision)?)
        .bind(decision_text(&operation.decision)?)
        .bind(fmt_dt(&operation.created_at))
        .bind(fmt_dt(&operation.expires_at))
        .bind(fmt_dt_opt(operation.decided_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("authorization operation", e))?;
        Self::commit_mutation(tx, &chain(operation.id), ctx).await
    }

    async fn authorization_operation(
        &self,
        id: AuthorizationOperationId,
    ) -> SidResult<Option<AuthorizationOperation>> {
        sqlx::query("SELECT * FROM authorization_operations WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage("read an authorization operation"))?
            .as_ref()
            .map(operation_of)
            .transpose()
    }

    async fn decide_authorization_operation(
        &self,
        id: AuthorizationOperationId,
        session: SessionId,
        revision: u64,
        decision: &AuthorizationDecision,
        now: Timestamp,
        ctx: MutationContext,
    ) -> SidResult<DecisionOutcome> {
        let mut tx = self.begin_write().await?;
        let Some(held) = stored(&mut tx, id).await? else {
            return Ok(DecisionOutcome::NotFound);
        };
        let decided = match held.decide(session, revision, decision, now) {
            DecisionStep::Apply(decided) => *decided,
            DecisionStep::Replayed => {
                Self::commit_unchanged(tx, &ctx).await?;
                return Ok(DecisionOutcome::Replayed(held));
            }
            DecisionStep::Conflict => return Ok(DecisionOutcome::Conflict),
            DecisionStep::NotFound => return Ok(DecisionOutcome::NotFound),
        };
        sqlx::query(
            "UPDATE authorization_operations
             SET status = ?, revision = ?, decision = ?, decided_at = ? WHERE id = ?",
        )
        .bind(decided.status.as_str())
        .bind(revision_of(decided.revision)?)
        .bind(decision_text(&decided.decision)?)
        .bind(fmt_dt_opt(decided.decided_at))
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage("record an authorization decision"))?;
        if let AuthorizationDecision::Approve { choices } = decision {
            let consent = held_consent(&mut tx, &decided).await?;
            store_consent(&mut tx, &decided.approved_consent(consent, choices)).await?;
        }
        Self::commit_mutation(tx, &chain(id), ctx).await?;
        Ok(DecisionOutcome::Recorded(decided))
    }

    async fn complete_authorization_operation(
        &self,
        id: AuthorizationOperationId,
        code: Option<&AuthorizationCode>,
        now: Timestamp,
        ctx: MutationContext,
    ) -> SidResult<CompletionOutcome> {
        let mut tx = self.begin_write().await?;
        let completable = stored(&mut tx, id)
            .await?
            .is_some_and(|held| held.completable_at(now));
        if !completable {
            return Ok(CompletionOutcome::NotDecided);
        }
        sqlx::query("UPDATE authorization_operations SET status = 'completed' WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage("complete an authorization operation"))?;
        if let Some(code) = code {
            insert_auth_code(&mut tx, code).await?;
        }
        Self::commit_mutation(tx, &chain(id), ctx).await?;
        Ok(CompletionOutcome::Completed)
    }
}
