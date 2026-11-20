// SPDX-License-Identifier: AGPL-3.0-only
//! Browser authorization operations in PostgreSQL. A decision and a
//! completion lock the operation's row, so replicas racing on one operation
//! serialize on it and apply the one rule of
//! [`AuthorizationOperation::decide`] to the state they read; an approval
//! locks the Profile's consent to the client and commits it with the
//! decision, a completion commits the code with it.

use async_trait::async_trait;
use jiff::Timestamp;
use sid_core::models::consent::{ConsentId, ConsentRecord};
use sid_core::models::{
    AuthorizationCode, AuthorizationDecision, AuthorizationOperation, AuthorizationOperationId,
    CompletionOutcome, DecisionOutcome, DecisionStep, MutationContext, SessionId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::authorization_operation::AuthorizationOperationStore;
use sqlx::Row;

use super::session_grants::insert_auth_code;
use super::{ClaimGrantRow, ConsentRow, PostgresBackend, insert_error};
use crate::pg_time::{FromPg, PgTime, ToPg};

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn chain(id: AuthorizationOperationId) -> String {
    format!("authorization_operation:{id}")
}

fn revision_of(value: u64) -> SidResult<i64> {
    i64::try_from(value).map_err(|_| SidError::Validation("operation revision".into()))
}

fn operation_of(row: &sqlx::postgres::PgRow) -> SidResult<AuthorizationOperation> {
    let column =
        |name: &'static str| move |e: sqlx::Error| SidError::Storage(format!("column {name}: {e}"));
    let revision: i64 = row.try_get("revision").map_err(column("revision"))?;
    let decision: Option<serde_json::Value> =
        row.try_get("decision").map_err(column("decision"))?;
    let scopes: String = row.try_get("scopes").map_err(column("scopes"))?;
    let claim_requests: serde_json::Value = row
        .try_get("claim_requests")
        .map_err(column("claim_requests"))?;
    let status: String = row.try_get("status").map_err(column("status"))?;
    Ok(AuthorizationOperation {
        id: row.try_get("id").map_err(column("id"))?,
        issuer_id: row.try_get("issuer_id").map_err(column("issuer_id"))?,
        client_id: row.try_get("client_id").map_err(column("client_id"))?,
        redirect_uri: row
            .try_get("redirect_uri")
            .map_err(column("redirect_uri"))?,
        response_type: row
            .try_get("response_type")
            .map_err(column("response_type"))?,
        state: row.try_get("state").map_err(column("state"))?,
        code_challenge: row
            .try_get("code_challenge")
            .map_err(column("code_challenge"))?,
        code_challenge_method: row
            .try_get("code_challenge_method")
            .map_err(column("code_challenge_method"))?,
        nonce: row.try_get("nonce").map_err(column("nonce"))?,
        resource_id: row.try_get("resource_id").map_err(column("resource_id"))?,
        scopes: scopes.split_whitespace().map(str::to_owned).collect(),
        acr_values: row.try_get("acr_values").map_err(column("acr_values"))?,
        claim_requests: serde_json::from_value(claim_requests)
            .map_err(|e| SidError::Storage(format!("operation claim requests: {e}")))?,
        session_id: row.try_get("session_id").map_err(column("session_id"))?,
        profile_id: row.try_get("profile_id").map_err(column("profile_id"))?,
        status: status.parse().map_err(SidError::Storage)?,
        revision: u64::try_from(revision)
            .map_err(|_| SidError::Storage("a negative operation revision".into()))?,
        decision: decision
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| SidError::Storage(format!("operation decision: {e}")))?,
        created_at: row
            .try_get::<PgTime, _>("created_at")
            .map_err(column("created_at"))?
            .jiff(),
        expires_at: row
            .try_get::<PgTime, _>("expires_at")
            .map_err(column("expires_at"))?
            .jiff(),
        decided_at: row
            .try_get::<Option<PgTime>, _>("decided_at")
            .map_err(column("decided_at"))?
            .jiff(),
    })
}

fn decision_json(decision: &Option<AuthorizationDecision>) -> SidResult<Option<serde_json::Value>> {
    decision
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| SidError::Validation(format!("operation decision: {e}")))
}

/// The operation `id`, its row locked for the rest of `tx`.
async fn locked(
    tx: &mut Tx<'_>,
    id: AuthorizationOperationId,
) -> SidResult<Option<AuthorizationOperation>> {
    sqlx::query("SELECT * FROM authorization_operations WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage("lock an authorization operation"))?
        .as_ref()
        .map(operation_of)
        .transpose()
}

/// Write `decided` over the locked row it was read from.
async fn store_decided(tx: &mut Tx<'_>, decided: &AuthorizationOperation) -> SidResult<()> {
    sqlx::query(
        "UPDATE authorization_operations
         SET status = $2, revision = $3, decision = $4, decided_at = $5
         WHERE id = $1",
    )
    .bind(decided.id)
    .bind(decided.status.as_str())
    .bind(revision_of(decided.revision)?)
    .bind(decision_json(&decided.decision)?)
    .bind(decided.decided_at.pg())
    .execute(&mut **tx)
    .await
    .map_err(storage("record an authorization decision"))?;
    Ok(())
}

/// The consent of the operation's Profile to its client, its row locked for
/// the rest of `tx`. A pair without a consent gets an empty requested one
/// first, so two approvals of it serialize on the same row.
async fn locked_consent(
    tx: &mut Tx<'_>,
    operation: &AuthorizationOperation,
) -> SidResult<ConsentRecord> {
    let fresh = ConsentRecord::new(operation.profile_id, operation.client_id.clone());
    sqlx::query(
        "INSERT INTO consents (id, profile_id, client_id, status, consented_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)
         ON CONFLICT (profile_id, client_id) DO NOTHING",
    )
    .bind(fresh.id.0)
    .bind(fresh.profile_id)
    .bind(&fresh.client_id)
    .bind(fresh.status.as_str())
    .bind(fresh.consented_at.pg())
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("consent", e))?;
    let row = sqlx::query_as::<_, ConsentRow>(
        "SELECT id, profile_id, client_id, status, consented_at, revoked_at, updated_at
         FROM consents WHERE profile_id = $1 AND client_id = $2 FOR UPDATE",
    )
    .bind(operation.profile_id)
    .bind(&operation.client_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("lock a consent"))?;
    let grants = sqlx::query_as::<_, ClaimGrantRow>(concat!(
        "SELECT ",
        claim_grant_columns!(),
        " FROM claim_grants WHERE consent_id = $1 ORDER BY granted_at"
    ))
    .bind(row.id)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("read claim grants"))?
    .into_iter()
    .map(ClaimGrantRow::into_claim_grant)
    .collect::<SidResult<Vec<_>>>()?;
    let scope_grants = sqlx::query_as::<_, (sid_core::models::ResourceId, String, PgTime)>(
        "SELECT resource_id, scopes, granted_at FROM consent_scope_grants
         WHERE consent_id = $1 ORDER BY granted_at, resource_id",
    )
    .bind(row.id)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("read scope grants"))?
    .into_iter()
    .map(
        |(resource_id, scopes, granted_at)| sid_core::models::consent::ScopeGrant {
            resource_id,
            scopes: scopes.split_whitespace().map(str::to_owned).collect(),
            granted_at: granted_at.jiff(),
        },
    )
    .collect();
    row.into_consent_record(grants, scope_grants)
}

/// Write `consent` over its locked row: its state, and its claim and scope
/// grants as they now stand.
async fn store_consent(tx: &mut Tx<'_>, consent: &ConsentRecord) -> SidResult<()> {
    let id: ConsentId = consent.id;
    sqlx::query("UPDATE consents SET status = $2, revoked_at = $3, updated_at = $4 WHERE id = $1")
        .bind(id.0)
        .bind(consent.status.as_str())
        .bind(consent.revoked_at.pg())
        .bind(consent.updated_at.pg())
        .execute(&mut **tx)
        .await
        .map_err(storage("store a consent"))?;
    // The grants as they now stand replace the stored ones: a grant the
    // record no longer holds (cleared by a re-approval after revocation)
    // must not survive in the store.
    sqlx::query("DELETE FROM claim_grants WHERE consent_id = $1")
        .bind(id.0)
        .execute(&mut **tx)
        .await
        .map_err(storage("replace claim grants"))?;
    sqlx::query("DELETE FROM consent_scope_grants WHERE consent_id = $1")
        .bind(id.0)
        .execute(&mut **tx)
        .await
        .map_err(storage("replace scope grants"))?;
    for grant in &consent.grants {
        sqlx::query(
            "INSERT INTO claim_grants (id, consent_id, claim_name, claim_type, mode, granted_at,
                revoked_at, disclosed_value, disclosed_verified)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(grant.id.0)
        .bind(id.0)
        .bind(&grant.claim_name)
        .bind(grant.claim_type.as_str())
        .bind(grant.mode.as_str())
        .bind(grant.granted_at.pg())
        .bind(grant.revoked_at.pg())
        .bind(grant.disclosed.as_ref().map(|d| d.value.as_str()))
        .bind(grant.disclosed.as_ref().and_then(|d| d.verified))
        .execute(&mut **tx)
        .await
        .map_err(storage("store a claim grant"))?;
    }
    for grant in &consent.scope_grants {
        sqlx::query(
            "INSERT INTO consent_scope_grants (consent_id, resource_id, scopes, granted_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id.0)
        .bind(grant.resource_id)
        .bind(grant.scopes.join(" "))
        .bind(grant.granted_at.pg())
        .execute(&mut **tx)
        .await
        .map_err(storage("store a scope grant"))?;
    }
    Ok(())
}

#[async_trait]
impl AuthorizationOperationStore for PostgresBackend {
    async fn create_authorization_operation(
        &self,
        operation: &AuthorizationOperation,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(storage("begin an authorization operation"))?;
        sqlx::query(
            "INSERT INTO authorization_operations (id, issuer_id, client_id, redirect_uri,
                response_type, state, code_challenge, code_challenge_method, nonce, resource_id,
                scopes, session_id, profile_id, status, revision, decision,
                created_at, expires_at, decided_at, acr_values, claim_requests)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                $18, $19, $20, $21)",
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
        .bind(decision_json(&operation.decision)?)
        .bind(operation.created_at.pg())
        .bind(operation.expires_at.pg())
        .bind(operation.decided_at.pg())
        .bind(&operation.acr_values)
        .bind(
            serde_json::to_value(&operation.claim_requests)
                .map_err(|e| SidError::Validation(format!("operation claim requests: {e}")))?,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("authorization operation", e))?;
        Self::audit_in_tx(&mut tx, &chain(operation.id), ctx).await?;
        tx.commit()
            .await
            .map_err(storage("commit an authorization operation"))
    }

    async fn authorization_operation(
        &self,
        id: AuthorizationOperationId,
    ) -> SidResult<Option<AuthorizationOperation>> {
        sqlx::query("SELECT * FROM authorization_operations WHERE id = $1")
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
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(storage("begin an authorization decision"))?;
        let Some(stored) = locked(&mut tx, id).await? else {
            return Ok(DecisionOutcome::NotFound);
        };
        let decided = match stored.decide(session, revision, decision, now) {
            DecisionStep::Apply(decided) => *decided,
            DecisionStep::Replayed => {
                Self::unchanged_in_tx(tx, &ctx).await?;
                return Ok(DecisionOutcome::Replayed(stored));
            }
            DecisionStep::Conflict => return Ok(DecisionOutcome::Conflict),
            DecisionStep::NotFound => return Ok(DecisionOutcome::NotFound),
        };
        store_decided(&mut tx, &decided).await?;
        if let AuthorizationDecision::Approve { choices } = decision {
            let held = locked_consent(&mut tx, &decided).await?;
            let consent = decided.approved_consent(Some(held), choices);
            store_consent(&mut tx, &consent).await?;
        }
        Self::audit_in_tx(&mut tx, &chain(id), ctx).await?;
        tx.commit()
            .await
            .map_err(storage("commit an authorization decision"))?;
        Ok(DecisionOutcome::Recorded(decided))
    }

    async fn complete_authorization_operation(
        &self,
        id: AuthorizationOperationId,
        code: Option<&AuthorizationCode>,
        now: Timestamp,
        ctx: MutationContext,
    ) -> SidResult<CompletionOutcome> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(storage("begin an authorization completion"))?;
        let completable = locked(&mut tx, id)
            .await?
            .is_some_and(|stored| stored.completable_at(now));
        if !completable {
            return Ok(CompletionOutcome::NotDecided);
        }
        sqlx::query("UPDATE authorization_operations SET status = 'completed' WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage("complete an authorization operation"))?;
        if let Some(code) = code {
            insert_auth_code(&mut tx, code).await?;
        }
        Self::audit_in_tx(&mut tx, &chain(id), ctx).await?;
        tx.commit()
            .await
            .map_err(storage("commit an authorization completion"))?;
        Ok(CompletionOutcome::Completed)
    }
}
