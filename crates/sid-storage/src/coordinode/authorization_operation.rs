// SPDX-License-Identifier: AGPL-3.0-only
//! Browser authorization operations in CoordiNode: one node per operation,
//! unique by its id. A decision or a completion writes the node it read, so
//! a concurrent one conflicts and runs again on what the first committed,
//! applying the one rule of [`AuthorizationOperation::decide`]; an approval
//! writes the consent it grants in the same commit, a completion the code.

use async_trait::async_trait;
use coordinode_core::graph::types::Value;
use jiff::Timestamp;
use sid_core::models::{
    AuthorizationCode, AuthorizationDecision, AuthorizationOperation, AuthorizationOperationId,
    CompletionOutcome, DecisionOutcome, DecisionStep, MutationContext, SessionId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::authorization_operation::AuthorizationOperationStore;

use super::consent::{consent_of_pair, store_consent};
use super::profile::profile_value;
use super::session::store_code;
use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bytes, get_id,
    get_int, get_opt_text, get_opt_time, get_parsed, get_text, get_texts, get_time, hold_first,
    opt_text, opt_time, texts, time, uuid,
};

const FIELDS: &str = "o.id AS id, o.issuer_id AS issuer_id, o.client_id AS client_id,
    o.redirect_uri AS redirect_uri, o.response_type AS response_type, o.state AS state,
    o.code_challenge AS code_challenge, o.code_challenge_method AS code_challenge_method,
    o.nonce AS nonce, o.resource_id AS resource_id, o.scopes AS scopes,
    o.acr_values AS acr_values, o.claim_requests AS claim_requests,
    o.session_id AS session_id, o.profile_id AS profile_id, o.status AS status,
    o.revision AS revision, o.decision AS decision,
    o.created_at AS created_at, o.expires_at AS expires_at, o.decided_at AS decided_at";

fn chain(id: AuthorizationOperationId) -> String {
    format!("authorization_operation:{id}")
}

fn revision_of(value: u64) -> SidResult<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| SidError::Validation("operation revision".into()))
}

fn decision_value(decision: &Option<AuthorizationDecision>) -> SidResult<Value> {
    match decision {
        Some(d) => serde_json::to_string(d)
            .map(Value::String)
            .map_err(|e| SidError::Validation(format!("operation decision: {e}"))),
        None => Ok(Value::Null),
    }
}

fn operation_of(row: &Row) -> SidResult<AuthorizationOperation> {
    let profile = get_bytes(row, "profile_id")?;
    Ok(AuthorizationOperation {
        id: get_id(row, "id")?,
        issuer_id: get_id(row, "issuer_id")?,
        client_id: get_text(row, "client_id")?,
        redirect_uri: get_text(row, "redirect_uri")?,
        response_type: get_text(row, "response_type")?,
        state: get_opt_text(row, "state")?,
        code_challenge: get_opt_text(row, "code_challenge")?,
        code_challenge_method: get_opt_text(row, "code_challenge_method")?,
        nonce: get_opt_text(row, "nonce")?,
        resource_id: get_id(row, "resource_id")?,
        scopes: get_texts(row, "scopes")?,
        acr_values: get_opt_text(row, "acr_values")?,
        claim_requests: super::get_document(row, "claim_requests")?,
        session_id: get_id(row, "session_id")?,
        profile_id: sid_core::models::ProfileId::from_slice(&profile)
            .map_err(|e| SidError::Storage(format!("profile_id: {e}")))?,
        status: get_parsed(row, "status")?,
        revision: u64::try_from(get_int(row, "revision")?)
            .map_err(|_| SidError::Storage("a negative operation revision".into()))?,
        decision: get_opt_text(row, "decision")?
            .map(|d| serde_json::from_str(&d))
            .transpose()
            .map_err(|e| SidError::Storage(format!("operation decision: {e}")))?,
        created_at: get_time(row, "created_at")?,
        expires_at: get_time(row, "expires_at")?,
        decided_at: get_opt_time(row, "decided_at")?,
    })
}

fn stored(
    tx: &Statements<'_>,
    id: AuthorizationOperationId,
) -> SidResult<Option<AuthorizationOperation>> {
    tx.run(
        &format!("MATCH (o:SidAuthorizationOperation) WHERE o.id = $id RETURN {FIELDS}"),
        Params::default().with("id", uuid(id.as_uuid())),
    )?
    .first()
    .map(operation_of)
    .transpose()
}

/// Refuse `what` unless the node of `label` whose `id` is `value` exists;
/// `claim` makes its deletion conflict with this commit, else it is held.
fn referenced(
    tx: &Statements<'_>,
    label: &str,
    value: Value,
    what: &str,
    claim: bool,
) -> SidResult<()> {
    let rows = tx.run(
        &format!("MATCH (n:{label}) WHERE n.id = $id RETURN id(n) AS node"),
        Params::default().with("id", value),
    )?;
    let present = if claim {
        claim_first(tx, &rows)?
    } else {
        hold_first(tx, &rows)?
    };
    if !present {
        return Err(SidError::NotFound(what.to_owned()));
    }
    Ok(())
}

#[async_trait]
impl AuthorizationOperationStore for CoordinodeBackend {
    async fn create_authorization_operation(
        &self,
        operation: &AuthorizationOperation,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let o = operation.clone();
        self.mutate(chain(o.id), ctx, move |tx| {
            // The session and the profile are claimed: ending either ends
            // the operation with it. Issuer and resource are only held.
            referenced(
                tx,
                "SidSession",
                uuid(o.session_id.as_uuid()),
                "the operation's session",
                true,
            )?;
            referenced(
                tx,
                "SidProfile",
                profile_value(o.profile_id),
                "the operation's profile",
                true,
            )?;
            referenced(
                tx,
                "SidIssuer",
                uuid(o.issuer_id.as_uuid()),
                "the operation's issuer",
                false,
            )?;
            referenced(
                tx,
                "SidResource",
                Value::Binary(o.resource_id.as_bytes().to_vec()),
                "the operation's protected resource",
                false,
            )?;
            if stored(tx, o.id)?.is_some() {
                return Err(SidError::Conflict(
                    "authorization operation already exists".into(),
                ));
            }
            tx.run(
                "CREATE (o:SidAuthorizationOperation {id: $id, issuer_id: $issuer_id,
                    client_id: $client_id, redirect_uri: $redirect_uri,
                    response_type: $response_type, state: $state,
                    code_challenge: $code_challenge,
                    code_challenge_method: $code_challenge_method, nonce: $nonce,
                    resource_id: $resource_id, scopes: $scopes, acr_values: $acr_values,
                    claim_requests: $claim_requests, session_id: $session_id,
                    profile_id: $profile_id, status: $status, revision: $revision,
                    decision: $decision, created_at: $created_at,
                    expires_at: $expires_at, decided_at: $decided_at})",
                Params::default()
                    .with("id", uuid(o.id.as_uuid()))
                    .with("issuer_id", uuid(o.issuer_id.as_uuid()))
                    .with("client_id", Value::String(o.client_id.clone()))
                    .with("redirect_uri", Value::String(o.redirect_uri.clone()))
                    .with("response_type", Value::String(o.response_type.clone()))
                    .with("state", opt_text(o.state.as_deref()))
                    .with("code_challenge", opt_text(o.code_challenge.as_deref()))
                    .with(
                        "code_challenge_method",
                        opt_text(o.code_challenge_method.as_deref()),
                    )
                    .with("nonce", opt_text(o.nonce.as_deref()))
                    .with("resource_id", uuid(o.resource_id.as_uuid()))
                    .with("scopes", texts(&o.scopes))
                    .with("acr_values", opt_text(o.acr_values.as_deref()))
                    .with(
                        "claim_requests",
                        super::document(&o.claim_requests, "operation claim requests")?,
                    )
                    .with("session_id", uuid(o.session_id.as_uuid()))
                    .with("profile_id", profile_value(o.profile_id))
                    .with("status", Value::String(o.status.as_str().into()))
                    .with("revision", revision_of(o.revision)?)
                    .with("decision", decision_value(&o.decision)?)
                    .with("created_at", time(o.created_at))
                    .with("expires_at", time(o.expires_at))
                    .with("decided_at", opt_time(o.decided_at)),
            )?;
            Ok(())
        })
        .await
    }

    async fn authorization_operation(
        &self,
        id: AuthorizationOperationId,
    ) -> SidResult<Option<AuthorizationOperation>> {
        self.read(move |tx| stored(tx, id)).await
    }

    async fn decide_authorization_operation(
        &self,
        id: AuthorizationOperationId,
        session: SessionId,
        revision: u64,
        decision: &AuthorizationDecision,
        shown: &[(String, Option<sid_core::models::DisclosedValue>)],
        now: Timestamp,
        ctx: MutationContext,
    ) -> SidResult<DecisionOutcome> {
        let decision = decision.clone();
        let shown = shown.to_vec();
        self.transaction(move |tx| {
            let Some(held) = stored(tx, id)? else {
                return Ok(Decision::Abandon(DecisionOutcome::NotFound));
            };
            let decided = match held.decide(session, revision, &decision, now) {
                DecisionStep::Apply(decided) => *decided,
                DecisionStep::Replayed => {
                    return match &ctx.operation {
                        Some(completion) => {
                            super::operation::record(tx, completion)?;
                            Ok(Decision::Commit(DecisionOutcome::Replayed(held)))
                        }
                        None => Ok(Decision::Abandon(DecisionOutcome::Replayed(held))),
                    };
                }
                DecisionStep::Conflict => return Ok(Decision::Abandon(DecisionOutcome::Conflict)),
                DecisionStep::NotFound => return Ok(Decision::Abandon(DecisionOutcome::NotFound)),
            };
            if matches!(decision, AuthorizationDecision::Approve { .. })
                && decided.shown(&super::profile::held_claim_values(tx, decided.profile_id)?)
                    != shown
            {
                return Ok(Decision::Abandon(DecisionOutcome::Stale));
            }
            tx.run(
                "MATCH (o:SidAuthorizationOperation) WHERE o.id = $id
                 SET o.status = $status, o.revision = $revision, o.decision = $decision,
                     o.decided_at = $decided_at",
                Params::default()
                    .with("id", uuid(id.as_uuid()))
                    .with("status", Value::String(decided.status.as_str().into()))
                    .with("revision", revision_of(decided.revision)?)
                    .with("decision", decision_value(&decided.decision)?)
                    .with("decided_at", opt_time(decided.decided_at)),
            )?;
            if let AuthorizationDecision::Approve { choices } = &decision {
                let consent = consent_of_pair(tx, decided.profile_id, &decided.client_id)?;
                store_consent(tx, &decided.approved_consent(consent, choices))?;
            }
            finalize(tx, &chain(id), ctx.clone())?;
            Ok(Decision::Commit(DecisionOutcome::Recorded(decided)))
        })
        .await
    }

    async fn complete_authorization_operation(
        &self,
        id: AuthorizationOperationId,
        code: Option<&AuthorizationCode>,
        now: Timestamp,
        ctx: MutationContext,
    ) -> SidResult<CompletionOutcome> {
        let code = code.cloned();
        self.transaction(move |tx| {
            let completable = stored(tx, id)?.is_some_and(|held| held.completable_at(now));
            if !completable {
                return Ok(Decision::Abandon(CompletionOutcome::NotDecided));
            }
            tx.run(
                "MATCH (o:SidAuthorizationOperation) WHERE o.id = $id SET o.status = 'completed'",
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            if let Some(code) = &code {
                store_code(tx, code)?;
            }
            finalize(tx, &chain(id), ctx.clone())?;
            Ok(Decision::Commit(CompletionOutcome::Completed))
        })
        .await
    }
}
