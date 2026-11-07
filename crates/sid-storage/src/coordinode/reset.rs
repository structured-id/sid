// SPDX-License-Identifier: AGPL-3.0-only
//! Password reset sessions in CoordiNode: requested, verified by their
//! emailed link, completed once by installing the new password. Each step
//! writes the session's node, so of concurrent steps one commits.

use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::models::{
    Credential, CredentialType, HistoryCommit, MutationContext, PasswordResetSession, ProfileId,
    ResetSessionId, Session, SessionEnd,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bytes, get_opt_time,
    get_parsed, get_text, get_time, get_uuid, opt_time, time, uuid,
};

const RESET: &str = "r.id AS id, r.profile_id AS profile_id, r.email AS email,
    r.destination AS destination, r.token_hash AS token_hash, r.sealed_token AS sealed_token,
    r.status AS status, r.created_at AS created_at, r.expires_at AS expires_at,
    r.verified_at AS verified_at, r.completed_at AS completed_at";

fn reset(row: &Row) -> SidResult<PasswordResetSession> {
    Ok(PasswordResetSession {
        id: ResetSessionId(get_uuid(row, "id")?),
        profile_id: ProfileId::from_slice(&get_bytes(row, "profile_id")?)
            .map_err(|e| SidError::Storage(format!("profile_id: {e}")))?,
        email: get_text(row, "email")?,
        destination: get_text(row, "destination")?,
        token_hash: get_text(row, "token_hash")?,
        sealed_token: get_bytes(row, "sealed_token")?,
        status: get_parsed(row, "status")?,
        created_at: get_time(row, "created_at")?,
        expires_at: get_time(row, "expires_at")?,
        verified_at: get_opt_time(row, "verified_at")?,
        completed_at: get_opt_time(row, "completed_at")?,
    })
}

fn get_reset(tx: &Statements<'_>, id: ResetSessionId) -> SidResult<Option<PasswordResetSession>> {
    let rows = tx.run(
        &format!("MATCH (r:SidResetSession) WHERE r.id = $id RETURN {RESET}"),
        Params::default().with("id", uuid(&id.0)),
    )?;
    rows.first().map(reset).transpose()
}

/// Delete in `tx` the reset sessions of `profile`.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    tx.run(
        "MATCH (r:SidResetSession) WHERE r.profile_id = $id DETACH DELETE r",
        Params::default().with("id", Value::Binary(profile.as_bytes().to_vec())),
    )?;
    Ok(())
}

impl CoordinodeBackend {
    pub(super) async fn create_reset_session(
        &self,
        s: &PasswordResetSession,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let s = s.clone();
        self.mutate(format!("reset_session:{}", s.id.0), ctx, move |tx| {
            let held = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", Value::Binary(s.profile_id.as_bytes().to_vec())),
            )?;
            if !super::claim_first(tx, &held)? {
                return Err(SidError::NotFound(format!("profile {}", s.profile_id)));
            }
            if get_reset(tx, s.id)?.is_some() {
                return Err(SidError::Conflict("reset session already exists".into()));
            }
            tx.run(
                "CREATE (r:SidResetSession {id: $id, profile_id: $profile_id, email: $email,
                    destination: $destination, token_hash: $token_hash,
                    sealed_token: $sealed_token, status: $status, created_at: $created_at,
                    expires_at: $expires_at, verified_at: $verified_at,
                    completed_at: $completed_at})",
                Params::default()
                    .with("id", uuid(&s.id.0))
                    .with(
                        "profile_id",
                        Value::Binary(s.profile_id.as_bytes().to_vec()),
                    )
                    .with("email", Value::String(s.email.clone()))
                    .with("destination", Value::String(s.destination.clone()))
                    .with("token_hash", Value::String(s.token_hash.clone()))
                    .with("sealed_token", Value::Binary(s.sealed_token.clone()))
                    .with("status", Value::String(s.status.as_str().into()))
                    .with("created_at", time(s.created_at))
                    .with("expires_at", time(s.expires_at))
                    .with("verified_at", opt_time(s.verified_at))
                    .with("completed_at", opt_time(s.completed_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_reset_session(
        &self,
        id: ResetSessionId,
    ) -> SidResult<Option<PasswordResetSession>> {
        self.read(move |tx| get_reset(tx, id)).await
    }

    pub(super) async fn export_reset_sessions(&self) -> SidResult<Vec<PasswordResetSession>> {
        self.read(|tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidResetSession) RETURN {RESET}"),
                Params::default(),
            )?;
            let mut all = rows.iter().map(reset).collect::<SidResult<Vec<_>>>()?;
            all.sort_by_key(|s| s.id.0);
            Ok(all)
        })
        .await
    }

    pub(super) async fn verify_reset_session(
        &self,
        id: ResetSessionId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let now = Utc::now();
            // Not pending or expired: nothing written, nothing audited.
            let pending = get_reset(tx, id)?
                .is_some_and(|s| s.status.as_str() == "pending" && s.expires_at > now);
            if !pending {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (r:SidResetSession) WHERE r.id = $id AND r.status = 'pending'
                 SET r.status = 'verified', r.verified_at = $now, r.sealed_token = $empty",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("now", time(now))
                    .with("empty", Value::Binary(Vec::new())),
            )?;
            finalize(tx, &format!("reset_session:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn complete_password_reset(
        &self,
        id: ResetSessionId,
        credential: &Credential,
        history: Option<&HistoryCommit>,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> SidResult<Option<Vec<Session>>> {
        if history.is_some_and(|h| h.owner != credential.profile_id) {
            return Err(SidError::Validation(
                "password history belongs to the credential's profile".into(),
            ));
        }
        if credential.credential_type != CredentialType::Opaque {
            return Err(SidError::Validation(
                "a password replacement installs an OPAQUE credential".into(),
            ));
        }
        let (credential, history, end) = (credential.clone(), history.cloned(), end.clone());
        self.transaction(move |tx| {
            let now = Utc::now();
            // Not verified or expired: nothing written.
            let Some(verified) = get_reset(tx, id)?
                .filter(|s| s.status.as_str() == "verified" && s.expires_at > now)
            else {
                return Ok(Decision::Abandon(None));
            };
            if verified.profile_id != credential.profile_id {
                return Err(SidError::Validation(
                    "the new password belongs to another profile than the reset".into(),
                ));
            }
            tx.run(
                "MATCH (r:SidResetSession) WHERE r.id = $id AND r.status = 'verified'
                 SET r.status = 'completed', r.completed_at = $now",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("now", time(now)),
            )?;
            if let Some(history) = &history
                && !super::credential::apply_history(tx, history)?
            {
                return Ok(Decision::Abandon(None));
            }
            super::credential::replace(tx, &credential)?;
            let mut ctx = ctx.clone();
            let sessions =
                super::session::end_profile_sessions(tx, verified.profile_id, &end, &mut ctx)?;
            finalize(tx, &format!("profile:{}", verified.profile_id), ctx)?;
            Ok(Decision::Commit(Some(sessions)))
        })
        .await
    }

    pub(super) async fn count_active_reset_sessions(&self, profile: ProfileId) -> SidResult<u32> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidResetSession) WHERE r.profile_id = $id RETURN {RESET}"),
                Params::default().with("id", Value::Binary(profile.as_bytes().to_vec())),
            )?;
            let now = Utc::now();
            let active = rows
                .iter()
                .map(reset)
                .collect::<SidResult<Vec<_>>>()?
                .into_iter()
                .filter(|s| {
                    matches!(s.status.as_str(), "pending" | "verified") && s.expires_at > now
                })
                .count();
            u32::try_from(active).map_err(|_| SidError::Storage("reset count".into()))
        })
        .await
    }

    pub(super) async fn delete_expired_reset_sessions(
        &self,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (r:SidResetSession) WHERE r.expires_at < $now AND r.status = 'pending'
                 DETACH DELETE r RETURN count(*) AS n",
                Params::default().with("now", time(Utc::now())),
            )?;
            let removed = super::get_count(&rows)?;
            if removed == 0 && ctx.work.is_empty() && ctx.operation.is_none() {
                return Ok(Decision::Abandon(0));
            }
            finalize(tx, "reset_sessions:cleanup", ctx.clone())?;
            Ok(Decision::Commit(removed))
        })
        .await
    }
}
