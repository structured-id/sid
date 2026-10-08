// SPDX-License-Identifier: AGPL-3.0-only
//! Revocation cascade engine (CE).
//!
//! Orchestrates synchronous cascade revocation of dependent entities.
//! CE implements Level 1 (single entity) with Tier 1 (immediate) + Tier 2 (fast) propagation.

use std::sync::Arc;

use sid_core::Result as SidResult;
use sid_core::models::{
    AuditEntry, CascadeTier, MachineUserId, PatId, ProfileId, RevocationReason, RevocationRequest,
    RevocationTarget, SessionEnd, SessionId,
};
use sid_plugin::StorageBackend;
use sid_plugin::cache::CacheError;
use tracing::info;

use super::revocation_cache::RevocationCache;

/// A revocation applied in this process but not delivered to the others.
/// Reported after the rest of the cascade is done: revocation is idempotent,
/// so a retry of the operation delivers it.
fn propagated(unpropagated: Option<CacheError>) -> SidResult<()> {
    match unpropagated {
        None => Ok(()),
        Some(e) => Err(sid_core::Error::Internal(format!(
            "revocation not propagated to other processes: {e}"
        ))),
    }
}

/// The audit entry of sessions ended by a profile's revocation.
fn cascade_audit(profile_id: ProfileId) -> AuditEntry {
    AuditEntry::system("session.cascade_delete", profile_id.to_string())
}

/// Orchestrates cascade revocation of dependent entities when a parent entity is revoked.
///
/// Cascade tiers (CE):
/// - Tier 1 (Immediate): Sessions, active tokens — sub-second via in-memory cache + DB.
/// - Tier 2 (Fast): Credentials, PATs, machine user credentials — seconds via DB.
///
/// Every ended session owes its client a back-channel logout and a
/// `sid.session.revoked.v1` event naming the reason and the actor; storage
/// commits that work with the session's deletion and a worker delivers it, so
/// a slow or failing RP never blocks or undoes the revocation.
pub struct RevocationCascadeService {
    storage: Arc<dyn StorageBackend>,
    revocation_cache: Arc<RevocationCache>,
}

impl RevocationCascadeService {
    pub fn new(storage: Arc<dyn StorageBackend>, revocation_cache: Arc<RevocationCache>) -> Self {
        Self {
            storage,
            revocation_cache,
        }
    }

    /// Revoke a profile and cascade to all dependent entities.
    ///
    /// Cascade order:
    /// 1. Kill all sessions (Tier 1: immediate via cache + DB), each owing
    ///    its client a back-channel logout.
    /// 2. Delete all credentials (Tier 2: fast via DB).
    /// 3. Revoke all PATs (Tier 2: fast via DB).
    pub async fn revoke_profile(
        &self,
        profile_id: ProfileId,
        reason: RevocationReason,
        initiated_by: &str,
    ) -> SidResult<RevocationRequest> {
        let mut req = RevocationRequest::new(
            RevocationTarget::Profile,
            profile_id.to_string(),
            reason,
            initiated_by,
        );
        let end = SessionEnd::new(reason, initiated_by);
        let unpropagated = self
            .end_sessions(&mut req, profile_id, &end, cascade_audit(profile_id))
            .await?;
        self.revoke_pats(&mut req, profile_id, initiated_by).await?;

        // Revoke all credentials (Tier 2: fast).
        let cred_count = self
            .storage
            .delete_credentials_by_profile(
                profile_id,
                AuditEntry::system("credential.cascade_delete", profile_id.to_string()).into(),
            )
            .await?;

        if cred_count > 0 {
            for _ in 0..cred_count {
                req.add_cascade(
                    RevocationTarget::Credential,
                    format!("profile:{profile_id}"),
                    CascadeTier::Fast,
                );
            }
            info!(
                profile_id = %profile_id,
                deleted_credentials = cred_count,
                "Cascade: deleted credentials for profile",
            );
        }

        // Revoke all consents (Tier 2: GDPR compliance).
        let consent_count = self
            .storage
            .revoke_consents_by_profile(
                profile_id,
                AuditEntry::system("consent.cascade_revoke", profile_id.to_string()).into(),
            )
            .await?;

        if consent_count > 0 {
            for _ in 0..consent_count {
                req.add_cascade(
                    RevocationTarget::Consent,
                    format!("profile:{profile_id}"),
                    CascadeTier::Fast,
                );
            }
            info!(
                profile_id = %profile_id,
                revoked_consents = consent_count,
                "Cascade: revoked consents for profile",
            );
        }

        propagated(unpropagated)?;

        req.complete();
        info!(
            profile_id = %profile_id,
            total_revoked = req.total_revoked(),
            "Profile revoked with cascade",
        );
        Ok(req)
    }

    /// End every signed-in use of a profile: its sessions (with their refresh
    /// and access tokens), its PATs, and the sessions RPs hold through
    /// back-channel logout. What the profile signs in with (credentials) and
    /// its consents are kept, so a suspended profile can be reactivated; the
    /// ended sessions and tokens are not restored by reactivation.
    pub async fn end_access(
        &self,
        profile_id: ProfileId,
        reason: RevocationReason,
        initiated_by: &str,
    ) -> SidResult<RevocationRequest> {
        let mut req = RevocationRequest::new(
            RevocationTarget::Profile,
            profile_id.to_string(),
            reason,
            initiated_by,
        );
        let end = SessionEnd::new(reason, initiated_by);
        let unpropagated = self
            .end_sessions(&mut req, profile_id, &end, cascade_audit(profile_id))
            .await?;
        self.revoke_pats(&mut req, profile_id, initiated_by).await?;
        propagated(unpropagated)?;
        req.complete();
        info!(
            profile_id = %profile_id,
            total_revoked = req.total_revoked(),
            "Profile access ended",
        );
        Ok(req)
    }

    /// End every session of a profile, recorded under `audit`: its access and
    /// refresh tokens stop and every RP it signed in to is sent a
    /// back-channel logout. Its PATs and credentials are kept.
    pub async fn revoke_sessions(
        &self,
        profile_id: ProfileId,
        reason: RevocationReason,
        initiated_by: &str,
        audit: AuditEntry,
    ) -> SidResult<RevocationRequest> {
        let mut req = RevocationRequest::new(
            RevocationTarget::Profile,
            profile_id.to_string(),
            reason,
            initiated_by,
        );
        let end = SessionEnd::new(reason, initiated_by);
        let unpropagated = self.end_sessions(&mut req, profile_id, &end, audit).await?;
        propagated(unpropagated)?;
        req.complete();
        Ok(req)
    }

    /// Delete every session of the profile with its refresh tokens; the
    /// storage commits what each ended session owes under `end` (its client's
    /// back-channel logout, the revoked event) with the deletion. Then revoke
    /// them in the revocation cache (their access tokens stop at once).
    async fn end_sessions(
        &self,
        req: &mut RevocationRequest,
        profile_id: ProfileId,
        end: &SessionEnd,
        audit: AuditEntry,
    ) -> SidResult<Option<CacheError>> {
        let sessions = self
            .storage
            .delete_sessions_by_profile(profile_id, end, audit.into())
            .await?;

        let mut unpropagated = None;
        for session in &sessions {
            if let Err(e) = self
                .revocation_cache
                .revoke_session(session.id.to_string())
                .await
            {
                unpropagated.get_or_insert(e);
            }
            req.add_cascade(
                RevocationTarget::Session,
                session.id.to_string(),
                CascadeTier::Immediate,
            );
        }
        info!(
            profile_id = %profile_id,
            deleted_sessions = sessions.len(),
            "Cascade: deleted sessions for profile",
        );
        Ok(unpropagated)
    }

    /// Revoke every active PAT of the profile (one conditional update).
    async fn revoke_pats(
        &self,
        req: &mut RevocationRequest,
        profile_id: ProfileId,
        initiated_by: &str,
    ) -> SidResult<()> {
        let pat_count = self
            .storage
            .revoke_active_pats_by_profile(
                profile_id,
                initiated_by,
                AuditEntry::system("pat.cascade_revoke", profile_id.to_string()).into(),
            )
            .await?;

        if pat_count > 0 {
            for _ in 0..pat_count {
                req.add_cascade(
                    RevocationTarget::Pat,
                    format!("profile:{profile_id}"),
                    CascadeTier::Fast,
                );
            }
            info!(
                profile_id = %profile_id,
                revoked_pats = pat_count,
                "Cascade: revoked active PATs for profile",
            );
        }
        Ok(())
    }

    /// Revoke a single session with cascade to refresh tokens, audited as
    /// `action`, and the sessions it authenticated. Each deleted session owes
    /// its client a back-channel logout.
    ///
    /// Cascade order:
    /// 1. Revoke session in in-memory cache (immediate).
    /// 2. Revoke refresh tokens for this session (immediate).
    /// 3. Delete session and its dependents from DB (their refresh tokens go
    ///    with them).
    /// 4. Revoke the dependents in the cache.
    pub async fn revoke_session(
        &self,
        session_id: SessionId,
        reason: RevocationReason,
        initiated_by: &str,
        action: &str,
    ) -> SidResult<RevocationRequest> {
        let mut req = RevocationRequest::new(
            RevocationTarget::Session,
            session_id.to_string(),
            reason,
            initiated_by,
        );

        // 1. Revocation cache (immediate, then every other process).
        let unpropagated = self
            .revocation_cache
            .revoke_session(session_id.to_string())
            .await
            .err();

        // 2. Revoke refresh tokens.
        let revoked = self
            .storage
            .revoke_refresh_tokens_by_session(
                session_id,
                AuditEntry::system(action, session_id.to_string()).into(),
            )
            .await?;

        if revoked > 0 {
            req.add_cascade(
                RevocationTarget::RefreshToken,
                format!("session:{session_id}"),
                CascadeTier::Immediate,
            );
        }

        // 3. Delete session from DB, with what it owes, and the sessions it
        //    authenticated.
        let ended = self
            .storage
            .delete_session(
                session_id,
                &SessionEnd::new(reason, initiated_by),
                AuditEntry::system(action, session_id.to_string()).into(),
            )
            .await?;

        // 4. The dependents' access tokens stop too.
        let mut unpropagated = unpropagated;
        for dependent in ended.into_iter().filter(|id| *id != session_id) {
            if let Err(e) = self
                .revocation_cache
                .revoke_session(dependent.to_string())
                .await
            {
                unpropagated.get_or_insert(e);
            }
            req.add_cascade(
                RevocationTarget::Session,
                dependent.to_string(),
                CascadeTier::Immediate,
            );
        }
        propagated(unpropagated)?;

        req.complete();
        Ok(req)
    }

    /// Revoke a single PAT. Leaf node — no cascade.
    pub async fn revoke_pat(
        &self,
        pat_id: PatId,
        initiated_by: &str,
    ) -> SidResult<RevocationRequest> {
        let mut req = RevocationRequest::new(
            RevocationTarget::Pat,
            pat_id.0.to_string(),
            RevocationReason::UserRequested,
            initiated_by,
        );

        self.storage
            .revoke_pat(
                pat_id,
                initiated_by,
                AuditEntry::system("pat.revoke", pat_id.0.to_string()).into(),
            )
            .await?;

        req.complete();
        Ok(req)
    }

    /// Suspend a machine user and revoke all active credentials.
    ///
    /// Cascade order:
    /// 1. Delete (soft) the machine user.
    /// 2. Revoke all usable credentials (Tier 2: fast).
    pub async fn suspend_machine_user(
        &self,
        mu_id: MachineUserId,
        reason: RevocationReason,
        initiated_by: &str,
    ) -> SidResult<RevocationRequest> {
        let mut req = RevocationRequest::new(
            RevocationTarget::MachineUser,
            mu_id.to_string(),
            reason,
            initiated_by,
        );

        // 1. Set machine user status = deleted (soft delete via storage).
        self.storage
            .delete_machine_user(
                mu_id,
                AuditEntry::system("machine_user.suspend", mu_id.to_string()).into(),
            )
            .await?;

        // 2. Revoke all active credentials atomically.
        // Uses UPDATE ... WHERE status = 'active' — no TOCTOU race.
        let cred_count = self
            .storage
            .revoke_active_machine_credentials_by_user(
                mu_id,
                AuditEntry::system("credential.cascade_revoke", mu_id.to_string()).into(),
            )
            .await?;

        if cred_count > 0 {
            for _ in 0..cred_count {
                req.add_cascade(
                    RevocationTarget::Credential,
                    format!("machine_user:{mu_id}"),
                    CascadeTier::Fast,
                );
            }
        }

        req.complete();
        info!(
            machine_user_id = %mu_id,
            credentials_revoked = cred_count,
            "Machine user suspended with cascade",
        );
        Ok(req)
    }
}

#[cfg(test)]
mod tests;
