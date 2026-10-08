// SPDX-License-Identifier: AGPL-3.0-only
//! Account closure lifecycle orchestration (CE).
//!
//! Manages the closure state machine:
//! Active → ClosureRequested → GracePeriod → Closed → Purged.
//!
//! The closure flow ensures:
//! - Grace period for user to change their mind (voluntary/GDPR).
//! - Principal quarantine prevents re-registration abuse.
//! - Full cascade revocation of all dependent entities.
//! - Audit trail for every state transition.

use std::sync::Arc;

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use sid_core::models::{
    AuditEntry, ClosureMode, ClosureRequest, IDENTIFIER_QUARANTINE_DAYS,
    MAX_CANCEL_CYCLES_PER_YEAR, ProfileId, ProfileStatus, RevocationReason,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::StorageBackend;
use tracing::info;

use super::revocation_cascade::RevocationCascadeService;

/// Orchestrates the account closure lifecycle.
///
/// Closure is a multi-step process:
/// 1. `request_closure` — validates state, creates closure request with grace period.
/// 2. Grace period elapses (or immediate for regulatory orders).
/// 3. `execute_closure` — cascade revocation, principal quarantine, data deletion.
///
/// Cancellation is allowed for voluntary/GDPR modes (up to [`MAX_CANCEL_CYCLES_PER_YEAR`]).
pub struct AccountClosureService {
    storage: Arc<dyn StorageBackend>,
    cascade: Arc<RevocationCascadeService>,
}

impl AccountClosureService {
    pub fn new(storage: Arc<dyn StorageBackend>, cascade: Arc<RevocationCascadeService>) -> Self {
        Self { storage, cascade }
    }

    /// Initiate account closure.
    ///
    /// Validates that the profile is in a closable state (Active or Suspended),
    /// checks cancel cycle limits, transitions profile status to ClosureRequested,
    /// and creates a closure request with the appropriate grace period.
    pub async fn request_closure(
        &self,
        profile_id: ProfileId,
        mode: ClosureMode,
        requested_by: ProfileId,
    ) -> SidResult<ClosureRequest> {
        // 1. Validate profile exists and is in valid state.
        let profile = self
            .storage
            .get_profile(profile_id)
            .await?
            .ok_or_else(|| SidError::NotFound("profile not found".into()))?;

        // Only Active or Suspended profiles can request closure.
        if !matches!(
            profile.status,
            ProfileStatus::Active | ProfileStatus::Suspended
        ) {
            return Err(SidError::InvalidState(format!(
                "cannot close profile in {} state",
                profile.status
            )));
        }

        // 2. The last administrator is refused by the store, in the write
        // below (`request_profile_closure`), so concurrent requests cannot
        // both pass.

        // 3. Check existing closure request for cancel count.
        let previous = self.storage.get_closure_request(profile_id).await?;
        if let Some(existing) = &previous
            && existing.cancel_count >= MAX_CANCEL_CYCLES_PER_YEAR
        {
            return Err(SidError::RateLimited(
                "maximum closure cancel/re-request cycles exceeded".into(),
            ));
        }

        // 4. The closing status and the request with its grace period are
        // stored together, over the profile revision read above.
        let mut profile = profile;
        profile
            .transition_status(ProfileStatus::ClosureRequested)
            .map_err(|e| SidError::InvalidState(e.to_string()))?;
        let grace_days = mode.max_grace_period_days();
        let mut closure_req =
            ClosureRequest::new(profile_id, mode, requested_by).with_grace_period_days(grace_days);
        // The store keeps the previous request's cancel count and legal hold;
        // the returned request shows them.
        if let Some(previous) = previous {
            closure_req.cancel_count = previous.cancel_count;
            closure_req.legal_hold = previous.legal_hold;
        }
        if !self
            .storage
            .request_profile_closure(
                &profile,
                &closure_req,
                AuditEntry::user(
                    requested_by.to_string(),
                    "closure.requested",
                    profile_id.to_string(),
                )
                .into(),
            )
            .await?
        {
            return Err(SidError::InvalidState(
                "profile changed while its closure was requested".into(),
            ));
        }

        info!(
            profile_id = %profile_id,
            mode = %mode,
            grace_days = grace_days,
            "Closure requested for profile",
        );
        Ok(closure_req)
    }

    /// Cancel an in-progress closure.
    ///
    /// Only voluntary and GDPR closures can be cancelled. Each cancellation
    /// increments the cancel counter (capped at [`MAX_CANCEL_CYCLES_PER_YEAR`]).
    pub async fn cancel_closure(
        &self,
        profile_id: ProfileId,
        requested_by: ProfileId,
    ) -> SidResult<()> {
        let profile = self
            .storage
            .get_profile(profile_id)
            .await?
            .ok_or_else(|| SidError::NotFound("profile not found".into()))?;

        if !profile.status.is_closing() {
            return Err(SidError::InvalidState(format!(
                "profile is not in closure state (current: {})",
                profile.status
            )));
        }

        let closure_req = self
            .storage
            .get_closure_request(profile_id)
            .await?
            .ok_or_else(|| SidError::NotFound("no active closure request".into()))?;

        if !closure_req.mode.is_cancellable() {
            return Err(SidError::InvalidState(format!(
                "{} closure cannot be cancelled",
                closure_req.mode
            )));
        }

        // Restore profile to Active via gateway.
        let mut profile = profile;
        profile
            .as_closing()
            .ok_or_else(|| {
                SidError::InvalidState("profile not in closing state for cancel".into())
            })?
            .cancel();
        // Over the revision read above, with the cancellation counted in the
        // same write: once the closure has executed (Closed stored), the
        // cancellation no longer applies.
        if !self
            .storage
            .cancel_profile_closure(
                &profile,
                AuditEntry::user(
                    requested_by.to_string(),
                    "closure.cancelled",
                    profile_id.to_string(),
                )
                .into(),
            )
            .await?
        {
            return Err(SidError::InvalidState(
                "profile changed while its closure was cancelled".into(),
            ));
        }

        info!(
            profile_id = %profile_id,
            cancel_count = closure_req.cancel_count + 1,
            "Closure cancelled for profile",
        );
        Ok(())
    }

    /// Execute closure — called when grace period expires.
    ///
    /// This is the destructive operation that cannot be undone:
    /// 1. Cascade revocation (sessions, PATs, back-channel logout).
    /// 2. Quarantine principals (prevents re-registration abuse).
    /// 3. Delete principals, credentials, and metadata.
    /// 4. Transition profile to Closed.
    pub async fn execute_closure(&self, profile_id: ProfileId) -> SidResult<()> {
        let profile = self
            .storage
            .get_profile(profile_id)
            .await?
            .ok_or_else(|| SidError::NotFound("profile not found".into()))?;

        // A closure stored as Closed whose erasure was interrupted resumes it.
        if profile.status == ProfileStatus::Closed {
            return self.erase(profile_id).await;
        }
        if !profile.status.is_closing() {
            return Err(SidError::InvalidState(format!(
                "profile is not in closure state (current: {})",
                profile.status
            )));
        }

        // Closed is stored before anything is destroyed and only over the
        // revision read here: a cancellation that won the race keeps the
        // account intact, and once Closed is stored no cancellation applies.
        // The grace period (counted from the request) has ended, so the
        // profile passes through GracePeriod to Closed.
        let mut closed = profile.clone();
        if closed.status != ProfileStatus::GracePeriod {
            closed
                .as_closing()
                .ok_or_else(|| SidError::InvalidState("profile not in closing state".into()))?
                .start_grace_period()
                .map_err(|e| SidError::InvalidState(e.to_string()))?;
        }
        closed
            .as_closing()
            .ok_or_else(|| SidError::InvalidState("profile not in closing state".into()))?
            .close()
            .map_err(|e| SidError::InvalidState(e.to_string()))?;
        if !self
            .storage
            .update_profile(
                &closed,
                AuditEntry::system("profile.closed", profile_id.to_string()).into(),
            )
            .await?
        {
            // Another execution (another replica) stored Closed first: the
            // closure took place, and its erasure is finished here too, as
            // after an interruption. Any other change (a cancellation) wins.
            let now = self.storage.get_profile(profile_id).await?;
            if now.is_some_and(|p| p.status == ProfileStatus::Closed) {
                return self.erase(profile_id).await;
            }
            return Err(SidError::InvalidState(
                "profile changed while its closure was executed".into(),
            ));
        }
        self.erase(profile_id).await
    }

    /// Whether a Closed profile still holds data its closure has to erase.
    pub async fn erasure_pending(&self, profile_id: ProfileId) -> SidResult<bool> {
        Ok(!self
            .storage
            .get_principals_by_profile(profile_id)
            .await?
            .is_empty()
            || !self
                .storage
                .get_credentials_by_profile(profile_id, None)
                .await?
                .is_empty()
            || !self
                .storage
                .list_profile_metadata(profile_id)
                .await?
                .is_empty())
    }

    /// Erase a Closed profile's access and data. Every step is idempotent,
    /// so an interrupted erasure is repeated from the start.
    async fn erase(&self, profile_id: ProfileId) -> SidResult<()> {
        // 1. Execute revocation cascade.
        let revocation = self
            .cascade
            .revoke_profile(profile_id, RevocationReason::GdprErasure, "system")
            .await?;

        info!(
            profile_id = %profile_id,
            total_revoked = revocation.total_revoked(),
            "Closure cascade completed",
        );

        // 2. Quarantine principals.
        let principals = self.storage.get_principals_by_profile(profile_id).await?;

        let quarantine_until = Utc::now() + Duration::days(i64::from(IDENTIFIER_QUARANTINE_DAYS));

        for principal in &principals {
            let principal_hash =
                Self::hash_principal(principal.principal_type.as_str(), &principal.value);
            self.storage
                .quarantine_principal(
                    &principal_hash,
                    principal.principal_type.as_str(),
                    quarantine_until,
                    AuditEntry::system("principal.quarantine", principal.id.0.to_string()).into(),
                )
                .await?;
        }

        // 3. Release this profile's principals; another holder of the same
        // value keeps it.
        for principal in &principals {
            self.storage
                .unbind_principal(
                    principal.id,
                    profile_id,
                    AuditEntry::system("principal.cascade_delete", principal.id.0.to_string())
                        .into(),
                )
                .await?;
        }

        // 4. Delete credentials.
        let creds = self
            .storage
            .get_credentials_by_profile(profile_id, None)
            .await?;
        for cred in &creds {
            self.storage
                .delete_credential(
                    cred.id,
                    AuditEntry::system("credential.cascade_delete", cred.id.0.to_string()).into(),
                )
                .await?;
        }

        // 5. Delete metadata.
        let metadata = self.storage.list_profile_metadata(profile_id).await?;
        for meta in &metadata {
            self.storage
                .delete_profile_metadata(
                    profile_id,
                    &meta.key,
                    AuditEntry::system(
                        "metadata.cascade_delete",
                        format!("{}:{}", profile_id, meta.key),
                    )
                    .into(),
                )
                .await?;
        }

        info!(
            profile_id = %profile_id,
            principals_quarantined = principals.len(),
            quarantine_days = IDENTIFIER_QUARANTINE_DAYS,
            "Profile closed",
        );
        Ok(())
    }

    /// Get current closure status.
    pub async fn get_closure_status(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ClosureRequest>> {
        self.storage.get_closure_request(profile_id).await
    }

    /// Hash a principal for quarantine storage (no PII stored).
    ///
    /// Uses SHA-256 with type prefix to prevent cross-type collisions.
    fn hash_principal(principal_type: &str, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(principal_type.as_bytes());
        hasher.update(b":");
        hasher.update(value.as_bytes());
        let result = hasher.finalize();
        result
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }
}

#[cfg(test)]
mod tests;
