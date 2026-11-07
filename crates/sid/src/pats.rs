// SPDX-License-Identifier: AGPL-3.0-only
//! Personal access tokens: a user's own tokens, created, listed and revoked
//! from their own sign-in session; every user's tokens for an administrator;
//! and the exchange of a stored token. SID keeps only a token's hash; its
//! value is shown once, in the answer that creates it.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::pat::{PAT_MAX_ACTIVE_PER_USER, PAT_MAX_LIFETIME_DAYS};
use sid_core::models::{
    AuditEntry, MutationContext, OperationContext, PatId, PatStatus as DomainPatStatus,
    PersonalAccessToken,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{
    self, AdminRevokePatRequest, CreatePatRequest, CreatePatResponse, ExchangePatRequest,
    GetPatRequest, ListAllPatsResponse, ListPatsResponse, Pat, PatResponse, RevokePatRequest,
};
use tracing::info;

use crate::wire::{FieldError, to_timestamp, wire_id};

/// Why a personal access token operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum PatError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// A token that does not exist or is not the caller's: both answer
    /// alike, so another user's token is not revealed.
    #[error("personal access token {0} not found")]
    NotFound(PatId),
    /// A token that cannot be exchanged: unknown, revoked or expired alike.
    #[error("the token is not valid")]
    Unusable,
    /// The user holds the most active tokens allowed.
    #[error("the limit of active personal access tokens is reached")]
    QuotaReached,
    /// A stored token names no registered resource to bind an issued token
    /// to.
    #[error("token {0} is not bound to a registered resource")]
    NotResourceBound(PatId),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

impl From<FieldError> for PatError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> PatError {
    PatError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// The personal access tokens of one installation.
pub struct Pats {
    storage: Arc<dyn StorageBackend>,
}

impl Pats {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// The caller's own stored token `pat_id`; another user's is not found.
    async fn owned(&self, caller: &Caller, pat_id: PatId) -> Result<PersonalAccessToken, PatError> {
        self.storage
            .get_pat(pat_id)
            .await?
            .filter(|pat| pat.profile_id == caller.profile_id)
            .ok_or(PatError::NotFound(pat_id))
    }

    /// Create a token for the caller: only a user's own sign-in session may,
    /// never a personal access token or an impersonation token. A retry of a
    /// completed creation answers with the token it created, its value
    /// empty, and creates no second token.
    pub async fn create(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreatePatRequest,
    ) -> Result<CreatePatResponse, PatError> {
        caller.require_interactive()?;
        let profile_id = caller.profile_id;
        let command = KeyedCommand::by_profile::<sid_proto::keyed::machine::pat_service::CreatePat>(
            profile_id, operation, &req,
        );
        if let Some(recorded) = command.replay::<CreatePatResponse>(&*self.storage).await? {
            return Ok(recorded);
        }
        // A refusal a concurrent attempt of this command caused (the slot its
        // token took) is that attempt's answer.
        let answer: Result<CreatePatResponse, PatError> = async {
            if req.name.is_empty() {
                return Err(PatError::MissingField("name"));
            }
            if req.scopes.is_empty() {
                return Err(PatError::MissingField("scopes"));
            }
            let expires_at = req
                .expires_at
                .as_ref()
                .ok_or(PatError::MissingField("expires_at"))?;
            let expires_at = u32::try_from(expires_at.nanos)
                .ok()
                .and_then(|nanos| chrono::DateTime::from_timestamp(expires_at.seconds, nanos))
                .ok_or_else(|| invalid("expires_at", "not a representable time"))?;
            let now = chrono::Utc::now();
            if expires_at > now + chrono::Duration::days(i64::from(PAT_MAX_LIFETIME_DAYS)) {
                return Err(invalid(
                    "expires_at",
                    format!("at most {PAT_MAX_LIFETIME_DAYS} days ahead"),
                ));
            }
            if expires_at <= now {
                return Err(invalid("expires_at", "must be in the future"));
            }
            let (plaintext, hash, prefix) = generate_pat_token();
            let mut pat =
                PersonalAccessToken::new(profile_id, &req.name, &hash, &prefix, req.scopes.clone())
                    .with_expires_at(expires_at);
            if !req.description.is_empty() {
                pat.description = Some(req.description.clone());
            }
            if !req.ip_allowlist.is_empty() {
                pat.ip_allowlist = req.ip_allowlist.clone();
            }
            let mut response = CreatePatResponse {
                pat_id: Some(pat.id.into()),
                token: String::new(),
                token_prefix: prefix,
                metadata: Some(pat_to_proto(&pat)),
            };
            let audit = MutationContext::from(AuditEntry::user(
                profile_id.to_string(),
                "pat.create",
                pat.id.to_string(),
            ))
            .with_operation(command.completion(prost::Message::encode_to_vec(&response)));
            // The per-user limit is checked with the insert, so concurrent
            // creates cannot exceed it.
            match self
                .storage
                .create_pat(&pat, Some(PAT_MAX_ACTIVE_PER_USER as u64), audit)
                .await
            {
                Ok(_) => {}
                // Another attempt of this command committed first: its token
                // is the created one.
                Err(SidError::OperationCompleted(_)) => return Err(PatError::ChangedConcurrently),
                // The limit is counted before the key: the slot may be full
                // with the token a concurrent attempt of this command made.
                Err(SidError::ResourceExhausted(_)) => return Err(PatError::QuotaReached),
                Err(e) => return Err(e.into()),
            }
            info!(
                "Created PAT {} ({}) for profile {}",
                pat.id, pat.name, pat.profile_id
            );
            // The value is shown in this answer only.
            response.token = plaintext;
            Ok(response)
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    pub async fn list(&self, caller: &Caller) -> Result<ListPatsResponse, PatError> {
        caller.require_interactive()?;
        let pats = self.storage.list_pats_by_profile(caller.profile_id).await?;
        Ok(ListPatsResponse {
            pats: pats.iter().map(pat_to_proto).collect(),
        })
    }

    pub async fn get(&self, caller: &Caller, req: GetPatRequest) -> Result<PatResponse, PatError> {
        caller.require_interactive()?;
        let pat_id = wire_id(req.pat_id.as_ref(), "pat_id")?;
        let pat = self.owned(caller, pat_id).await?;
        Ok(PatResponse {
            pat: Some(pat_to_proto(&pat)),
        })
    }

    /// Revoke one of the caller's own tokens.
    pub async fn revoke(&self, caller: &Caller, req: RevokePatRequest) -> Result<(), PatError> {
        caller.require_interactive()?;
        let pat_id = wire_id(req.pat_id.as_ref(), "pat_id")?;
        self.owned(caller, pat_id).await?;
        let by = caller.profile_id.to_string();
        let audit: MutationContext =
            AuditEntry::user(by.clone(), "pat.revoke", pat_id.to_string()).into();
        self.storage.revoke_pat(pat_id, &by, audit).await?;
        info!("Revoked PAT {} by profile {}", pat_id, by);
        Ok(())
    }

    /// Exchange a stored token. A stored token carries no registered
    /// resource to bind the issued token to, so no verifier could accept
    /// what it would be exchanged for: it is inadmissible until replaced by
    /// a resource-bound grant, and nothing is issued or recorded. The answer
    /// is the reason it is refused.
    pub async fn exchange(&self, req: ExchangePatRequest) -> PatError {
        if req.token.is_empty() {
            return PatError::MissingField("token");
        }
        match self
            .storage
            .get_pat_by_token_hash(&sha256_hex(req.token.as_bytes()))
            .await
        {
            Err(e) => e.into(),
            Ok(Some(pat)) if pat.is_usable() => PatError::NotResourceBound(pat.id),
            Ok(_) => PatError::Unusable,
        }
    }

    /// Every user's tokens: instance administration.
    pub async fn list_all(&self, caller: &Caller) -> Result<ListAllPatsResponse, PatError> {
        caller.require_admin()?;
        let pats = self.storage.list_all_pats().await?;
        Ok(ListAllPatsResponse {
            pats: pats.iter().map(pat_to_proto).collect(),
        })
    }

    /// Revoke any user's token. Revoking a revoked token is a no-op; one
    /// that does not exist is not found.
    pub async fn admin_revoke(
        &self,
        caller: &Caller,
        req: AdminRevokePatRequest,
    ) -> Result<(), PatError> {
        caller.require_admin()?;
        let pat_id = wire_id(req.pat_id.as_ref(), "pat_id")?;
        let by = caller.profile_id.to_string();
        let audit: MutationContext =
            AuditEntry::admin(by.clone(), "pat.admin_revoke", pat_id.to_string()).into();
        if !self.storage.revoke_pat(pat_id, &by, audit).await?
            && self.storage.get_pat(pat_id).await?.is_none()
        {
            return Err(PatError::NotFound(pat_id));
        }
        info!("Admin {} revoked PAT {}", by, pat_id);
        Ok(())
    }
}

/// A new token: `(plaintext, sha256_hash, prefix)`. Format
/// `sid_pat_{32 base62 chars}` (40 chars); the hash is the SHA-256 hex
/// digest of the full plaintext; the prefix, its first 16 chars, names it in
/// the UI.
fn generate_pat_token() -> (String, String, String) {
    use rand::TryRng;
    use rand::rngs::SysRng;

    let mut bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system random source is available");
    const BASE62: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let random: String = bytes
        .iter()
        .map(|b| BASE62[(*b as usize) % 62] as char)
        .collect();
    let token = format!("sid_pat_{random}");
    let hash = sha256_hex(token.as_bytes());
    let prefix = token[..16].to_string();
    (token, hash, prefix)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// A token as the API returns it, never with its value.
fn pat_to_proto(pat: &PersonalAccessToken) -> Pat {
    let status = match pat.status {
        DomainPatStatus::Active => v1::PatStatus::Active,
        DomainPatStatus::Revoked => v1::PatStatus::Revoked,
        DomainPatStatus::Expired => v1::PatStatus::Expired,
    };
    Pat {
        id: Some(pat.id.into()),
        profile_id: Some(pat.profile_id.into()),
        name: pat.name.clone(),
        description: pat.description.clone().unwrap_or_default(),
        token_prefix: pat.token_prefix.clone(),
        scopes: pat.scopes.clone(),
        status: status.into(),
        created_at: Some(to_timestamp(pat.created_at)),
        expires_at: pat.expires_at.map(to_timestamp),
        last_used_at: pat.last_used_at.map(to_timestamp),
        last_used_ip: pat.last_used_ip.clone().unwrap_or_default(),
        use_count: pat.use_count,
        revoked_at: pat.revoked_at.map(to_timestamp),
        revoked_by: pat.revoked_by.clone().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests;
