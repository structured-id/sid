// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC PatService implementation.
//!
//! Manages personal access token lifecycle (create, list, revoke) and
//! token exchange (opaque -> short-lived JWT) + introspection (RFC 7662).

use sha2::{Digest, Sha256};
use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{
    AuditEntry, MutationContext, PatId, PatStatus as DomainPatStatus, PersonalAccessToken,
    ProfileId,
    pat::{PAT_MAX_ACTIVE_PER_USER, PAT_MAX_LIFETIME_DAYS},
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{
    self, AdminRevokePatRequest, CreatePatRequest, CreatePatResponse, ExchangePatRequest,
    ExchangePatResponse, GetPatRequest, ListAllPatsRequest, ListAllPatsResponse, ListPatsRequest,
    ListPatsResponse, Pat, PatResponse, RevokePatRequest, RevokePatResponse,
    pat_service_server::PatService,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use sid_core::grpc_error::{ApiError, ErrorReason};

use super::convert;
use sid_core::grpc_error::refuse::{invalid_field, missing_field, not_found, storage_failure};

/// Proto `PatStatus` enum alias to avoid collision with domain type.
type ProtoPatStatus = v1::PatStatus;

/// gRPC service for personal access token management.
pub struct PatServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation_cache: Arc<RevocationCache>,
}

impl PatServiceImpl {
    /// Create a new PAT service instance.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation_cache: Arc<RevocationCache>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation_cache,
        }
    }

    /// The profile of the caller managing its own tokens. Only a user's own
    /// sign-in session may: a personal access token or an impersonation token
    /// cannot mint, list or revoke personal access tokens.
    #[allow(clippy::result_large_err)]
    async fn token_owner<T>(&self, request: &Request<T>) -> Result<ProfileId, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation_cache).await?;
        caller.require_interactive()?;
        Ok(caller.profile_id)
    }

    /// The administrator calling: listing every user's tokens and revoking
    /// another user's token are instance administration.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<ProfileId, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation_cache).await?;
        caller.require_admin()?;
        Ok(caller.profile_id)
    }
}

// ── Helper functions ──

/// Generate a new PAT token: returns `(plaintext, sha256_hash, prefix)`.
///
/// Format: `sid_pat_{32 base62 chars}` (40 chars total).
/// Hash: SHA-256 hex digest of the full plaintext.
/// Prefix: first 16 chars (`sid_pat_` + 8 random chars) for UI identification.
fn generate_pat_token() -> (String, String, String) {
    use rand::RngCore;
    use rand::rngs::OsRng;

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    const BASE62: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let random: String = bytes
        .iter()
        .map(|b| BASE62[(*b as usize) % 62] as char)
        .collect();
    let token = format!("sid_pat_{random}");
    let hash = sha256_hex(token.as_bytes());
    let prefix = token[..16].to_string(); // "sid_pat_" (8) + 8 chars
    (token, hash, prefix)
}

/// SHA-256 hex digest (no `hex` crate dependency).
fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// CREDENTIAL_NOT_FOUND for a token that does not exist or is not the
/// caller's: both answer alike, so another user's token is not revealed.
fn pat_not_found(id: &str) -> Status {
    not_found(ErrorReason::CredentialNotFound, "PersonalAccessToken", id)
}

/// TOKEN_INVALID for a token that cannot be exchanged: unknown, revoked or
/// expired alike.
fn pat_unusable() -> Status {
    ApiError::new(ErrorReason::TokenInvalid, "the token is not valid").into()
}

/// Convert domain `PersonalAccessToken` to proto `Pat` message.
///
/// NEVER includes the plaintext token value.
fn pat_to_proto(pat: &PersonalAccessToken) -> Pat {
    let status = match pat.status {
        DomainPatStatus::Active => ProtoPatStatus::Active,
        DomainPatStatus::Revoked => ProtoPatStatus::Revoked,
        DomainPatStatus::Expired => ProtoPatStatus::Expired,
    };

    Pat {
        id: pat.id.0.to_string(),
        profile_id: pat.profile_id.to_string(),
        name: pat.name.clone(),
        description: pat.description.clone().unwrap_or_default(),
        token_prefix: pat.token_prefix.clone(),
        scopes: pat.scopes.clone(),
        status: status.into(),
        created_at: Some(convert::to_timestamp(pat.created_at)),
        expires_at: pat.expires_at.map(convert::to_timestamp),
        last_used_at: pat.last_used_at.map(convert::to_timestamp),
        last_used_ip: pat.last_used_ip.clone().unwrap_or_default(),
        use_count: pat.use_count,
        revoked_at: pat.revoked_at.map(convert::to_timestamp),
        revoked_by: pat.revoked_by.clone().unwrap_or_default(),
    }
}

/// Parse a PAT ID string into the domain type.
fn parse_pat_id(s: &str) -> Result<PatId, Status> {
    Uuid::parse_str(s)
        .map(PatId)
        .map_err(|_| invalid_field("pat_id", "not a token identifier"))
}

#[tonic::async_trait]
impl PatService for PatServiceImpl {
    // ── User-facing CRUD ──

    async fn create_pat(
        &self,
        request: Request<CreatePatRequest>,
    ) -> Result<Response<CreatePatResponse>, Status> {
        let profile_id = self.token_owner(&request).await?;
        let req = request.into_inner();

        // Validate required fields.
        if req.name.is_empty() {
            return Err(missing_field("name"));
        }
        if req.scopes.is_empty() {
            return Err(missing_field("scopes"));
        }

        // Validate expiration: must be provided and within policy limit.
        let expires_at_ts = req
            .expires_at
            .as_ref()
            .ok_or_else(|| missing_field("expires_at"))?;

        let expires_at =
            chrono::DateTime::from_timestamp(expires_at_ts.seconds, expires_at_ts.nanos as u32)
                .ok_or_else(|| invalid_field("expires_at", "not a representable time"))?;

        let max_expiry =
            chrono::Utc::now() + chrono::Duration::days(i64::from(PAT_MAX_LIFETIME_DAYS));
        if expires_at > max_expiry {
            return Err(invalid_field(
                "expires_at",
                format!("at most {PAT_MAX_LIFETIME_DAYS} days ahead"),
            ));
        }
        if expires_at <= chrono::Utc::now() {
            return Err(invalid_field("expires_at", "must be in the future"));
        }

        // Generate token (plaintext shown once, hash stored).
        let (plaintext, hash, prefix) = generate_pat_token();

        let mut pat =
            PersonalAccessToken::new(profile_id, &req.name, &hash, &prefix, req.scopes.clone())
                .with_expires_at(expires_at);

        if !req.description.is_empty() {
            pat.description = Some(req.description.clone());
        }
        if !req.ip_allowlist.is_empty() {
            pat.ip_allowlist = req.ip_allowlist;
        }

        let audit: MutationContext =
            AuditEntry::user(profile_id.to_string(), "pat.create", pat.id.0.to_string()).into();

        // The per-user limit is checked with the insert, so concurrent creates
        // cannot exceed it.
        self.storage
            .create_pat(&pat, Some(PAT_MAX_ACTIVE_PER_USER as u64), audit)
            .await
            .map_err(|e| match e {
                sid_core::Error::ResourceExhausted(_) => Status::from(
                    ApiError::new(
                        ErrorReason::QuotaExceeded,
                        "the limit of active personal access tokens is reached",
                    )
                    .with_quota_violation(
                        "personal_access_tokens",
                        format!("at most {PAT_MAX_ACTIVE_PER_USER} active tokens per user"),
                    ),
                ),
                e => storage_failure(e),
            })?;

        info!(
            "Created PAT {} ({}) for profile {}",
            pat.id.0, pat.name, pat.profile_id
        );

        Ok(Response::new(CreatePatResponse {
            pat_id: pat.id.0.to_string(),
            token: plaintext,
            token_prefix: prefix,
            metadata: Some(pat_to_proto(&pat)),
        }))
    }

    async fn list_pats(
        &self,
        request: Request<ListPatsRequest>,
    ) -> Result<Response<ListPatsResponse>, Status> {
        let profile_id = self.token_owner(&request).await?;

        let pats = self
            .storage
            .list_pats_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListPatsResponse {
            pats: pats.iter().map(pat_to_proto).collect(),
        }))
    }

    async fn get_pat(
        &self,
        request: Request<GetPatRequest>,
    ) -> Result<Response<PatResponse>, Status> {
        let caller_id = self.token_owner(&request).await?;
        let req = request.into_inner();
        let pat_id = parse_pat_id(&req.pat_id)?;

        let pat = self
            .storage
            .get_pat(pat_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| pat_not_found(&req.pat_id))?;

        // Ownership check: users can only see their own PATs.
        if pat.profile_id != caller_id {
            return Err(pat_not_found(&req.pat_id));
        }

        Ok(Response::new(PatResponse {
            pat: Some(pat_to_proto(&pat)),
        }))
    }

    async fn revoke_pat(
        &self,
        request: Request<RevokePatRequest>,
    ) -> Result<Response<RevokePatResponse>, Status> {
        let caller_id = self.token_owner(&request).await?;
        let req = request.into_inner();
        let pat_id = parse_pat_id(&req.pat_id)?;

        // Ownership check: users can only revoke their own PATs.
        let pat = self
            .storage
            .get_pat(pat_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| pat_not_found(&req.pat_id))?;

        if pat.profile_id != caller_id {
            return Err(pat_not_found(&req.pat_id));
        }

        let audit: MutationContext =
            AuditEntry::user(caller_id.to_string(), "pat.revoke", pat_id.0.to_string()).into();

        self.storage
            .revoke_pat(pat_id, &caller_id.to_string(), audit)
            .await
            .map_err(storage_failure)?;

        info!("Revoked PAT {} by profile {}", pat_id.0, caller_id);

        Ok(Response::new(RevokePatResponse {}))
    }

    // ── Token exchange ──

    async fn exchange_pat(
        &self,
        request: Request<ExchangePatRequest>,
    ) -> Result<Response<ExchangePatResponse>, Status> {
        let req = request.into_inner();

        if req.token.is_empty() {
            return Err(missing_field("token"));
        }

        // Hash the incoming opaque token to look up the stored PAT.
        let token_hash = sha256_hex(req.token.as_bytes());

        let pat = self
            .storage
            .get_pat_by_token_hash(&token_hash)
            .await
            .map_err(storage_failure)?
            .ok_or_else(pat_unusable)?;

        if !pat.is_usable() {
            return Err(pat_unusable());
        }

        // A stored token carries no registered resource to bind the issued
        // token to, so no verifier could accept what it would be exchanged
        // for. It is inadmissible until replaced by a resource-bound grant;
        // nothing is issued and no use is recorded.
        Err(ApiError::new(
            ErrorReason::InvalidState,
            "the token is not bound to a registered resource; replace it",
        )
        .with_precondition(
            "PAT_RESOURCE_BINDING",
            pat.id.0.to_string(),
            "the token names no registered resource",
        )
        .into())
    }

    // ── Admin ──

    async fn list_all_pats(
        &self,
        request: Request<ListAllPatsRequest>,
    ) -> Result<Response<ListAllPatsResponse>, Status> {
        self.admin(&request).await?;
        let pats = self
            .storage
            .list_all_pats()
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListAllPatsResponse {
            pats: pats.iter().map(pat_to_proto).collect(),
        }))
    }

    async fn admin_revoke_pat(
        &self,
        request: Request<AdminRevokePatRequest>,
    ) -> Result<Response<RevokePatResponse>, Status> {
        let admin_id = self.admin(&request).await?;
        let req = request.into_inner();
        let pat_id = parse_pat_id(&req.pat_id)?;

        let audit: MutationContext = AuditEntry::admin(
            admin_id.to_string(),
            "pat.admin_revoke",
            pat_id.0.to_string(),
        )
        .into();

        let revoked = self
            .storage
            .revoke_pat(pat_id, &admin_id.to_string(), audit)
            .await
            .map_err(storage_failure)?;
        if !revoked {
            // Revoking a revoked token is a no-op; a token that does not
            // exist is not found.
            let exists = self
                .storage
                .get_pat(pat_id)
                .await
                .map_err(storage_failure)?
                .is_some();
            if !exists {
                return Err(pat_not_found(&req.pat_id));
            }
        }

        info!("Admin {} revoked PAT {}", admin_id, pat_id.0);

        Ok(Response::new(RevokePatResponse {}))
    }
}

#[cfg(test)]
mod tests;
