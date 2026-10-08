// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC MachineUserService implementation.
//!
//! Manages non-human identity lifecycle (service accounts, bots, agents),
//! credential management (client_secret, private_key_jwt), and
//! impersonation grants (RFC 8693 token exchange).

use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{
    AuditEntry, ImpersonationGrant, ImpersonationTargetType as DomainImpersonationTargetType,
    MachineCredentialType as DomainCredentialType, MachineRestrictions, MachineUser,
    MachineUserCredential, MachineUserId, MachineUserStatus as DomainMachineUserStatus,
    MachineUserType as DomainMachineUserType, MutationContext, OwnerType, ProjectId,
    machine_user::CredentialStatus as DomainCredentialStatus,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{
    self, AddMachineCredentialRequest, AddMachineCredentialResponse, CreateMachineUserRequest,
    CreateMachineUserResponse, DeleteMachineUserRequest, DeleteMachineUserResponse,
    GetMachineUserRequest, GrantImpersonationRequest, GrantImpersonationResponse,
    ImpersonationGrantInfo, ListImpersonationGrantsRequest, ListImpersonationGrantsResponse,
    ListMachineCredentialsRequest, ListMachineCredentialsResponse, ListMachineUsersRequest,
    ListMachineUsersResponse, MachineCredentialInfo, MachineUserInfo, MachineUserResponse,
    ReactivateMachineUserRequest, RevokeImpersonationRequest, RevokeImpersonationResponse,
    RevokeMachineCredentialRequest, RevokeMachineCredentialResponse,
    RotateMachineCredentialRequest, RotateMachineCredentialResponse, SuspendMachineUserRequest,
    UpdateMachineUserRequest, machine_user_service_server::MachineUserService,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use sid_core::grpc_error::{ApiError, ErrorReason};

use super::convert;
use sid_core::grpc_error::refuse::{
    changed_concurrently, invalid_field, missing_field, not_found, storage_failure,
};

/// Proto enum aliases to avoid collision with domain types.
type ProtoMachineUserType = v1::MachineUserType;
type ProtoMachineUserStatus = v1::MachineUserStatus;
type ProtoCredentialType = v1::MachineCredentialType;
type ProtoCredentialStatus = v1::MachineCredentialStatus;
type ProtoImpersonationTargetType = v1::ImpersonationTargetType;

/// gRPC service for machine user management.
pub struct MachineUserServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    /// The installation's organization, which owns the machine users its
    /// administrators create.
    organization: sid_core::models::OrgId,
}

impl MachineUserServiceImpl {
    /// Create a new machine user service instance.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        organization: sid_core::models::OrgId,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
            organization,
        }
    }

    /// Authenticate the caller and require the administrator role: machine
    /// users, their credentials and their impersonation grants are instance
    /// administration. An agent owned by a Profile is managed by its owner
    /// through the application's consent flow, not through this service.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    /// Stop the tokens issued for `kids` at every replica and resource: a
    /// machine token's `sid` is the credential it was issued for. The stored
    /// change has committed; a resource of this installation rechecks the
    /// stored state anyway, so a cache failure is logged, not refused.
    async fn stop_tokens(&self, kids: &[String]) {
        for kid in kids {
            if let Err(e) = self.revocation.revoke_session(kid.clone()).await {
                tracing::warn!(kid = %kid, error = %e, "machine credential revocation not propagated");
            }
        }
    }

    /// Stop the tokens of every credential of machine user `id`.
    #[allow(clippy::result_large_err)]
    async fn stop_all_tokens(&self, id: MachineUserId) -> Result<(), Status> {
        let kids: Vec<String> = self
            .storage
            .list_machine_credentials_by_user(id)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .map(|c| c.kid)
            .collect();
        self.stop_tokens(&kids).await;
        Ok(())
    }
}

// ── Helper functions ──

/// Generate a client_id for a machine user: `mu_{24 base62 chars}` (27 chars total).
fn generate_client_id() -> String {
    use rand::RngCore;
    use rand::rngs::OsRng;

    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);

    const BASE62: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let random: String = bytes
        .iter()
        .map(|b| BASE62[(*b as usize) % 62] as char)
        .collect();
    format!("mu_{random}")
}

/// Prefix of a machine user's client secret.
const MACHINE_SECRET_PREFIX: &str = "ms_";

/// Generate a kid for a credential: `kid_{16 base62 chars}`.
fn generate_kid() -> String {
    use rand::RngCore;
    use rand::rngs::OsRng;

    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);

    const BASE62: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let random: String = bytes
        .iter()
        .map(|b| BASE62[(*b as usize) % 62] as char)
        .collect();
    format!("kid_{random}")
}

/// SHA-256 hex digest (no `hex` crate dependency).
fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Parse a machine user ID string into the domain type.
fn parse_machine_user_id(s: &str) -> Result<MachineUserId, Status> {
    MachineUserId::parse(s)
        .map_err(|_| invalid_field("machine_user_id", "not a machine user identifier"))
}

/// Parse a project ID string into the domain type.
fn parse_project_id(s: &str) -> Result<ProjectId, Status> {
    Uuid::parse_str(s)
        .map(ProjectId)
        .map_err(|_| invalid_field("project_id", "not a project identifier"))
}

/// MACHINE_USER_NOT_FOUND for `id`.
fn machine_user_not_found(id: MachineUserId) -> Status {
    not_found(
        ErrorReason::MachineUserNotFound,
        "MachineUser",
        id.to_string(),
    )
}

/// INVALID_STATE: the machine user is not in a state that allows `change`.
fn machine_user_state(id: MachineUserId, state: &'static str, change: &'static str) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        format!("a {state} machine user cannot be {change}"),
    )
    .with_precondition("MACHINE_USER_STATE", id.to_string(), state)
    .into()
}

/// CREDENTIAL_NOT_FOUND: no credential `kid` belongs to the machine user.
fn credential_not_found(kid: &str) -> Status {
    not_found(ErrorReason::CredentialNotFound, "MachineCredential", kid)
}

/// QUOTA_EXCEEDED: the machine user holds the most active credentials allowed.
fn credential_limit_reached(id: MachineUserId) -> Status {
    ApiError::new(
        ErrorReason::QuotaExceeded,
        "the limit of active machine credentials is reached",
    )
    .with_quota_violation(
        format!("machine_credentials/{id}"),
        format!(
            "at most {} active credentials per machine user",
            sid_core::models::machine_user::MAX_ACTIVE_CREDENTIALS
        ),
    )
    .into()
}

/// Convert proto `MachineUserType` to domain type.
fn proto_to_machine_type(proto: i32) -> DomainMachineUserType {
    match ProtoMachineUserType::try_from(proto) {
        Ok(ProtoMachineUserType::Service) => DomainMachineUserType::Service,
        Ok(ProtoMachineUserType::Bot) => DomainMachineUserType::Bot,
        Ok(ProtoMachineUserType::Agent) => DomainMachineUserType::Agent,
        _ => DomainMachineUserType::Service, // default
    }
}

/// Convert domain `MachineUserType` to proto.
fn machine_type_to_proto(t: DomainMachineUserType) -> ProtoMachineUserType {
    match t {
        DomainMachineUserType::Service => ProtoMachineUserType::Service,
        DomainMachineUserType::Bot => ProtoMachineUserType::Bot,
        DomainMachineUserType::Agent => ProtoMachineUserType::Agent,
    }
}

/// Convert domain `MachineUserStatus` to proto.
fn status_to_proto(s: DomainMachineUserStatus) -> ProtoMachineUserStatus {
    match s {
        DomainMachineUserStatus::Active => ProtoMachineUserStatus::Active,
        DomainMachineUserStatus::Suspended => ProtoMachineUserStatus::Suspended,
        DomainMachineUserStatus::Expired => ProtoMachineUserStatus::Expired,
        DomainMachineUserStatus::Deleted => ProtoMachineUserStatus::Deleted,
    }
}

/// Convert proto `MachineCredentialType` to domain type.
fn proto_to_credential_type(proto: i32) -> Result<DomainCredentialType, Status> {
    match ProtoCredentialType::try_from(proto) {
        Ok(ProtoCredentialType::ClientSecret) => Ok(DomainCredentialType::ClientSecret),
        Ok(ProtoCredentialType::PrivateKeyJwt) => Ok(DomainCredentialType::PrivateKeyJwt),
        Ok(ProtoCredentialType::Mtls) => Ok(DomainCredentialType::Mtls),
        Ok(ProtoCredentialType::WorkloadIdentity) => Ok(DomainCredentialType::WorkloadIdentity),
        _ => Err(invalid_field(
            "credential_type",
            "not a supported credential type",
        )),
    }
}

/// Convert domain `MachineCredentialType` to proto.
fn credential_type_to_proto(t: DomainCredentialType) -> ProtoCredentialType {
    match t {
        DomainCredentialType::ClientSecret => ProtoCredentialType::ClientSecret,
        DomainCredentialType::PrivateKeyJwt => ProtoCredentialType::PrivateKeyJwt,
        DomainCredentialType::Mtls => ProtoCredentialType::Mtls,
        DomainCredentialType::WorkloadIdentity => ProtoCredentialType::WorkloadIdentity,
    }
}

/// Convert domain `CredentialStatus` to proto.
fn credential_status_to_proto(s: DomainCredentialStatus) -> ProtoCredentialStatus {
    match s {
        DomainCredentialStatus::Active => ProtoCredentialStatus::Active,
        DomainCredentialStatus::GracePeriod => ProtoCredentialStatus::GracePeriod,
        DomainCredentialStatus::Expired => ProtoCredentialStatus::Expired,
        DomainCredentialStatus::Revoked => ProtoCredentialStatus::Revoked,
    }
}

/// Convert proto `ImpersonationTargetType` to domain type.
fn proto_to_impersonation_target(proto: i32) -> Result<DomainImpersonationTargetType, Status> {
    match ProtoImpersonationTargetType::try_from(proto) {
        Ok(ProtoImpersonationTargetType::Role) => Ok(DomainImpersonationTargetType::Role),
        Ok(ProtoImpersonationTargetType::User) => Ok(DomainImpersonationTargetType::User),
        _ => Err(invalid_field("target_type", "must be a role or a user")),
    }
}

/// Convert domain `ImpersonationTargetType` to proto.
fn impersonation_target_to_proto(t: DomainImpersonationTargetType) -> ProtoImpersonationTargetType {
    match t {
        DomainImpersonationTargetType::Role => ProtoImpersonationTargetType::Role,
        DomainImpersonationTargetType::User => ProtoImpersonationTargetType::User,
    }
}

/// Convert domain `MachineUser` to proto `MachineUserInfo`.
fn machine_user_to_proto(mu: &MachineUser) -> MachineUserInfo {
    MachineUserInfo {
        id: mu.id.to_string(),
        project_id: mu.project_id.0.to_string(),
        client_id: mu.client_id.clone(),
        display_name: mu.display_name.clone(),
        description: mu.description.clone().unwrap_or_default(),
        machine_type: machine_type_to_proto(mu.machine_type).into(),
        status: status_to_proto(mu.status).into(),
        owner_type: mu.owner_type.as_str().to_string(),
        owner_id: mu.owner_id.clone(),
        scopes: mu.scopes.clone(),
        ip_allowlist: mu.restrictions.ip_allowlist.clone(),
        rate_limit_rpm: mu.restrictions.rate_limit_rpm as i32,
        max_token_lifetime: mu.max_token_lifetime.map(|v| v as i32).unwrap_or(0),
        expires_at: mu.expires_at.map(convert::to_timestamp),
        last_used_at: None, // TODO: Track last_used_at in domain model
        created_at: Some(convert::to_timestamp(mu.created_at)),
        updated_at: Some(convert::to_timestamp(mu.updated_at)),
    }
}

/// Convert domain `MachineUserCredential` to proto `MachineCredentialInfo`.
fn credential_to_proto(cred: &MachineUserCredential) -> MachineCredentialInfo {
    MachineCredentialInfo {
        kid: cred.kid.clone(),
        credential_type: credential_type_to_proto(cred.credential_type).into(),
        status: credential_status_to_proto(cred.status).into(),
        algorithm: cred.algorithm.clone().unwrap_or_default(),
        expires_at: cred.expires_at.map(convert::to_timestamp),
        created_at: Some(convert::to_timestamp(cred.created_at)),
    }
}

/// Convert domain `ImpersonationGrant` to proto `ImpersonationGrantInfo`.
fn grant_to_proto(grant: &ImpersonationGrant) -> ImpersonationGrantInfo {
    ImpersonationGrantInfo {
        id: format!(
            "{}:{}:{}",
            grant.machine_user_id,
            grant.target_type.as_str(),
            grant.target
        ),
        machine_user_id: grant.machine_user_id.to_string(),
        target_type: impersonation_target_to_proto(grant.target_type).into(),
        target: grant.target.clone(),
        allowed_scopes: grant.allowed_scopes.clone(),
        created_at: Some(convert::to_timestamp(grant.created_at)),
    }
}

/// Parse a timestamp from a proto optional field.
fn parse_optional_timestamp(
    ts: &Option<prost_types::Timestamp>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, Status> {
    match ts {
        Some(t) => {
            let dt = chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                .ok_or_else(|| invalid_field("expires_at", "not a representable time"))?;
            Ok(Some(dt))
        }
        None => Ok(None),
    }
}

#[tonic::async_trait]
impl MachineUserService for MachineUserServiceImpl {
    // ── CRUD ──

    async fn create_machine_user(
        &self,
        request: Request<CreateMachineUserRequest>,
    ) -> Result<Response<CreateMachineUserResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();

        if req.display_name.is_empty() {
            return Err(missing_field("display_name"));
        }

        let project_id = parse_project_id(&req.project_id)?;

        // Generate client_id.
        let client_id = generate_client_id();

        // An administrator acts for the installation's organization; a
        // system-owned machine is established only by installation
        // provisioning, never through this API.
        let mut mu = MachineUser::new(
            project_id,
            &client_id,
            &req.display_name,
            OwnerType::Organization,
            self.organization.to_string(),
        );

        mu.machine_type = proto_to_machine_type(req.machine_type);

        if !req.description.is_empty() {
            mu.description = Some(req.description);
        }
        if !req.scopes.is_empty() {
            mu.scopes = req.scopes;
        }
        if !req.ip_allowlist.is_empty() || req.rate_limit_rpm > 0 {
            mu.restrictions = MachineRestrictions {
                ip_allowlist: req.ip_allowlist,
                rate_limit_rpm: req.rate_limit_rpm as u32,
            };
        }
        if req.max_token_lifetime > 0 {
            mu.max_token_lifetime = Some(req.max_token_lifetime as u32);
        }
        mu.expires_at = parse_optional_timestamp(&req.expires_at)?;

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.create",
            mu.id.to_string(),
        )
        .into();

        self.storage
            .create_machine_user(&mu, audit)
            .await
            .map_err(storage_failure)?;

        info!(
            "Created machine user {} ({}) for project {}",
            mu.id, mu.display_name, mu.project_id.0
        );

        Ok(Response::new(CreateMachineUserResponse {
            machine_user: Some(machine_user_to_proto(&mu)),
        }))
    }

    async fn get_machine_user(
        &self,
        request: Request<GetMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let id = parse_machine_user_id(&req.machine_user_id)?;

        let mu = self
            .storage
            .get_machine_user(id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| machine_user_not_found(id))?;

        Ok(Response::new(MachineUserResponse {
            machine_user: Some(machine_user_to_proto(&mu)),
        }))
    }

    async fn update_machine_user(
        &self,
        request: Request<UpdateMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let id = parse_machine_user_id(&req.machine_user_id)?;

        let mut mu = self
            .storage
            .get_machine_user(id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| machine_user_not_found(id))?;

        // Apply updates (only non-empty/non-zero fields).
        if !req.display_name.is_empty() {
            mu.display_name = req.display_name;
        }
        if !req.description.is_empty() {
            mu.description = Some(req.description);
        }
        if !req.scopes.is_empty() {
            mu.scopes = req.scopes;
        }
        // ip_allowlist can be explicitly set (even empty to clear).
        if !req.ip_allowlist.is_empty() {
            mu.restrictions.ip_allowlist = req.ip_allowlist;
        }
        if req.rate_limit_rpm > 0 {
            mu.restrictions.rate_limit_rpm = req.rate_limit_rpm as u32;
        }
        if req.max_token_lifetime > 0 {
            mu.max_token_lifetime = Some(req.max_token_lifetime as u32);
        }
        if req.expires_at.is_some() {
            mu.expires_at = parse_optional_timestamp(&req.expires_at)?;
        }

        mu.updated_at = chrono::Utc::now();

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.update",
            mu.id.to_string(),
        )
        .into();

        // Settings only: a suspension or deletion made meanwhile stays.
        let updated = self
            .storage
            .update_machine_user(&mu, audit)
            .await
            .map_err(storage_failure)?;
        if !updated {
            return Err(machine_user_not_found(id));
        }

        info!("Updated machine user {}", mu.id);

        Ok(Response::new(MachineUserResponse {
            machine_user: Some(machine_user_to_proto(&mu)),
        }))
    }

    async fn delete_machine_user(
        &self,
        request: Request<DeleteMachineUserRequest>,
    ) -> Result<Response<DeleteMachineUserResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let id = parse_machine_user_id(&req.machine_user_id)?;

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.delete",
            id.to_string(),
        )
        .into();

        self.storage
            .delete_machine_user(id, audit)
            .await
            .map_err(storage_failure)?;
        self.stop_all_tokens(id).await?;

        info!("Deleted machine user {}", id);

        Ok(Response::new(DeleteMachineUserResponse {}))
    }

    async fn list_machine_users(
        &self,
        request: Request<ListMachineUsersRequest>,
    ) -> Result<Response<ListMachineUsersResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let project_id = parse_project_id(&req.project_id)?;

        let users = self
            .storage
            .list_machine_users_by_project(project_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListMachineUsersResponse {
            machine_users: users.iter().map(machine_user_to_proto).collect(),
        }))
    }

    async fn suspend_machine_user(
        &self,
        request: Request<SuspendMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let id = parse_machine_user_id(&req.machine_user_id)?;

        let mut mu = self
            .storage
            .get_machine_user(id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| machine_user_not_found(id))?;

        if mu.status == DomainMachineUserStatus::Deleted {
            return Err(machine_user_state(id, "deleted", "suspended"));
        }
        if mu.status == DomainMachineUserStatus::Suspended {
            // Idempotent: already suspended, return current state.
            return Ok(Response::new(MachineUserResponse {
                machine_user: Some(machine_user_to_proto(&mu)),
            }));
        }

        // Expired is the one state left here.
        let active = mu
            .as_active()
            .ok_or_else(|| machine_user_state(id, "expired", "suspended"))?;
        active.suspend();

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.suspend",
            mu.id.to_string(),
        )
        .into();

        // Only from active: a deletion made meanwhile is not turned back.
        let suspended = self
            .storage
            .transition_machine_user(
                mu.id,
                DomainMachineUserStatus::Active,
                DomainMachineUserStatus::Suspended,
                audit,
            )
            .await
            .map_err(storage_failure)?;
        if !suspended {
            return Err(changed_concurrently());
        }
        self.stop_all_tokens(mu.id).await?;

        info!("Suspended machine user {}", mu.id);

        Ok(Response::new(MachineUserResponse {
            machine_user: Some(machine_user_to_proto(&mu)),
        }))
    }

    async fn reactivate_machine_user(
        &self,
        request: Request<ReactivateMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let id = parse_machine_user_id(&req.machine_user_id)?;

        let mut mu = self
            .storage
            .get_machine_user(id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| machine_user_not_found(id))?;

        if mu.status == DomainMachineUserStatus::Deleted {
            return Err(machine_user_state(id, "deleted", "reactivated"));
        }
        if mu.status == DomainMachineUserStatus::Active {
            // Idempotent: already active, return current state.
            return Ok(Response::new(MachineUserResponse {
                machine_user: Some(machine_user_to_proto(&mu)),
            }));
        }

        let previous = mu.status;
        mu.status = DomainMachineUserStatus::Active;
        mu.updated_at = chrono::Utc::now();

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.reactivate",
            mu.id.to_string(),
        )
        .into();

        // Only from the state just read: a deletion made meanwhile stays.
        let reactivated = self
            .storage
            .transition_machine_user(mu.id, previous, DomainMachineUserStatus::Active, audit)
            .await
            .map_err(storage_failure)?;
        if !reactivated {
            return Err(changed_concurrently());
        }

        info!("Reactivated machine user {}", mu.id);

        Ok(Response::new(MachineUserResponse {
            machine_user: Some(machine_user_to_proto(&mu)),
        }))
    }

    // ── Credentials ──

    async fn add_machine_credential(
        &self,
        request: Request<AddMachineCredentialRequest>,
    ) -> Result<Response<AddMachineCredentialResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let mu_id = parse_machine_user_id(&req.machine_user_id)?;
        let cred_type = proto_to_credential_type(req.credential_type)?;

        let mu = self
            .storage
            .get_machine_user(mu_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| machine_user_not_found(mu_id))?;

        if mu.status == DomainMachineUserStatus::Deleted {
            return Err(machine_user_state(mu_id, "deleted", "given a credential"));
        }

        let kid = generate_kid();
        let mut plaintext_secret: Option<SecretBox<String>> = None;

        let credential_data = match cred_type {
            DomainCredentialType::ClientSecret => {
                let issued = sid_authn::bearer_secret::issue(MACHINE_SECRET_PREFIX);
                plaintext_secret = Some(issued.secret);
                issued.verifier
            }
            DomainCredentialType::PrivateKeyJwt => {
                if req.public_key_pem.is_empty() {
                    return Err(missing_field("public_key_pem"));
                }
                req.public_key_pem.clone()
            }
            DomainCredentialType::Mtls => {
                if req.public_key_pem.is_empty() {
                    return Err(missing_field("public_key_pem"));
                }
                // Store certificate fingerprint (SHA-256 of PEM).
                sha256_hex(req.public_key_pem.as_bytes())
            }
            DomainCredentialType::WorkloadIdentity => {
                // Trust bundle reference — stored as credential_data.
                req.public_key_pem.clone()
            }
        };

        let mut cred = MachineUserCredential::new(mu_id, &kid, cred_type, credential_data);

        if !req.algorithm.is_empty() {
            cred.algorithm = Some(req.algorithm);
        }
        cred.expires_at = parse_optional_timestamp(&req.expires_at)?;

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.credential.add",
            format!("{}:{}", mu_id, kid),
        )
        .into();

        // The limit is checked with the insert, so concurrent adds cannot
        // exceed it.
        self.storage
            .add_machine_credential(
                &cred,
                Some(sid_core::models::machine_user::MAX_ACTIVE_CREDENTIALS as u64),
                audit,
            )
            .await
            .map_err(|e| match e {
                sid_core::Error::ResourceExhausted(_) => credential_limit_reached(mu_id),
                e => storage_failure(e),
            })?;

        info!("Added credential {} to machine user {}", kid, mu_id);

        Ok(Response::new(AddMachineCredentialResponse {
            credential: Some(credential_to_proto(&cred)),
            client_secret: plaintext_secret
                .as_ref()
                .map(|s| s.expose_secret().clone())
                .unwrap_or_default(),
        }))
    }

    async fn revoke_machine_credential(
        &self,
        request: Request<RevokeMachineCredentialRequest>,
    ) -> Result<Response<RevokeMachineCredentialResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let mu_id = parse_machine_user_id(&req.machine_user_id)?;

        if req.kid.is_empty() {
            return Err(missing_field("kid"));
        }

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.credential.revoke",
            format!("{}:{}", req.machine_user_id, req.kid),
        )
        .into();

        let revoked = self
            .storage
            .revoke_machine_credential(mu_id, &req.kid, audit)
            .await
            .map_err(storage_failure)?;
        if !revoked {
            // Revoking a revoked credential is a no-op; a kid of another
            // machine user, or none, is not found.
            let already = self
                .storage
                .get_machine_credential_by_kid(&req.kid)
                .await
                .map_err(storage_failure)?
                .is_some_and(|c| {
                    c.machine_user_id == mu_id && c.status == DomainCredentialStatus::Revoked
                });
            if !already {
                return Err(credential_not_found(&req.kid));
            }
        }

        self.stop_tokens(std::slice::from_ref(&req.kid)).await;
        info!(
            "Revoked credential {} for machine user {}",
            req.kid, req.machine_user_id
        );

        Ok(Response::new(RevokeMachineCredentialResponse {}))
    }

    async fn list_machine_credentials(
        &self,
        request: Request<ListMachineCredentialsRequest>,
    ) -> Result<Response<ListMachineCredentialsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let mu_id = parse_machine_user_id(&req.machine_user_id)?;

        let creds = self
            .storage
            .list_machine_credentials_by_user(mu_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListMachineCredentialsResponse {
            credentials: creds.iter().map(credential_to_proto).collect(),
        }))
    }

    async fn rotate_machine_credential(
        &self,
        request: Request<RotateMachineCredentialRequest>,
    ) -> Result<Response<RotateMachineCredentialResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let mu_id = parse_machine_user_id(&req.machine_user_id)?;

        if req.kid.is_empty() {
            return Err(missing_field("kid"));
        }

        // A kid of another machine user is not found, as one that does not exist.
        let mut old_cred = self
            .storage
            .get_machine_credential_by_kid(&req.kid)
            .await
            .map_err(storage_failure)?
            .filter(|c| c.machine_user_id == mu_id)
            .ok_or_else(|| credential_not_found(&req.kid))?;

        if old_cred.status != DomainCredentialStatus::Active {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "only an active credential can be rotated",
            )
            .with_precondition(
                "MACHINE_CREDENTIAL_STATE",
                req.kid.clone(),
                old_cred.status.as_str(),
            )
            .into());
        }

        // Create new credential of same type.
        let new_kid = generate_kid();
        let mut plaintext_secret: Option<SecretBox<String>> = None;

        let credential_data = match old_cred.credential_type {
            DomainCredentialType::ClientSecret => {
                let issued = sid_authn::bearer_secret::issue(MACHINE_SECRET_PREFIX);
                plaintext_secret = Some(issued.secret);
                issued.verifier
            }
            DomainCredentialType::PrivateKeyJwt => {
                if req.public_key_pem.is_empty() {
                    return Err(missing_field("public_key_pem"));
                }
                req.public_key_pem.clone()
            }
            DomainCredentialType::Mtls => {
                if req.public_key_pem.is_empty() {
                    return Err(missing_field("public_key_pem"));
                }
                sha256_hex(req.public_key_pem.as_bytes())
            }
            DomainCredentialType::WorkloadIdentity => req.public_key_pem.clone(),
        };

        let mut new_cred =
            MachineUserCredential::new(mu_id, &new_kid, old_cred.credential_type, credential_data);

        if !req.algorithm.is_empty() {
            new_cred.algorithm = Some(req.algorithm);
        } else {
            new_cred.algorithm = old_cred.algorithm.clone();
        }
        new_cred.expires_at = parse_optional_timestamp(&req.expires_at)?;

        let audit_new: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.credential.rotate",
            format!("{}:{}->{}", mu_id, old_cred.kid, new_kid),
        )
        .into();

        // The old credential enters its grace period and the new one is
        // stored in one step, only if the old one is still active. The grace
        // ends, at the latest, ROTATION_GRACE_PERIOD_HOURS from now.
        let grace_until = chrono::Utc::now()
            + chrono::Duration::hours(i64::from(
                sid_core::models::machine_user::ROTATION_GRACE_PERIOD_HOURS,
            ));
        let rotated = self
            .storage
            .rotate_machine_credential(mu_id, &old_cred.kid, &new_cred, grace_until, audit_new)
            .await
            .map_err(storage_failure)?;
        if !rotated {
            return Err(changed_concurrently());
        }
        old_cred.status = DomainCredentialStatus::GracePeriod;
        old_cred.expires_at = Some(
            old_cred
                .expires_at
                .map_or(grace_until, |own| own.min(grace_until)),
        );

        info!(
            "Rotated credential {} -> {} for machine user {}",
            old_cred.kid, new_kid, mu_id
        );

        Ok(Response::new(RotateMachineCredentialResponse {
            old_credential: Some(credential_to_proto(&old_cred)),
            new_credential: Some(credential_to_proto(&new_cred)),
            client_secret: plaintext_secret
                .as_ref()
                .map(|s| s.expose_secret().clone())
                .unwrap_or_default(),
        }))
    }

    // ── Impersonation ──

    async fn grant_impersonation(
        &self,
        request: Request<GrantImpersonationRequest>,
    ) -> Result<Response<GrantImpersonationResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let mu_id = parse_machine_user_id(&req.machine_user_id)?;
        let target_type = proto_to_impersonation_target(req.target_type)?;

        if req.target.is_empty() {
            return Err(missing_field("target"));
        }

        let mu = self
            .storage
            .get_machine_user(mu_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| machine_user_not_found(mu_id))?;

        if mu.status == DomainMachineUserStatus::Deleted {
            return Err(machine_user_state(
                mu_id,
                "deleted",
                "granted impersonation",
            ));
        }

        let grant = ImpersonationGrant::new(mu_id, target_type, &req.target, req.allowed_scopes);

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.impersonation.grant",
            format!("{}:{}:{}", mu_id, target_type.as_str(), req.target),
        )
        .into();

        self.storage
            .save_impersonation_grant(&grant, audit)
            .await
            .map_err(storage_failure)?;

        info!(
            "Granted impersonation to machine user {} for {} {}",
            mu_id,
            target_type.as_str(),
            req.target
        );

        Ok(Response::new(GrantImpersonationResponse {
            grant: Some(grant_to_proto(&grant)),
        }))
    }

    async fn revoke_impersonation(
        &self,
        request: Request<RevokeImpersonationRequest>,
    ) -> Result<Response<RevokeImpersonationResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let mu_id = parse_machine_user_id(&req.machine_user_id)?;

        if req.target_type.is_empty() {
            return Err(missing_field("target_type"));
        }
        if req.target.is_empty() {
            return Err(missing_field("target"));
        }

        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.impersonation.revoke",
            format!("{}:{}:{}", mu_id, req.target_type, req.target),
        )
        .into();

        self.storage
            .delete_impersonation_grant(mu_id, &req.target_type, &req.target, audit)
            .await
            .map_err(storage_failure)?;

        info!(
            "Revoked impersonation from machine user {} for {} {}",
            mu_id, req.target_type, req.target
        );

        Ok(Response::new(RevokeImpersonationResponse {}))
    }

    async fn list_impersonation_grants(
        &self,
        request: Request<ListImpersonationGrantsRequest>,
    ) -> Result<Response<ListImpersonationGrantsResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let mu_id = parse_machine_user_id(&req.machine_user_id)?;

        let grants = self
            .storage
            .list_impersonation_grants(mu_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListImpersonationGrantsResponse {
            grants: grants.iter().map(grant_to_proto).collect(),
        }))
    }
}

#[cfg(test)]
mod tests;
