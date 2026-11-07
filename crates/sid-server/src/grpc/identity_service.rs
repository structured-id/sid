// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC IdentityService: the Profile management the `sid` library owns
//! ([`sid::identity`]), behind authentication, the maintenance switch and the
//! operation context.

use crate::feature_flags::FeatureFlagService;
use sid::identity::{AccountRecord, Identity, IdentityError};
use sid_authn::account_closure::AccountClosureService;
use sid_authn::caller::Caller;
use sid_authn::data_export::DataExportService;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::models::{OperationContext, PrincipalType};
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, invalid_field, maintenance, missing_field, not_configured, not_found,
    not_in_this_build, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

/// The status a Profile management refusal answers with.
pub(crate) fn refusal(e: IdentityError) -> Status {
    use IdentityError as E;
    match e {
        E::Caller(e) => e.into_status(),
        E::Enrollment(e) => e.into_status(),
        E::Operation(e) => e.into_status(),
        E::Store(e) => storage_failure(e),
        // A deferring operation's adapter answers with the context's own
        // refusal (see [`deferred`]); reaching here is a broken invariant.
        E::Internal | E::ContextRequired => ApiError::internal().into(),
        E::MissingField(field) => missing_field(field),
        E::InvalidField { field, reason } => invalid_field(field, reason),
        E::SignupHandleRequired => ApiError::new(
            ErrorReason::RequiredFieldMissing,
            "a username, email or phone is required",
        )
        .with_field_violation("username", "one of username, email, phone is required")
        .with_field_violation("email", "one of username, email, phone is required")
        .with_field_violation("phone", "one of username, email, phone is required")
        .into(),
        E::ProfileNotFound(named) => not_found(ErrorReason::ProfileNotFound, "Profile", named),
        E::CredentialNotFound(id) => not_found(
            ErrorReason::CredentialNotFound,
            "Credential",
            id.0.to_string(),
        ),
        E::DeviceNotFound(id) => not_found(ErrorReason::DeviceNotFound, "Device", id.to_string()),
        E::PrincipalNotFound(id) => not_found(
            ErrorReason::PrincipalNotFound,
            "Principal",
            id.0.to_string(),
        ),
        E::Taken(principal_type) => taken(principal_type),
        E::ChangedConcurrently => changed_concurrently(),
        E::AddressUnconfirmed => ApiError::new(
            ErrorReason::InvalidState,
            "this address must be confirmed before it signs in again",
        )
        .with_precondition(
            "EMAIL_ADDRESS_UNCONFIRMED",
            "principal",
            "confirm the address from the account",
        )
        .into(),
        E::SeveralHolders(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the principal has several holders; remove it from a specific account",
        )
        .with_precondition("PRINCIPAL_HOLDERS", id.0.to_string(), "several")
        .into(),
        E::LastPrimary(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the profile's last way to sign in cannot be revoked; add another first",
        )
        .with_precondition(
            "LAST_PRIMARY_CREDENTIAL",
            id.0.to_string(),
            "the profile has no other active primary credential",
        )
        .into(),
        E::TrustedDeviceLimit => ApiError::new(
            ErrorReason::QuotaExceeded,
            "the limit of trusted devices is reached",
        )
        .with_quota_violation(
            "trusted_devices",
            format!(
                "at most {} trusted devices per profile",
                sid_core::models::device::MAX_TRUSTED_DEVICES
            ),
        )
        .into(),
        E::OtherProfileDevices => ApiError::new(
            ErrorReason::InsufficientPermissions,
            "only the profile's own devices are listed",
        )
        .into(),
        E::AccountState { record, owner, why } => ApiError::new(
            ErrorReason::InvalidState,
            "the account is not in a state that allows this",
        )
        .with_precondition(record.state(), owner.to_string(), why)
        .into(),
        E::AccountRecordNotFound { record, owner } => {
            let (reason, resource_type) = match record {
                AccountRecord::Closure => (ErrorReason::ClosureRequestNotFound, "ClosureRequest"),
                AccountRecord::Export => (ErrorReason::ExportNotFound, "Export"),
            };
            not_found(reason, resource_type, owner.to_string())
        }
        E::CancelLimit => ApiError::new(
            ErrorReason::QuotaExceeded,
            "the yearly limit of cancelled closures is reached",
        )
        .with_quota_violation(
            "closure_cancellations",
            format!(
                "at most {} cancelled closures per year",
                sid_core::models::MAX_CANCEL_CYCLES_PER_YEAR
            ),
        )
        .into(),
        E::NotInThisBuild(what) => not_in_this_build(what),
    }
}

/// A handle or contact of `principal_type` is held by another account.
fn taken(principal_type: PrincipalType) -> Status {
    let reason = match principal_type {
        PrincipalType::Username => ErrorReason::UsernameAlreadyTaken,
        PrincipalType::Email => ErrorReason::EmailAlreadyRegistered,
        PrincipalType::Phone => ErrorReason::PhoneAlreadyRegistered,
        PrincipalType::FaceEmbedding | PrincipalType::NfcTag | PrincipalType::FederatedSubject => {
            ErrorReason::PrincipalAlreadyHeld
        }
    };
    let field = principal_type.as_str();
    ApiError::new(
        reason,
        format!("the {field} is registered to another account"),
    )
    .with_resource("Principal", field)
    .into()
}

/// The answer of a management operation.
#[allow(clippy::result_large_err)]
fn answered<T>(result: Result<T, IdentityError>) -> Result<Response<T>, Status> {
    result.map(Response::new).map_err(refusal)
}

/// A request's operation context for an operation that requires it only
/// after its other checks: the context, or the refusal of its absence.
fn deferred_context<T>(request: &Request<T>) -> (Option<OperationContext>, Option<Status>) {
    match context(request) {
        Ok(context) => (Some(context), None),
        Err(refused) => (None, Some(refused)),
    }
}

/// The answer of a deferring operation: its context's own refusal where the
/// operation required it.
#[allow(clippy::result_large_err)]
fn deferred<T>(
    result: Result<T, IdentityError>,
    refused: Option<Status>,
) -> Result<Response<T>, Status> {
    result.map(Response::new).map_err(|e| match (e, refused) {
        (IdentityError::ContextRequired, Some(refused)) => refused,
        (e, _) => refusal(e),
    })
}

pub struct IdentityServiceImpl {
    identity: Identity,
    jwt: Arc<JwtService>,
    revocation_cache: Arc<RevocationCache>,
    feature_flags: FeatureFlagService,
}

impl IdentityServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation_cache: Arc<RevocationCache>,
        feature_flags: FeatureFlagService,
        cascade_service: Arc<RevocationCascadeService>,
        closure_service: Arc<AccountClosureService>,
        data_export: Arc<DataExportService>,
    ) -> Self {
        Self {
            identity: Identity::new(storage, cascade_service, closure_service, data_export),
            jwt,
            revocation_cache,
            feature_flags,
        }
    }

    /// The authenticated caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation_cache).await
    }

    #[allow(clippy::result_large_err)]
    async fn check_maintenance(&self) -> Result<(), Status> {
        if self.feature_flags.is_maintenance_mode().await {
            Err(maintenance())
        } else {
            Ok(())
        }
    }
}

#[tonic::async_trait]
impl IdentityService for IdentityServiceImpl {
    #[instrument(skip_all, fields(method = "create_profile"))]
    async fn create_profile(
        &self,
        request: Request<CreateProfileRequest>,
    ) -> Result<Response<CreateProfileResponse>, Status> {
        // Provisioning an account for someone else is an administrator action;
        // self-registration goes through the registration ceremonies.
        let caller = self.caller(&request).await?;
        caller.require_admin().or_status()?;
        self.check_maintenance().await?;
        if !self.feature_flags.is_registration_enabled().await {
            return Err(not_configured("registration"));
        }
        let operation = context(&request)?;
        answered(
            self.identity
                .create_profile(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "get_profile"))]
    async fn get_profile(
        &self,
        request: Request<GetProfileRequest>,
    ) -> Result<Response<GetProfileResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(
            self.identity
                .get_profile(&caller, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "update_profile"))]
    async fn update_profile(
        &self,
        request: Request<UpdateProfileRequest>,
    ) -> Result<Response<UpdateProfileResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        // The context is checked after the caller is authorized for the
        // target: a refused caller learns nothing more than without one.
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .update_profile(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "delete_profile"))]
    async fn delete_profile(
        &self,
        request: Request<DeleteProfileRequest>,
    ) -> Result<Response<DeleteProfileResponse>, Status> {
        // Hard deletion is an administrator action; a user closes their own
        // account through the closure flow.
        let caller = self.caller(&request).await?;
        caller.require_admin().or_status()?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answered(
            self.identity
                .delete_profile(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "list_profiles"))]
    async fn list_profiles(
        &self,
        request: Request<ListProfilesRequest>,
    ) -> Result<Response<ListProfilesResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(
            self.identity
                .list_profiles(&caller, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "add_credential"))]
    async fn add_credential(
        &self,
        _request: Request<AddCredentialRequest>,
    ) -> Result<Response<AddCredentialResponse>, Status> {
        // Credentials are added only through their registration ceremonies
        // (OPAQUE, WebAuthn, TOTP enrollment), which prove the factor.
        Err(not_in_this_build("add_credential"))
    }

    #[instrument(skip_all, fields(method = "list_credentials"))]
    async fn list_credentials(
        &self,
        request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(
            self.identity
                .list_credentials(&caller, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "update_credential"))]
    async fn update_credential(
        &self,
        request: Request<UpdateCredentialRequest>,
    ) -> Result<Response<UpdateCredentialResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive().or_status()?;
        self.check_maintenance().await?;
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .update_credential(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "revoke_credential"))]
    async fn revoke_credential(
        &self,
        request: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive().or_status()?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answered(
            self.identity
                .revoke_credential(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "add_principal"))]
    async fn add_principal(
        &self,
        request: Request<AddPrincipalRequest>,
    ) -> Result<Response<AddPrincipalResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive().or_status()?;
        self.check_maintenance().await?;
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .add_principal(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "list_principals"))]
    async fn list_principals(
        &self,
        request: Request<ListPrincipalsRequest>,
    ) -> Result<Response<ListPrincipalsResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(
            self.identity
                .list_principals(&caller, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "remove_principal"))]
    async fn remove_principal(
        &self,
        request: Request<RemovePrincipalRequest>,
    ) -> Result<Response<RemovePrincipalResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive().or_status()?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answered(
            self.identity
                .remove_principal(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "list_sessions"))]
    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(
            self.identity
                .list_sessions(&caller, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "revoke_session"))]
    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<RevokeSessionResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_interactive().or_status()?;
        self.check_maintenance().await?;
        answered(
            self.identity
                .revoke_session(&caller, request.into_inner())
                .await,
        )
    }

    // ── Passkey Registration Prompts ──

    #[instrument(skip_all, fields(method = "get_passkey_prompt_state"))]
    async fn get_passkey_prompt_state(
        &self,
        request: Request<GetPasskeyPromptStateRequest>,
    ) -> Result<Response<GetPasskeyPromptStateResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(self.identity.passkey_prompt(&caller).await)
    }

    #[instrument(skip_all, fields(method = "record_passkey_prompt_dismissal"))]
    async fn record_passkey_prompt_dismissal(
        &self,
        request: Request<RecordPasskeyPromptDismissalRequest>,
    ) -> Result<Response<RecordPasskeyPromptDismissalResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answered(
            self.identity
                .record_passkey_prompt_dismissal(&caller, operation, request.into_inner())
                .await,
        )
    }

    // ── Revocation Cascade ──

    #[instrument(skip_all, fields(method = "revoke_profile"))]
    async fn revoke_profile(
        &self,
        request: Request<RevokeProfileRequest>,
    ) -> Result<Response<RevokeProfileResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        answered(
            self.identity
                .revoke_profile(&caller, request.into_inner())
                .await,
        )
    }

    // ── Account Closure ──

    #[instrument(skip_all, fields(method = "request_closure"))]
    async fn request_closure(
        &self,
        request: Request<RequestClosureRequest>,
    ) -> Result<Response<RequestClosureResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .request_closure(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "cancel_closure"))]
    async fn cancel_closure(
        &self,
        request: Request<CancelClosureRequest>,
    ) -> Result<Response<CancelClosureResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.check_maintenance().await?;
        let operation = context(&request)?;
        answered(
            self.identity
                .cancel_closure(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "get_closure_status"))]
    async fn get_closure_status(
        &self,
        request: Request<GetClosureStatusRequest>,
    ) -> Result<Response<GetClosureStatusResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(self.identity.closure_status(&caller).await)
    }

    // === Data Export (GDPR Art. 20) ===

    #[instrument(skip_all, fields(method = "prepare_export"))]
    async fn prepare_export(
        &self,
        request: Request<PrepareExportRequest>,
    ) -> Result<Response<PrepareExportResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answered(
            self.identity
                .prepare_export(&caller, operation, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "get_export_status"))]
    async fn get_export_status(
        &self,
        request: Request<GetExportStatusRequest>,
    ) -> Result<Response<GetExportStatusResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(self.identity.export_status(&caller).await)
    }

    type DownloadExportStream =
        tokio_stream::wrappers::ReceiverStream<Result<DownloadExportChunk, Status>>;

    #[instrument(skip_all, fields(method = "download_export"))]
    async fn download_export(
        &self,
        request: Request<DownloadExportRequest>,
    ) -> Result<Response<Self::DownloadExportStream>, Status> {
        let caller = self.caller(&request).await?;
        let archive = self
            .identity
            .export_archive(&caller)
            .await
            .map_err(refusal)?;

        let data = archive.data;
        let total_size = data.len() as i64;
        let chunk_size = 64 * 1024; // 64 KiB chunks.
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut offset: i64 = 0;
            for chunk in data.chunks(chunk_size) {
                let msg = DownloadExportChunk {
                    data: chunk.to_vec(),
                    offset,
                    total_size,
                };
                if tx.send(Ok(msg)).await.is_err() {
                    break;
                }
                offset += chunk.len() as i64;
            }
        });

        info!(
            profile_id = %caller.profile_id,
            export_id = %archive.job.id,
            size_bytes = total_size,
            "Export download started",
        );
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    #[instrument(skip_all, fields(method = "acknowledge_export"))]
    async fn acknowledge_export(
        &self,
        request: Request<AcknowledgeExportRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answered(
            self.identity
                .acknowledge_export(&caller, operation, request.into_inner())
                .await,
        )
    }

    // === Device management ===

    #[instrument(skip_all, fields(method = "list_devices"))]
    async fn list_devices(
        &self,
        request: Request<ListDevicesRequest>,
    ) -> Result<Response<ListDevicesResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(
            self.identity
                .list_devices(&caller, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "get_device"))]
    async fn get_device(
        &self,
        request: Request<GetDeviceRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller = self.caller(&request).await?;
        answered(
            self.identity
                .get_device(&caller, request.into_inner())
                .await,
        )
    }

    #[instrument(skip_all, fields(method = "update_device"))]
    async fn update_device(
        &self,
        request: Request<UpdateDeviceRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller = self.caller(&request).await?;
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .update_device(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "remove_device"))]
    async fn remove_device(
        &self,
        request: Request<RemoveDeviceRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .remove_device(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "trust_device"))]
    async fn trust_device(
        &self,
        request: Request<TrustDeviceRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller = self.caller(&request).await?;
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .trust_device(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "revoke_device_trust"))]
    async fn revoke_device_trust(
        &self,
        request: Request<RevokeDeviceTrustRequest>,
    ) -> Result<Response<sid_proto::sid::v1::Device>, Status> {
        let caller = self.caller(&request).await?;
        let (operation, refused) = deferred_context(&request);
        deferred(
            self.identity
                .revoke_device_trust(&caller, operation, request.into_inner())
                .await,
            refused,
        )
    }

    #[instrument(skip_all, fields(method = "get_current_profile"))]
    async fn get_current_profile(
        &self,
        request: Request<GetCurrentProfileRequest>,
    ) -> Result<Response<GetProfileResponse>, Status> {
        let caller = self.caller(&request).await?;
        answered(self.identity.current_profile(&caller).await)
    }
}

#[cfg(test)]
mod tests;
