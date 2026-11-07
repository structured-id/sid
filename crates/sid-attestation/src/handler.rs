// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AttestationService over the engine's device keys
//! ([`sid::devices::DeviceKeys`]). It is served only behind its receiver
//! (`crate::access`), which admits each call and asks the issuer whether its
//! token is current before it reaches a handler; the issuer decides what a
//! caller may do on a device it does not own.

use sid::devices::{DeviceAccess, DeviceKeyError, DeviceKeys, KeyCaller};
use sid_core::models::{OperationContext, SessionId};
use sid_infra::authn::operation::context;
use sid_infra::authn::sign_in_refusal::{authentication_failed, ceremony_expired};
use sid_infra::grpc_error::refuse::{invalid_field, missing_field, not_found, storage_failure};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::attestation::attestation_service_server::AttestationService;
use sid_proto::sid::v1::attestation::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

/// The ceremony a refusal names.
const CEREMONY: &str = "device-key ceremony";

pub struct AttestationServiceImpl {
    storage: Arc<dyn StorageBackend>,
    keys: DeviceKeys,
}

/// The receiver's decision for one admitted call: the owner's own object,
/// or the issuer's answer for another.
struct ReceiverAccess<'r, T>(&'r mut Request<T>);

#[async_trait::async_trait]
impl<T: Send> DeviceAccess for ReceiverAccess<'_, T> {
    type Error = Status;

    async fn owner(&mut self) -> Result<(), Status> {
        sid_auth::receiver::allow_owner(self.0)
    }

    async fn may(&mut self, object: &str) -> Result<bool, Status> {
        match sid_auth::receiver::authorize_object(self.0, object).await {
            Ok(()) => Ok(true),
            Err(status) if status.code() == tonic::Code::PermissionDenied => Ok(false),
            Err(status) => Err(status),
        }
    }

    async fn require(&mut self, object: &str) -> Result<(), Status> {
        sid_auth::receiver::authorize_object(self.0, object).await
    }
}

/// The admitted call without its message, which the engine takes by value.
fn split<T>(request: Request<T>) -> (Request<()>, T) {
    let (metadata, extensions, message) = request.into_parts();
    (Request::from_parts(metadata, extensions, ()), message)
}

/// The call's operation context, or why it has none: the refusal answers
/// only where the operation requires the context.
fn deferred_context<T>(request: &Request<T>) -> (Option<OperationContext>, Option<Status>) {
    match context(request) {
        Ok(context) => (Some(context), None),
        Err(refused) => (None, Some(refused)),
    }
}

/// The answer to a refused or failed device key operation; a missing
/// operation context is answered with the context's own refusal.
fn refusal(e: DeviceKeyError<Status>, context: Option<Status>) -> Status {
    match e {
        DeviceKeyError::Access(status) => status,
        DeviceKeyError::Denied => ApiError::new(
            ErrorReason::InsufficientPermissions,
            "the caller may not perform this operation",
        )
        .into(),
        DeviceKeyError::Enrollment(refusal) => refusal.into_status(),
        DeviceKeyError::DeviceNotFound(id) => {
            not_found(ErrorReason::DeviceNotFound, "Device", id.to_string())
        }
        DeviceKeyError::NoAttestation(id) => not_found(
            ErrorReason::AttestationNotFound,
            "DeviceAttestation",
            id.to_string(),
        ),
        DeviceKeyError::AlreadyEnrolled(id) => ApiError::new(
            ErrorReason::AttestationAlreadyExists,
            "the device already has a key attestation; rotate its key instead",
        )
        .with_resource("DeviceAttestation", id.to_string())
        .into(),
        DeviceKeyError::CeremonyExpired => ceremony_expired(CEREMONY),
        DeviceKeyError::Changed => ApiError::new(
            ErrorReason::InvalidState,
            "the device's key changed since the ceremony started; start it again",
        )
        .with_precondition("CEREMONY_STATE", CEREMONY, "superseded")
        .into(),
        // A proof that does not prove the ceremony is answered as any failed
        // authentication, without saying which binding it missed.
        DeviceKeyError::Proof(_) => authentication_failed(),
        DeviceKeyError::MissingField(field) => missing_field(field),
        DeviceKeyError::InvalidField { field, reason } => invalid_field(field, reason),
        // Only a keyed call requires its context, and its context's refusal
        // is passed along with the error.
        DeviceKeyError::ContextRequired => context.unwrap_or_else(|| ApiError::internal().into()),
        DeviceKeyError::Operation(e) => e.into_status(),
        DeviceKeyError::Store(e) => storage_failure(e),
    }
}

impl AttestationServiceImpl {
    /// The service over `storage`, sealing pending ceremonies under `keys`.
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn sid_keys::KeyManager>) -> Self {
        Self {
            keys: DeviceKeys::new(storage.clone(), keys),
            storage,
        }
    }

    /// The caller of `request`: the Profile of the stored, live sign-in its
    /// token was issued from, never the token's subject, and that sign-in. A
    /// token of no sign-in (a client's own) has no Profile and owns no
    /// device.
    async fn caller<T>(&self, request: &Request<T>) -> Result<KeyCaller, Status> {
        let claims = sid_auth::receiver::owner_claims(request)?;
        let session = match SessionId::parse(&claims.sid) {
            Ok(id) => self
                .storage
                .get_session(id)
                .await
                .map_err(storage_failure)?
                .filter(|s| !s.is_expired()),
            Err(_) => None,
        };
        let profile = session.as_ref().map(|s| s.profile_id);
        Ok(KeyCaller {
            profile,
            session: session.map(|s| s.id),
            subject: claims.sub.clone(),
            interactive: profile.is_some() && claims.acr != sid_authn::caller::ACR_IMPERSONATION,
        })
    }
}

#[tonic::async_trait]
impl AttestationService for AttestationServiceImpl {
    #[instrument(skip_all, fields(method = "start_device_enrollment"))]
    async fn start_device_enrollment(
        &self,
        request: Request<StartDeviceEnrollmentRequest>,
    ) -> Result<Response<DeviceEnrollmentChallenge>, Status> {
        let caller = self.caller(&request).await?;
        // The ceremony binds the issuer whose sign-in authorized it.
        let issuer = sid_auth::receiver::owner_claims(&request)?.iss.clone();
        let (mut head, req) = split(request);
        self.keys
            .start_enrollment(&mut ReceiverAccess(&mut head), &caller, &issuer, req)
            .await
            .map(Response::new)
            .map_err(|e| refusal(e, None))
    }

    #[instrument(skip_all, fields(method = "finish_device_enrollment"))]
    async fn finish_device_enrollment(
        &self,
        request: Request<FinishDeviceEnrollmentRequest>,
    ) -> Result<Response<DeviceAttestation>, Status> {
        let caller = self.caller(&request).await?;
        let (operation, refused) = deferred_context(&request);
        let (mut head, req) = split(request);
        self.keys
            .finish_enrollment(&mut ReceiverAccess(&mut head), &caller, operation, req)
            .await
            .map(Response::new)
            .map_err(|e| refusal(e, refused))
    }

    #[instrument(skip_all, fields(method = "get_device_attestation"))]
    async fn get_device_attestation(
        &self,
        request: Request<GetDeviceAttestationRequest>,
    ) -> Result<Response<DeviceAttestation>, Status> {
        let caller = self.caller(&request).await?;
        let (mut head, req) = split(request);
        self.keys
            .get_attestation(&mut ReceiverAccess(&mut head), &caller, req)
            .await
            .map(Response::new)
            .map_err(|e| refusal(e, None))
    }

    #[instrument(skip_all, fields(method = "rotate_device_key"))]
    async fn rotate_device_key(
        &self,
        request: Request<RotateDeviceKeyRequest>,
    ) -> Result<Response<DeviceAttestation>, Status> {
        let caller = self.caller(&request).await?;
        let (operation, refused) = deferred_context(&request);
        let (mut head, req) = split(request);
        self.keys
            .rotate_key(&mut ReceiverAccess(&mut head), &caller, operation, req)
            .await
            .map(Response::new)
            .map_err(|e| refusal(e, refused))
    }

    #[instrument(skip_all, fields(method = "revoke_device_key"))]
    async fn revoke_device_key(
        &self,
        request: Request<RevokeDeviceKeyRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let (operation, refused) = deferred_context(&request);
        let (mut head, req) = split(request);
        self.keys
            .revoke_key(&mut ReceiverAccess(&mut head), &caller, operation, req)
            .await
            .map(Response::new)
            .map_err(|e| refusal(e, refused))
    }

    #[instrument(skip_all, fields(method = "list_device_attestations"))]
    async fn list_device_attestations(
        &self,
        request: Request<ListDeviceAttestationsRequest>,
    ) -> Result<Response<ListDeviceAttestationsResponse>, Status> {
        let caller = self.caller(&request).await?;
        let (mut head, req) = split(request);
        self.keys
            .list_attestations(&mut ReceiverAccess(&mut head), &caller, req)
            .await
            .map(Response::new)
            .map_err(|e| refusal(e, None))
    }
}

#[cfg(test)]
mod tests;
