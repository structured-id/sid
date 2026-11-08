// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AttestationService over the engine's device keys
//! ([`sid::devices::DeviceKeys`]). It is served only behind its receiver
//! (`crate::access`), which admits each call and asks the issuer whether its
//! token is current before it reaches a handler; the issuer decides what a
//! caller may do on a device it does not own.

use sid::devices::{DeviceAccess, DeviceKeyError, DeviceKeys, KeyCaller};
use sid_core::models::SessionId;
use sid_infra::grpc_error::refuse::{invalid_field, missing_field, not_found, storage_failure};
use sid_infra::grpc_error::{ApiError, ErrorReason};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::attestation::attestation_service_server::AttestationService;
use sid_proto::sid::v1::attestation::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

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

/// The answer to a refused or failed device key operation.
fn refusal(e: DeviceKeyError<Status>) -> Status {
    match e {
        DeviceKeyError::Access(status) => status,
        DeviceKeyError::Denied => ApiError::new(
            ErrorReason::InsufficientPermissions,
            "the caller may not perform this operation",
        )
        .into(),
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
        DeviceKeyError::MissingField(field) => missing_field(field),
        DeviceKeyError::InvalidId(field) => invalid_field(field, "not an identifier of its kind"),
        DeviceKeyError::Store(e) => storage_failure(e),
    }
}

impl AttestationServiceImpl {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            keys: DeviceKeys::new(storage.clone()),
            storage,
        }
    }

    /// The caller of `request`: the Profile of the stored, live sign-in its
    /// token was issued from, never the token's subject. A token of no
    /// sign-in (a client's own) has no Profile and owns no device.
    async fn caller<T>(&self, request: &Request<T>) -> Result<KeyCaller, Status> {
        let claims = sid_auth::receiver::owner_claims(request)?;
        let profile = match SessionId::parse(&claims.sid) {
            Ok(id) => self
                .storage
                .get_session(id)
                .await
                .map_err(storage_failure)?
                .filter(|s| !s.is_expired())
                .map(|s| s.profile_id),
            Err(_) => None,
        };
        Ok(KeyCaller {
            profile,
            subject: claims.sub.clone(),
            interactive: profile.is_some() && claims.acr != sid_authn::caller::ACR_IMPERSONATION,
        })
    }
}

#[tonic::async_trait]
impl AttestationService for AttestationServiceImpl {
    #[instrument(skip_all, fields(method = "register_device_key"))]
    async fn register_device_key(
        &self,
        request: Request<RegisterDeviceKeyRequest>,
    ) -> Result<Response<DeviceAttestation>, Status> {
        let caller = self.caller(&request).await?;
        let (mut head, req) = split(request);
        self.keys
            .register_key(&mut ReceiverAccess(&mut head), &caller, req)
            .await
            .map(Response::new)
            .map_err(refusal)
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
            .map_err(refusal)
    }

    #[instrument(skip_all, fields(method = "rotate_device_key"))]
    async fn rotate_device_key(
        &self,
        request: Request<RotateDeviceKeyRequest>,
    ) -> Result<Response<DeviceAttestation>, Status> {
        let caller = self.caller(&request).await?;
        let (mut head, req) = split(request);
        self.keys
            .rotate_key(&mut ReceiverAccess(&mut head), &caller, req)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, fields(method = "revoke_device_key"))]
    async fn revoke_device_key(
        &self,
        request: Request<RevokeDeviceKeyRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let (mut head, req) = split(request);
        self.keys
            .revoke_key(&mut ReceiverAccess(&mut head), &caller, req)
            .await
            .map(Response::new)
            .map_err(refusal)
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
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
