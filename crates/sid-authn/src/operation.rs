// SPDX-License-Identifier: AGPL-3.0-only
//! Keyed commands over gRPC. A method that promises safe retry takes the
//! caller's operation key, answers a retry of a completed command with its
//! recorded result, and commits its completion with its effect.

use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{OperationCompletion, OperationKey};
use sid_plugin::storage::StorageBackend;
use tonic::Status;
use tonic::metadata::MetadataMap;

/// The metadata key carrying the operation key: the `Idempotency-Key` header
/// of draft-ietf-httpapi-idempotency-key-header §2, which gRPC metadata
/// names in lower case.
pub const OPERATION_KEY_HEADER: &str = "idempotency-key";

/// The operation key of a call to a method that requires one; a missing or
/// malformed key is refused before any effect.
#[allow(clippy::result_large_err)]
pub fn required_key(metadata: &MetadataMap) -> Result<OperationKey, Status> {
    let Some(value) = metadata.get(OPERATION_KEY_HEADER) else {
        return Err(ApiError::new(
            ErrorReason::RequiredFieldMissing,
            "this method requires an operation key",
        )
        .with_field_violation(OPERATION_KEY_HEADER, "required")
        .into());
    };
    value
        .to_str()
        .ok()
        .and_then(|v| OperationKey::parse(v).ok())
        .ok_or_else(|| {
            ApiError::new(
                ErrorReason::InvalidFieldValue,
                "the operation key is 1 to 255 visible ASCII characters",
            )
            .with_field_violation(OPERATION_KEY_HEADER, "malformed")
            .into()
        })
}

/// One logical command: the caller's key within its authorized namespace,
/// the method, and its significant inputs in a canonical encoding.
pub struct KeyedCommand {
    namespace: String,
    key: OperationKey,
    method: &'static str,
    inputs: Vec<u8>,
}

impl KeyedCommand {
    pub fn new(
        namespace: impl Into<String>,
        key: OperationKey,
        method: &'static str,
        inputs: Vec<u8>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key,
            method,
            inputs,
        }
    }

    /// The recorded result when this command already completed. The same key
    /// used for another method or other inputs is a conflict: a new command
    /// needs a new key.
    pub async fn completed(&self, storage: &dyn StorageBackend) -> Result<Option<Vec<u8>>, Status> {
        let record = storage
            .get_operation_result(&self.namespace, &self.key)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "operation result lookup failed");
                Status::from(ApiError::internal())
            })?;
        match record {
            None => Ok(None),
            Some(record) if record.matches(self.method, &self.inputs) => {
                Ok(Some(record.completion.result))
            }
            Some(_) => Err(ApiError::new(
                ErrorReason::OperationKeyConflict,
                "the operation key already names another command",
            )
            .into()),
        }
    }

    /// The completion to commit with the effect, answering retries with
    /// `result`.
    pub fn completion(&self, result: Vec<u8>) -> OperationCompletion {
        OperationCompletion::new(
            self.namespace.clone(),
            self.key.clone(),
            self.method,
            &self.inputs,
            result,
        )
    }

    /// After a commit refused as already completed: the result another
    /// attempt of this command committed.
    pub async fn committed_elsewhere(
        &self,
        storage: &dyn StorageBackend,
    ) -> Result<Vec<u8>, Status> {
        self.completed(storage).await?.ok_or_else(|| {
            ApiError::new(
                ErrorReason::OperationOutcomeUnknown,
                "retry the operation with the same key",
            )
            .into()
        })
    }
}

#[cfg(test)]
mod tests;
