// SPDX-License-Identifier: AGPL-3.0-only
//! Keyed commands over gRPC. A method that promises safe retry takes the
//! caller's operation key, answers a retry of a completed command with its
//! recorded result, and commits its completion with its effect.

use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{OperationCompletion, OperationKey};
use sid_plugin::OperationResultStore;
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
    pub async fn completed(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<Option<Vec<u8>>, Status> {
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

    /// Run this command once: a completed one answers with its recorded
    /// result; otherwise `effect` commits the mutation with
    /// [`Self::completion`] of its response, and a concurrent attempt that
    /// committed first answers with that attempt's result. Retries never
    /// apply the effect again.
    pub async fn run<T, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        effect: F,
    ) -> Result<T, Status>
    where
        T: prost::Message + Default,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect>>,
    {
        self.run_with(storage, decode, effect).await
    }

    /// [`Self::run`] for a mutation whose store records the state it leaves
    /// ([`sid_core::models::MutationContext::record_effect`]): `effect`
    /// passes the completion from [`Self::effect_completion`] and returns
    /// that state; a retry returns the state the first commit left.
    pub async fn run_recorded<T, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        effect: F,
    ) -> Result<T, Status>
    where
        T: serde::de::DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect>>,
    {
        self.run_with(storage, decode_recorded, effect).await
    }

    /// The completion of a mutation whose store records its effect as the
    /// result.
    pub fn effect_completion(&self) -> OperationCompletion {
        self.completion(Vec::new())
    }

    async fn run_with<T, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        decode: fn(&[u8]) -> Result<T, Status>,
        effect: F,
    ) -> Result<T, Status>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect>>,
    {
        if let Some(result) = self.completed(storage).await? {
            return decode(&result);
        }
        match effect().await {
            Ok(response) => Ok(response),
            Err(Effect::Store(sid_core::Error::OperationCompleted(_))) => {
                decode(&self.committed_elsewhere(storage).await?)
            }
            Err(Effect::Store(e)) => {
                tracing::warn!(method = self.method, error = %e, "keyed command not committed");
                Err(ApiError::internal().into())
            }
            Err(Effect::Refused(status)) => Err(status),
        }
    }

    /// After a commit refused as already completed: the result another
    /// attempt of this command committed.
    pub async fn committed_elsewhere(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
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

/// Why a keyed command's effect did not commit.
pub enum Effect {
    /// Refused before or by the commit, answered as is.
    Refused(Status),
    /// The store's failure; an already completed key is resolved to its
    /// recorded result.
    Store(sid_core::Error),
}

impl From<Status> for Effect {
    fn from(status: Status) -> Self {
        Self::Refused(status)
    }
}

impl From<sid_core::Error> for Effect {
    fn from(e: sid_core::Error) -> Self {
        Self::Store(e)
    }
}

/// A recorded result, decoded as the method's response.
#[allow(clippy::result_large_err)]
fn decode<T: prost::Message + Default>(result: &[u8]) -> Result<T, Status> {
    T::decode(result).map_err(|e| {
        tracing::error!(error = %e, "recorded operation result unreadable");
        Status::from(ApiError::internal())
    })
}

/// A result its store recorded from the effect, decoded.
#[allow(clippy::result_large_err)]
fn decode_recorded<T: serde::de::DeserializeOwned>(result: &[u8]) -> Result<T, Status> {
    serde_json::from_slice(result).map_err(|e| {
        tracing::error!(error = %e, "recorded operation result unreadable");
        Status::from(ApiError::internal())
    })
}

#[cfg(test)]
mod tests;
