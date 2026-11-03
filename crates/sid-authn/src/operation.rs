// SPDX-License-Identifier: AGPL-3.0-only
//! Keyed commands. A method that promises safe retry is called with the
//! caller's operation context, answers a retry of a completed command with
//! its recorded result, and commits its completion with its effect. This
//! core takes no transport; [`grpc`] reads the context from a call and turns
//! [`OperationError`] into its status.

use sid_core::models::{
    OperationCompletion, OperationContext, OperationKey, OperationPeriod, OperationPeriodRefusal,
};
use sid_plugin::OperationResultStore;
use sid_proto::KeyedMethod;

#[cfg(feature = "grpc")]
pub mod grpc;

/// Why a keyed command answered with no result of its own.
#[derive(Debug, thiserror::Error)]
pub enum OperationError {
    /// The key already names another command: another method, other inputs
    /// or another period. A new command needs a new key.
    #[error("the operation key already names another command")]
    KeyConflict,
    /// The store does not admit the command's period; nothing was committed.
    #[error("operation period {0}")]
    PeriodRefused(OperationPeriodRefusal),
    /// Another attempt committed the command and its record could not be
    /// read back: the caller retries with the same context.
    #[error("the command's outcome is unknown")]
    OutcomeUnknown,
    /// The store failed.
    #[error("operation store: {0}")]
    Store(sid_core::Error),
    /// A recorded result could not be decoded as the method's response.
    #[error("recorded operation result unreadable")]
    ResultUnreadable,
}

/// One logical command: the caller's key (and, for a keyed method, the
/// period it was named with) within its authorized namespace, the method,
/// and its significant inputs in a canonical encoding.
#[derive(Debug)]
pub struct KeyedCommand {
    namespace: String,
    key: OperationKey,
    period: Option<OperationPeriod>,
    method: &'static str,
    inputs: Vec<u8>,
}

impl KeyedCommand {
    /// The command of keyed method `M` named by `context` within
    /// `namespace`, with `request` as its inputs.
    pub fn of<M: KeyedMethod>(
        namespace: impl Into<String>,
        context: OperationContext,
        request: &M::Request,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: context.key,
            period: Some(context.period),
            method: M::METHOD,
            inputs: prost::Message::encode_to_vec(request),
        }
    }

    /// [`Self::of`] for `profile`: one key namespace per authenticated
    /// Profile, whatever service it calls.
    pub fn by_profile<M: KeyedMethod>(
        profile: sid_core::models::ProfileId,
        context: OperationContext,
        request: &M::Request,
    ) -> Self {
        Self::of::<M>(format!("profile:{profile}"), context, request)
    }

    /// The record a ceremony keeps of its own operation `key` of `method`
    /// with `inputs`: named by the ceremony, under no period.
    pub fn ceremony(
        namespace: impl Into<String>,
        key: OperationKey,
        method: &'static str,
        inputs: Vec<u8>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key,
            period: None,
            method,
            inputs,
        }
    }

    /// The recorded result when this command already completed. The same key
    /// used for another method, other inputs or another period is a
    /// conflict.
    pub async fn completed(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<Option<Vec<u8>>, OperationError> {
        let record = storage
            .get_operation_result(&self.namespace, &self.key)
            .await
            .map_err(OperationError::Store)?;
        match record {
            // A new command: its period is admitted before any effect, those
            // a method makes before its commit included.
            None => {
                if let Some(period) = self.period {
                    storage
                        .admit_operation_period(period)
                        .await
                        .map_err(|e| match e {
                            sid_core::Error::OperationPeriodRefused(refusal) => {
                                OperationError::PeriodRefused(refusal)
                            }
                            e => OperationError::Store(e),
                        })?;
                }
                Ok(None)
            }
            Some(record) if record.matches(self.method, &self.inputs, self.period) => {
                Ok(Some(record.completion.result))
            }
            Some(_) => Err(OperationError::KeyConflict),
        }
    }

    /// The response a completed command recorded, for a method whose checks
    /// before the effect would refuse its own retry (a creation whose new
    /// record now holds the name it checks).
    pub async fn replay<T: prost::Message + Default>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<Option<T>, OperationError> {
        self.completed(storage)
            .await?
            .map(|result| decode(&result))
            .transpose()
    }

    /// The completion to commit with the effect, answering retries with
    /// `result`.
    pub fn completion(&self, result: Vec<u8>) -> OperationCompletion {
        let completion = OperationCompletion::new(
            self.namespace.clone(),
            self.key.clone(),
            self.method,
            &self.inputs,
            result,
        );
        match self.period {
            Some(period) => completion.in_period(period),
            None => completion,
        }
    }

    /// Run this command once: a completed one answers with its recorded
    /// result; otherwise `effect` commits the mutation with
    /// [`Self::completion`] of its response, and a concurrent attempt that
    /// committed first answers with that attempt's result. Retries never
    /// apply the effect again. A refusal `E` is answered as is; `run` in
    /// [`grpc`] is this with a status.
    pub async fn execute<T, E, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        effect: F,
    ) -> Result<T, E>
    where
        T: prost::Message + Default,
        E: From<OperationError>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect<E>>>,
    {
        self.run_with(storage, decode, effect).await
    }

    /// [`Self::execute`] for a mutation whose store records the state it
    /// leaves ([`sid_core::models::MutationContext::record_effect`]): `effect`
    /// passes the completion from [`Self::effect_completion`] and returns
    /// that state; a retry returns the state the first commit left.
    pub async fn execute_recorded<T, E, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        effect: F,
    ) -> Result<T, E>
    where
        T: serde::de::DeserializeOwned,
        E: From<OperationError>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect<E>>>,
    {
        self.run_with(storage, decode_recorded, effect).await
    }

    /// This command when it changes nothing: the response `current` reads is
    /// its outcome, recorded alone with `audit`, so a retry after a later
    /// change answers the same and changes nothing. A completed command
    /// answers with its recorded result before anything is read, a
    /// concurrent attempt that recorded first with that attempt's, and a key
    /// or period the rules refuse is refused here too.
    pub async fn unchanged<T, E, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        audit: sid_core::models::AuditEntry,
        current: F,
    ) -> Result<T, E>
    where
        T: prost::Message + Default,
        E: From<OperationError>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        if let Some(result) = self.completed(storage).await? {
            return Ok(decode(&result)?);
        }
        let response = current().await?;
        let ctx = sid_core::models::MutationContext::from(audit)
            .with_operation(self.completion(response.encode_to_vec()));
        match storage.record_outcome(ctx).await {
            Ok(()) => Ok(response),
            Err(e) => Ok(decode(&self.not_committed(storage, e).await?)?),
        }
    }

    /// [`Self::unchanged`] for a method answering with the state its store
    /// records ([`Self::execute_recorded`]): the state `current` reads is
    /// recorded as is.
    pub async fn unchanged_recorded<T, E, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        audit: sid_core::models::AuditEntry,
        current: F,
    ) -> Result<T, E>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
        E: From<OperationError>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        if let Some(result) = self.completed(storage).await? {
            return Ok(decode_recorded(&result)?);
        }
        let state = current().await?;
        let mut ctx =
            sid_core::models::MutationContext::from(audit).with_operation(self.effect_completion());
        ctx.record_effect(&state).map_err(OperationError::Store)?;
        match storage.record_outcome(ctx).await {
            Ok(()) => Ok(state),
            Err(e) => Ok(decode_recorded(&self.not_committed(storage, e).await?)?),
        }
    }

    /// After this command's commit, the state its store recorded in that
    /// commit ([`sid_core::models::MutationContext::record_effect`]): the
    /// answer, never a state read before or after it.
    pub async fn recorded_effect<T: serde::de::DeserializeOwned>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<T, OperationError> {
        decode_recorded(&self.committed_elsewhere(storage).await?)
    }

    /// The completion of a mutation whose store records its effect as the
    /// result.
    pub fn effect_completion(&self) -> OperationCompletion {
        self.completion(Vec::new())
    }

    async fn run_with<T, E, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        decode: fn(&[u8]) -> Result<T, OperationError>,
        effect: F,
    ) -> Result<T, E>
    where
        E: From<OperationError>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect<E>>>,
    {
        if let Some(result) = self.completed(storage).await? {
            return Ok(decode(&result)?);
        }
        match effect().await {
            Ok(response) => Ok(response),
            // Another attempt's result is answered as this one's.
            Err(Effect::Store(e)) => Ok(decode(&self.not_committed(storage, e).await?)?),
            // A refusal caused by a concurrent attempt of this command that
            // committed first (a limit counted before the key) is that
            // attempt's result; any other refusal is answered as is.
            Err(Effect::Refused(refusal)) => match self.completed(storage).await {
                Ok(Some(result)) => Ok(decode(&result)?),
                _ => Err(refusal),
            },
        }
    }

    /// Why a commit of this command failed in its store: an already
    /// completed key resolves to the result another attempt committed.
    async fn not_committed(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        error: sid_core::Error,
    ) -> Result<Vec<u8>, OperationError> {
        match error {
            sid_core::Error::OperationCompleted(_) => self.committed_elsewhere(storage).await,
            sid_core::Error::OperationPeriodRefused(refusal) => {
                Err(OperationError::PeriodRefused(refusal))
            }
            e => {
                tracing::warn!(method = self.method, error = %e, "keyed command not committed");
                Err(OperationError::Store(e))
            }
        }
    }

    /// After a commit refused as already completed: the result another
    /// attempt of this command committed.
    pub async fn committed_elsewhere(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<Vec<u8>, OperationError> {
        self.completed(storage)
            .await?
            .ok_or(OperationError::OutcomeUnknown)
    }
}

/// Why a keyed command's effect did not commit.
pub enum Effect<E> {
    /// Refused before or by the commit, answered as is.
    Refused(E),
    /// The store's failure; an already completed key is resolved to its
    /// recorded result.
    Store(sid_core::Error),
}

impl<E> From<sid_core::Error> for Effect<E> {
    fn from(e: sid_core::Error) -> Self {
        Self::Store(e)
    }
}

/// A recorded result, decoded as the method's response.
fn decode<T: prost::Message + Default>(result: &[u8]) -> Result<T, OperationError> {
    T::decode(result).map_err(|e| {
        tracing::error!(error = %e, "recorded operation result unreadable");
        OperationError::ResultUnreadable
    })
}

/// A result its store recorded from the effect, decoded.
fn decode_recorded<T: serde::de::DeserializeOwned>(result: &[u8]) -> Result<T, OperationError> {
    serde_json::from_slice(result).map_err(|e| {
        tracing::error!(error = %e, "recorded operation result unreadable");
        OperationError::ResultUnreadable
    })
}

#[cfg(test)]
mod tests;
