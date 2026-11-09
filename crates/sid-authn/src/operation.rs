// SPDX-License-Identifier: AGPL-3.0-only
//! Keyed commands. A method that promises safe retry is called with the
//! caller's operation context, answers a retry of a completed command with
//! its recorded result, and commits its completion with its effect. This
//! core takes no transport: an adapter reads the context from a call and
//! answers [`CommandError`] in its protocol.

use sid_core::models::{
    OperationCompletion, OperationContext, OperationKey, OperationPeriod, OperationPeriodRefusal,
};
use sid_plugin::OperationResultStore;
use sid_proto::KeyedMethod;

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
    /// The commit needed room the store does not have (a completion this
    /// large, another in a full period, more owed work): nothing was
    /// committed. A new command needs a new key.
    #[error("capacity exhausted: {0}")]
    Exhausted(String),
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

    /// [`Self::of`] for a method whose significant inputs are not its
    /// request's encoding: `inputs`, its own canonical encoding of them (a
    /// set given in any order is one command).
    pub fn of_inputs<M: KeyedMethod>(
        namespace: impl Into<String>,
        context: OperationContext,
        inputs: Vec<u8>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: context.key,
            period: Some(context.period),
            method: M::METHOD,
            inputs,
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

    /// The identifier of the resource this command creates, allocated in its
    /// domain format (UUIDv7) and bound to the command in the owning store,
    /// the same for every attempt of it: a creation committed in several
    /// steps (a tenant schema beside its record) resumes under it after a lost
    /// reply instead of creating a second one. The binding is durable before
    /// the caller's first effect outside `storage`; it proves neither that the
    /// creation finished nor who executes it. The key bound or completed for
    /// another call is [`OperationError::KeyConflict`].
    pub async fn resource_id(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<uuid::Uuid, OperationError> {
        Ok(self.bind(storage).await?.1)
    }

    /// Whether this attempt is the command's first, for a command whose
    /// effect lies outside `storage` (a message a provider accepts): the
    /// first attempt binds the command durably before that effect, and every
    /// later one, concurrent or after a lost reply, finds the binding. A
    /// later attempt without a recorded completion cannot know whether the
    /// first made its effect and must not make it again.
    pub async fn first_attempt(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<bool, OperationError> {
        let (proposed, bound) = self.bind(storage).await?;
        Ok(proposed == bound)
    }

    /// Bind this command to a fresh identifier: the one proposed and the one
    /// the store holds for it.
    async fn bind(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
    ) -> Result<(uuid::Uuid, uuid::Uuid), OperationError> {
        let proposal = sid_core::models::OperationResourceBinding {
            namespace: self.namespace.clone(),
            key: self.key.clone(),
            method: self.method.to_string(),
            fingerprint: sid_core::models::operation::fingerprint(&self.inputs),
            period: self.period,
            resource: uuid::Uuid::now_v7(),
        };
        let bound = storage
            .bind_operation_resource(&proposal)
            .await
            .map_err(|e| match e {
                sid_core::Error::OperationKeyReused(_) => OperationError::KeyConflict,
                sid_core::Error::OperationPeriodRefused(refusal) => {
                    OperationError::PeriodRefused(refusal)
                }
                e => OperationError::Store(e),
            })?;
        Ok((proposal.resource, bound))
    }

    /// A correlation key of this command, the same for every attempt of it,
    /// for records the command names internally (an issuance it asks another
    /// component for). Never the identifier of a resource it creates, which
    /// is [`Self::resource_id`]. A name-based UUID of the command (RFC 9562
    /// 5.5), so it reveals neither the caller nor the key.
    pub fn command_id(&self) -> uuid::Uuid {
        /// The UUID namespace of keyed command names.
        const COMMANDS: uuid::Uuid = uuid::uuid!("0192f3a4-7c1e-7b2a-9d4e-6b1f0c2d3e4f");
        let mut name = Vec::new();
        for part in [
            self.namespace.as_bytes(),
            self.key.as_str().as_bytes(),
            self.method.as_bytes(),
        ] {
            name.extend_from_slice(&(part.len() as u64).to_be_bytes());
            name.extend_from_slice(part);
        }
        name.extend_from_slice(&self.period.map_or(0, OperationPeriod::get).to_be_bytes());
        uuid::Uuid::new_v5(&COMMANDS, &name)
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

    /// `answer`, this command's outcome as a handler reached it after its
    /// first completion lookup, with a refusal resolved: when a concurrent
    /// attempt of this command completed meanwhile (its effect being what
    /// this attempt was refused for: a value it took, a state it moved on, a
    /// record it removed), that attempt's recorded answer is this one's; when
    /// another command completed under the key meanwhile, the key conflicts.
    pub async fn settle<T, E>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        answer: Result<T, E>,
    ) -> Result<T, CommandError<E>>
    where
        T: prost::Message + Default,
    {
        match answer {
            Ok(answer) => Ok(answer),
            Err(refusal) => match self.replay::<T>(storage).await {
                Ok(Some(recorded)) => Ok(recorded),
                Err(OperationError::KeyConflict) => {
                    Err(CommandError::Operation(OperationError::KeyConflict))
                }
                _ => Err(CommandError::Refused(refusal)),
            },
        }
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
    /// apply the effect again. A refusal `E` is answered as is.
    pub async fn execute<T, E, F, Fut>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        effect: F,
    ) -> Result<T, CommandError<E>>
    where
        T: prost::Message + Default,
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
    ) -> Result<T, CommandError<E>>
    where
        T: serde::de::DeserializeOwned,
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
    ) -> Result<T, CommandError<E>>
    where
        T: prost::Message + Default,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        if let Some(result) = self.completed(storage).await? {
            return Ok(decode(&result)?);
        }
        let response = current().await.map_err(CommandError::Refused)?;
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
    ) -> Result<T, CommandError<E>>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        if let Some(result) = self.completed(storage).await? {
            return Ok(decode_recorded(&result)?);
        }
        let state = current().await.map_err(CommandError::Refused)?;
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
    ) -> Result<T, CommandError<E>>
    where
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
            Err(Effect::Refused(refusal)) => {
                self.refused(storage, decode, CommandError::Refused(refusal))
                    .await
            }
            Err(Effect::Operation(e)) => {
                self.refused(storage, decode, CommandError::Operation(e))
                    .await
            }
        }
    }

    /// An effect's `refusal`, unless a concurrent attempt of this command
    /// committed meanwhile: then that attempt's result.
    async fn refused<T, E>(
        &self,
        storage: &(impl OperationResultStore + ?Sized),
        decode: fn(&[u8]) -> Result<T, OperationError>,
        refusal: CommandError<E>,
    ) -> Result<T, CommandError<E>> {
        match self.completed(storage).await {
            Ok(Some(result)) => Ok(decode(&result)?),
            _ => Err(refusal),
        }
    }

    /// Why a commit of this command failed in its store: an already
    /// completed key resolves to the result another attempt committed, and so
    /// does any other failure that attempt's effect caused before the key was
    /// reached (a unique value it took, a revision it moved on).
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
            sid_core::Error::ResourceExhausted(why) => Err(OperationError::Exhausted(why)),
            e => match self.completed(storage).await {
                Ok(Some(result)) => Ok(result),
                _ => {
                    tracing::warn!(method = self.method, error = %e, "keyed command not committed");
                    Err(OperationError::Store(e))
                }
            },
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
    /// Refused by a keyed command the effect ran itself (another command's
    /// key it resolved), answered as that command's refusal.
    Operation(OperationError),
    /// The store's failure; an already completed key is resolved to its
    /// recorded result.
    Store(sid_core::Error),
}

impl<E> From<sid_core::Error> for Effect<E> {
    fn from(e: sid_core::Error) -> Self {
        Self::Store(e)
    }
}

impl<E> From<OperationError> for Effect<E> {
    fn from(e: OperationError) -> Self {
        Self::Operation(e)
    }
}

/// Why a keyed command answered with no result of its own: its effect's
/// refusal `E`, or the command's own.
#[derive(Debug)]
pub enum CommandError<E> {
    Refused(E),
    Operation(OperationError),
}

impl<E> From<OperationError> for CommandError<E> {
    fn from(e: OperationError) -> Self {
        Self::Operation(e)
    }
}

impl<E: From<OperationError>> CommandError<E> {
    /// The refusal, in a vocabulary that also names the command's own.
    pub fn refusal(self) -> E {
        match self {
            Self::Refused(e) => e,
            Self::Operation(e) => e.into(),
        }
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

/// One round of a store's upkeep at `now`: completions past their retention
/// are dropped, and periods whose retention after their acceptance end
/// passed, under the store's persisted policy, are retired with their
/// completions. Both are idempotent and serialized in the store, so every
/// replica of a host runs this, about once a minute, under no job lock.
/// Returns how many periods were retired.
pub async fn upkeep(
    store: &(impl OperationResultStore + ?Sized),
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    if let Err(e) = store.purge_expired_operation_results(now).await {
        tracing::warn!(error = %e, "operation result expiry failed");
    }
    let retired = async {
        let policy = store.operation_period_policy().await?;
        let before = now
            .checked_sub_signed(policy.retention)
            .ok_or_else(|| sid_core::Error::Internal("operation period retention".into()))?;
        store.retire_operation_periods(before).await
    };
    match retired.await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "operation period retirement failed");
            0
        }
    }
}

#[cfg(test)]
mod tests;
