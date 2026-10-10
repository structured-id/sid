// SPDX-License-Identifier: AGPL-3.0-only
//! One password-installing operation, shared by registration, password change
//! and authorized reset:
//!
//! - **prepare**: the purpose's own authorized step starts the operation from
//!   the owner's history snapshot; the history evaluator admits it and
//!   selects its comparison domains, answering with the public description
//!   of each one's epoch;
//! - **evaluate**: the VOPRF evaluator answers the blinded history input,
//!   charged before any key is used, once per operation;
//! - **OPAQUE**: the operation's registration request and its response, under
//!   the OPRF key of the credential the operation installs;
//! - **finish**: proof verification, the evaluator's proofs the client relays
//!   and the history check run outside any database transaction, then the
//!   purpose commits the credential, its evidence, the accepted history entry
//!   with its epochs' descriptions and the operation's durable result
//!   together.
//!
//! Two authorities, each with its own record of the operation and nothing
//! secret in common:
//!
//! - the credential service ([`PasswordOperations`]) prepares, starts and
//!   finishes the operation and runs the history checker. Its record (owner,
//!   purpose, current-password confirmation, the selected epochs'
//!   descriptions) is sealed with its own keys; it reads retained entries and
//!   the proof's tags, and holds no history key;
//! - the history evaluator ([`HistoryEvaluation`]) admits the operation,
//!   selects its epochs, creating or replacing the owner's key, and evaluates
//!   the blinded input. Its record (admission, selection, evaluation) is
//!   sealed with its own keys and its keys live in its own store; it knows
//!   the owner only by the history input domain and never reads an entry, a
//!   tag or the credential service's record.
//!
//! The client relays the evaluator's proofs with the finish; the checker
//! verifies them against the registration proof's own blinded input and
//! evaluated elements, so the finish needs no evaluator read. A standalone
//! installation runs both authorities in one process, so compromising that
//! process merges them. A split deployment runs the evaluator as its own
//! service ([`PasswordHistoryEvaluatorImpl`], with the deployment's own
//! [`PrepareAdmission`]) and the credential service reaches it through
//! [`RemoteHistoryEvaluator`].
//!
//! Every credential has its own OPRF key (`credential_identifier`, drawn at
//! prepare and stored with the credential). Before the commit that key has
//! evaluated exactly one element, the request the proof is bound to. This
//! prevents borrowing another operation's OPRF evaluation. Supported clients
//! derive their final record with the prescribed KSF; this input binding is
//! not a proof of the final record's client-side derivation.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::operation::KeyedCommand;
use sid_authn::password_history::{
    CheckRequest, EpochPolicy, HistoryCheckError, HistoryChecker, HistoryEvaluator,
    OperationDomain, OperationEvaluation, RelayedProof, decoy_epoch, owner_domain, verify_inputs,
};
use sid_core::grpc_error::refuse::invalid_field;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::password_history::DEFAULT_HISTORY_DEPTH;
use sid_core::models::password_history::MAX_HISTORY_DOMAINS;
use sid_core::models::{
    AuditEntry, Credential, CredentialId, CredentialType, EnrollmentAdmission, EnrollmentCleanup,
    HistoryCommit, HistoryEpochDescriptor, HistoryEpochId, HistoryEvidence, HistoryKsf,
    HistoryLiveSet, HistorySuite, KeyEpochs, OperationCompletion, OperationKey, PasswordHistory,
    PolicyEvidence, ProfileId, ResetSessionId,
};
use sid_ids::PasswordOperationId;
use sid_pake_core::prover::BoundProof;
use sid_pake_core::types::ZkppProof;
use sid_plugin::cache::CacheBackend;
use sid_plugin::crypto::{CurveId, LoginState};
use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::authn::password_history_evaluator_service_client::PasswordHistoryEvaluatorServiceClient;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorService;
use sid_proto::sid::v1::authn::{
    EvaluatePasswordHistoryRequest, EvaluatePasswordHistoryResponse, PasswordHistoryContext,
    PasswordHistoryDomain, PasswordHistoryEpochDescriptor, PasswordHistoryEvaluation,
    PasswordHistoryEvaluationProof, PasswordHistoryKsf, PasswordHistoryOwnerKind,
    PasswordRegistrationProof, PreparePasswordHistoryRequest, PreparePasswordHistoryResponse,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::{Request, Response, Status};
use tracing::warn;

use super::auth_service::PendingRegistration;

/// How long a prepared operation waits for its next step. Covers proving on
/// a weak device (tens of seconds) with room for the user.
const OPERATION_TTL: Duration = Duration::from_secs(15 * 60);
/// How far the credential service's clock may run ahead of the evaluator's
/// when it sets an admission's expiry.
const ADMISSION_CLOCK_SKEW: Duration = Duration::from_secs(60);
/// History evaluations one subject may be charged per window.
const EVALUATIONS_PER_WINDOW: u64 = 30;
const EVALUATION_WINDOW: Duration = Duration::from_secs(60 * 60);
/// How long a finish waits for KSF memory before reporting unavailable.
const KSF_WAIT: Duration = Duration::from_secs(10);
/// Concurrent KSF memory one replica admits, MiB.
const KSF_BUDGET_MIB: u32 = 512;
/// Namespace of the operations' durable results.
const RESULT_NAMESPACE: &str = "password-operation";
/// Longest charge key the evaluator admits (`PreparePasswordHistoryRequest.charge_key`).
const MAX_CHARGE_KEY: usize = 128;
/// First enrollments admitted and not yet ended (committed, or aborted and
/// their key reclaimed), across replicas. Past it a new registration is
/// refused before the evaluator makes a key, so an outage of the cleanup
/// becomes backpressure rather than unbounded key storage.
const ENROLLMENT_CAPACITY: u64 = 100_000;

mod enrollment;
pub(crate) use enrollment::{EnrollmentDelivery, EnrollmentHandler};

/// What the operation installs a password for, and the authority it rests on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum OperationPurpose {
    /// A self-registration; an existing identifier's start is a decoy that
    /// commits nothing.
    Registration { pending: PendingRegistration },
    /// A password change of the caller's own credential.
    Change {
        profile_id: ProfileId,
        credential_id: CredentialId,
        /// The OPRF credential identifier of the password the change began
        /// on: each password has its own, so it names that version.
        password: [u8; 16],
    },
    /// A reset under a verified reset session.
    Reset { session: ResetSessionId },
}

impl OperationPurpose {
    /// The method name of the operation's durable result.
    fn method(&self) -> &'static str {
        match self {
            Self::Registration { .. } => "registration",
            Self::Change { .. } => "change",
            Self::Reset { .. } => "reset",
        }
    }
}

/// Whose history an operation is compared against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OwnerKind {
    /// An existing profile: its stored history applies.
    Existing,
    /// A profile the operation creates: it starts its own history.
    New,
    /// A registration start for an identifier someone holds: it behaves like
    /// any other and commits nothing.
    Decoy,
}

impl OwnerKind {
    fn message(self) -> PasswordHistoryOwnerKind {
        match self {
            Self::Existing => PasswordHistoryOwnerKind::Existing,
            Self::New => PasswordHistoryOwnerKind::New,
            Self::Decoy => PasswordHistoryOwnerKind::Decoy,
        }
    }

    fn of_message(kind: i32) -> Option<Self> {
        match PasswordHistoryOwnerKind::try_from(kind).ok()? {
            PasswordHistoryOwnerKind::Existing => Some(Self::Existing),
            PasswordHistoryOwnerKind::New => Some(Self::New),
            PasswordHistoryOwnerKind::Decoy => Some(Self::Decoy),
            PasswordHistoryOwnerKind::Unspecified => None,
        }
    }
}

/// A prepared operation between its steps, as the credential service keeps
/// it. Holds nothing of the evaluator's: no key, no evaluation.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PendingOperation {
    pub id: PasswordOperationId,
    pub purpose: OperationPurpose,
    /// The credential owner; random for a decoy.
    pub owner: ProfileId,
    pub kind: OwnerKind,
    pub owner_domain: [u8; 32],
    /// The public description of each comparison domain's epoch, as the
    /// evaluator selected them, the operation's active epoch first. The
    /// domains the client proves over follow from them.
    pub epochs: Vec<HistoryEpochDescriptor>,
    /// The owner's history revision the selection was made at.
    pub history_revision: i64,
    pub policy_version: u32,
    /// The OPRF credential identifier of the password this operation installs:
    /// the key under which its registration request is evaluated and, once
    /// committed, its logins are.
    pub credential_identifier: [u8; 16],
    /// The operation's OPAQUE registration request, once sent.
    pub registration_request: Option<Vec<u8>>,
    /// A change's sign-in with the current password.
    #[serde(default)]
    pub current_password: CurrentPassword,
}

/// What execute's KE3 established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CurrentPasswordCheck {
    /// The change proved the current password.
    Proven,
    /// The change began no sign-in and sent no KE3.
    NotBegun,
    /// KE3 did not verify: a wrong current password.
    Failed,
}

/// Where a change's sign-in with the current password stands.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) enum CurrentPassword {
    /// The change did not begin one.
    #[default]
    Absent,
    /// Begun in the challenge: the server's OPAQUE state awaiting KE3.
    Started(LoginState),
    /// KE3 verified: the change authenticated with the current password.
    Proven,
}

impl PendingOperation {
    /// Whether the operation authenticated with the current password.
    pub fn current_password_proven(&self) -> bool {
        matches!(self.current_password, CurrentPassword::Proven)
    }

    /// The operation's comparison domains, in proof order.
    pub fn domains(&self) -> Vec<OperationDomain> {
        self.epochs.iter().map(OperationDomain::of).collect()
    }

    /// The durable-result command of this operation's finish with `record`.
    fn finish_command(&self, record: &[u8]) -> KeyedCommand {
        finish_command(&self.id, self.purpose.method(), record)
    }
}

/// Purpose label of a change's current-password sign-in context.
const CHANGE_CONTEXT_LABEL: &[u8] = b"SID-PASSWORD-CHANGE-v1";

/// The OPAQUE context (RFC 9807 §6) of the change `id`'s current-password
/// sign-in: the purpose, the operation and SHA-256 of the new password's
/// registration request, so its KE3 confirms this change of this request
/// and no ordinary sign-in or other change.
pub(crate) fn change_context(id: &PasswordOperationId, registration_request: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut context = Vec::with_capacity(CHANGE_CONTEXT_LABEL.len() + 16 + 32);
    context.extend_from_slice(CHANGE_CONTEXT_LABEL);
    context.extend_from_slice(id.as_bytes());
    context.extend_from_slice(&sha2::Sha256::digest(registration_request));
    context
}

fn finish_command(id: &PasswordOperationId, method: &'static str, record: &[u8]) -> KeyedCommand {
    let key = OperationKey::parse(&id.to_string()).expect("an operation id is a valid key");
    KeyedCommand::new(RESULT_NAMESPACE, key, method, record.to_vec())
}

/// Who owns the password an operation installs.
pub(crate) enum OperationOwner {
    /// An existing profile: its stored history applies.
    Existing(ProfileId),
    /// A profile the operation will create: it starts its own history.
    New(ProfileId),
    /// Nobody: a registration start for a held identifier.
    Decoy,
}

/// What a prepared operation hands back to the client.
pub(crate) struct Prepared {
    pub context: PasswordHistoryContext,
    /// The OPAQUE registration response, when the preparation carried the
    /// request (registration start).
    pub registration_response: Option<Vec<u8>>,
}

/// What a finished operation hands its purpose to commit.
pub(crate) struct FinishedOperation {
    pub operation: PendingOperation,
    pub password_file: Vec<u8>,
    /// What an accepted proof, if any, established about this password.
    pub evidence: PolicyEvidence,
    /// The accepted password's history, for a verified proof.
    pub history: Option<HistoryCommit>,
    /// The durable-result command the commit completes.
    pub command: KeyedCommand,
}

impl FinishedOperation {
    /// The credential this operation installs for `profile_id`, with the
    /// evidence its proof gave it, over the sealed `data`.
    pub(crate) fn credential(&self, profile_id: ProfileId, data: Vec<u8>) -> Credential {
        let mut credential = Credential::new(profile_id, CredentialType::Opaque, data, None);
        credential.opaque_curve = Some(CurveId::Pallas as u8);
        credential.policy_evidence = self.evidence;
        credential.opaque_credential_identifier = Some(self.operation.credential_identifier);
        credential
    }

    /// The completion the commit records: a retry of this finish returns `result`.
    pub(crate) fn completion(&self, result: Vec<u8>) -> OperationCompletion {
        self.command.completion(result)
    }
}

/// The outcome of a finish.
pub(crate) enum Finish {
    /// The operation is ready to commit (boxed: it carries the whole pending
    /// operation, the recorded result is a few bytes).
    Ready(Box<FinishedOperation>),
    /// The operation was already committed by an earlier attempt with this
    /// record: the recorded result.
    Completed(Vec<u8>),
}

/// The credential service's side of the lifecycle; one per replica.
pub(crate) struct PasswordOperations {
    storage: Arc<dyn StorageBackend>,
    /// Admits each operation and selects its comparison domains.
    evaluator: Arc<dyn HistoryPreparation>,
    checker: HistoryChecker,
    // Local compute capacity, not authorization/rate-limit authority. A permit
    // bounds one fixed-shape verifier workspace and remains with its task.
    proof_permits: Arc<Semaphore>,
    ops: ChallengeStore<PendingOperation>,
    installation: [u8; 16],
    depth: u32,
    /// First enrollments admitted and not yet ended, across replicas.
    enrollment_capacity: u64,
}

/// What the credential service, which holds the entries, tells the evaluator
/// about the owner's history with each preparation
/// (`PreparePasswordHistoryRequest`): the revision, the comparison domains of
/// the epochs holding an entry at it, and the operations it records committed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LiveDomains {
    pub revision: i64,
    /// Sorted, without duplicates.
    pub domains: Vec<[u8; 32]>,
    pub settled: Vec<uuid::Uuid>,
}

impl LiveDomains {
    /// The live domains of `history`, as read in one snapshot.
    pub(crate) fn of(history: &PasswordHistory) -> Self {
        let set = HistoryLiveSet::of(history);
        let mut domains: Vec<[u8; 32]> = history
            .epochs
            .iter()
            .filter(|e| set.live.contains(&e.id))
            .map(|e| OperationDomain::of(&e.descriptor()).comparison_domain)
            .collect();
        domains.sort_unstable();
        Self {
            revision: set.revision,
            domains,
            settled: set.settled,
        }
    }
}

/// What the credential service asks the evaluator to admit: the operation,
/// its owner by history input domain, what it does to the owner's history,
/// until when it can commit, who its evaluations are charged to, and the
/// owner's live history domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HistoryAdmission {
    pub id: PasswordOperationId,
    pub owner_domain: [u8; 32],
    pub kind: OwnerKind,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub charge_key: String,
    pub live: LiveDomains,
}

/// Admits a password operation at the history evaluator and returns its
/// selected epochs: the evaluator in this process, or as its own service.
#[tonic::async_trait]
pub(crate) trait HistoryPreparation: Send + Sync {
    /// The public description of the epochs `admission`'s operation uses,
    /// its active epoch first. Repeating the call with the same admission
    /// returns the same epochs; any other admission of that operation fails.
    async fn prepare(
        &self,
        admission: &HistoryAdmission,
    ) -> Result<Vec<HistoryEpochDescriptor>, Status>;
}

fn domain_message(d: &OperationDomain) -> PasswordHistoryDomain {
    PasswordHistoryDomain {
        comparison_domain: d.comparison_domain.to_vec(),
        evaluator_public_key: d.public_key.to_vec(),
    }
}

fn descriptor_message(e: &HistoryEpochDescriptor) -> PasswordHistoryEpochDescriptor {
    PasswordHistoryEpochDescriptor {
        epoch_id: e.id.0.as_bytes().to_vec(),
        public_key: e.public_key.to_vec(),
        suite: e.suite.as_str().to_owned(),
        ksf: Some(PasswordHistoryKsf {
            memory_kib: e.ksf.memory_kib,
            passes: e.ksf.passes,
            lanes: e.ksf.lanes,
        }),
        ksf_salt: e.ksf_salt.to_vec(),
        created_at: Some(super::convert::to_timestamp(e.created_at)),
    }
}

/// The descriptor a message describes, when every field is well formed.
fn descriptor_of(m: &PasswordHistoryEpochDescriptor) -> Option<HistoryEpochDescriptor> {
    let ksf = m.ksf.as_ref()?;
    Some(HistoryEpochDescriptor {
        id: HistoryEpochId(uuid::Uuid::from_slice(&m.epoch_id).ok()?),
        suite: HistorySuite::parse(&m.suite).ok()?,
        public_key: m.public_key.as_slice().try_into().ok()?,
        ksf: HistoryKsf {
            memory_kib: ksf.memory_kib,
            passes: ksf.passes,
            lanes: ksf.lanes,
        },
        ksf_salt: m.ksf_salt.as_slice().try_into().ok()?,
        created_at: m.created_at.as_ref().and_then(|t| {
            chrono::DateTime::from_timestamp(t.seconds, u32::try_from(t.nanos).ok()?)
        })?,
    })
}

fn unavailable(what: &str) -> Status {
    ApiError::new(
        ErrorReason::PasswordHistoryUnavailable,
        format!("password history unavailable: {what}"),
    )
    .with_retry_after(Duration::from_secs(5))
    .into()
}

fn internal(e: impl std::fmt::Display) -> Status {
    warn!("password operation: {e}");
    ApiError::internal().into()
}

/// Hold the reservation in the blocking task itself: cancelling its caller
/// cannot release capacity while non-cancellable cryptographic work continues.
async fn run_proof<T: Send + 'static>(
    permit: OwnedSemaphorePermit,
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Status> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        job()
    })
    .await
    .map_err(internal)
}

/// The refusal of a step whose operation is not pending for it: unknown,
/// expired, already finished or of another purpose or owner. One answer for
/// all of them, so a step reveals nothing about operations it does not own.
pub(crate) fn operation_not_pending() -> Status {
    ApiError::new(
        ErrorReason::OperationExpired,
        "the password operation is not pending; start a new one",
    )
    .into()
}

fn expired() -> Status {
    operation_not_pending()
}

/// INVALID_STATE: a step of the operation was skipped; the client runs it
/// before finishing.
fn step_missing(what: &'static str) -> Status {
    ApiError::new(ErrorReason::InvalidState, what)
        .with_precondition("PASSWORD_OPERATION_STEP", "password_operation", what)
        .into()
}

/// FAILED_PRECONDITION: the history key this operation would write under was
/// withdrawn by a write cutoff after the operation began; a new operation
/// gets a current key. Nothing was installed.
pub(crate) fn history_key_withdrawn() -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        "the operation's password history key was withdrawn; start a new operation",
    )
    .with_precondition(
        "PASSWORD_HISTORY_WRITE_CUTOFF",
        "password_operation",
        "start a new operation under a current history key",
    )
    .into()
}

/// The refusal of a purpose's commit: a write cutoff that won the commit's
/// serialization is [`history_key_withdrawn`], anything else `other`.
pub(crate) fn commit_refusal(
    e: sid_core::Error,
    other: impl FnOnce(sid_core::Error) -> Status,
) -> Status {
    match e {
        sid_core::Error::Fenced(reason) => {
            warn!("password commit refused by the history write cutoff: {reason}");
            history_key_withdrawn()
        }
        // The operation is taken exclusively before its commit, so another
        // completion of its key is its terminal abort, which won.
        sid_core::Error::OperationCompleted(_) => expired(),
        e => other(e),
    }
}

fn invalid_proof() -> Status {
    ApiError::new(
        ErrorReason::PasswordProofInvalid,
        "the password proof does not verify for this operation",
    )
    .into()
}

#[allow(clippy::result_large_err)]
fn array32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], Status> {
    bytes
        .try_into()
        .map_err(|_| invalid_field(field, "not exactly 32 bytes"))
}

/// Decode a proof: its SNARK bytes and canonical field-element instances.
#[allow(clippy::result_large_err)]
pub(crate) fn decode_proof(proof: PasswordRegistrationProof) -> Result<BoundProof, Status> {
    use ff::PrimeField;
    use pasta_curves::pallas;

    if proof.instances.len() > sid_pake_core::circuit::instance_count(MAX_HISTORY_DOMAINS) {
        return Err(invalid_field("proof.instances", "too many instances"));
    }

    let instances = proof
        .instances
        .iter()
        .map(|bytes| {
            Option::from(pallas::Base::from_repr(array32(bytes, "proof.instances")?))
                .ok_or_else(|| invalid_field("proof.instances", "not a canonical field element"))
        })
        .collect::<Result<Vec<_>, Status>>()?;
    Ok(BoundProof {
        snark_proof: ZkppProof(proof.zkpp_proof),
        instances,
    })
}

/// The evaluator's proofs a finish relays, decoded: one per domain, each a
/// challenge and a response of 32 bytes. Whether they verify is the
/// checker's question.
#[allow(clippy::result_large_err)]
fn relayed_proofs(proofs: &[PasswordHistoryEvaluationProof]) -> Result<Vec<RelayedProof>, Status> {
    const FIELD: &str = "proof.evaluation_proofs";
    proofs
        .iter()
        .map(|p| {
            Ok(RelayedProof {
                challenge: array32(&p.challenge, FIELD)?,
                response: array32(&p.response, FIELD)?,
            })
        })
        .collect()
}

/// The operation an RPC names, or `INVALID_ARGUMENT`.
#[allow(clippy::result_large_err)]
pub(crate) fn operation_id(
    field: Option<&sid_ids_proto::PasswordOperationId>,
) -> Result<PasswordOperationId, Status> {
    sid_ids_proto::required(field).map_err(|e| {
        ApiError::new(ErrorReason::InvalidFieldValue, e.to_string())
            .with_field_violation("operation_id", "a password operation id")
            .into()
    })
}

/// Who charges an operation's evaluations: an opaque digest of the
/// authorized actor, so its length is bounded whatever the actor's name.
fn charge_key(actor: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(actor.as_bytes()))
}

/// Where a credential service's history evaluator runs.
pub enum PasswordHistoryAuthority {
    /// In this process, over its own store `store`, sealing history keys and
    /// its operation records with `history_keys`: a standalone installation,
    /// where compromising the process merges evaluator and checker.
    InProcess {
        store: Arc<dyn HistoryKeyStore>,
        history_keys: Arc<dyn sid_keys::KeyManager>,
    },
    /// Its own service: this process holds no history key and no evaluator
    /// state.
    Remote(RemoteHistoryEvaluator),
}

impl PasswordOperations {
    /// The credential side under `authority`, with the evaluator when that
    /// runs in this process. `field_keys` seal the credential service's own
    /// operation records.
    pub(crate) fn with_authority(
        storage: Arc<dyn StorageBackend>,
        cache: Arc<dyn CacheBackend>,
        field_keys: Arc<dyn sid_keys::KeyManager>,
        installation: sid_core::models::OrgId,
        authority: PasswordHistoryAuthority,
    ) -> (Self, Option<Arc<HistoryEvaluation>>) {
        match authority {
            PasswordHistoryAuthority::InProcess {
                store,
                history_keys,
            } => {
                let evaluation =
                    Arc::new(HistoryEvaluation::new(store, cache.clone(), history_keys));
                let ops = Self::new(storage, cache, field_keys, installation, evaluation.clone());
                (ops, Some(evaluation))
            }
            PasswordHistoryAuthority::Remote(evaluator) => (
                Self::new(
                    storage,
                    cache,
                    field_keys,
                    installation,
                    Arc::new(evaluator),
                ),
                None,
            ),
        }
    }

    /// The credential side over `storage`, sealing its operation records
    /// with `operation_keys` and admitting operations at `evaluator`.
    pub(crate) fn new(
        storage: Arc<dyn StorageBackend>,
        cache: Arc<dyn CacheBackend>,
        operation_keys: Arc<dyn sid_keys::KeyManager>,
        installation: sid_core::models::OrgId,
        evaluator: Arc<dyn HistoryPreparation>,
    ) -> Self {
        Self {
            storage,
            evaluator,
            checker: HistoryChecker::new(sid_authn::password_history::KsfAdmission::new(
                KSF_BUDGET_MIB,
                KSF_WAIT,
            )),
            proof_permits: Arc::new(Semaphore::new(
                std::thread::available_parallelism()
                    .expect("password verification requires a known CPU capacity")
                    .get(),
            )),
            ops: ChallengeStore::new(cache, operation_keys, "password-operation", OPERATION_TTL),
            installation: *installation.as_bytes(),
            depth: DEFAULT_HISTORY_DEPTH,
            enrollment_capacity: ENROLLMENT_CAPACITY,
        }
    }

    /// The same, admitting at most `capacity` open first enrollments.
    #[cfg(test)]
    fn with_enrollment_capacity(mut self, capacity: u64) -> Self {
        self.enrollment_capacity = capacity;
        self
    }

    async fn store(&self, op: &PendingOperation) -> Result<(), Status> {
        self.ops.insert(&op.id.to_string(), op).await?;
        Ok(())
    }

    /// Take the pending operation `id` exclusively; a concurrent step of the
    /// same operation, an expired one or an unknown id is refused.
    async fn take(&self, id: &PasswordOperationId) -> Result<PendingOperation, Status> {
        self.ops.take(&id.to_string()).await?.ok_or_else(expired)
    }

    /// Prepare an operation for `owner` under `purpose`, charging its
    /// evaluations to `actor`: the evaluator admits it and selects its
    /// epochs from the owner's history as read now, the selection is checked
    /// against that history, then the operation is stored. With
    /// `registration_request` the OPAQUE start runs here too, so a
    /// registration needs no separate start step.
    pub(crate) async fn prepare(
        &self,
        zkpp: &ZkppOpaqueServer,
        purpose: OperationPurpose,
        owner: OperationOwner,
        actor: String,
        registration_request: Option<Vec<u8>>,
    ) -> Result<Prepared, Status> {
        let (owner, kind) = match owner {
            OperationOwner::New(profile_id) => (profile_id, OwnerKind::New),
            OperationOwner::Existing(profile_id) => (profile_id, OwnerKind::Existing),
            OperationOwner::Decoy => (ProfileId::generate(), OwnerKind::Decoy),
        };
        let mut op = PendingOperation {
            id: PasswordOperationId::generate(),
            purpose,
            owner,
            kind,
            owner_domain: owner_domain(&self.installation, owner),
            epochs: Vec::new(),
            history_revision: 0,
            policy_version: zkpp.config().policy_version,
            credential_identifier: rand::random(),
            registration_request: None,
            current_password: CurrentPassword::Absent,
        };
        let registration_response = match registration_request {
            Some(request) => Some(Self::start_opaque(zkpp, &mut op, request)?),
            None => None,
        };
        // Read for every kind, a decoy's random owner included, so a start
        // for a held identifier costs what any other does.
        let history = self
            .storage
            .get_password_history(owner)
            .await
            .map_err(internal)?;
        let expires_at = chrono::Utc::now()
            + chrono::Duration::from_std(OPERATION_TTL)
                .expect("the operation lifetime fits a duration");
        if kind == OwnerKind::New {
            // Durable before the evaluator makes the new owner's key, so a
            // registration that never commits (abandoned, or lost to a crash
            // before its reply or this record) still has its key reclaimed.
            let admission = EnrollmentAdmission {
                operation: op.id.into_uuid(),
                owner_domain: op.owner_domain,
                expires_at,
            };
            match self
                .storage
                .enqueue_work(&admission.work(), self.enrollment_capacity)
                .await
            {
                Ok(_) => {}
                Err(sid_core::Error::ResourceExhausted(reason)) => {
                    warn!("first enrollments at capacity: {reason}");
                    return Err(unavailable("enrollment capacity"));
                }
                Err(e) => return Err(internal(e)),
            }
        }
        let epochs = self
            .evaluator
            .prepare(&HistoryAdmission {
                id: op.id,
                owner_domain: op.owner_domain,
                kind,
                expires_at,
                charge_key: charge_key(&actor),
                live: LiveDomains::of(&history),
            })
            .await?;
        // The evaluator chose the epochs; the credential service, which
        // reads the entries, accepts only a complete selection whose known
        // epochs keep the descriptions it recorded.
        if !selection_is_complete(kind, &epochs, &history) {
            warn!(
                "password operation {} got a history selection its history does not require",
                op.id
            );
            return Err(unavailable("history selection"));
        }
        op.epochs = epochs;
        op.history_revision = history.revision;
        self.store(&op).await?;
        let context = PasswordHistoryContext {
            operation_id: Some(op.id.into()),
            owner_domain: op.owner_domain.to_vec(),
            domains: op.domains().iter().map(domain_message).collect(),
            policy_version: op.policy_version,
        };
        Ok(Prepared {
            context,
            registration_response,
        })
    }

    /// The OPAQUE start of `op` for `request`, under the operation's own
    /// credential identifier. The request is fixed on first use: a retry
    /// with the same request gets the same response, another request is
    /// refused, since the proof is bound to it.
    #[allow(clippy::result_large_err)]
    fn start_opaque(
        zkpp: &ZkppOpaqueServer,
        op: &mut PendingOperation,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        if let Some(sent) = &op.registration_request
            && sent != &request
        {
            return Err(ApiError::new(
                ErrorReason::OperationKeyConflict,
                "this operation already started another registration request",
            )
            .into());
        }
        let response = zkpp
            .opaque_start(&request, &op.credential_identifier)
            .map_err(|e| {
                warn!("OPAQUE start failed: {e}");
                invalid_field("registration_request", "not an OPAQUE registration request")
            })?;
        op.registration_request = Some(request);
        Ok(response)
    }

    /// Begin the change `id`'s sign-in with the current password, when
    /// `authorized` accepts its purpose: `state` is the server side of the
    /// KE2 the challenge answers with. Its KE3 comes in execute.
    pub(crate) async fn begin_current_password(
        &self,
        id: &PasswordOperationId,
        state: LoginState,
        authorized: impl FnOnce(&PendingOperation) -> Result<(), Status>,
    ) -> Result<(), Status> {
        let mut op = self.take(id).await?;
        let result = authorized(&op);
        if result.is_ok() {
            op.current_password = CurrentPassword::Started(state);
        }
        self.store(&op).await?;
        result
    }

    /// Execute's half of the change `id`'s sign-in with the current
    /// password: `verify` checks `finalization` (KE3) against the begun
    /// state, once, under the change's context over the request the
    /// challenge fixed. A failed check leaves the operation without a proof;
    /// a retry of a proven operation stays proven.
    pub(crate) async fn prove_current_password(
        &self,
        id: &PasswordOperationId,
        finalization: &[u8],
        authorized: impl FnOnce(&PendingOperation) -> Result<(), Status>,
        verify: impl FnOnce(&LoginState, &[u8], &[u8]) -> bool,
    ) -> Result<CurrentPasswordCheck, Status> {
        let mut op = self.take(id).await?;
        let context = op
            .registration_request
            .as_deref()
            .map(|request| change_context(&op.id, request));
        let checked = authorized(&op).and_then(|()| {
            match (
                std::mem::take(&mut op.current_password),
                finalization.is_empty(),
            ) {
                (CurrentPassword::Absent, true) => Ok(CurrentPasswordCheck::NotBegun),
                (CurrentPassword::Absent, false) => Err(invalid_field(
                    "credential_finalization",
                    "the challenge began no current-password sign-in",
                )),
                (CurrentPassword::Started(state), true) => {
                    op.current_password = CurrentPassword::Started(state);
                    Err(ApiError::new(
                        ErrorReason::RequiredFieldMissing,
                        "the current-password sign-in needs its finalization",
                    )
                    .with_field_violation("credential_finalization", "required")
                    .into())
                }
                (CurrentPassword::Started(state), false) => {
                    let Some(context) = context.as_deref() else {
                        op.current_password = CurrentPassword::Started(state);
                        return Err(step_missing("the change fixed no new registration request"));
                    };
                    if verify(&state, finalization, context) {
                        op.current_password = CurrentPassword::Proven;
                        Ok(CurrentPasswordCheck::Proven)
                    } else {
                        Ok(CurrentPasswordCheck::Failed)
                    }
                }
                (CurrentPassword::Proven, _) => {
                    op.current_password = CurrentPassword::Proven;
                    Ok(CurrentPasswordCheck::Proven)
                }
            }
        });
        self.store(&op).await?;
        checked
    }

    /// The OPAQUE start of the operation `id` over the registration request
    /// it already fixed, when `authorized` accepts its purpose: a change
    /// answers execute with the response to the request its challenge fixed,
    /// never a new one.
    pub(crate) async fn fixed_opaque_start(
        &self,
        zkpp: &ZkppOpaqueServer,
        id: &PasswordOperationId,
        authorized: impl FnOnce(&PendingOperation) -> Result<(), Status>,
    ) -> Result<Vec<u8>, Status> {
        let mut op = self.take(id).await?;
        let result = authorized(&op).and_then(|()| {
            let request = op
                .registration_request
                .clone()
                .ok_or_else(|| step_missing("the change fixed no new registration request"))?;
            Self::start_opaque(zkpp, &mut op, request)
        });
        self.store(&op).await?;
        result
    }

    /// The OPAQUE start of the operation `id`, when `authorized` accepts its
    /// purpose (see [`Self::start_opaque`]).
    pub(crate) async fn opaque_start(
        &self,
        zkpp: &ZkppOpaqueServer,
        id: &PasswordOperationId,
        request: Vec<u8>,
        authorized: impl FnOnce(&PendingOperation) -> Result<(), Status>,
    ) -> Result<Vec<u8>, Status> {
        let mut op = self.take(id).await?;
        let result = authorized(&op).and_then(|()| Self::start_opaque(zkpp, &mut op, request));
        self.store(&op).await?;
        result
    }

    /// Finish the operation `id`: the final record and, when the client
    /// proved, the proof with the evaluator's proofs relayed. Takes the
    /// operation for good; a proof, history or record that fails leaves
    /// nothing to retry but a new operation. An operation already committed
    /// answers with its recorded result when the record is the one it was
    /// committed with. Exhausted proof capacity restores the pending
    /// operation for an exact retry; it is not a rejected proof.
    pub(crate) async fn finish(
        &self,
        zkpp: Arc<ZkppOpaqueServer>,
        id: &PasswordOperationId,
        method: &'static str,
        record: &[u8],
        proof: Option<PasswordRegistrationProof>,
        authorized: impl FnOnce(&PendingOperation) -> Result<(), Status>,
    ) -> Result<Finish, Status> {
        let Some(op) = self.ops.take(&id.to_string()).await? else {
            return match finish_command(id, method, record)
                .completed(self.storage.as_ref())
                .await?
            {
                Some(result) => Ok(Finish::Completed(result)),
                None => Err(expired()),
            };
        };
        authorized(&op)?;
        if op.purpose.method() != method {
            return Err(expired());
        }
        if op.policy_version != zkpp.config().policy_version {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "the password operation's policy is no longer accepted",
            )
            .with_precondition(
                "PASSWORD_POLICY_VERSION",
                "password_operation",
                "start a new operation under the current policy",
            )
            .into());
        }
        if op.epochs.is_empty() {
            return Err(step_missing(
                "the operation's history domains were not selected",
            ));
        }
        let command = op.finish_command(record);
        let request = op
            .registration_request
            .clone()
            .ok_or_else(|| step_missing("the operation has no OPAQUE start"))?;
        let password_file = zkpp.opaque_finish(record).map_err(|e| {
            warn!("OPAQUE finish failed: {e}");
            invalid_field("registration_record", "not an OPAQUE registration record")
        })?;
        let Some(proof) = proof else {
            if zkpp.config().require_proof {
                return Err(ApiError::new(
                    ErrorReason::RequiredFieldMissing,
                    "a password proof is required",
                )
                .with_field_violation("proof", "required")
                .into());
            }
            return Ok(Finish::Ready(Box::new(FinishedOperation {
                operation: op,
                password_file,
                evidence: PolicyEvidence::Unverified,
                history: None,
                command,
            })));
        };
        let domains = op.domains();
        let (proof_len, instance_count) = zkpp
            .proof_lengths(domains.len())
            .map_err(|_| invalid_proof())?;
        if proof.zkpp_proof.len() != proof_len
            || proof.instances.len() != instance_count
            || proof.evaluation_proofs.len() != domains.len()
        {
            return Err(invalid_proof());
        }
        let relayed = relayed_proofs(&proof.evaluation_proofs)?;
        let proof = decode_proof(proof)?;
        let op_id = *op.id.as_bytes();

        // Microsecond checks before the SNARK: the proof's form, then its
        // claimed history inputs against what this operation holds (owner
        // domain, domains) and the evaluator's relayed proofs over its
        // claimed blinded input and evaluated elements. A submission made
        // for another operation, or garbage, never costs a SNARK check; the
        // operation is taken, so each attempt is one try.
        let claimed = zkpp.claimed_inputs(&proof, domains.len()).map_err(|e| {
            warn!("password proof refused before verification: {e}");
            invalid_proof()
        })?;
        if let Err(e) = verify_inputs(&claimed, &op.owner_domain, &domains, &relayed, &op_id) {
            warn!("password proof refused before verification: {e}");
            return Err(invalid_proof());
        }

        // No queue of secret-bearing proofs. Saturation leaves the original
        // operation pending, so the caller can retry without another evaluation
        // or another proof. Never turn overload into unverified installation.
        let permit = match Arc::clone(&self.proof_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.store(&op).await?;
                return Err(unavailable("proof verification capacity"));
            }
        };
        // CPU-bound verification runs outside transactions and the async
        // runtime; its permit also bounds fixed-shape concurrent workspaces.
        let verifier = Arc::clone(&zkpp);
        let count = domains.len();
        let verified = run_proof(permit, move || {
            verifier.verify(&proof, &op_id, &request, count)
        })
        .await?
        .map_err(|e| {
            warn!("password proof refused: {e}");
            invalid_proof()
        })?;
        let public = verified.inputs;
        let evidence = PolicyEvidence::Verified {
            policy_version: op.policy_version,
            artifact: verified.artifact,
        };

        if op.kind == OwnerKind::Decoy {
            // Verified like any proof; the purpose refuses the commit.
            return Ok(Finish::Ready(Box::new(FinishedOperation {
                operation: op,
                password_file,
                evidence,
                history: None,
                command,
            })));
        }

        // A new owner's history is empty at revision 0 until this commit;
        // either way the history must still be the one the operation read.
        let history = self
            .storage
            .get_password_history(op.owner)
            .await
            .map_err(internal)?;
        if history.revision != op.history_revision {
            return Err(ApiError::new(
                ErrorReason::ConcurrentModification,
                "the password history changed; start a new operation",
            )
            .into());
        }
        if !selection_is_complete(op.kind, &op.epochs, &history) {
            warn!(
                "password operation {} has a history selection its history does not require",
                op.id
            );
            return Err(internal("history selection does not match the history"));
        }
        let checked = self
            .checker
            .check(
                &public,
                CheckRequest {
                    owner_domain: op.owner_domain,
                    domains: &domains,
                    epochs: &op.epochs,
                    proofs: &relayed,
                    context: &op_id,
                    history: &history,
                },
            )
            .await
            .map_err(|e| match e {
                HistoryCheckError::Reused => ApiError::new(
                    ErrorReason::PasswordReused,
                    "this password was used before; choose another",
                )
                .into(),
                HistoryCheckError::Busy => unavailable("checker capacity"),
                HistoryCheckError::Ksf => unavailable("history KSF"),
                HistoryCheckError::Mismatch | HistoryCheckError::EvaluationProof => {
                    warn!("password history inputs refused: {e}");
                    invalid_proof()
                }
            })?;
        let commit = HistoryCommit {
            owner: op.owner,
            expected_revision: op.history_revision,
            epochs: op.epochs.clone(),
            entries: checked.new_entries,
            evidence: HistoryEvidence {
                operation: op.id.into_uuid(),
                policy_version: op.policy_version,
            },
            depth: self.depth,
            // The purpose sets the installation's age retention as it commits.
            max_age_days: 0,
        };
        Ok(Finish::Ready(Box::new(FinishedOperation {
            operation: op,
            password_file,
            evidence,
            history: Some(commit),
            command,
        })))
    }
}

/// Whether `epochs`, the evaluator's selection for an operation of `kind`,
/// is what `history` requires: one epoch for a decoy; for a new owner one
/// epoch and no history yet; for an existing owner each epoch once, the
/// operation's active epoch first (the history's active epoch, or a
/// replacement the history does not know yet), every epoch that retains an
/// entry, and every epoch the history knows with the description it
/// recorded. An epoch the history knows without entries may be named (it was
/// emptied after the evaluator last heard of it); one it does not know may
/// only be the new active epoch.
fn selection_is_complete(
    kind: OwnerKind,
    epochs: &[HistoryEpochDescriptor],
    history: &PasswordHistory,
) -> bool {
    let once = epochs
        .iter()
        .enumerate()
        .all(|(i, e)| !epochs[..i].iter().any(|o| o.id == e.id));
    if !once || epochs.is_empty() || epochs.len() > MAX_HISTORY_DOMAINS {
        return false;
    }
    match kind {
        OwnerKind::Decoy => epochs.len() == 1,
        OwnerKind::New => epochs.len() == 1 && history.revision == 0 && history.epochs.is_empty(),
        OwnerKind::Existing => {
            let recorded = |id: HistoryEpochId| history.epochs.iter().find(|e| e.id == id);
            let described = epochs
                .iter()
                .enumerate()
                .all(|(i, e)| match recorded(e.id) {
                    Some(r) => r.descriptor() == *e,
                    None => i == 0,
                });
            let active = history
                .active_epoch()
                .is_none_or(|a| epochs[0].id == a.id || recorded(epochs[0].id).is_none());
            let complete = history
                .epochs
                .iter()
                .filter(|r| history.entries_of(r.id).next().is_some())
                .all(|r| epochs.iter().any(|e| e.id == r.id));
            described && active && complete
        }
    }
}

/// The evaluator's own record of one operation: the admission it accepted,
/// its selection and its charged evaluation. Never the credential service's
/// record, and nothing that confirms or commits a password.
#[derive(Debug, Serialize, Deserialize)]
struct EvaluatorOperation {
    owner_domain: [u8; 32],
    kind: OwnerKind,
    expires_at: chrono::DateTime<chrono::Utc>,
    charge_key: String,
    /// The selected epochs, active first.
    epochs: Vec<HistoryEpochDescriptor>,
    /// A decoy's throwaway evaluation keys, one per epoch: its answers verify
    /// under the keys the client got, as a real one's do. Empty otherwise.
    decoy_keys: Vec<[u8; 32]>,
    /// The charged evaluation, kept for an exact retry.
    evaluation: Option<OperationEvaluation>,
}

impl EvaluatorOperation {
    /// Whether `admission` repeats the one this record was made from.
    fn admits(&self, admission: &HistoryAdmission) -> bool {
        self.owner_domain == admission.owner_domain
            && self.kind == admission.kind
            && self.expires_at == admission.expires_at
            && self.charge_key == admission.charge_key
    }
}

/// The history evaluator: it alone holds the history keys, in its own store.
/// It admits each operation, selects its epochs (creating or replacing the
/// owner's key) and evaluates the operation's blinded input. It knows the
/// owner by history input domain and reads no entry, tag or credential.
pub struct HistoryEvaluation {
    keys: Arc<dyn HistoryKeyStore>,
    cache: Arc<dyn CacheBackend>,
    evaluator: HistoryEvaluator,
    ops: ChallengeStore<EvaluatorOperation>,
    /// The KSF new epochs are made with; an active epoch under another one
    /// is replaced.
    ksf: HistoryKsf,
}

impl HistoryEvaluation {
    /// The evaluator over its key store `keys`, sealing history keys and its
    /// operation records with `history_keys`, which open nothing of the
    /// credential service's in a split deployment.
    pub fn new(
        keys: Arc<dyn HistoryKeyStore>,
        cache: Arc<dyn CacheBackend>,
        history_keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            keys,
            cache: cache.clone(),
            evaluator: HistoryEvaluator::new(history_keys.clone()),
            ops: ChallengeStore::new(
                cache,
                history_keys,
                "password-history-evaluation",
                OPERATION_TTL,
            ),
            ksf: HistoryKsf::DEFAULT,
        }
    }

    /// The epoch policy in force: the current KSF and the write cutoff the
    /// store records, read at every use, so a replica started with an older
    /// or no cutoff setting still applies the newest one.
    async fn epoch_policy(&self) -> Result<EpochPolicy, Status> {
        Ok(EpochPolicy {
            ksf: self.ksf,
            not_before: self.keys.write_cutoff().await.map_err(internal)?,
        })
    }

    async fn store(
        &self,
        id: &PasswordOperationId,
        record: &EvaluatorOperation,
    ) -> Result<(), Status> {
        self.ops.insert(&id.to_string(), record).await?;
        Ok(())
    }

    /// Admit the operation of `admission` and select its epochs, recorded
    /// with the admission. An operation already admitted returns its
    /// original selection when the admission repeats exactly; any other
    /// admission of it is a conflict.
    pub(crate) async fn prepare(
        &self,
        admission: &HistoryAdmission,
    ) -> Result<Vec<HistoryEpochDescriptor>, Status> {
        let now = chrono::Utc::now();
        // The expiry comes from the credential service's clock; an ordinary
        // skew between the two hosts is tolerated, as at JWT expiry
        // (RFC 7519 §4.1.4).
        let latest = now
            + chrono::Duration::from_std(OPERATION_TTL + ADMISSION_CLOCK_SKEW)
                .expect("the operation lifetime fits a duration");
        if admission.expires_at <= now || admission.expires_at > latest {
            return Err(invalid_field(
                "expires_at",
                "outside the operation lifetime",
            ));
        }
        if admission.charge_key.is_empty() || admission.charge_key.len() > MAX_CHARGE_KEY {
            return Err(invalid_field("charge_key", "1 to 128 bytes"));
        }
        let policy = self.epoch_policy().await?;
        if let Some(record) = self.ops.take(&admission.id.to_string()).await? {
            let repeated = record.admits(admission);
            let epochs = record.epochs.clone();
            self.store(&admission.id, &record).await?;
            return if repeated {
                // A repeat never hands out a key a cutoff has since withdrawn.
                if record.kind != OwnerKind::Decoy && !policy.permits_writes(&epochs[0]) {
                    return Err(history_key_withdrawn());
                }
                Ok(epochs)
            } else {
                Err(ApiError::new(
                    ErrorReason::OperationKeyConflict,
                    "this operation was admitted with other fields",
                )
                .into())
            };
        }
        let mut record = EvaluatorOperation {
            owner_domain: admission.owner_domain,
            kind: admission.kind,
            expires_at: admission.expires_at,
            charge_key: admission.charge_key.clone(),
            epochs: Vec::new(),
            decoy_keys: Vec::new(),
            evaluation: None,
        };
        self.select(&mut record, admission, &policy, now).await?;
        self.store(&admission.id, &record).await?;
        Ok(record.epochs)
    }

    async fn select(
        &self,
        record: &mut EvaluatorOperation,
        admission: &HistoryAdmission,
        policy: &EpochPolicy,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Status> {
        let owner_domain = admission.owner_domain;
        match admission.kind {
            OwnerKind::New => {
                let new = self
                    .evaluator
                    .new_epoch(owner_domain, self.ksf)
                    .await
                    .map_err(internal)?;
                // Durable before the first evaluation; never over an
                // existing history, so a new-owner admission resets nothing.
                let epoch = self
                    .keys
                    .create_first_epoch(
                        &new,
                        admission.id.into_uuid(),
                        audit("password_history.epoch_created"),
                    )
                    .await
                    .map_err(|e| match e {
                        sid_core::Error::Conflict(reason) => {
                            warn!("a new owner's history domain already has keys: {reason}");
                            unavailable("history keys")
                        }
                        // Its registration was aborted before this
                        // preparation arrived.
                        sid_core::Error::Fenced(_) => expired(),
                        other => internal(other),
                    })?;
                record.epochs = vec![epoch.descriptor()];
            }
            OwnerKind::Existing => {
                let live = live_set_bounds(&admission.live)?;
                let epochs = self
                    .current_epochs(&owner_domain, live.revision, policy)
                    .await?;
                let live = live_epochs(&epochs, live)?;
                let selected = self
                    .keys
                    .prepare_epochs(
                        &sid_core::models::HistoryPreparation {
                            owner_domain,
                            live,
                            operation: admission.id.into_uuid(),
                            expires_at: admission.expires_at,
                            now,
                        },
                        audit("password_history.prepared"),
                    )
                    .await
                    .map_err(|e| match e {
                        sid_core::Error::Conflict(reason) => {
                            warn!("history lifecycle refused: {reason}");
                            unavailable("history lifecycle conflict")
                        }
                        other => internal(other),
                    })?;
                if selected.is_empty() || selected.len() > MAX_HISTORY_DOMAINS {
                    warn!("an owner requires {} history domains", selected.len());
                    return Err(unavailable("history epochs"));
                }
                record.epochs = selected.iter().map(|e| e.descriptor()).collect();
                if !policy.permits_writes(&record.epochs[0]) {
                    // Another replica made the selection's active epoch
                    // before the cutoff it has not applied yet.
                    return Err(history_key_withdrawn());
                }
            }
            OwnerKind::Decoy => {
                let (epoch, key) = decoy_epoch(self.ksf);
                record.epochs = vec![epoch];
                record.decoy_keys = vec![key];
            }
        }
        Ok(())
    }

    /// The owner's epochs with a current active one: one is created (key
    /// sealed and stored before first use) when the owner has none, and an
    /// active epoch the [`EpochPolicy`] no longer accepts is replaced from
    /// the revision after `revision`, staying comparable while it retains
    /// entries.
    async fn current_epochs(
        &self,
        owner_domain: &[u8; 32],
        revision: i64,
        policy: &EpochPolicy,
    ) -> Result<KeyEpochs, Status> {
        let epochs = self
            .keys
            .get_key_epochs(owner_domain)
            .await
            .map_err(internal)?;
        let replaces = match epochs.active_epoch() {
            Some(active) if policy.is_current(active) => return Ok(epochs),
            Some(active) => Some(active.id),
            None => None,
        };
        let new = self
            .evaluator
            .new_epoch(*owner_domain, self.ksf)
            .await
            .map_err(internal)?;
        match replaces {
            Some(replaces) => {
                // The replaced epoch took entries up to this revision; a
                // live set of it or older may still need it.
                let from = revision
                    .checked_add(1)
                    .ok_or_else(|| invalid_field("history_revision", "out of range"))?;
                self.keys
                    .rotate_epoch(
                        &new,
                        replaces,
                        from,
                        audit("password_history.epoch_rotated"),
                    )
                    .await
                    .map_err(internal)?
            }
            None => self
                .keys
                .ensure_epoch(&new, audit("password_history.epoch_created"))
                .await
                .map_err(internal)?,
        };
        self.keys
            .get_key_epochs(owner_domain)
            .await
            .map_err(internal)
    }

    /// The terminal step of the aborted first enrollment `operation` of the
    /// owner of `owner_domain`: from now on it creates no key and is evaluated
    /// no more, and the key it created is destroyed when nothing else can
    /// need it. The credential authority alone decides that a registration
    /// aborted; this is called only with that decision.
    pub async fn abandon_enrollment(
        &self,
        owner_domain: &[u8; 32],
        operation: uuid::Uuid,
    ) -> sid_core::Result<EnrollmentCleanup> {
        self.keys
            .abandon_enrollment(
                owner_domain,
                operation,
                audit("password_history.enrollment_abandoned"),
            )
            .await
    }

    /// Evaluate the operation's blinded input under each selected epoch.
    /// Charged once per operation before any key is used; an exact retry
    /// returns the recorded answers, another input is refused, and nothing
    /// is evaluated once the operation can no longer commit.
    pub(crate) async fn evaluate(
        &self,
        id: &PasswordOperationId,
        blinded: &[u8],
    ) -> Result<Vec<PasswordHistoryEvaluation>, Status> {
        let blinded = array32(blinded, "blinded_input")?;
        let mut record = self.ops.take(&id.to_string()).await?.ok_or_else(expired)?;
        if record.expires_at <= chrono::Utc::now() {
            return Err(expired());
        }
        // Checked before a recorded answer is returned too: no evaluation,
        // new or repeated, is handed out under a withdrawn key. The record
        // stays, so every repeat of this operation is refused alike rather
        // than admitted afresh.
        if record.kind != OwnerKind::Decoy {
            let refusal = match self.epoch_policy().await {
                Ok(policy) if policy.permits_writes(&record.epochs[0]) => None,
                Ok(_) => Some(history_key_withdrawn()),
                Err(unavailable) => Some(unavailable),
            };
            // An aborted first enrollment is evaluated no more, whether or
            // not its key could be reclaimed.
            let refusal = match refusal {
                None if record.kind == OwnerKind::New => {
                    match self.keys.enrollment_abandoned(id.into_uuid()).await {
                        Ok(false) => None,
                        Ok(true) => Some(expired()),
                        Err(e) => Some(internal(e)),
                    }
                }
                refusal => refusal,
            };
            if let Some(refusal) = refusal {
                self.store(id, &record).await?;
                return Err(refusal);
            }
        }
        let result = self.evaluate_taken(id, &mut record, &blinded).await;
        self.store(id, &record).await?;
        let evaluation = result?;
        Ok(evaluation
            .evaluations
            .iter()
            .map(|e| PasswordHistoryEvaluation {
                evaluated_element: e.evaluated.to_vec(),
                proof: Some(PasswordHistoryEvaluationProof {
                    challenge: e.challenge.to_vec(),
                    response: e.response.to_vec(),
                }),
            })
            .collect())
    }

    async fn evaluate_taken(
        &self,
        id: &PasswordOperationId,
        record: &mut EvaluatorOperation,
        blinded: &[u8; 32],
    ) -> Result<OperationEvaluation, Status> {
        if let Some(done) = &record.evaluation {
            return if &done.blinded == blinded {
                Ok(done.clone())
            } else {
                Err(ApiError::new(
                    ErrorReason::OperationKeyConflict,
                    "this operation already evaluated another input",
                )
                .into())
            };
        }
        let charged = self
            .cache
            .incr(
                &format!("password-history-evaluations:{}", record.charge_key),
                EVALUATION_WINDOW,
            )
            .await
            .map_err(|e| {
                warn!("history evaluation budget unavailable: {e}");
                unavailable("evaluation budget")
            })?;
        if charged > EVALUATIONS_PER_WINDOW {
            return Err(ApiError::new(
                ErrorReason::RateLimitExceeded,
                "too many password history evaluations",
            )
            .with_retry_after(EVALUATION_WINDOW)
            .into());
        }
        let context = id.as_bytes();
        let evaluation = if record.kind == OwnerKind::Decoy {
            self.evaluator
                .evaluate_decoy(blinded, &record.decoy_keys, context)
        } else {
            let mut keys = Vec::with_capacity(record.epochs.len());
            for epoch in &record.epochs {
                let key = self.keys.get_epoch_key(epoch.id).await.map_err(internal)?;
                let key = key.ok_or_else(|| {
                    warn!("history epoch {} has no stored key", epoch.id.0);
                    unavailable("history key missing")
                })?;
                keys.push((epoch.id, key));
            }
            self.evaluator
                .evaluate(blinded, &record.owner_domain, &keys, context)
                .await
        }
        .map_err(|e| match e {
            sid_core::Error::Validation(_) => {
                invalid_field("blinded_input", "not a valid group element")
            }
            other => {
                warn!("history evaluation failed: {other}");
                unavailable("evaluator")
            }
        })?;
        record.evaluation = Some(evaluation.clone());
        Ok(evaluation)
    }
}

/// The evaluator's audit entry for `action`: it acts as the system on an
/// owner it knows only by history domain, which the entry does not name.
fn audit(action: &str) -> AuditEntry {
    AuditEntry::system(action, "password_history")
}

/// A live set within the bounds an operation can hold, or refused before
/// any key is touched.
#[allow(clippy::result_large_err)]
fn live_set_bounds(live: &LiveDomains) -> Result<&LiveDomains, Status> {
    if live.revision < 0 {
        return Err(invalid_field("history_revision", "out of range"));
    }
    if live.domains.len() > MAX_HISTORY_DOMAINS {
        return Err(invalid_field(
            "live_comparison_domains",
            "more domains than an operation holds",
        ));
    }
    if live.settled.len() > sid_core::models::password_history::MAX_HISTORY_DEPTH as usize {
        return Err(invalid_field(
            "settled_operations",
            "more operations than history retains",
        ));
    }
    Ok(live)
}

/// The owner's epochs named by `live`: each domain must be one the evaluator
/// issued for this owner, once. Anything else retains every key: the
/// preparation is refused.
#[allow(clippy::result_large_err)]
fn live_epochs(epochs: &KeyEpochs, live: &LiveDomains) -> Result<HistoryLiveSet, Status> {
    let refused = |why: &str| {
        warn!("live history set refused: {why}");
        unavailable("history lifecycle")
    };
    let mut ids = Vec::with_capacity(live.domains.len());
    for domain in &live.domains {
        let epoch = epochs
            .epochs
            .iter()
            .find(|e| OperationDomain::of(&e.descriptor()).comparison_domain == *domain)
            .ok_or_else(|| refused("a domain not issued for the owner"))?;
        ids.push(epoch.id);
    }
    ids.sort_unstable();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(refused("a domain named twice"));
    }
    let mut settled = live.settled.clone();
    settled.sort_unstable();
    settled.dedup();
    Ok(HistoryLiveSet {
        revision: live.revision,
        live: ids,
        settled,
    })
}

#[tonic::async_trait]
impl HistoryPreparation for HistoryEvaluation {
    async fn prepare(
        &self,
        admission: &HistoryAdmission,
    ) -> Result<Vec<HistoryEpochDescriptor>, Status> {
        HistoryEvaluation::prepare(self, admission).await
    }
}

/// The evaluator as its own service, called by the credential service with
/// its own token for the evaluator's resource.
pub struct RemoteHistoryEvaluator {
    client: PasswordHistoryEvaluatorServiceClient<
        sid_authn::client_credential::WithCredential<tonic::transport::Channel>,
    >,
}

impl RemoteHistoryEvaluator {
    /// The evaluator reached over `channel`, authenticated with `credential`
    /// (a client credential for the evaluator's resource).
    pub fn new(
        channel: tonic::transport::Channel,
        credential: Arc<sid_authn::client_credential::ClientCredential>,
    ) -> Self {
        Self {
            client: PasswordHistoryEvaluatorServiceClient::new(
                sid_authn::client_credential::WithCredential::new(channel, credential),
            ),
        }
    }
}

/// The selection a preparation answer carries, when it is well formed: as
/// many epochs as domains, within the bound, each domain the one its epoch
/// describes under the shared relation.
fn selection_of(response: &PreparePasswordHistoryResponse) -> Option<Vec<HistoryEpochDescriptor>> {
    if response.epochs.is_empty()
        || response.epochs.len() > MAX_HISTORY_DOMAINS
        || response.epochs.len() != response.domains.len()
    {
        return None;
    }
    response
        .epochs
        .iter()
        .zip(&response.domains)
        .map(|(epoch, domain)| {
            let epoch = descriptor_of(epoch)?;
            (domain_message(&OperationDomain::of(&epoch)) == *domain).then_some(epoch)
        })
        .collect()
}

#[tonic::async_trait]
impl HistoryPreparation for RemoteHistoryEvaluator {
    async fn prepare(
        &self,
        admission: &HistoryAdmission,
    ) -> Result<Vec<HistoryEpochDescriptor>, Status> {
        let live = &admission.live;
        let response = self
            .client
            .clone()
            .prepare_password_history(PreparePasswordHistoryRequest {
                operation_id: Some(admission.id.into()),
                owner_domain: admission.owner_domain.to_vec(),
                owner_kind: admission.kind.message() as i32,
                expires_at: Some(super::convert::to_timestamp(admission.expires_at)),
                charge_key: admission.charge_key.clone(),
                live_comparison_domains: live.domains.iter().map(|d| d.to_vec()).collect(),
                history_revision: u64::try_from(live.revision).map_err(internal)?,
                settled_operations: live
                    .settled
                    .iter()
                    .map(|op| sid_ids_proto::PasswordOperationId {
                        value: op.as_bytes().to_vec(),
                    })
                    .collect(),
            })
            .await
            .map_err(|status| {
                // The client learns that history is unavailable, not why the
                // evaluator refused this service.
                warn!(
                    "history evaluator refused preparation: {:?} {}",
                    status.code(),
                    status.message()
                );
                unavailable("evaluator")
            })?
            .into_inner();
        selection_of(&response).ok_or_else(|| {
            warn!(
                "history evaluator answered a malformed selection of {} epochs",
                response.epochs.len()
            );
            unavailable("evaluator")
        })
    }
}

/// The admission a preparation request carries, decoded; the evaluator
/// checks each live domain against the owner's epochs.
#[allow(clippy::result_large_err)]
fn admission_of(req: &PreparePasswordHistoryRequest) -> Result<HistoryAdmission, Status> {
    if req.live_comparison_domains.len() > MAX_HISTORY_DOMAINS {
        return Err(invalid_field(
            "live_comparison_domains",
            "more domains than an operation holds",
        ));
    }
    if req.settled_operations.len() > sid_core::models::password_history::MAX_HISTORY_DEPTH as usize
    {
        return Err(invalid_field(
            "settled_operations",
            "more operations than history retains",
        ));
    }
    let mut domains = req
        .live_comparison_domains
        .iter()
        .map(|d| array32(d, "live_comparison_domains"))
        .collect::<Result<Vec<_>, Status>>()?;
    domains.sort_unstable();
    let settled = req
        .settled_operations
        .iter()
        .map(|op| operation_id(Some(op)).map(|id| id.into_uuid()))
        .collect::<Result<Vec<_>, Status>>()?;
    let expires_at = req
        .expires_at
        .as_ref()
        .and_then(|t| chrono::DateTime::from_timestamp(t.seconds, u32::try_from(t.nanos).ok()?))
        .ok_or_else(|| invalid_field("expires_at", "a valid instant"))?;
    Ok(HistoryAdmission {
        id: operation_id(req.operation_id.as_ref())?,
        owner_domain: array32(&req.owner_domain, "owner_domain")?,
        kind: OwnerKind::of_message(req.owner_kind)
            .ok_or_else(|| invalid_field("owner_kind", "a specified owner kind"))?,
        expires_at,
        charge_key: req.charge_key.clone(),
        live: LiveDomains {
            revision: i64::try_from(req.history_revision)
                .map_err(|_| invalid_field("history_revision", "out of range"))?,
            domains,
            settled,
        },
    })
}

/// Who may prepare at the evaluator over the network: the deployment that
/// serves the evaluator decides, for the one credential service it serves.
#[tonic::async_trait]
pub trait PrepareAdmission: Send + Sync {
    /// Admit `request` as the credential service's, or refuse it without
    /// saying which check failed.
    async fn admit(&self, request: &Request<PreparePasswordHistoryRequest>) -> Result<(), Status>;
}

/// Nobody prepares over the network: the credential service in this process
/// prepares in process.
pub struct InProcessOnly;

#[tonic::async_trait]
impl PrepareAdmission for InProcessOnly {
    async fn admit(&self, _: &Request<PreparePasswordHistoryRequest>) -> Result<(), Status> {
        Err(ApiError::new(
            ErrorReason::InsufficientPermissions,
            "preparing password history is reserved to the credential service",
        )
        .into())
    }
}

/// The VOPRF evaluator interface: its own gRPC service, composed from a
/// [`HistoryEvaluation`] and the deployment's [`PrepareAdmission`] alone, so
/// a split deployment serves it from the key-holding process without any
/// other part of an identity provider; a standalone installation
/// co-locates it with the credential service.
pub struct PasswordHistoryEvaluatorImpl {
    evaluation: Arc<HistoryEvaluation>,
    admission: Arc<dyn PrepareAdmission>,
}

impl PasswordHistoryEvaluatorImpl {
    pub fn new(evaluation: Arc<HistoryEvaluation>, admission: Arc<dyn PrepareAdmission>) -> Self {
        Self {
            evaluation,
            admission,
        }
    }
}

#[tonic::async_trait]
impl PasswordHistoryEvaluatorService for PasswordHistoryEvaluatorImpl {
    #[tracing::instrument(skip_all, fields(rpc = "evaluate_password_history"))]
    async fn evaluate_password_history(
        &self,
        request: Request<EvaluatePasswordHistoryRequest>,
    ) -> Result<Response<EvaluatePasswordHistoryResponse>, Status> {
        let req = request.into_inner();
        let id = operation_id(req.operation_id.as_ref())?;
        let evaluations = self.evaluation.evaluate(&id, &req.blinded_input).await?;
        Ok(Response::new(EvaluatePasswordHistoryResponse {
            evaluations,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "prepare_password_history"))]
    async fn prepare_password_history(
        &self,
        request: Request<PreparePasswordHistoryRequest>,
    ) -> Result<Response<PreparePasswordHistoryResponse>, Status> {
        self.admission.admit(&request).await?;
        let admission = admission_of(request.get_ref())?;
        let epochs = self.evaluation.prepare(&admission).await?;
        Ok(Response::new(PreparePasswordHistoryResponse {
            domains: epochs
                .iter()
                .map(|e| domain_message(&OperationDomain::of(e)))
                .collect(),
            epochs: epochs.iter().map(descriptor_message).collect(),
        }))
    }
}

#[cfg(test)]
mod tests;
