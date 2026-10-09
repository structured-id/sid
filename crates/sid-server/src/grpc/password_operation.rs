// SPDX-License-Identifier: AGPL-3.0-only
//! One password-installing operation, shared by registration, password change
//! and authorized reset:
//!
//! - **prepare**: the purpose's own authorized step starts the operation, with
//!   the owner's history snapshot, required comparison domains and revision;
//! - **evaluate**: the VOPRF evaluator answers the blinded history input,
//!   charged before any key is used, once per operation;
//! - **OPAQUE**: the operation's registration request and its response, under
//!   the OPRF key of the credential the operation installs;
//! - **finish**: proof verification and the history check run outside any
//!   database transaction, then the purpose commits the credential, its
//!   evidence, the accepted history entry and the operation's durable result
//!   together.
//!
//! The pending operation lives in the shared ceremony store, sealed, so any
//! replica serves any step and a step takes it exclusively. No tag or
//! candidate KSF output is ever stored in it.
//!
//! Two authorities share that store and nothing else secret:
//!
//! - the credential service ([`PasswordOperations`]) prepares, starts and
//!   finishes the operation and runs the history checker: it reads retained
//!   entries and the proof's tags, and holds no history key;
//! - the history evaluator ([`HistoryEvaluation`]) selects the operation's
//!   comparison domains, creating or replacing the owner's epoch, and
//!   evaluates the blinded input: it holds the history keys and never reads
//!   an entry or a tag.
//!
//! A standalone installation runs both in one process with one key manager,
//! so compromising that process merges them. A split deployment runs the
//! evaluator as its own service with its own key manager for history keys;
//! both seal the pending operation with a shared operation key that opens
//! nothing else. The credential service asks the evaluator for domains over
//! [`PasswordHistoryEvaluatorService`], authenticated as itself.
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
    OperationDomain, OperationEvaluation, decoy_domain, inputs_match, owner_domain,
};
use sid_core::grpc_error::refuse::invalid_field;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::password_history::DEFAULT_HISTORY_DEPTH;
use sid_core::models::password_history::MAX_HISTORY_DOMAINS;
use sid_core::models::{
    AuditEntry, Credential, CredentialId, CredentialType, HistoryCommit, HistoryEpochUse,
    HistoryEpochs, HistoryEvidence, HistoryKsf, MutationContext, NewHistoryEpoch,
    OperationCompletion, OperationKey, PasswordHistory, PolicyEvidence, ProfileId, ResetSessionId,
};
use sid_ids::PasswordOperationId;
use sid_pake_core::prover::BoundProof;
use sid_pake_core::types::ZkppProof;
use sid_plugin::cache::CacheBackend;
use sid_plugin::crypto::{CurveId, LoginState};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::authn::password_history_evaluator_service_client::PasswordHistoryEvaluatorServiceClient;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorService;
use sid_proto::sid::v1::authn::{
    EvaluatePasswordHistoryRequest, EvaluatePasswordHistoryResponse, PasswordHistoryContext,
    PasswordHistoryDomain, PasswordHistoryEvaluation, PasswordHistoryEvaluationProof,
    PasswordRegistrationProof, PreparePasswordHistoryRequest, PreparePasswordHistoryResponse,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::{Request, Response, Status};
use tracing::warn;

use super::auth_service::PendingRegistration;

/// How long a prepared operation waits for its next step. Covers proving on
/// a weak device (tens of seconds) with room for the user.
const OPERATION_TTL: Duration = Duration::from_secs(15 * 60);
/// History evaluations one subject may be charged per window.
const EVALUATIONS_PER_WINDOW: u64 = 30;
const EVALUATION_WINDOW: Duration = Duration::from_secs(60 * 60);
/// How long a finish waits for KSF memory before reporting unavailable.
const KSF_WAIT: Duration = Duration::from_secs(10);
/// Concurrent KSF memory one replica admits, MiB.
const KSF_BUDGET_MIB: u32 = 512;
/// Namespace of the operations' durable results.
const RESULT_NAMESPACE: &str = "password-operation";

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

/// A prepared operation between its steps.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PendingOperation {
    pub id: PasswordOperationId,
    pub purpose: OperationPurpose,
    /// The credential owner; random for a decoy.
    pub owner: ProfileId,
    pub kind: OwnerKind,
    pub owner_domain: [u8; 32],
    /// Selected by the evaluator; empty until it has.
    pub domains: Vec<OperationDomain>,
    /// The owner's history revision the domains were read at.
    pub history_revision: i64,
    /// A new owner's first epoch, created by the evaluator and stored with
    /// the account; its key is sealed for the evaluator alone.
    pub new_epoch: Option<NewHistoryEpoch>,
    /// A decoy's throwaway evaluation keys, one per domain: its answers
    /// verify under the domain keys the client got, as a real one's do.
    /// Empty for any other operation.
    pub decoy_keys: Vec<[u8; 32]>,
    pub policy_version: u32,
    /// Who this operation's evaluation is charged to.
    pub charge_key: String,
    /// The OPRF credential identifier of the password this operation installs:
    /// the key under which its registration request is evaluated and, once
    /// committed, its logins are.
    pub credential_identifier: [u8; 16],
    /// The operation's OPAQUE registration request, once sent.
    pub registration_request: Option<Vec<u8>>,
    /// The evaluator's answers, kept for an exact retry and for the checker.
    pub evaluation: Option<OperationEvaluation>,
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
    /// Selects each operation's comparison domains.
    evaluator: Arc<dyn HistoryPreparation>,
    checker: HistoryChecker,
    // Local compute capacity, not authorization/rate-limit authority. A permit
    // bounds one fixed-shape verifier workspace and remains with its task.
    proof_permits: Arc<Semaphore>,
    ops: ChallengeStore<PendingOperation>,
    installation: [u8; 16],
    depth: u32,
}

/// The pending-operation store both authorities read: sealed under the
/// operation key, which opens nothing else in a split deployment.
fn operation_store(
    cache: Arc<dyn CacheBackend>,
    operation_keys: Arc<dyn sid_keys::KeyManager>,
) -> ChallengeStore<PendingOperation> {
    ChallengeStore::new(cache, operation_keys, "password-operation", OPERATION_TTL)
}

/// Selects the comparison domains of a stored pending operation: the
/// history evaluator, in this process or as its own service.
#[tonic::async_trait]
pub(crate) trait HistoryPreparation: Send + Sync {
    /// The domains of the operation `id`, as the client receives them. The
    /// evaluator records them in the operation; repeating the call returns
    /// the same domains.
    async fn prepare(&self, id: &PasswordOperationId)
    -> Result<Vec<PasswordHistoryDomain>, Status>;
}

fn domain_message(d: &OperationDomain) -> PasswordHistoryDomain {
    PasswordHistoryDomain {
        comparison_domain: d.comparison_domain.to_vec(),
        evaluator_public_key: d.public_key.to_vec(),
    }
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

/// Where a credential service's history evaluator runs.
pub enum PasswordHistoryAuthority {
    /// In this process, sealing history keys with `history_keys`: a
    /// standalone installation, where compromising the process merges
    /// evaluator and checker. Pending operations are sealed with the
    /// service's own field keys.
    InProcess {
        history_keys: Arc<dyn sid_keys::KeyManager>,
        /// Epochs created before it are replaced at their next operation.
        epoch_cutoff: Option<chrono::DateTime<chrono::Utc>>,
        /// Also the evaluator of a remote credential service: pending
        /// operations are then sealed with the key shared with it.
        serve: Option<EvaluatorService>,
    },
    /// Its own service. Pending operations are sealed with
    /// `operation_keys`, which the evaluator shares and which open nothing
    /// else; this process holds no history key.
    Remote {
        evaluator: RemoteHistoryEvaluator,
        operation_keys: Arc<dyn sid_keys::KeyManager>,
    },
}

/// What this server needs to serve the evaluator to a remote credential
/// service.
pub struct EvaluatorService {
    /// Seals pending operations; the credential service holds the same key.
    pub operation_keys: Arc<dyn sid_keys::KeyManager>,
    /// The authorization subject of the one service admitted to prepare.
    pub caller: String,
    /// The evaluator's resource indicator its access tokens name.
    pub resource: sid_core::models::ResourceIndicator,
}

impl PasswordOperations {
    /// The credential side under `authority`, with the evaluator it serves
    /// when that runs in this process. `field_keys` seal pending operations
    /// unless the evaluator is remote.
    pub(crate) fn with_authority(
        storage: Arc<dyn StorageBackend>,
        cache: Arc<dyn CacheBackend>,
        field_keys: Arc<dyn sid_keys::KeyManager>,
        installation: sid_core::models::OrgId,
        authority: PasswordHistoryAuthority,
    ) -> (Self, Option<Arc<HistoryEvaluation>>) {
        match authority {
            PasswordHistoryAuthority::InProcess {
                history_keys,
                epoch_cutoff,
                serve,
            } => {
                let operation_keys = serve.map_or(field_keys, |s| s.operation_keys);
                let evaluation = Arc::new(
                    HistoryEvaluation::new(
                        storage.clone(),
                        cache.clone(),
                        history_keys,
                        operation_keys.clone(),
                    )
                    .with_epoch_cutoff(epoch_cutoff),
                );
                let ops = Self::new(
                    storage,
                    cache,
                    operation_keys,
                    installation,
                    evaluation.clone(),
                );
                (ops, Some(evaluation))
            }
            PasswordHistoryAuthority::Remote {
                evaluator,
                operation_keys,
            } => (
                Self::new(
                    storage,
                    cache,
                    operation_keys,
                    installation,
                    Arc::new(evaluator),
                ),
                None,
            ),
        }
    }

    /// The credential side over `storage`, sealing pending operations with
    /// `operation_keys` and asking `evaluator` for comparison domains.
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
            ops: operation_store(cache, operation_keys),
            installation: *installation.as_bytes(),
            depth: DEFAULT_HISTORY_DEPTH,
        }
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

    /// Prepare an operation for `owner` under `purpose`: stored first, then
    /// the evaluator selects its history domains (for a new owner, its first
    /// epoch) and the revision they were read at. With
    /// `registration_request` the OPAQUE start runs here too, so a
    /// registration needs no separate start step.
    pub(crate) async fn prepare(
        &self,
        zkpp: &ZkppOpaqueServer,
        purpose: OperationPurpose,
        owner: OperationOwner,
        charge_key: String,
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
            domains: Vec::new(),
            history_revision: 0,
            new_epoch: None,
            decoy_keys: Vec::new(),
            policy_version: zkpp.config().policy_version,
            charge_key,
            credential_identifier: rand::random(),
            registration_request: None,
            evaluation: None,
            current_password: CurrentPassword::Absent,
        };
        let registration_response = match registration_request {
            Some(request) => Some(Self::start_opaque(zkpp, &mut op, request)?),
            None => None,
        };
        self.store(&op).await?;
        let domains = self.evaluator.prepare(&op.id).await?;
        let context = PasswordHistoryContext {
            operation_id: Some(op.id.into()),
            owner_domain: op.owner_domain.to_vec(),
            domains,
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
    /// proved, the proof. Takes the operation for good; a proof, history or
    /// record that fails leaves nothing to retry but a new operation. An
    /// operation already committed answers with its recorded result when the
    /// record is the one it was committed with. Exhausted proof capacity restores
    /// the pending operation for an exact retry; it is not a rejected proof.
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
        if op.domains.is_empty() {
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
        let (proof_len, instance_count) = zkpp
            .proof_lengths(op.domains.len())
            .map_err(|_| invalid_proof())?;
        if proof.zkpp_proof.len() != proof_len || proof.instances.len() != instance_count {
            return Err(invalid_proof());
        }
        let proof = decode_proof(proof)?;
        let (op_id, domains) = (*op.id.as_bytes(), op.domains.len());

        // Microsecond checks before the SNARK: the proof's form, then its
        // claimed history inputs against what this operation already holds
        // (owner domain, blinded input, domains, the evaluator's answers).
        // A submission made for another operation, or garbage, never costs a
        // SNARK check; the operation is taken, so each attempt is one try.
        let claimed = zkpp.claimed_inputs(&proof, domains).map_err(|e| {
            warn!("password proof refused before verification: {e}");
            invalid_proof()
        })?;
        if let Some(evaluation) = &op.evaluation
            && !inputs_match(&claimed, &op.owner_domain, &op.domains, evaluation)
        {
            warn!("password proof refused before verification: inputs are not the operation's");
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
        let verified = run_proof(permit, move || {
            verifier.verify(&proof, &op_id, &request, domains)
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

        let evaluation = op
            .evaluation
            .clone()
            .ok_or_else(|| step_missing("the operation was not evaluated"))?;
        let history = match (op.kind, &op.new_epoch) {
            (OwnerKind::New, Some(new)) => PasswordHistory {
                revision: 0,
                epochs: vec![new.epoch.clone()],
                entries: vec![],
            },
            _ => {
                let current = self
                    .storage
                    .get_password_history(op.owner)
                    .await
                    .map_err(internal)?;
                if current.revision != op.history_revision {
                    return Err(ApiError::new(
                        ErrorReason::ConcurrentModification,
                        "the password history changed; start a new operation",
                    )
                    .into());
                }
                current
            }
        };
        // The evaluator chose the domains; the checker, which reads the
        // entries, accepts only the complete set its own read requires.
        if !selection_is_complete(&op, &history) {
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
                    domains: &op.domains,
                    evaluation: &evaluation,
                    context: op.id.as_bytes(),
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
            new_epoch: op.new_epoch.clone(),
            entries: checked.new_entries,
            evidence: HistoryEvidence {
                operation: op.id.into_uuid(),
                policy_version: op.policy_version,
            },
            depth: self.depth,
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

/// Whether `op`'s domains are exactly what `history` requires, in order: a
/// new owner's first epoch alone, or the active epoch and every compare-only
/// epoch that retains an entry.
fn selection_is_complete(op: &PendingOperation, history: &PasswordHistory) -> bool {
    let required: Vec<OperationDomain> = match (op.kind, &op.new_epoch) {
        (OwnerKind::New, Some(new)) => {
            if new.epoch.owner != op.owner || new.epoch.status != HistoryEpochUse::Active {
                return false;
            }
            vec![OperationDomain::of(&new.epoch)]
        }
        (OwnerKind::Existing, None) => history
            .required_epochs()
            .into_iter()
            .map(OperationDomain::of)
            .collect(),
        _ => return false,
    };
    op.domains == required
}

/// The history evaluator: it alone holds the history keys. It selects each
/// operation's comparison domains, creating or replacing the owner's epoch,
/// and evaluates the operation's blinded input; it reads epochs, never a
/// retained entry or a tag.
pub struct HistoryEvaluation {
    storage: Arc<dyn StorageBackend>,
    cache: Arc<dyn CacheBackend>,
    evaluator: HistoryEvaluator,
    ops: ChallengeStore<PendingOperation>,
    /// What new epochs are made with and when an active one is replaced.
    epochs: EpochPolicy,
}

impl HistoryEvaluation {
    /// The evaluator over `storage`, sealing history keys with
    /// `history_keys` and reading pending operations sealed with
    /// `operation_keys`. In a split deployment the two differ and only this
    /// service holds `history_keys`.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        cache: Arc<dyn CacheBackend>,
        history_keys: Arc<dyn sid_keys::KeyManager>,
        operation_keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            storage,
            cache: cache.clone(),
            evaluator: HistoryEvaluator::new(history_keys),
            ops: operation_store(cache, operation_keys),
            epochs: EpochPolicy {
                ksf: HistoryKsf::DEFAULT,
                not_before: None,
            },
        }
    }

    /// Replace epochs created before `cutoff` at their owner's next operation.
    pub fn with_epoch_cutoff(mut self, cutoff: Option<chrono::DateTime<chrono::Utc>>) -> Self {
        self.epochs.not_before = cutoff;
        self
    }

    async fn store(&self, op: &PendingOperation) -> Result<(), Status> {
        self.ops.insert(&op.id.to_string(), op).await?;
        Ok(())
    }

    async fn take(&self, id: &PasswordOperationId) -> Result<PendingOperation, Status> {
        self.ops.take(&id.to_string()).await?.ok_or_else(expired)
    }

    /// Select the domains of the stored operation `id` and record them, with
    /// the revision they were read at and a new owner's first epoch. An
    /// operation already prepared returns its domains unchanged.
    pub(crate) async fn prepare(
        &self,
        id: &PasswordOperationId,
    ) -> Result<Vec<OperationDomain>, Status> {
        let mut op = self.take(id).await?;
        let result = self.select(&mut op).await;
        self.store(&op).await?;
        result?;
        Ok(op.domains.clone())
    }

    async fn select(&self, op: &mut PendingOperation) -> Result<(), Status> {
        if !op.domains.is_empty() {
            return Ok(());
        }
        match op.kind {
            OwnerKind::New => {
                let epoch = self
                    .evaluator
                    .new_epoch(op.owner, self.epochs.ksf)
                    .await
                    .map_err(internal)?;
                op.domains = vec![OperationDomain::of(&epoch.epoch)];
                op.history_revision = 0;
                op.new_epoch = Some(epoch);
            }
            OwnerKind::Existing => {
                let epochs = self.current_epochs(op.owner).await?;
                let required = epochs.required_epochs();
                if required.len() > MAX_HISTORY_DOMAINS {
                    warn!(
                        "profile {} requires {} history domains",
                        op.owner,
                        required.len()
                    );
                    return Err(unavailable("too many history epochs"));
                }
                op.domains = required.into_iter().map(OperationDomain::of).collect();
                op.history_revision = epochs.revision;
            }
            OwnerKind::Decoy => {
                let (domain, key) = decoy_domain();
                op.domains = vec![domain];
                op.decoy_keys = vec![key];
            }
        }
        Ok(())
    }

    /// The owner's epochs with a current active one: one is created (key
    /// sealed and stored before first use) when the owner has none, and an
    /// active epoch the [`EpochPolicy`] no longer accepts is replaced, staying
    /// comparable while it retains entries.
    async fn current_epochs(&self, owner: ProfileId) -> Result<HistoryEpochs, Status> {
        let epochs = self
            .storage
            .get_history_epochs(owner)
            .await
            .map_err(internal)?;
        let replaces = match epochs.active_epoch() {
            Some(active) if self.epochs.is_current(active) => return Ok(epochs),
            Some(active) => Some(active.id),
            None => None,
        };
        let epoch = self
            .evaluator
            .new_epoch(owner, self.epochs.ksf)
            .await
            .map_err(internal)?;
        match replaces {
            Some(replaces) => self
                .storage
                .rotate_history_epoch(
                    &epoch,
                    replaces,
                    MutationContext::from(AuditEntry::system(
                        "password_history.epoch_rotated",
                        owner.to_string(),
                    )),
                )
                .await
                .map_err(internal)?,
            None => self
                .storage
                .ensure_history_epoch(
                    &epoch,
                    MutationContext::from(AuditEntry::system(
                        "password_history.epoch_created",
                        owner.to_string(),
                    )),
                )
                .await
                .map_err(internal)?,
        };
        self.storage
            .get_history_epochs(owner)
            .await
            .map_err(internal)
    }

    /// Evaluate the operation's blinded input under each required domain.
    /// Charged once per operation before any key is used; an exact retry
    /// returns the recorded answers, another input is refused.
    pub(crate) async fn evaluate(
        &self,
        id: &PasswordOperationId,
        blinded: &[u8],
    ) -> Result<Vec<PasswordHistoryEvaluation>, Status> {
        let blinded = array32(blinded, "blinded_input")?;
        let mut op = self.take(id).await?;
        let result = self.evaluate_taken(&mut op, &blinded).await;
        self.store(&op).await?;
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
        op: &mut PendingOperation,
        blinded: &[u8; 32],
    ) -> Result<OperationEvaluation, Status> {
        if op.domains.is_empty() {
            // Never handed to a client: its preparation did not complete.
            return Err(expired());
        }
        if let Some(done) = &op.evaluation {
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
                &format!("password-history-evaluations:{}", op.charge_key),
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
        let context = op.id.as_bytes();
        let evaluation = if op.kind == OwnerKind::Decoy {
            self.evaluator
                .evaluate_decoy(blinded, &op.decoy_keys, context)
        } else {
            let mut keys = Vec::with_capacity(op.domains.len());
            for domain in &op.domains {
                let key = match &op.new_epoch {
                    Some(new) if new.epoch.id == domain.epoch => Some(new.key.clone()),
                    _ => self
                        .storage
                        .get_history_epoch_key(domain.epoch)
                        .await
                        .map_err(internal)?,
                };
                let key = key.ok_or_else(|| {
                    warn!("history epoch {} has no stored key", domain.epoch.0);
                    unavailable("history key missing")
                })?;
                keys.push((domain.epoch, op.owner, key));
            }
            self.evaluator.evaluate(blinded, &keys, context).await
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
        op.evaluation = Some(evaluation.clone());
        Ok(evaluation)
    }
}

#[tonic::async_trait]
impl HistoryPreparation for HistoryEvaluation {
    async fn prepare(
        &self,
        id: &PasswordOperationId,
    ) -> Result<Vec<PasswordHistoryDomain>, Status> {
        Ok(HistoryEvaluation::prepare(self, id)
            .await?
            .iter()
            .map(domain_message)
            .collect())
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

#[tonic::async_trait]
impl HistoryPreparation for RemoteHistoryEvaluator {
    async fn prepare(
        &self,
        id: &PasswordOperationId,
    ) -> Result<Vec<PasswordHistoryDomain>, Status> {
        let domains = self
            .client
            .clone()
            .prepare_password_history(PreparePasswordHistoryRequest {
                operation_id: Some((*id).into()),
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
            .into_inner()
            .domains;
        if domains.is_empty() || domains.len() > MAX_HISTORY_DOMAINS {
            warn!("history evaluator answered {} domains", domains.len());
            return Err(unavailable("evaluator"));
        }
        Ok(domains)
    }
}

/// Who may ask the evaluator to prepare an operation.
#[derive(Clone)]
pub enum PrepareAdmission {
    /// Nobody over the network: the credential service in this process
    /// prepares in process.
    InProcess,
    /// The credential service, by its own access token for the evaluator's
    /// resource: a service caller whose authorization subject is `caller`.
    Service {
        storage: Arc<dyn StorageBackend>,
        tokens: Arc<sid_authn::resource_token::ResourceTokenVerifier>,
        revocation: Arc<sid_authn::revocation_cache::RevocationCache>,
        caller: String,
    },
}

/// The VOPRF evaluator interface: its own gRPC service, so a split deployment
/// serves it from the key-holding process alone; a standalone installation
/// co-locates it with the credential service.
pub struct PasswordHistoryEvaluatorImpl {
    evaluation: Arc<HistoryEvaluation>,
    admission: PrepareAdmission,
}

impl PasswordHistoryEvaluatorImpl {
    pub fn new(evaluation: Arc<HistoryEvaluation>, admission: PrepareAdmission) -> Self {
        Self {
            evaluation,
            admission,
        }
    }

    /// Admit a preparation request: only the configured credential service.
    /// Every refusal is the same, so a caller learns nothing about which
    /// check failed.
    async fn admit(&self, request: &Request<PreparePasswordHistoryRequest>) -> Result<(), Status> {
        let refused = || -> Status {
            ApiError::new(
                ErrorReason::InsufficientPermissions,
                "preparing password history is reserved to the credential service",
            )
            .into()
        };
        match &self.admission {
            PrepareAdmission::InProcess => Err(refused()),
            PrepareAdmission::Service {
                storage,
                tokens,
                revocation,
                caller,
            } => {
                let service = sid_authn::service_auth::authenticate_service(
                    request,
                    storage.as_ref(),
                    tokens,
                    revocation,
                )
                .await?;
                if service.subject() != *caller {
                    warn!(
                        "history preparation refused for service {}",
                        service.subject()
                    );
                    return Err(refused());
                }
                Ok(())
            }
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
        self.admit(&request).await?;
        let id = operation_id(request.get_ref().operation_id.as_ref())?;
        let domains = self.evaluation.prepare(&id).await?;
        Ok(Response::new(PreparePasswordHistoryResponse {
            domains: domains.iter().map(domain_message).collect(),
        }))
    }
}

#[cfg(test)]
mod tests;
