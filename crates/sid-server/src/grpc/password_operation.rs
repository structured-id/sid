// SPDX-License-Identifier: AGPL-3.0-only
//! One password-installing operation, shared by registration, password change
//! and authorized reset (arch/auth/password-history.md,
//! #rpc-composition-and-performance):
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
//! Every credential has its own OPRF key (`credential_identifier`, drawn at
//! prepare and stored with the credential). Before the commit that key has
//! evaluated exactly one element, the request the proof is bound to, so the
//! final record can only be the enrollment of the proved password: an OPRF
//! output for another password under this key does not exist anywhere.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::operation::KeyedCommand;
use sid_authn::password_history::{
    CheckRequest, HistoryCheckError, HistoryChecker, HistoryEvaluator, MAX_HISTORY_DOMAINS,
    OperationDomain, OperationEvaluation, decoy_domain, inputs_match, owner_domain,
};
use sid_core::grpc_error::refuse::invalid_field;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::password_history::DEFAULT_HISTORY_DEPTH;
use sid_core::models::{
    AuditEntry, Credential, CredentialId, CredentialType, HistoryCommit, HistoryEvidence,
    HistoryKsf, MutationContext, NewHistoryEpoch, OperationCompletion, OperationKey,
    PasswordHistory, ProfileId, ResetSessionId,
};
use sid_ids::PasswordOperationId;
use sid_pake_core::prover::BoundProof;
use sid_pake_core::types::ZkppProof;
use sid_plugin::cache::CacheBackend;
use sid_plugin::crypto::CurveId;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorService;
use sid_proto::sid::v1::authn::{
    EvaluatePasswordHistoryRequest, EvaluatePasswordHistoryResponse, PasswordHistoryContext,
    PasswordHistoryDomain, PasswordHistoryEvaluation, PasswordHistoryEvaluationProof,
    PasswordRegistrationProof,
};
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

/// A prepared operation between its steps.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PendingOperation {
    pub id: PasswordOperationId,
    pub purpose: OperationPurpose,
    /// The credential owner; random for a decoy.
    pub owner: ProfileId,
    /// A registration start for an identifier someone holds: it behaves like
    /// any other and commits nothing.
    pub decoy: bool,
    pub owner_domain: [u8; 32],
    pub domains: Vec<OperationDomain>,
    /// The owner's history revision the domains were read at.
    pub history_revision: i64,
    /// A new owner's first epoch, created at preparation and stored with the
    /// account.
    pub new_epoch: Option<NewHistoryEpoch>,
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
}

impl PendingOperation {
    /// The durable-result command of this operation's finish with `record`.
    fn finish_command(&self, record: &[u8]) -> KeyedCommand {
        finish_command(&self.id, self.purpose.method(), record)
    }
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
    /// Whether an accepted proof verified this password.
    pub proof_verified: bool,
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
        credential.zkpp_verified = self.proof_verified;
        credential.policy_version = self.proof_verified.then_some(self.operation.policy_version);
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

/// The shared lifecycle; one per replica.
pub(crate) struct PasswordOperations {
    storage: Arc<dyn StorageBackend>,
    cache: Arc<dyn CacheBackend>,
    evaluator: HistoryEvaluator,
    checker: HistoryChecker,
    ops: ChallengeStore<PendingOperation>,
    installation: [u8; 16],
    ksf: HistoryKsf,
    depth: u32,
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

impl PasswordOperations {
    pub(crate) fn new(
        storage: Arc<dyn StorageBackend>,
        cache: Arc<dyn CacheBackend>,
        keys: Arc<dyn sid_keys::KeyManager>,
        installation: sid_core::models::OrgId,
    ) -> Self {
        Self {
            storage,
            cache: cache.clone(),
            evaluator: HistoryEvaluator::new(keys.clone()),
            checker: HistoryChecker::new(sid_authn::password_history::KsfAdmission::new(
                KSF_BUDGET_MIB,
                KSF_WAIT,
            )),
            ops: ChallengeStore::new(cache, keys, "password-operation", OPERATION_TTL),
            installation: *installation.as_bytes(),
            ksf: HistoryKsf::DEFAULT,
            depth: DEFAULT_HISTORY_DEPTH,
        }
    }

    fn key(id: &PasswordOperationId) -> String {
        id.to_string()
    }

    async fn store(&self, op: &PendingOperation) -> Result<(), Status> {
        self.ops.insert(&Self::key(&op.id), op).await?;
        Ok(())
    }

    /// Take the pending operation `id` exclusively; a concurrent step of the
    /// same operation, an expired one or an unknown id is refused.
    async fn take(&self, id: &PasswordOperationId) -> Result<PendingOperation, Status> {
        self.ops.take(&Self::key(id)).await?.ok_or_else(expired)
    }

    /// Prepare an operation for `owner` under `purpose`: its history domains,
    /// the revision they were read at and, for a new owner, its first epoch.
    /// With `registration_request` the OPAQUE start runs here too, so a
    /// registration needs no separate start step.
    pub(crate) async fn prepare(
        &self,
        zkpp: &ZkppOpaqueServer,
        purpose: OperationPurpose,
        owner: OperationOwner,
        charge_key: String,
        registration_request: Option<Vec<u8>>,
    ) -> Result<Prepared, Status> {
        let (owner, decoy, domains, history_revision, new_epoch) = match owner {
            OperationOwner::New(profile_id) => {
                let epoch = self
                    .evaluator
                    .new_epoch(profile_id, self.ksf)
                    .await
                    .map_err(internal)?;
                let domains = vec![OperationDomain::of(&epoch.epoch)];
                (profile_id, false, domains, 0, Some(epoch))
            }
            OperationOwner::Existing(profile_id) => {
                let history = self.current_history(profile_id).await?;
                let required = history.required_epochs();
                if required.len() > MAX_HISTORY_DOMAINS {
                    warn!(
                        "profile {profile_id} requires {} history domains",
                        required.len()
                    );
                    return Err(unavailable("too many history epochs"));
                }
                let domains = required.into_iter().map(OperationDomain::of).collect();
                (profile_id, false, domains, history.revision, None)
            }
            OperationOwner::Decoy => (ProfileId::generate(), true, vec![decoy_domain()], 0, None),
        };
        let mut op = PendingOperation {
            id: PasswordOperationId::generate(),
            purpose,
            owner,
            decoy,
            owner_domain: owner_domain(&self.installation, owner),
            domains,
            history_revision,
            new_epoch,
            policy_version: zkpp.config().policy_version,
            charge_key,
            credential_identifier: rand::random(),
            registration_request: None,
            evaluation: None,
        };
        let registration_response = match registration_request {
            Some(request) => Some(Self::start_opaque(zkpp, &mut op, request)?),
            None => None,
        };
        self.store(&op).await?;
        let context = PasswordHistoryContext {
            operation_id: Some(op.id.into()),
            owner_domain: op.owner_domain.to_vec(),
            domains: op
                .domains
                .iter()
                .map(|d| PasswordHistoryDomain {
                    comparison_domain: d.comparison_domain.to_vec(),
                    evaluator_public_key: d.public_key.to_vec(),
                })
                .collect(),
            policy_version: op.policy_version,
        };
        Ok(Prepared {
            context,
            registration_response,
        })
    }

    /// The owner's history with an active epoch, creating one (key sealed
    /// and stored before first use) when the owner has none.
    async fn current_history(&self, owner: ProfileId) -> Result<PasswordHistory, Status> {
        let history = self
            .storage
            .get_password_history(owner)
            .await
            .map_err(internal)?;
        if history.active_epoch().is_some() {
            return Ok(history);
        }
        let epoch = self
            .evaluator
            .new_epoch(owner, self.ksf)
            .await
            .map_err(internal)?;
        self.storage
            .ensure_history_epoch(
                &epoch,
                MutationContext::from(AuditEntry::system(
                    "password_history.epoch_created",
                    owner.to_string(),
                )),
            )
            .await
            .map_err(internal)?;
        self.storage
            .get_password_history(owner)
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
        let evaluation = if op.decoy {
            self.evaluator
                .evaluate_decoy(blinded, op.domains.len(), context)
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
    /// record is the one it was committed with.
    pub(crate) async fn finish(
        &self,
        zkpp: Arc<ZkppOpaqueServer>,
        id: &PasswordOperationId,
        method: &'static str,
        record: &[u8],
        proof: Option<PasswordRegistrationProof>,
        authorized: impl FnOnce(&PendingOperation) -> Result<(), Status>,
    ) -> Result<Finish, Status> {
        let Some(op) = self.ops.take(&Self::key(id)).await? else {
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
                proof_verified: false,
                history: None,
                command,
            })));
        };
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

        // Proof verification is CPU-bound: off the async runtime, outside
        // any transaction.
        let verifier = Arc::clone(&zkpp);
        let public =
            tokio::task::spawn_blocking(move || verifier.verify(&proof, &op_id, &request, domains))
                .await
                .map_err(internal)?
                .map_err(|e| {
                    warn!("password proof refused: {e}");
                    invalid_proof()
                })?;

        if op.decoy {
            // Verified like any proof; the purpose refuses the commit.
            return Ok(Finish::Ready(Box::new(FinishedOperation {
                operation: op,
                password_file,
                proof_verified: true,
                history: None,
                command,
            })));
        }

        let evaluation = op
            .evaluation
            .clone()
            .ok_or_else(|| step_missing("the operation was not evaluated"))?;
        let history = match &op.new_epoch {
            Some(new) => PasswordHistory {
                revision: 0,
                epochs: vec![new.epoch.clone()],
                entries: vec![],
            },
            None => {
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
            proof_verified: true,
            history: Some(commit),
            command,
        })))
    }
}

/// The VOPRF evaluator interface: its own gRPC service, so a SaaS deployment
/// serves it from the key-holding process alone; a CE installation
/// co-locates it with the credential service.
pub struct PasswordHistoryEvaluatorImpl {
    ops: Arc<PasswordOperations>,
}

impl PasswordHistoryEvaluatorImpl {
    pub(crate) fn new(ops: Arc<PasswordOperations>) -> Self {
        Self { ops }
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
        let evaluations = self.ops.evaluate(&id, &req.blinded_input).await?;
        Ok(Response::new(EvaluatePasswordHistoryResponse {
            evaluations,
        }))
    }
}

#[cfg(test)]
mod tests;
