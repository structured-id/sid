// SPDX-License-Identifier: AGPL-3.0-only
//! The password operation over gRPC: the status of each refusal, the
//! evaluator reached as its own service and the evaluator's service.

use std::sync::Arc;
use std::time::Duration;

use sid_core::grpc_error::refuse::invalid_field;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::HistoryEpochDescriptor;
use sid_core::models::password_history::MAX_HISTORY_DOMAINS;
use sid_proto::sid::v1::authn::password_history_evaluator_service_client::PasswordHistoryEvaluatorServiceClient;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorService;
use sid_proto::sid::v1::authn::{
    EvaluatePasswordHistoryRequest, EvaluatePasswordHistoryResponse, PreparePasswordHistoryRequest,
    PreparePasswordHistoryResponse,
};
use tonic::{Request, Response, Status};
use tracing::warn;

use super::{
    EVALUATION_WINDOW, HistoryAdmission, HistoryEvaluation, HistoryPreparation, LiveDomains,
    OwnerKind, PasswordOperationError, array32, descriptor_message, descriptor_of, domain_message,
    internal, operation_id, timestamp, unavailable,
};
use crate::password_history::OperationDomain;

impl From<PasswordOperationError> for Status {
    fn from(e: PasswordOperationError) -> Self {
        use PasswordOperationError as E;
        let message = e.to_string();
        match e {
            E::Unavailable(_) => ApiError::new(ErrorReason::PasswordHistoryUnavailable, message)
                .with_retry_after(Duration::from_secs(5))
                .into(),
            E::Internal => ApiError::internal().into(),
            E::NotPending => ApiError::new(ErrorReason::OperationExpired, message).into(),
            E::StepMissing(what) => ApiError::new(ErrorReason::InvalidState, what)
                .with_precondition("PASSWORD_OPERATION_STEP", "password_operation", what)
                .into(),
            E::HistoryKeyWithdrawn => ApiError::new(ErrorReason::InvalidState, message)
                .with_precondition(
                    "PASSWORD_HISTORY_WRITE_CUTOFF",
                    "password_operation",
                    "start a new operation under a current history key",
                )
                .into(),
            E::PolicyChanged => ApiError::new(ErrorReason::InvalidState, message)
                .with_precondition(
                    "PASSWORD_POLICY_VERSION",
                    "password_operation",
                    "start a new operation under the current policy",
                )
                .into(),
            E::HistoryChanged => ApiError::new(ErrorReason::ConcurrentModification, message).into(),
            E::InvalidProof => ApiError::new(ErrorReason::PasswordProofInvalid, message).into(),
            E::Reused => ApiError::new(ErrorReason::PasswordReused, message).into(),
            E::RateLimited => ApiError::new(ErrorReason::RateLimitExceeded, message)
                .with_retry_after(EVALUATION_WINDOW)
                .into(),
            E::Conflict(_) => ApiError::new(ErrorReason::OperationKeyConflict, message).into(),
            E::Required { field, .. } => ApiError::new(ErrorReason::RequiredFieldMissing, message)
                .with_field_violation(field, "required")
                .into(),
            E::InvalidField { field, reason } => invalid_field(field, reason),
            E::InvalidOperationId(_) => ApiError::new(ErrorReason::InvalidFieldValue, message)
                .with_field_violation("operation_id", "a password operation id")
                .into(),
            E::Ceremony(e) => e.into(),
            E::Operation(e) => e.into(),
        }
    }
}

/// The evaluator as its own service: a component of the same password
/// service, reached over the deployment's protected internal transport. The
/// evaluator is not a separate resource the credential service needs a grant
/// for; the deployment keeps its Prepare route internal ([`InternalTransport`]).
pub struct RemoteHistoryEvaluator {
    client: PasswordHistoryEvaluatorServiceClient<tonic::transport::Channel>,
}

impl RemoteHistoryEvaluator {
    /// The evaluator's internal Prepare listener reached over `channel`.
    pub fn new(channel: tonic::transport::Channel) -> Self {
        Self {
            client: PasswordHistoryEvaluatorServiceClient::new(channel),
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

#[async_trait::async_trait]
impl HistoryPreparation for RemoteHistoryEvaluator {
    async fn prepare(
        &self,
        admission: &HistoryAdmission,
    ) -> Result<Vec<HistoryEpochDescriptor>, PasswordOperationError> {
        let live = &admission.live;
        let response = self
            .client
            .clone()
            .prepare_password_history(PreparePasswordHistoryRequest {
                operation_id: Some(admission.id.into()),
                owner_domain: admission.owner_domain.to_vec(),
                owner_kind: admission.kind.message() as i32,
                expires_at: Some(timestamp(admission.expires_at)),
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
fn admission_of(
    req: &PreparePasswordHistoryRequest,
) -> Result<HistoryAdmission, PasswordOperationError> {
    let field = |field, reason| PasswordOperationError::InvalidField { field, reason };
    if req.live_comparison_domains.len() > MAX_HISTORY_DOMAINS {
        return Err(field(
            "live_comparison_domains",
            "more domains than an operation holds",
        ));
    }
    if req.settled_operations.len() > sid_core::models::password_history::MAX_HISTORY_DEPTH as usize
    {
        return Err(field(
            "settled_operations",
            "more operations than history retains",
        ));
    }
    let mut domains = req
        .live_comparison_domains
        .iter()
        .map(|d| array32(d, "live_comparison_domains"))
        .collect::<Result<Vec<_>, _>>()?;
    domains.sort_unstable();
    let settled = req
        .settled_operations
        .iter()
        .map(|op| operation_id(Some(op)).map(|id| id.into_uuid()))
        .collect::<Result<Vec<_>, _>>()?;
    let expires_at = req
        .expires_at
        .as_ref()
        .and_then(|t| chrono::DateTime::from_timestamp(t.seconds, u32::try_from(t.nanos).ok()?))
        .ok_or_else(|| field("expires_at", "a valid instant"))?;
    Ok(HistoryAdmission {
        id: operation_id(req.operation_id.as_ref())?,
        owner_domain: array32(&req.owner_domain, "owner_domain")?,
        kind: OwnerKind::of_message(req.owner_kind)
            .ok_or_else(|| field("owner_kind", "a specified owner kind"))?,
        expires_at,
        charge_key: req.charge_key.clone(),
        live: LiveDomains {
            revision: i64::try_from(req.history_revision)
                .map_err(|_| field("history_revision", "out of range"))?,
            domains,
            settled,
        },
    })
}

/// Whether the listener serving the evaluator offers Prepare. Prepare is an
/// internal call of the credential component; which listener carries it is
/// the deployment's transport boundary, not a SID authorization decision.
#[tonic::async_trait]
pub trait PrepareAdmission: Send + Sync {
    /// Admit `request` on this listener, or refuse it without saying why.
    async fn admit(&self, request: &Request<PreparePasswordHistoryRequest>) -> Result<(), Status>;
}

/// A listener clients reach: it serves Evaluate and refuses Prepare. A
/// standalone installation's co-located credential service prepares in
/// process; a separate evaluator takes Prepare on its internal listener.
pub struct ClientListener;

#[tonic::async_trait]
impl PrepareAdmission for ClientListener {
    async fn admit(&self, _: &Request<PreparePasswordHistoryRequest>) -> Result<(), Status> {
        Err(ApiError::new(
            ErrorReason::InsufficientPermissions,
            "preparing password history is reserved to the credential service",
        )
        .into())
    }
}

/// The separate evaluator's internal listener, which the deployment's
/// protected internal transport (mesh mTLS and network isolation) makes
/// reachable by the credential service alone and by no ingress route. It
/// admits every Prepare it receives; no request header establishes origin.
pub struct InternalTransport;

#[tonic::async_trait]
impl PrepareAdmission for InternalTransport {
    async fn admit(&self, _: &Request<PreparePasswordHistoryRequest>) -> Result<(), Status> {
        Ok(())
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
