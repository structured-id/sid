// SPDX-License-Identifier: AGPL-3.0-only
//! The password operation over gRPC: the status of each refusal, the
//! evaluator reached as its own service and the evaluator's service. The
//! operation and its wire messages are [`sid_authn::password_operation`]'s.

use std::sync::Arc;
use std::time::Duration;

use sid_authn::password_operation::{
    EVALUATION_WINDOW, HistoryAdmission, HistoryEvaluation, HistoryPreparation,
    PasswordOperationError, StepError, operation_id, preparation_response, selection_of,
};
use sid_core::models::HistoryEpochDescriptor;
use sid_proto::sid::v1::authn::password_history_evaluator_service_client::PasswordHistoryEvaluatorServiceClient;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorService;
use sid_proto::sid::v1::authn::{
    EvaluatePasswordHistoryRequest, EvaluatePasswordHistoryResponse, PreparePasswordHistoryRequest,
    PreparePasswordHistoryResponse,
};
use tonic::{Request, Response, Status};
use tracing::warn;

use crate::grpc_error::refuse::invalid_field;
use crate::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};

impl IntoStatus for PasswordOperationError {
    fn into_status(self) -> Status {
        use PasswordOperationError as E;
        let message = self.to_string();
        match self {
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
            E::Ceremony(e) => e.into_status(),
            E::Operation(e) => e.into_status(),
        }
    }
}

impl<E: IntoStatus> IntoStatus for StepError<E> {
    fn into_status(self) -> Status {
        match self {
            StepError::Operation(e) => e.into_status(),
            StepError::Host(e) => e.into_status(),
        }
    }
}

impl From<PasswordOperationError> for super::operation::Effect {
    fn from(e: PasswordOperationError) -> Self {
        Self::Refused(e.into_status())
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

#[async_trait::async_trait]
impl HistoryPreparation for RemoteHistoryEvaluator {
    async fn prepare(
        &self,
        admission: &HistoryAdmission,
    ) -> Result<Vec<HistoryEpochDescriptor>, PasswordOperationError> {
        let response = self
            .client
            .clone()
            .prepare_password_history(admission.request()?)
            .await
            .map_err(|status| {
                // The client learns that history is unavailable, not why the
                // evaluator refused this service.
                warn!(
                    "history evaluator refused preparation: {:?} {}",
                    status.code(),
                    status.message()
                );
                PasswordOperationError::Unavailable("evaluator")
            })?
            .into_inner();
        selection_of(&response).ok_or_else(|| {
            warn!(
                "history evaluator answered a malformed selection of {} epochs",
                response.epochs.len()
            );
            PasswordOperationError::Unavailable("evaluator")
        })
    }
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
        let id = operation_id(req.operation_id.as_ref()).or_status()?;
        let evaluations = self
            .evaluation
            .evaluate(&id, &req.blinded_input)
            .await
            .or_status()?;
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
        let admission = HistoryAdmission::of_request(request.get_ref()).or_status()?;
        let epochs = self.evaluation.prepare(&admission).await.or_status()?;
        Ok(Response::new(preparation_response(&epochs)))
    }
}

#[cfg(test)]
mod tests;
