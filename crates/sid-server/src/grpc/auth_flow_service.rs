// SPDX-License-Identifier: AGPL-3.0-only
//! The browser authorization consent interaction over gRPC
//! (ux/branding-theming.md, authorization consent API): the typed form of
//! the engine's review, decision and state, called by this authority's
//! sign-in page with the IdP session cookie. Every answer is `no-store`.

use std::sync::Arc;

use sid::oauth::consent::{
    ConsentReview, FlowView, Submission, SubmittedDecision, claim_request_to_wire, level_to_wire,
};
use sid_core::models::consent::allowed_sharing;
use sid_core::models::{
    AuthorizationOperationId, AuthorizationStatus, ClaimSharing as Sharing, ClaimType,
};
use sid_proto::sid::v1::authn::auth_flow_service_server::AuthFlowService;
use sid_proto::sid::v1::authn::{
    AuthorizationStep, ClaimSharing, ConsentClaim, ConsentDecision, ConsentDetails, FlowState,
    GetConsentRequest, GetFlowStateRequest, SubmitConsentRequest,
};
use sid_proto::sid::v1::ids::AuthorizationOperationId as WireOperationId;
use tonic::{Request, Response, Status};

use super::auth_service::AuthServiceImpl;

pub struct AuthFlowServiceImpl {
    auth: Arc<AuthServiceImpl>,
}

impl AuthFlowServiceImpl {
    pub fn new(auth: Arc<AuthServiceImpl>) -> Self {
        Self { auth }
    }
}

/// The operation a request names; an absent or malformed id names none.
#[allow(clippy::result_large_err)]
fn operation_of(id: Option<&WireOperationId>) -> Result<AuthorizationOperationId, Status> {
    super::convert::wire_id(id, "operation_id")
}

fn wire_operation(id: AuthorizationOperationId) -> WireOperationId {
    WireOperationId::from(id)
}

/// `message` answered with `Cache-Control: no-store` (consent-flow.md: the
/// interaction's answers carry session-bound review data).
fn no_store<T>(message: T) -> Result<Response<T>, Status> {
    let mut response = Response::new(message);
    response.metadata_mut().insert(
        "cache-control",
        tonic::metadata::MetadataValue::from_static("no-store"),
    );
    Ok(response)
}

fn wire_sharing(sharing: Sharing) -> ClaimSharing {
    match sharing {
        Sharing::None => ClaimSharing::None,
        Sharing::Static => ClaimSharing::Static,
        Sharing::Subscribed => ClaimSharing::Subscribed,
    }
}

fn details(review: ConsentReview) -> ConsentDetails {
    ConsentDetails {
        operation_id: Some(wire_operation(review.operation.id)),
        revision: review.operation.revision,
        csrf_token: review.csrf.to_vec(),
        issuer: review.issuer,
        client_id: review.client.client_id.clone(),
        client_name: review.client.client_name.clone(),
        resource: review.resource,
        scopes: review.operation.scopes.clone(),
        claims: review
            .operation
            .claim_requests
            .iter()
            .zip(&review.shown)
            .map(|(request, (_, shown))| ConsentClaim {
                name: request.claim_name.clone(),
                level: level_to_wire(request.level) as i32,
                r#type: claim_request_to_wire(request).r#type,
                justification: request.justification.clone(),
                allowed: allowed_sharing(request, shown.is_some())
                    .into_iter()
                    .map(|s| wire_sharing(s) as i32)
                    .collect(),
                // An attestation discloses only whether the value was
                // verified: `true` or `false`.
                value: shown.as_ref().map(|shown| match request.claim_type {
                    ClaimType::Data => shown.value.clone(),
                    ClaimType::Attestation => shown.verified.unwrap_or(false).to_string(),
                }),
            })
            .collect(),
        identity_display_name: review.identity,
        expires_at: Some(prost_types::Timestamp {
            seconds: review.operation.expires_at.as_second(),
            nanos: review.operation.expires_at.subsec_nanosecond(),
        }),
    }
}

fn state(view: FlowView) -> FlowState {
    let step = match view.operation.status {
        AuthorizationStatus::AwaitingConsent => AuthorizationStep::AwaitingConsent,
        AuthorizationStatus::Approved => AuthorizationStep::Approved,
        AuthorizationStatus::Denied => AuthorizationStep::Denied,
        AuthorizationStatus::Completed => AuthorizationStep::Completed,
        AuthorizationStatus::Expired => AuthorizationStep::Expired,
    };
    // Past its lifetime it waits for nothing, whatever it last recorded.
    let step = if view.continuation.is_none()
        && matches!(
            step,
            AuthorizationStep::AwaitingConsent
                | AuthorizationStep::Approved
                | AuthorizationStep::Denied
        )
        && view.operation.is_expired_at(jiff::Timestamp::now())
    {
        AuthorizationStep::Expired
    } else {
        step
    };
    FlowState {
        operation_id: Some(wire_operation(view.operation.id)),
        step: step as i32,
        continuation_uri: view.continuation.map(String::from),
    }
}

/// The decision a submission carries; an unspecified decision or sharing is
/// a malformed request, not a choice.
#[allow(clippy::result_large_err)]
fn submitted(request: &SubmitConsentRequest) -> Result<SubmittedDecision, Status> {
    let refuse = |field: &'static str, what: &'static str| {
        sid_infra::grpc_error::refuse::invalid_field(field, what)
    };
    match ConsentDecision::try_from(request.decision) {
        Ok(ConsentDecision::Deny) => Ok(SubmittedDecision::Deny),
        Ok(ConsentDecision::Approve) => request
            .choices
            .iter()
            .map(|choice| {
                let sharing = match ClaimSharing::try_from(choice.sharing) {
                    Ok(ClaimSharing::None) => Sharing::None,
                    Ok(ClaimSharing::Static) => Sharing::Static,
                    Ok(ClaimSharing::Subscribed) => Sharing::Subscribed,
                    _ => return Err(refuse("choices.sharing", "a sharing choice")),
                };
                Ok((choice.name.clone(), sharing))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(SubmittedDecision::Approve),
        _ => Err(refuse("decision", "approve or deny")),
    }
}

#[tonic::async_trait]
impl AuthFlowService for AuthFlowServiceImpl {
    async fn get_consent(
        &self,
        request: Request<GetConsentRequest>,
    ) -> Result<Response<ConsentDetails>, Status> {
        let operation = operation_of(request.get_ref().operation_id.as_ref())?;
        let review = self
            .auth
            .review_consent(request.metadata(), request.extensions().get(), operation)
            .await?;
        no_store(details(review))
    }

    async fn submit_consent(
        &self,
        request: Request<SubmitConsentRequest>,
    ) -> Result<Response<FlowState>, Status> {
        let message = request.get_ref();
        let submission = Submission {
            operation: operation_of(message.operation_id.as_ref())?,
            revision: message.revision,
            csrf: message.csrf_token.clone(),
            decision: submitted(message)?,
        };
        let view = self
            .auth
            .submit_consent(request.metadata(), request.extensions().get(), submission)
            .await?;
        no_store(state(view))
    }

    async fn get_flow_state(
        &self,
        request: Request<GetFlowStateRequest>,
    ) -> Result<Response<FlowState>, Status> {
        let operation = operation_of(request.get_ref().operation_id.as_ref())?;
        let view = self
            .auth
            .flow_state(request.metadata(), request.extensions().get(), operation)
            .await?;
        no_store(state(view))
    }
}
